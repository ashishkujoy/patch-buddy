# Context: Handling Breaking-Change Vulnerability Fixes in patchbot

## 1. Problem this covers

patchbot currently: run `govulncheck` → parse JSON → for each finding, `go get module@fixedVersion` → done.

That flow silently assumes the fix is always a same-module version bump that stays API-compatible.
Two cases break that assumption:

- **Cross-module fix**: the fixed code doesn't live at the same import path. Example:
  `github.com/dgrijalva/jwt-go` (vulnerable, no fix ever published) vs.
  `github.com/dgrijalva/jwt-go/v4` (fix published, but it's a *different Go module*).
  `go get github.com/dgrijalva/jwt-go@latest` will never fix this — there is nothing to get.
- **API-incompatible fix**: even a same-module bump, or the cross-module target, can change a
  function/method signature your code calls. The `go get` succeeds; `go build` doesn't.

This doc gives you the data source, the detection logic, a worked/validated example, and a
recommended remediation pipeline for both cases.

## 2. Data source: `govulncheck -json` already has what you need

You don't need to separately query `vuln.go.dev`. `govulncheck -json ./...` emits a stream of
concatenated JSON objects (**not** newline-delimited — parse with `json.Decoder.Decode` in a loop,
or `json.NewDecoder(r)` and call `Decode` repeatedly until `io.EOF`). Relevant object shapes:

```jsonc
// One object early in the stream: the module/version inventory (SBOM)
{"SBOM": {"go_version": "go1.27.1", "modules": [
  {"path": "github.com/govwa"},
  {"path": "golang.org/x/text", "version": "v0.3.8"},
  {"path": "github.com/dgrijalva/jwt-go", "version": "v3.2.0+incompatible"}
]}}

// One object per distinct vulnerability: the full OSV record
{"osv": {
  "id": "GO-2020-0017",
  "summary": "Authorization bypass in github.com/dgrijalva/jwt-go",
  "affected": [
    {
      "package": {"name": "github.com/dgrijalva/jwt-go", "ecosystem": "Go"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.0.0-20150717181359-44718f8a89b0"}]}],
      "ecosystem_specific": {"imports": [
        {"path": "github.com/dgrijalva/jwt-go", "symbols": ["MapClaims.VerifyAudience"]}
      ]}
    },
    {
      "package": {"name": "github.com/dgrijalva/jwt-go/v4", "ecosystem": "Go"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.0.0-preview1"}]}],
      "ecosystem_specific": {"imports": [
        {"path": "github.com/dgrijalva/jwt-go/v4", "symbols": ["MapClaims.VerifyAudience"]}
      ]}
    }
  ]
}}

// One "Finding" object per reachable vulnerability instance, with the call trace
{"Finding": {
  "osv": "GO-2020-0017",
  "fixed_version": "",                          // empty/absent when the CURRENT module path has no fix
  "trace": [
    {"module": "github.com/govwa", "function": "main"},
    {"module": "github.com/govwa", "package": "github.com/govwa/util/middleware", "function": "VerifyAPIToken"},
    {"module": "github.com/dgrijalva/jwt-go", "package": "github.com/dgrijalva/jwt-go", "function": "MapClaims.VerifyAudience"}
  ]
}}
```

Key fields to key off of:

| Field | Meaning |
|---|---|
| `osv.affected[].package.name` | a module path this OSV entry is about (there can be **more than one** — that's your cross-module signal) |
| `osv.affected[].ranges[].events[].fixed` | the fixed version *for that specific module path*, if any |
| `Finding.fixed_version` | empty string when govulncheck can't find a fix for the module path you actually import — this is the same thing the human-readable CLI renders as `Fixed in: N/A` |
| `Finding.trace` | the reachability call chain — presence of a `Finding` at all (vs. only appearing in the module/package-level summary) means it's *reachable*, i.e. actually worth fixing urgently |

## 3. Classification algorithm

For each `Finding`, resolve against its `osv.affected[]` list:

```go
type FixTarget struct {
    ModulePath    string // may differ from the currently-imported path
    FixedVersion  string
    SameModule    bool
}

func classify(currentImportPath string, osv OSV) (target *FixTarget, ok bool) {
    var sameModuleFix, altModuleFix *FixTarget

    for _, aff := range osv.Affected {
        fixed := latestFixedVersion(aff.Ranges) // walk events, find "fixed"
        if fixed == "" {
            continue
        }
        ft := &FixTarget{ModulePath: aff.Package.Name, FixedVersion: fixed}
        if aff.Package.Name == currentImportPath {
            sameModuleFix = ft
        } else {
            altModuleFix = ft // note: could be >1; prefer one that shares the "base" path,
                               // e.g. foo/v4 for foo, or the well-known community fork if you maintain a lookup table
        }
    }

    switch {
    case sameModuleFix != nil:
        sameModuleFix.SameModule = true
        return sameModuleFix, true
    case altModuleFix != nil:
        return altModuleFix, true // CROSS-MODULE CASE — flag for import-path rewrite, not just `go get`
    default:
        return nil, false // no fix published anywhere — flag for manual triage / can't auto-remediate
    }
}
```

Notes on picking `altModuleFix` when there are several: prefer a path that is the same base path
plus a `/vN` suffix (semantically "the same project, next major version") over an unrelated fork.
If you want the *practically best* target rather than the *OSV-advisory* target — e.g. for
`dgrijalva/jwt-go` the OSV-listed fix (`jwt-go/v4@v4.0.0-preview1`) is an abandoned preview, while
the ecosystem actually migrated to `github.com/golang-jwt/jwt` — keep a small manual override table
(`map[string]string` from vulnerable module path → community-preferred replacement module) that you
consult before falling back to the OSV's own `affected[]` entries. Don't try to infer this
programmatically; it's a curated list.

## 4. Validated fixture: this repo (`govwa`)

This repository (`github.com/govwa`) now has **both** cases live, wired into real call paths (not
just present in `go.mod`), so you can point integration tests at it directly.

**Case A — same-module, non-breaking (the case patchbot already handles):**

- Dependency: `golang.org/x/text v0.3.8`, called via `language.Parse(os.Args[1])` in `app.go`.
- `govulncheck` reports it under `=== Module Results ===` (not `Symbol Results` — govulncheck
  hasn't proven your code calls the *vulnerable* symbol reachably in this case) as
  `GO-2026-5970`, `Found in: golang.org/x/text@v0.3.8`, `Fixed in: golang.org/x/text@v0.39.0`.
- Expected patchbot behavior: `go get golang.org/x/text@v0.39.0`, `go build ./...` succeeds
  (public API for `language.Parse` and `unicode/norm` didn't change between these versions —
  verified by hand via `go doc -all` diff), done.

**Case B — cross-module, breaking (the new case):**

- Dependency: `github.com/dgrijalva/jwt-go v3.2.0+incompatible`, called via
  `middleware.VerifyAPIToken` → `jwt.MapClaims.VerifyAudience(apiAudience, false)`
  (`util/middleware/middleware.go`), reachable from `main()` via the `/api/status` route.
- `govulncheck` reports it under `=== Symbol Results ===` (reachable) as `GO-2020-0017`,
  `Found in: github.com/dgrijalva/jwt-go@v3.2.0+incompatible`, **`Fixed in: N/A`**, with an
  example trace: `middleware.VerifyAPIToken calls jwt.MapClaims.VerifyAudience`.
- The OSV record's `affected[]` has a second entry for `github.com/dgrijalva/jwt-go/v4`, fixed at
  `v4.0.0-preview1`.
- Confirmed breaking: `MapClaims.VerifyAudience` signature changes from
  `(cmp string, req bool) bool` (v3) to `(h *ValidationHelper, cmp string) error` (v4). A plain
  `go get` + import-path swap will **fail to compile** — this is your test oracle. Expect:
  `go build` to fail with something like `not enough arguments in call to claims.VerifyAudience`
  or a type mismatch, depending on how naively the rewrite is done.

Reproduce anytime with:
```
go build ./...
GOFLAGS=-mod=mod govulncheck -show verbose ./...
```

## 5. Remediation pipeline

```
for each Finding:
    target, ok := classify(currentImportPath, finding.osv)
    if !ok:
        report "no fix available upstream" -> human triage queue
        continue

    if target.SameModule:
        run: go get target.ModulePath@target.FixedVersion
    else:
        rewrite imports: currentImportPath -> target.ModulePath  (AST-based; see §6)
        run: go get target.ModulePath@target.FixedVersion
        run: go mod tidy

    buildErr := run("go build ./...")
    if buildErr == nil:
        run tests; re-run govulncheck to confirm the Finding is gone
        if clean -> commit / open PR as "mechanical fix"
        continue

    // buildErr != nil -> breaking change confirmed, hand off to §6
    enter code-fix loop with buildErr as the seed context
```

Treat "cross-module + build succeeds on first try" as *lucky*, not the expectation — always
gate on tests + a follow-up `govulncheck` run before trusting either branch, since a build
succeeding doesn't prove the semantics are preserved (e.g., v4's `VerifyAudience` returns an
`error` instead of `bool` — code that silently ignored the return value would compile in a
degraded form if the types happened to be compatible; they aren't here, but don't rely on the
compiler to catch every kind of behavioral drift).

## 6. The breaking-change fix loop (where an LLM step earns its keep)

This is not mechanically solvable in general — `VerifyAudience(cmp, req bool) bool` →
`VerifyAudience(h *ValidationHelper, cmp string) error` requires understanding intent, not just
syntax. Recommended loop:

1. **Seed context** for the LLM step, per broken call site:
   - The Go compiler error verbatim (`go build ./... 2>&1`).
   - `go doc <oldModule>.<Symbol>` and `go doc <newModule>.<Symbol>` (old vs. new signature/doc).
   - The actual call site source (a few lines of surrounding context, via `go/ast` or just the
     file + line/col from the compiler error).
   - The OSV `summary`/`details` text — it often states *why* the API changed (e.g. "audience
     verification will be bypassed... if req set to false"), which matters for producing a
     correct fix rather than a merely-compiling one (e.g. don't just pass `req: true`
     mechanically if the new API removed that parameter entirely for a security reason).
2. **Apply** the proposed patch (unified diff, applied via `go/ast` rewrite or a plain patch tool).
3. **Rebuild.** If it still fails, feed the *new* error back in; cap at ~3-5 iterations.
4. **Verify**, don't just trust "it compiles":
   - `go vet ./...`
   - existing test suite (if none exist for the touched package, flag that as a gap rather than
     treating a clean build as sufficient)
   - re-run `govulncheck`; confirm the specific `Finding` for this OSV ID is gone
5. **Never auto-merge a breaking-case fix silently.** Route it to a PR/review queue distinct from
   the "mechanical, same-module, build-still-clean" fixes — those two categories deserve different
   trust levels in whatever changelog/notification patchbot produces.

## 7. Gotchas learned building this fixture (apply generally)

- **`+incompatible` suffix**: pre-module-era major versions (like `jwt-go` v3) show up in `go.mod`
  as `v3.2.0+incompatible`. These have no `go.mod` of their own, so no minimum-Go-version friction —
  don't assume every legacy dependency will be this easy; check with `go list -m -versions
  <module>` and `cat $(go env GOMODCACHE)/<module>@<version>/go.mod`.
- **`go.mod` "go" directive bumps**: a fixed version can require a newer minimum Go language
  version than your project declares (e.g. `x/text@v0.39.0` requires `go 1.25.0`; this repo's
  `go.mod` says `go 1.15`). Modern toolchains (1.21+) auto-fetch a newer toolchain rather than
  failing outright, but patchbot should still detect and probably bump the `go` directive
  explicitly rather than relying on that implicit behavior — CI environments pinned to an older
  toolchain won't auto-upgrade.
- **`/vN` module path suffix convention**: Go modules encode breaking major versions in the import
  path itself (`.../v4`), which is exactly why "just bump the version string" can't work for a
  major-version fix — the whole import path changes, which means every file importing it needs an
  edit, not just `go.mod`.
- **A missing `fixed` event doesn't mean "no risk fix exists"** — it can mean the ecosystem moved
  to an entirely different, unrelated replacement module that the advisory doesn't even list
  (see `jwt-go` → `golang-jwt/jwt` in §3). Worth a curated override table for well-known abandoned
  packages rather than relying solely on OSV data.
