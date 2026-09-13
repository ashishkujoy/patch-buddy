package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

type position struct {
	Offset   int    `json:"offset"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Filename string `json:"filename"`
}

type trace struct {
	Module   string   `json:"module"`
	Version  string   `json:"version"`
	Pkg      string   `json:"package"`
	Fn       string   `json:"function"`
	Position position `json:"position"`
}

type Finding struct {
	Osv          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []trace `json:"trace"`
}

// osvPackage identifies the module path a single OSV affected-entry describes.
type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvAffected struct {
	Package osvPackage `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

// OsvEntry is the subset of a vuln.go.dev OSV record patchbot needs to
// classify a fix: which module path(s) carry a fix, and at which version.
type OsvEntry struct {
	Id       string        `json:"id"`
	Summary  string        `json:"summary"`
	Affected []osvAffected `json:"affected"`
}

// UpgradableFinding is a fix patchbot can attempt to apply automatically.
// Module/FixedVersion is the target to `go get`; CurrentModule is the import
// path found in go.mod. They differ when the fix requires a cross-module
// import-path rewrite (see patchbot-breaking-upgrade-context.md).
type UpgradableFinding struct {
	Module        string          `json:"module"`
	CurrentModule string          `json:"current_module"`
	FixedVersion  *semver.Version `json:"fixed_version"`
	SameModule    bool            `json:"same_module"`
}

// UnresolvedFinding is a reachable vulnerability with no published fix for
// either the currently imported module path or any known alternative -
// there is nothing for patchbot to `go get`, so it needs human triage.
type UnresolvedFinding struct {
	Module  string
	Osv     string
	Summary string
}

type output struct {
	Finding Finding  `json:"finding"`
	Osv     OsvEntry `json:"osv"`
}

// RunVulnerabilityCheck reports vulnerabilities using govulncheck command.
// ensure to install govulncheck: https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
func RunVulnerabilityCheck(ctx context.Context, workdir string) (error, []*UpgradableFinding, []*UnresolvedFinding, string) {
	fmt.Println("Starting scanner")
	result, err := runCommand(ctx, workdir, "govulncheck", "-format=json", "./...")
	if err != nil {
		fmt.Printf("scan finished with error: %s\n", err)
	} else {
		fmt.Println("Scan complete")
	}
	findings, osvById := parseOutputs(result.Stdout)
	upgradableFindings, unresolvedFindings := toUpgradableFindings(findings, osvById)

	return err, upgradableFindings, unresolvedFindings, result.Stderr
}

func values[T any](m map[string]*T) []*T {
	v := make([]*T, 0, len(m))
	for _, value := range m {
		v = append(v, value)
	}
	return v
}

// toUpgradableFindings classifies each Finding against its OSV record,
// merging same-module-path findings and keeping the highest fixed version.
// Findings for which no fix is published anywhere are returned separately.
func toUpgradableFindings(findings []Finding, osvById map[string]OsvEntry) ([]*UpgradableFinding, []*UnresolvedFinding) {
	upgrades := make(map[string]*UpgradableFinding)
	unresolved := make(map[string]*UnresolvedFinding)

	for _, finding := range findings {
		currentModule := finding.Trace[0].Module
		entry, ok := osvById[finding.Osv]
		if !ok {
			_ = fmt.Errorf("no osv record found for finding %s\n", finding.Osv)
			continue
		}

		target := classify(currentModule, entry)
		if target == nil {
			unresolved[currentModule] = &UnresolvedFinding{
				Module:  currentModule,
				Osv:     finding.Osv,
				Summary: entry.Summary,
			}
			continue
		}

		upgradableFinding := &UpgradableFinding{
			Module:        target.Module,
			CurrentModule: currentModule,
			FixedVersion:  target.FixedVersion,
			SameModule:    target.SameModule,
		}
		if existing, exists := upgrades[currentModule]; exists && existing.FixedVersion.GreaterThan(target.FixedVersion) {
			upgradableFinding.FixedVersion = existing.FixedVersion
		}
		upgrades[currentModule] = upgradableFinding
	}

	return values(upgrades), values(unresolved)
}

// classify resolves an OSV record against the module path patchbot actually
// imports, returning the best fix target - or nil if no fix is published
// for the current module path or a viable alternative.
//
// A same-module fix always wins (it's a plain version bump). Otherwise, if
// the advisory only carries a fix for a different module path, that's a
// cross-module fix: the caller must rewrite import paths, not just `go get`.
// See patchbot-breaking-upgrade-context.md §3.
func classify(currentModule string, entry OsvEntry) *UpgradableFinding {
	var sameModuleFix, altModuleFix *UpgradableFinding
	altScore := -1

	for _, affected := range entry.Affected {
		fixedVersionStr := latestFixedVersion(affected.Ranges)
		if fixedVersionStr == "" {
			continue
		}
		fixedVersion, err := semver.NewVersion(fixedVersionStr)
		if err != nil {
			_ = fmt.Errorf(
				"failed to parse fixed version %s for %s\n",
				fixedVersionStr,
				affected.Package.Name,
			)
			continue
		}

		if affected.Package.Name == currentModule {
			sameModuleFix = &UpgradableFinding{
				Module:       affected.Package.Name,
				FixedVersion: fixedVersion,
				SameModule:   true,
			}
			continue
		}

		if score := altModuleScore(currentModule, affected.Package.Name); score > altScore {
			altScore = score
			altModuleFix = &UpgradableFinding{
				Module:       affected.Package.Name,
				FixedVersion: fixedVersion,
				SameModule:   false,
			}
		}
	}

	if sameModuleFix != nil {
		return sameModuleFix
	}
	return altModuleFix
}

// altModuleScore ranks a candidate alternative module path so classify can
// pick the practically best cross-module target when an advisory lists more
// than one: a same-base-path "/vN" major-version bump outranks any other
// listed module path (e.g. an unrelated fork).
//
// Some advisories only list a fix the ecosystem itself abandoned (e.g.
// jwt-go/v4's preview release) while the community migrated to an unrelated
// replacement module not present in affected[] at all - see context doc
// §3/§7. Steering classify() to such a module needs a curated
// vulnerable-path -> replacement table (deliberately not built here: it
// can't be inferred programmatically, and the replacement's own fixed
// version isn't sourced from this OSV record).
func altModuleScore(currentModule, candidate string) int {
	if isNextMajorVersionPath(currentModule, candidate) {
		return 1
	}
	return 0
}

// isNextMajorVersionPath reports whether candidate is base + "/vN", the Go
// module convention for encoding a breaking major version in the import
// path itself.
func isNextMajorVersionPath(base, candidate string) bool {
	suffix, ok := strings.CutPrefix(candidate, base+"/v")
	if !ok {
		return false
	}
	_, err := strconv.Atoi(suffix)
	return err == nil
}

// latestFixedVersion walks an affected[].ranges[].events[] list and returns
// the last "fixed" version recorded, or "" if the range is still open
// (govulncheck/the CLI renders this as `Fixed in: N/A`).
func latestFixedVersion(ranges []osvRange) string {
	var fixed string
	for _, r := range ranges {
		if r.Type != "SEMVER" {
			continue
		}
		for _, event := range r.Events {
			if event.Fixed != "" {
				fixed = event.Fixed
			}
		}
	}
	return fixed
}

// parseOutputs decodes a govulncheck -format=json stream (concatenated JSON
// objects, not newline-delimited) into the reachable Findings and an index
// of every OSV record seen, keyed by id, so each Finding can be classified
// against its full affected[] list.
func parseOutputs(stdout string) ([]Finding, map[string]OsvEntry) {
	decoder := json.NewDecoder(strings.NewReader(stdout))
	var findings []Finding
	osvById := make(map[string]OsvEntry)
	for {
		var _output output
		decodingErr := decoder.Decode(&_output)
		if decodingErr == io.EOF {
			break
		}
		if decodingErr != nil {
			continue
		}
		if _output.Osv.Id != "" {
			osvById[_output.Osv.Id] = _output.Osv
		}
		if _output.Finding.Osv != "" {
			findings = append(findings, _output.Finding)
		}
	}
	return findings, osvById
}
