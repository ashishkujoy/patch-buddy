package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// maxFixIterations bounds the breaking-change fix loop
// (patchbot-breaking-upgrade-context.md §6.3): a handful of rounds is enough
// to tell "the model is converging" from "the model is guessing" - it is not
// meant to brute-force an arbitrarily hard migration.
const maxFixIterations = 5

// patch is one proposed edit: replace the first exact occurrence of Search
// with Replace inside FilePath. Exact search/replace (rather than a unified
// diff) is enough context for the model to express any single-file edit and
// is trivial to apply/verify deterministically.
type patch struct {
	FilePath string
	Search   string
	Replace  string
}

// attemptRecord is one round of the fix loop, fed back into the next
// request so the model can see what it already tried and what broke.
type attemptRecord struct {
	Patches     []patch
	BuildStderr string
}

// fixRequest is everything a model needs to attempt one round of a
// breaking-change fix. It is rebuilt fresh (not threaded as a live
// conversation) on every call - see modelClient - which keeps each call
// self-contained and easy to fake in tests.
type fixRequest struct {
	OSVSummary   string
	OldModule    string
	NewModule    string
	OldModuleDoc string
	NewModuleDoc string
	// BuildStderr is the compiler error from the most recent build attempt.
	BuildStderr string
	// Files holds the full content (keyed by path relative to workdir) of
	// every file the compiler error references, so the model can produce an
	// exact Search string rather than guess at surrounding context.
	Files         map[string]string
	PriorAttempts []attemptRecord
}

// modelClient is the seam the breaking-change fix loop talks through, so it
// can be unit tested with a fake model instead of calling a real API.
type modelClient interface {
	// propose asks the model for the next round of patches. No patches
	// (nil, nil) means the model didn't propose a fix this round.
	propose(ctx context.Context, req fixRequest) ([]patch, error)
}

// BreakingChangeFixer attempts to resolve a confirmed breaking-change build
// failure - see patchbot-breaking-upgrade-context.md §6. UpdateDependencies
// calls it (if non-nil) after a dependency's build fails. A resolved
// FixAttempt still leaves its edits uncommitted: per §6.5, a breaking-change
// fix must never be auto-merged silently, unlike the mechanical fixes
// UpdateDependencies commits on its own.
type BreakingChangeFixer interface {
	Fix(ctx context.Context, workdir string, dependency *UpgradableFinding, buildStderr string) *FixAttempt
}

// FixAttempt is the outcome of trying to resolve a breaking-change build
// failure with a model.
type FixAttempt struct {
	Iterations  int
	Resolved    bool
	BuildStderr string
	Err         error
}

// attemptBreakingChangeFix is the loop itself, independent of which model
// client drives it: seed context in, apply proposed patches, rebuild, and
// either stop on success or feed the new compiler error back for another
// round, capped at maxFixIterations.
func attemptBreakingChangeFix(
	ctx context.Context,
	client modelClient,
	workdir string,
	dependency *UpgradableFinding,
	buildStderr string,
) *FixAttempt {
	req := fixRequest{
		OSVSummary:   dependency.Summary,
		OldModule:    dependency.CurrentModule,
		NewModule:    dependency.Module,
		OldModuleDoc: goDoc(ctx, workdir, dependency.CurrentModule),
		NewModuleDoc: goDoc(ctx, workdir, dependency.Module),
		BuildStderr:  buildStderr,
		Files:        referencedFiles(workdir, buildStderr),
	}

	attempt := &FixAttempt{}
	for iteration := 1; iteration <= maxFixIterations; iteration++ {
		attempt.Iterations = iteration

		patches, err := client.propose(ctx, req)
		if err != nil {
			attempt.Err = fmt.Errorf("model call failed on iteration %d: %w", iteration, err)
			return attempt
		}
		if len(patches) == 0 {
			attempt.Err = fmt.Errorf("model proposed no fix on iteration %d", iteration)
			return attempt
		}

		if err := applyPatches(workdir, patches); err != nil {
			attempt.Err = fmt.Errorf("failed to apply proposed patch on iteration %d: %w", iteration, err)
			return attempt
		}

		buildErr, _, newBuildStderr := runBuild(ctx, workdir)
		if buildErr == nil {
			attempt.Resolved = true
			return attempt
		}

		req.PriorAttempts = append(req.PriorAttempts, attemptRecord{Patches: patches, BuildStderr: newBuildStderr})
		req.BuildStderr = newBuildStderr
		req.Files = referencedFiles(workdir, newBuildStderr)
		attempt.BuildStderr = newBuildStderr
	}
	return attempt
}

// applyPatches applies each patch in order. A failure partway through
// leaves earlier patches in this round applied; the caller treats the whole
// round as failed regardless, and the next rebuild will reveal what's left.
func applyPatches(workdir string, patches []patch) error {
	for _, p := range patches {
		if err := applyPatch(workdir, p); err != nil {
			return err
		}
	}
	return nil
}

// applyPatch replaces the exact Search text with Replace in FilePath.
// Search must appear exactly once - an ambiguous or missing match is
// rejected rather than guessed at, since a wrong patch is worse than none.
func applyPatch(workdir string, p patch) error {
	path := filepath.Join(workdir, p.FilePath)
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", p.FilePath, err)
	}

	original := string(content)
	count := strings.Count(original, p.Search)
	switch count {
	case 0:
		return fmt.Errorf("search text not found in %s", p.FilePath)
	case 1:
		// exactly one match, proceed
	default:
		return fmt.Errorf("search text matches %d times in %s, expected exactly 1", count, p.FilePath)
	}

	updated := strings.Replace(original, p.Search, p.Replace, 1)
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", p.FilePath, err)
	}
	return nil
}

// buildErrorLocationPattern matches the "path/to/file.go:line:col:" prefix
// go build emits for each diagnostic.
var buildErrorLocationPattern = regexp.MustCompile(`(?m)^(\S+\.go):(\d+):(\d+):`)

// referencedFiles reads the full content of every file a build error
// references, keyed by the path as it appears in the error (relative to
// workdir) - the model needs the real source to produce an exact Search
// string, not just the error text.
func referencedFiles(workdir, buildStderr string) map[string]string {
	files := make(map[string]string)
	for _, match := range buildErrorLocationPattern.FindAllStringSubmatch(buildStderr, -1) {
		relPath := match[1]
		if _, ok := files[relPath]; ok {
			continue
		}
		content, err := os.ReadFile(filepath.Join(workdir, relPath))
		if err != nil {
			continue
		}
		files[relPath] = string(content)
	}
	return files
}

// goDoc runs `go doc <module>` as best-effort context for the model. It is
// not fatal if it fails - notably, for a cross-module fix, upgradeDependency
// already rewrote imports and ran `go mod tidy` before the build was
// attempted, so the OLD module may no longer be in the module graph at all.
func goDoc(ctx context.Context, workdir, module string) string {
	result, err := runCommand(ctx, workdir, "go", "doc", module)
	if err != nil {
		return ""
	}
	return result.Stdout
}

// parsePatchArguments decodes one propose_patch tool call's JSON arguments.
func parsePatchArguments(arguments string) (patch, error) {
	var args struct {
		FilePath string `json:"file_path"`
		Search   string `json:"search"`
		Replace  string `json:"replace"`
	}
	if err := json.Unmarshal([]byte(arguments), &args); err != nil {
		return patch{}, fmt.Errorf("failed to parse propose_patch arguments: %w", err)
	}
	return patch{FilePath: args.FilePath, Search: args.Search, Replace: args.Replace}, nil
}
