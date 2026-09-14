package internal

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

// UpgradeResult is the outcome of attempting one UpgradableFinding. BuildOK
// distinguishes a "mechanical fix" (safe to auto-merge) from a confirmed
// breaking change that needs the code-fix loop / human review - see
// patchbot-breaking-upgrade-context.md §5-6. It is only meaningful when
// Applied is true.
type UpgradeResult struct {
	Finding     *UpgradableFinding
	Applied     bool
	Err         error
	BuildOK     bool
	BuildLog    string
	BuildStderr string
	Committed   bool
	CommitErr   error
	// FixAttempt is set when the build failed and a BreakingChangeFixer was
	// given to UpdateDependencies. A resolved attempt means the working tree
	// now builds clean, but it is deliberately left uncommitted - see
	// BreakingChangeFixer.
	FixAttempt *FixAttempt
}

// UpdateDependencies applies each dependency's fix, in same-module-first
// order, committing every one that builds clean. When a build fails and
// fixer is non-nil, fixer.Fix is given a chance to resolve it before moving
// on - pass nil to skip the AI fix loop entirely (e.g. no API key
// configured).
func UpdateDependencies(
	ctx context.Context,
	workdir string,
	dependencies []*UpgradableFinding,
	fixer BreakingChangeFixer,
) ([]*UpgradeResult, error) {
	if len(dependencies) == 0 {
		return nil, nil
	}
	err := createUpgradeBranch(ctx, workdir)
	if err != nil {
		return nil, err
	}

	orderedDependencies := orderBySameModuleFirst(dependencies)

	results := make([]*UpgradeResult, 0, len(orderedDependencies))
	for _, dependency := range orderedDependencies {
		result := &UpgradeResult{Finding: dependency}
		if upgradeErr := upgradeDependency(ctx, workdir, dependency); upgradeErr != nil {
			result.Err = upgradeErr
			results = append(results, result)
			continue
		}
		result.Applied = true

		buildErr, buildLog, buildStderr := runBuild(ctx, workdir)
		result.BuildOK = buildErr == nil
		result.BuildLog = buildLog
		result.BuildStderr = buildStderr

		if result.BuildOK {
			if commitErr := commitUpgrade(ctx, workdir, dependency); commitErr != nil {
				result.CommitErr = commitErr
			} else {
				result.Committed = true
			}
		} else if fixer != nil {
			result.FixAttempt = fixer.Fix(ctx, workdir, dependency, buildStderr)
		}

		results = append(results, result)
	}
	return results, nil
}

// orderBySameModuleFirst runs same-module fixes (plain version bumps) before
// cross-module fixes (import rewrites): same-module fixes are far less
// likely to fail, so applying them first keeps as many mechanical fixes as
// possible even if a later cross-module rewrite needs manual triage.
func orderBySameModuleFirst(dependencies []*UpgradableFinding) []*UpgradableFinding {
	ordered := make([]*UpgradableFinding, len(dependencies))
	copy(ordered, dependencies)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].SameModule && !ordered[j].SameModule
	})
	return ordered
}

func createUpgradeBranch(ctx context.Context, workingDir string) error {
	branchName := fmt.Sprintf("patchbot-%d", time.Now().UnixMilli())
	result, err := runCommand(ctx, workingDir, "git", "checkout", "-b", branchName)
	if err != nil {
		return fmt.Errorf("failed to create branch %s\n %s\n", branchName, result.Stderr)
	}
	fmt.Printf("Checked out patch branch %s\n", branchName)
	return nil
}

// upgradeDependency applies one UpgradableFinding. Same-module findings are a
// plain version bump. Cross-module findings additionally need every import
// of CurrentModule rewritten to Module first (go get can't do this - there's
// nothing "to get" for a path that stops being imported), followed by
// `go mod tidy` to drop the now-unreferenced old module.
func upgradeDependency(ctx context.Context, workdir string, dependency *UpgradableFinding) error {
	if !dependency.SameModule {
		if err := RewriteImports(workdir, dependency.CurrentModule, dependency.Module); err != nil {
			return fmt.Errorf("failed to rewrite imports %s -> %s: %w", dependency.CurrentModule, dependency.Module, err)
		}
	}

	target := fmt.Sprintf("%s@%s", dependency.Module, goModuleVersion(dependency.FixedVersion))
	if _, err := runCommand(ctx, workdir, "go", "get", target); err != nil {
		return fmt.Errorf("go get %s failed: %w", target, err)
	}

	if !dependency.SameModule {
		if _, err := runCommand(ctx, workdir, "go", "mod", "tidy"); err != nil {
			return fmt.Errorf("go mod tidy failed after cross-module fix: %w", err)
		}
	}

	return nil
}

// commitUpgrade commits one dependency's fix as its own commit once its
// build has been verified clean, before the next dependency is attempted -
// so a later breaking-change fix never gets bundled into the same commit as
// fixes that already landed cleanly, and a failed fix leaves the working
// tree at the last known-good commit rather than piling on top of it.
func commitUpgrade(ctx context.Context, workdir string, dependency *UpgradableFinding) error {
	if _, err := runCommand(ctx, workdir, "git", "add", "-A"); err != nil {
		return fmt.Errorf("git add failed: %w", err)
	}
	message := commitMessage(dependency)
	if result, err := runCommand(ctx, workdir, "git", "commit", "-m", message); err != nil {
		return fmt.Errorf("git commit failed: %w\n%s", err, result.Stderr)
	}
	return nil
}

func commitMessage(dependency *UpgradableFinding) string {
	version := goModuleVersion(dependency.FixedVersion)
	if dependency.SameModule {
		return fmt.Sprintf("patchbot: upgrade %s to %s", dependency.Module, version)
	}
	return fmt.Sprintf("patchbot: migrate %s to %s@%s", dependency.CurrentModule, dependency.Module, version)
}

// goModuleVersion renders a fixed version as a Go module version query. The
// vulnerability DB records fixed versions for stdlib/golang.org/x-style
// modules without the "v" prefix (e.g. "0.39.0"), but `go get module@version`
// requires it - without it, go get rejects the version as an unknown
// revision instead of resolving the real tag.
func goModuleVersion(v *semver.Version) string {
	original := v.Original()
	if strings.HasPrefix(original, "v") {
		return original
	}
	return "v" + original
}

// runBuild is the test oracle from patchbot-breaking-upgrade-context.md §4/§5:
// a clean build doesn't prove semantics are preserved, but a failing one is a
// confirmed breaking change that needs the code-fix loop rather than being
// trusted as a mechanical fix. stderr is returned separately from stdout
// since that's where the compiler error text §6 wants as seed context lands.
func runBuild(ctx context.Context, workdir string) (error, string, string) {
	result, err := runCommand(ctx, workdir, "go", "build", "./...")
	return err, result.Stdout, result.Stderr
}
