package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ashishkujoy/patchbot/internal"
)

func main() {
	workdir := flag.String("workdir", ".", "Directory where patch bot needs to run")
	flag.Parse()
	ctx := context.Background()
	err, findings, unresolved, stderr := internal.RunVulnerabilityCheck(ctx, *workdir)

	fmt.Println(stderr)
	if err != nil {
		_ = fmt.Errorf("failed to run vulnerability check: %w", err)
		os.Exit(1)
	}
	printScanSummary(os.Stdout, findings, unresolved)

	results, err := internal.UpdateDependencies(ctx, *workdir, findings)
	if err != nil {
		_ = fmt.Errorf("failed to upgrade dependencies %w", err)
		os.Exit(2)
	}

	printResults(os.Stdout, results)
}

// printScanSummary renders the findings a scan produced: dependencies that
// can be upgraded (same-module vs. cross-module fixes) and vulnerabilities
// with no published fix at all.
func printScanSummary(
	w io.Writer,
	findings []*internal.UpgradableFinding,
	unresolved []*internal.UnresolvedFinding,
) {
	_, _ = fmt.Fprintf(w, "%d dependencies need upgrade\n", len(findings))
	for _, finding := range findings {
		if finding.SameModule {
			printSameModuleFix(w, finding)
		} else {
			printCrossModuleFix(w, finding)
		}
	}
	if len(unresolved) > 0 {
		_, _ = fmt.Fprintf(
			w,
			"%d vulnerabilities have no published fix, needs manual triage\n",
			len(unresolved),
		)
		for _, u := range unresolved {
			printUnresolvedModules(w, u)
		}
	}
}

func printUnresolvedModules(w io.Writer, u *internal.UnresolvedFinding) {
	_, _ = fmt.Fprintf(w, "%s (%s): %s\n", u.Module, u.Osv, u.Summary)
}

func printCrossModuleFix(w io.Writer, finding *internal.UpgradableFinding) {
	_, _ = fmt.Fprintf(
		w,
		"%s -> %s %s (cross-module fix)\n",
		finding.CurrentModule,
		finding.Module,
		finding.FixedVersion.Original(),
	)
}

func printSameModuleFix(w io.Writer, finding *internal.UpgradableFinding) {
	_, _ = fmt.Fprintf(w, "%s %s\n", finding.Module, finding.FixedVersion.Original())
}

// printResults renders the outcome of applying upgrades, split into fixes
// that landed cleanly and results that need a human to look at, tagged with
// why (apply failed vs. build failed).
func printResults(w io.Writer, results []*internal.UpgradeResult) {
	var fixed, needsAttention []*internal.UpgradeResult
	for _, result := range results {
		if result.Applied && result.BuildOK && result.Committed {
			fixed = append(fixed, result)
		} else {
			needsAttention = append(needsAttention, result)
		}
	}

	fmt.Fprintf(w, "\n=== Fixed (%d) ===\n", len(fixed))
	for _, result := range fixed {
		fmt.Fprintf(w, "%s -> %s: mechanical fix, build clean, committed\n", result.Finding.CurrentModule, result.Finding.FixedVersion.Original())
	}

	fmt.Fprintf(w, "\n=== Needs attention (%d) ===\n", len(needsAttention))
	for _, result := range needsAttention {
		switch {
		case !result.Applied:
			fmt.Fprintf(w, "[apply failed] %s -> %s: %s\n", result.Finding.CurrentModule, result.Finding.FixedVersion.Original(), result.Err)
		case !result.BuildOK:
			fmt.Fprintf(w, "[build failed] %s -> %s: breaking change\n%s\n", result.Finding.CurrentModule, result.Finding.FixedVersion.Original(), result.BuildStderr)
		default:
			fmt.Fprintf(w, "[commit failed] %s -> %s: %s\n", result.Finding.CurrentModule, result.Finding.FixedVersion.Original(), result.CommitErr)
		}
	}
}
