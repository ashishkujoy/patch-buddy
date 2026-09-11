package main

import (
	"context"
	"flag"
	"fmt"
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
	fmt.Printf("%d dependencies need upgrade\n", len(findings))
	for _, finding := range findings {
		if finding.SameModule {
			fmt.Printf("%s %s\n", finding.Module, finding.FixedVersion.Original())
		} else {
			fmt.Printf("%s -> %s %s (cross-module fix)\n", finding.CurrentModule, finding.Module, finding.FixedVersion.Original())
		}
	}
	if len(unresolved) > 0 {
		fmt.Printf("%d vulnerabilities have no published fix, needs manual triage\n", len(unresolved))
		for _, u := range unresolved {
			fmt.Printf("%s (%s): %s\n", u.Module, u.Osv, u.Summary)
		}
	}
	results, err := internal.UpdateDependencies(ctx, *workdir, findings)
	if err != nil {
		_ = fmt.Errorf("failed to upgrade dependencies %w", err)
		os.Exit(2)
	}

	printResults(results)
}

func printResults(results []*internal.UpgradeResult) {
	var fixed, needsAttention []*internal.UpgradeResult
	for _, result := range results {
		if result.Applied && result.BuildOK {
			fixed = append(fixed, result)
		} else {
			needsAttention = append(needsAttention, result)
		}
	}

	fmt.Printf("\n=== Fixed (%d) ===\n", len(fixed))
	for _, result := range fixed {
		fmt.Printf("%s -> %s: mechanical fix, build clean\n", result.Finding.CurrentModule, result.Finding.FixedVersion.Original())
	}

	fmt.Printf("\n=== Needs attention (%d) ===\n", len(needsAttention))
	for _, result := range needsAttention {
		switch {
		case !result.Applied:
			fmt.Printf("[apply failed] %s -> %s: %s\n", result.Finding.CurrentModule, result.Finding.FixedVersion.Original(), result.Err)
		default:
			fmt.Printf("[build failed] %s -> %s: breaking change\n%s\n", result.Finding.CurrentModule, result.Finding.FixedVersion.Original(), result.BuildStderr)
		}
	}
}
