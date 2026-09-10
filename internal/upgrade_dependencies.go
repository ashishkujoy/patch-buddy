package internal

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

func UpdateDependencies(ctx context.Context, workdir string, dependencies []*UpgradableFinding) error {
	if len(dependencies) == 0 {
		return nil
	}
	err := createUpgradeBranch(ctx, workdir)
	if err != nil {
		return err
	}
	for _, dependency := range dependencies {
		if upgradeErr := upgradeDependency(ctx, workdir, dependency); upgradeErr != nil {
			_ = fmt.Errorf("failed to upgrade %s to %s\n", dependency.Module, dependency.FixedVersion.Original())
		}
	}
	return nil
}

func createUpgradeBranch(ctx context.Context, workingDir string) error {
	branchName := fmt.Sprintf("patchbot-%d", time.Now().UnixMilli())
	cmd := exec.CommandContext(ctx, "git", "branch", branchName)
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	cmd.Dir = workingDir

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to create branch %s\n %s\n", branchName, string(stderr.Bytes()))
	}
	fmt.Printf("Created patch branch %s\n", branchName)
	return nil
}

func upgradeDependency(ctx context.Context, workdir string, dependency *UpgradableFinding) error {
	cmd := exec.CommandContext(
		ctx,
		"go",
		"get",
		fmt.Sprintf("%s@%s", dependency.Module, dependency.FixedVersion.Original()),
	)
	cmd.Dir = workdir
	return cmd.Run()
}
