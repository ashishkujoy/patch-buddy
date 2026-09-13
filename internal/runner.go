package internal

import (
	"bytes"
	"context"
	"os/exec"
)

// commandOutput is what running an external command produced.
type commandOutput struct {
	Stdout string
	Stderr string
}

// commandRunner abstracts running an external command (git, go, govulncheck)
// so the scan/upgrade logic can be unit tested without invoking real
// binaries or touching a real repo. runCommand is the seam tests swap out;
// production code always goes through it instead of calling exec.Command
// directly.
type commandRunner func(ctx context.Context, dir, name string, args ...string) (commandOutput, error)

var runCommand commandRunner = execCommand

func execCommand(ctx context.Context, dir, name string, args ...string) (commandOutput, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return commandOutput{Stdout: stdout.String(), Stderr: stderr.String()}, err
}
