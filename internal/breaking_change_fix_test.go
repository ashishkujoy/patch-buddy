package internal

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// proposeResponse is one canned reply for fakeModelClient.
type proposeResponse struct {
	patches []patch
	err     error
}

// fakeModelClient drives attemptBreakingChangeFix in tests without calling a
// real model: propose returns canned responses in order and records every
// request it was asked to answer.
type fakeModelClient struct {
	responses []proposeResponse
	calls     int
	requests  []fixRequest
}

func (f *fakeModelClient) propose(_ context.Context, req fixRequest) ([]patch, error) {
	f.requests = append(f.requests, req)
	if f.calls >= len(f.responses) {
		return nil, nil
	}
	resp := f.responses[f.calls]
	f.calls++
	return resp.patches, resp.err
}

func stubGoBuildAndDoc(t *testing.T, buildErr error, buildStderr string) {
	t.Helper()
	stubRunCommand(t, func(call fakeCall) (commandOutput, error) {
		if call.name == "go" && len(call.args) > 0 && call.args[0] == "build" {
			return commandOutput{Stderr: buildStderr}, buildErr
		}
		return commandOutput{Stdout: "doc text"}, nil // go doc
	})
}

func Test_AttemptBreakingChangeFix_ResolvesOnFirstIteration(t *testing.T) {
	workdir := t.TempDir()
	require.NoError(t, writeFile(workdir, "middleware.go", `package middleware

func Verify(ok bool) error {
	return oldCall(ok)
}
`))
	stubGoBuildAndDoc(t, nil, "")

	client := &fakeModelClient{responses: []proposeResponse{
		{patches: []patch{{FilePath: "middleware.go", Search: "oldCall(ok)", Replace: "newCall(ok)"}}},
	}}

	dependency := &UpgradableFinding{CurrentModule: "old/mod", Module: "new/mod", Summary: "auth bypass"}
	attempt := attemptBreakingChangeFix(context.Background(), client, workdir, dependency, "middleware.go:4:9: undefined: oldCall")

	require.True(t, attempt.Resolved)
	assert.Equal(t, 1, attempt.Iterations)
	assert.NoError(t, attempt.Err)
	assert.Contains(t, readFile(t, workdir, "middleware.go"), "newCall(ok)")

	require.Len(t, client.requests, 1)
	req := client.requests[0]
	assert.Equal(t, "old/mod", req.OldModule)
	assert.Equal(t, "new/mod", req.NewModule)
	assert.Equal(t, "auth bypass", req.OSVSummary)
	assert.Equal(t, "doc text", req.OldModuleDoc)
	assert.Equal(t, "doc text", req.NewModuleDoc)
	assert.Contains(t, req.Files["middleware.go"], "oldCall(ok)")
}

func Test_AttemptBreakingChangeFix_ResolvesAfterSecondIteration(t *testing.T) {
	workdir := t.TempDir()
	require.NoError(t, writeFile(workdir, "a.go", "package a\n\nconst v = 1\n"))

	buildCalls := 0
	stubRunCommand(t, func(call fakeCall) (commandOutput, error) {
		if call.name == "go" && len(call.args) > 0 && call.args[0] == "build" {
			buildCalls++
			if buildCalls == 1 {
				return commandOutput{Stderr: "still broken"}, errors.New("exit status 1")
			}
			return commandOutput{}, nil
		}
		return commandOutput{}, nil
	})

	client := &fakeModelClient{responses: []proposeResponse{
		{patches: []patch{{FilePath: "a.go", Search: "v = 1", Replace: "v = 2"}}},
		{patches: []patch{{FilePath: "a.go", Search: "v = 2", Replace: "v = 3"}}},
	}}

	dependency := &UpgradableFinding{CurrentModule: "old", Module: "new"}
	attempt := attemptBreakingChangeFix(context.Background(), client, workdir, dependency, "initial error")

	require.True(t, attempt.Resolved)
	assert.Equal(t, 2, attempt.Iterations)
	assert.Contains(t, readFile(t, workdir, "a.go"), "v = 3")
	require.Len(t, client.requests, 2)
	// the second call should see the build error from the first attempt
	assert.Equal(t, "still broken", client.requests[1].BuildStderr)
	require.Len(t, client.requests[1].PriorAttempts, 1)
}

func Test_AttemptBreakingChangeFix_StopsAfterMaxIterationsWithoutResolving(t *testing.T) {
	workdir := t.TempDir()
	require.NoError(t, writeFile(workdir, "broken.go", "package broken\n\nconst v0 = true\n"))
	stubGoBuildAndDoc(t, errors.New("exit status 1"), "still broken")

	client := &fakeModelClient{}
	for i := range maxFixIterations {
		search := fmt.Sprintf("v%d = true", i)
		replace := fmt.Sprintf("v%d = true", i+1)
		client.responses = append(client.responses, proposeResponse{
			patches: []patch{{FilePath: "broken.go", Search: search, Replace: replace}},
		})
	}

	dependency := &UpgradableFinding{CurrentModule: "old", Module: "new"}
	attempt := attemptBreakingChangeFix(context.Background(), client, workdir, dependency, "initial error")

	assert.False(t, attempt.Resolved)
	assert.Equal(t, maxFixIterations, attempt.Iterations)
	assert.Equal(t, "still broken", attempt.BuildStderr)
	assert.NoError(t, attempt.Err)
	assert.Len(t, client.requests, maxFixIterations)
}

func Test_AttemptBreakingChangeFix_StopsWhenModelProposesNothing(t *testing.T) {
	stubGoBuildAndDoc(t, nil, "")
	client := &fakeModelClient{responses: []proposeResponse{{}}}

	dependency := &UpgradableFinding{CurrentModule: "old", Module: "new"}
	attempt := attemptBreakingChangeFix(context.Background(), client, t.TempDir(), dependency, "err")

	assert.False(t, attempt.Resolved)
	assert.Equal(t, 1, attempt.Iterations)
	require.Error(t, attempt.Err)
	assert.Contains(t, attempt.Err.Error(), "model proposed no fix on iteration 1")
}

func Test_AttemptBreakingChangeFix_StopsOnModelCallError(t *testing.T) {
	stubGoBuildAndDoc(t, nil, "")
	client := &fakeModelClient{responses: []proposeResponse{{err: errors.New("network down")}}}

	dependency := &UpgradableFinding{CurrentModule: "old", Module: "new"}
	attempt := attemptBreakingChangeFix(context.Background(), client, t.TempDir(), dependency, "err")

	assert.False(t, attempt.Resolved)
	require.Error(t, attempt.Err)
	assert.Contains(t, attempt.Err.Error(), "model call failed on iteration 1")
	assert.Contains(t, attempt.Err.Error(), "network down")
}

func Test_AttemptBreakingChangeFix_StopsOnPatchApplyFailure(t *testing.T) {
	workdir := t.TempDir()
	require.NoError(t, writeFile(workdir, "a.go", "package a\n"))
	calls := stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{}, nil
	})

	client := &fakeModelClient{responses: []proposeResponse{
		{patches: []patch{{FilePath: "a.go", Search: "does not exist", Replace: "x"}}},
	}}

	dependency := &UpgradableFinding{CurrentModule: "old", Module: "new"}
	attempt := attemptBreakingChangeFix(context.Background(), client, workdir, dependency, "err")

	assert.False(t, attempt.Resolved)
	require.Error(t, attempt.Err)
	assert.Contains(t, attempt.Err.Error(), "search text not found")
	for _, call := range *calls {
		assert.NotEqual(t, "build", firstArgOrEmpty(call.args), "a failed patch must never trigger a rebuild")
	}
}

func Test_ApplyPatch_ReplacesExactMatch(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeFile(dir, "f.go", "package f\n\nvar x = \"old\"\n"))

	err := applyPatch(dir, patch{FilePath: "f.go", Search: `"old"`, Replace: `"new"`})
	require.NoError(t, err)
	assert.Equal(t, "package f\n\nvar x = \"new\"\n", readFile(t, dir, "f.go"))
}

func Test_ApplyPatch_ErrorsWhenSearchTextMissing(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeFile(dir, "f.go", "package f\n"))

	err := applyPatch(dir, patch{FilePath: "f.go", Search: "nope", Replace: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "search text not found")
}

func Test_ApplyPatch_ErrorsWhenSearchTextAmbiguous(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeFile(dir, "f.go", "package f\n\nvar a = 1\nvar b = 1\n"))

	err := applyPatch(dir, patch{FilePath: "f.go", Search: "= 1", Replace: "= 2"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "matches 2 times")
}

func Test_ApplyPatch_ErrorsOnMissingFile(t *testing.T) {
	err := applyPatch(t.TempDir(), patch{FilePath: "missing.go", Search: "a", Replace: "b"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read missing.go")
}

func Test_ReferencedFiles_ExtractsFilesFromBuildErrors(t *testing.T) {
	workdir := t.TempDir()
	require.NoError(t, writeFile(workdir, "pkg/file.go", "package pkg\n"))
	stderr := "pkg/file.go:5:10: undefined: Foo\nsome other unrelated line\npkg/file.go:9:2: undefined: Bar\n"

	files := referencedFiles(workdir, stderr)
	require.Len(t, files, 1)
	assert.Equal(t, "package pkg\n", files["pkg/file.go"])
}

func Test_ReferencedFiles_SkipsFilesItCannotRead(t *testing.T) {
	files := referencedFiles(t.TempDir(), "missing.go:1:1: undefined: X\n")
	assert.Empty(t, files)
}

func Test_GoDoc_ReturnsStdout(t *testing.T) {
	stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{Stdout: "func Foo()"}, nil
	})
	assert.Equal(t, "func Foo()", goDoc(context.Background(), t.TempDir(), "example.com/mod"))
}

func Test_GoDoc_ReturnsEmptyOnError(t *testing.T) {
	stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{}, errors.New("unknown module")
	})
	assert.Equal(t, "", goDoc(context.Background(), t.TempDir(), "example.com/mod"))
}
