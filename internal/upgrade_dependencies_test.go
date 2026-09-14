package internal

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCall records one invocation of the runCommand seam so tests can assert
// what patchbot actually shelled out to, without running real git/go/govulncheck.
type fakeCall struct {
	dir  string
	name string
	args []string
}

// stubRunCommand replaces the package-level runCommand for the duration of
// the test and restores it afterwards. handler decides the (output, error)
// for each call and is also handed a pointer to the running call log.
func stubRunCommand(t *testing.T, handler func(call fakeCall) (commandOutput, error)) *[]fakeCall {
	t.Helper()
	calls := &[]fakeCall{}
	original := runCommand
	runCommand = func(_ context.Context, dir, name string, args ...string) (commandOutput, error) {
		call := fakeCall{dir: dir, name: name, args: args}
		*calls = append(*calls, call)
		return handler(call)
	}
	t.Cleanup(func() { runCommand = original })
	return calls
}

func mustVersion(t *testing.T, v string) *semver.Version {
	t.Helper()
	parsed, err := semver.NewVersion(v)
	require.NoError(t, err)
	return parsed
}

func Test_OrderBySameModuleFirst(t *testing.T) {
	crossModule := &UpgradableFinding{Module: "github.com/dgrijalva/jwt-go/v4", SameModule: false}
	sameModuleA := &UpgradableFinding{Module: "golang.org/x/text", SameModule: true}
	sameModuleB := &UpgradableFinding{Module: "github.com/go-sql-driver/mysql", SameModule: true}

	ordered := orderBySameModuleFirst([]*UpgradableFinding{crossModule, sameModuleA, sameModuleB})

	require.Len(t, ordered, 3)
	assert.True(t, ordered[0].SameModule)
	assert.True(t, ordered[1].SameModule)
	assert.False(t, ordered[2].SameModule)
	// stable within the same-module group
	assert.Equal(t, sameModuleA, ordered[0])
	assert.Equal(t, sameModuleB, ordered[1])
	assert.Equal(t, crossModule, ordered[2])
}

func Test_UpgradeDependency_SameModule_RunsGoGetOnly(t *testing.T) {
	calls := stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{}, nil
	})

	dependency := &UpgradableFinding{
		Module:        "golang.org/x/text",
		CurrentModule: "golang.org/x/text",
		FixedVersion:  mustVersion(t, "0.39.0"),
		SameModule:    true,
	}

	err := upgradeDependency(context.Background(), t.TempDir(), dependency)
	require.NoError(t, err)

	require.Len(t, *calls, 1)
	assert.Equal(t, "go", (*calls)[0].name)
	assert.Equal(t, []string{"get", "golang.org/x/text@v0.39.0"}, (*calls)[0].args)
}

func Test_UpgradeDependency_CrossModule_RewritesThenGetsThenTidies(t *testing.T) {
	workdir := t.TempDir()
	writeGoFile(t, workdir, "main.go", `package main

import "github.com/dgrijalva/jwt-go"

func main() { _ = jwt.MapClaims{} }
`)

	calls := stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{}, nil
	})

	dependency := &UpgradableFinding{
		Module:        "github.com/dgrijalva/jwt-go/v4",
		CurrentModule: "github.com/dgrijalva/jwt-go",
		FixedVersion:  mustVersion(t, "4.0.0-preview1"),
		SameModule:    false,
	}

	err := upgradeDependency(context.Background(), workdir, dependency)
	require.NoError(t, err)

	require.Len(t, *calls, 2)
	assert.Equal(t, []string{"get", "github.com/dgrijalva/jwt-go/v4@v4.0.0-preview1"}, (*calls)[0].args)
	assert.Equal(t, []string{"mod", "tidy"}, (*calls)[1].args)

	content := readFile(t, workdir, "main.go")
	assert.Contains(t, content, `"github.com/dgrijalva/jwt-go/v4"`)
	assert.NotContains(t, content, `"github.com/dgrijalva/jwt-go"`)
}

func Test_UpgradeDependency_GoGetFailure_ReturnsError(t *testing.T) {
	stubRunCommand(t, func(call fakeCall) (commandOutput, error) {
		if call.name == "go" && len(call.args) > 0 && call.args[0] == "get" {
			return commandOutput{Stderr: "boom"}, errors.New("exit status 1")
		}
		return commandOutput{}, nil
	})

	dependency := &UpgradableFinding{
		Module:        "golang.org/x/text",
		CurrentModule: "golang.org/x/text",
		FixedVersion:  mustVersion(t, "0.39.0"),
		SameModule:    true,
	}

	err := upgradeDependency(context.Background(), t.TempDir(), dependency)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "go get golang.org/x/text@v0.39.0 failed")
}

func Test_UpgradeDependency_TidyFailure_ReturnsError(t *testing.T) {
	stubRunCommand(t, func(call fakeCall) (commandOutput, error) {
		if call.name == "go" && len(call.args) > 0 && call.args[0] == "mod" {
			return commandOutput{}, errors.New("tidy exploded")
		}
		return commandOutput{}, nil
	})

	dependency := &UpgradableFinding{
		Module:        "github.com/dgrijalva/jwt-go/v4",
		CurrentModule: "github.com/dgrijalva/jwt-go",
		FixedVersion:  mustVersion(t, "4.0.0-preview1"),
		SameModule:    false,
	}

	err := upgradeDependency(context.Background(), t.TempDir(), dependency)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "go mod tidy failed after cross-module fix")
}

func Test_CreateUpgradeBranch_ChecksOutNewBranch(t *testing.T) {
	calls := stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{}, nil
	})

	err := createUpgradeBranch(context.Background(), t.TempDir())
	require.NoError(t, err)

	require.Len(t, *calls, 1)
	call := (*calls)[0]
	assert.Equal(t, "git", call.name)
	require.Len(t, call.args, 3)
	assert.Equal(t, []string{"checkout", "-b"}, call.args[:2])
	assert.True(t, strings.HasPrefix(call.args[2], "patchbot-"))
}

func Test_CreateUpgradeBranch_PropagatesGitError(t *testing.T) {
	stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{Stderr: "not a git repo"}, errors.New("exit status 128")
	})

	err := createUpgradeBranch(context.Background(), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a git repo")
}

func Test_RunBuild_PassesThroughOutputAndError(t *testing.T) {
	stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{Stdout: "ok", Stderr: "compile error"}, errors.New("exit status 1")
	})

	err, stdout, stderr := runBuild(context.Background(), t.TempDir())
	require.Error(t, err)
	assert.Equal(t, "ok", stdout)
	assert.Equal(t, "compile error", stderr)
}

func Test_UpdateDependencies_NoDependencies_SkipsBranchCreation(t *testing.T) {
	calls := stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{}, nil
	})

	results, err := UpdateDependencies(context.Background(), t.TempDir(), nil, nil)
	require.NoError(t, err)
	assert.Nil(t, results)
	assert.Empty(t, *calls)
}

func Test_UpdateDependencies_BranchCreationFailure_ShortCircuits(t *testing.T) {
	calls := stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{}, errors.New("checkout failed")
	})

	dependencies := []*UpgradableFinding{
		{Module: "golang.org/x/text", CurrentModule: "golang.org/x/text", FixedVersion: mustVersion(t, "0.39.0"), SameModule: true},
	}

	results, err := UpdateDependencies(context.Background(), t.TempDir(), dependencies, nil)
	require.Error(t, err)
	assert.Nil(t, results)
	// only the failed branch-creation call was made - no upgrade was attempted
	assert.Len(t, *calls, 1)
}

func Test_UpdateDependencies_ProcessesSameModuleFirstAndTracksResults(t *testing.T) {
	stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{}, nil
	})

	crossModule := &UpgradableFinding{
		Module:        "github.com/dgrijalva/jwt-go/v4",
		CurrentModule: "github.com/dgrijalva/jwt-go",
		FixedVersion:  mustVersion(t, "4.0.0-preview1"),
		SameModule:    false,
	}
	sameModule := &UpgradableFinding{
		Module:        "golang.org/x/text",
		CurrentModule: "golang.org/x/text",
		FixedVersion:  mustVersion(t, "0.39.0"),
		SameModule:    true,
	}

	results, err := UpdateDependencies(context.Background(), t.TempDir(), []*UpgradableFinding{crossModule, sameModule}, nil)
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Same(t, sameModule, results[0].Finding, "same-module fix should be applied first")
	assert.Same(t, crossModule, results[1].Finding)
	for _, result := range results {
		assert.True(t, result.Applied)
		assert.True(t, result.BuildOK)
		assert.True(t, result.Committed)
		assert.NoError(t, result.CommitErr)
	}
}

func Test_UpdateDependencies_BuildFails_SkipsCommit(t *testing.T) {
	calls := stubRunCommand(t, func(call fakeCall) (commandOutput, error) {
		if call.name == "go" && len(call.args) > 0 && call.args[0] == "build" {
			return commandOutput{Stderr: "undefined: OldFunc"}, errors.New("exit status 1")
		}
		return commandOutput{}, nil
	})

	dependencies := []*UpgradableFinding{
		{Module: "golang.org/x/text", CurrentModule: "golang.org/x/text", FixedVersion: mustVersion(t, "0.39.0"), SameModule: true},
	}

	results, err := UpdateDependencies(context.Background(), t.TempDir(), dependencies, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.True(t, results[0].Applied)
	assert.False(t, results[0].BuildOK)
	assert.False(t, results[0].Committed)
	for _, call := range *calls {
		assert.NotEqual(t, "commit", firstArgOrEmpty(call.args), "a failed build must never be committed")
	}
}

// fakeFixer is a BreakingChangeFixer test double that records how it was
// called and returns a canned FixAttempt.
type fakeFixer struct {
	attempt       *FixAttempt
	calledWorkdir string
	calledFinding *UpgradableFinding
	calledStderr  string
	invocations   int
}

func (f *fakeFixer) Fix(_ context.Context, workdir string, dependency *UpgradableFinding, buildStderr string) *FixAttempt {
	f.invocations++
	f.calledWorkdir = workdir
	f.calledFinding = dependency
	f.calledStderr = buildStderr
	return f.attempt
}

func Test_UpdateDependencies_BuildFails_InvokesFixerAndStoresAttempt(t *testing.T) {
	stubRunCommand(t, func(call fakeCall) (commandOutput, error) {
		if call.name == "go" && len(call.args) > 0 && call.args[0] == "build" {
			return commandOutput{Stderr: "undefined: OldFunc"}, errors.New("exit status 1")
		}
		return commandOutput{}, nil
	})

	dependency := &UpgradableFinding{Module: "golang.org/x/text", CurrentModule: "golang.org/x/text", FixedVersion: mustVersion(t, "0.39.0"), SameModule: true}
	fixer := &fakeFixer{attempt: &FixAttempt{Resolved: true, Iterations: 2}}
	workdir := t.TempDir()

	results, err := UpdateDependencies(context.Background(), workdir, []*UpgradableFinding{dependency}, fixer)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Same(t, fixer.attempt, results[0].FixAttempt)
	assert.Equal(t, 1, fixer.invocations)
	assert.Equal(t, workdir, fixer.calledWorkdir)
	assert.Same(t, dependency, fixer.calledFinding)
	assert.Equal(t, "undefined: OldFunc", fixer.calledStderr)
}

func Test_UpdateDependencies_BuildSucceeds_NeverInvokesFixer(t *testing.T) {
	stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{}, nil
	})

	dependency := &UpgradableFinding{Module: "golang.org/x/text", CurrentModule: "golang.org/x/text", FixedVersion: mustVersion(t, "0.39.0"), SameModule: true}
	fixer := &fakeFixer{attempt: &FixAttempt{Resolved: true}}

	results, err := UpdateDependencies(context.Background(), t.TempDir(), []*UpgradableFinding{dependency}, fixer)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, 0, fixer.invocations)
	assert.Nil(t, results[0].FixAttempt)
}

func Test_UpdateDependencies_CommitFails_MarksResultUncommitted(t *testing.T) {
	stubRunCommand(t, func(call fakeCall) (commandOutput, error) {
		if call.name == "git" && len(call.args) > 0 && call.args[0] == "commit" {
			return commandOutput{Stderr: "nothing to commit"}, errors.New("exit status 1")
		}
		return commandOutput{}, nil
	})

	dependencies := []*UpgradableFinding{
		{Module: "golang.org/x/text", CurrentModule: "golang.org/x/text", FixedVersion: mustVersion(t, "0.39.0"), SameModule: true},
	}

	results, err := UpdateDependencies(context.Background(), t.TempDir(), dependencies, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.True(t, results[0].Applied)
	assert.True(t, results[0].BuildOK)
	assert.False(t, results[0].Committed)
	require.Error(t, results[0].CommitErr)
	assert.Contains(t, results[0].CommitErr.Error(), "nothing to commit")
}

func Test_CommitUpgrade_AddsAndCommitsWithADescriptiveMessage(t *testing.T) {
	calls := stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{}, nil
	})

	sameModule := &UpgradableFinding{
		Module:        "golang.org/x/text",
		CurrentModule: "golang.org/x/text",
		FixedVersion:  mustVersion(t, "0.39.0"),
		SameModule:    true,
	}
	require.NoError(t, commitUpgrade(context.Background(), t.TempDir(), sameModule))

	require.Len(t, *calls, 2)
	assert.Equal(t, []string{"add", "-A"}, (*calls)[0].args)
	assert.Equal(t, "git", (*calls)[1].name)
	require.Len(t, (*calls)[1].args, 3)
	assert.Equal(t, "commit", (*calls)[1].args[0])
	assert.Equal(t, "-m", (*calls)[1].args[1])
	assert.Equal(t, "patchbot: upgrade golang.org/x/text to v0.39.0", (*calls)[1].args[2])

	crossModule := &UpgradableFinding{
		Module:        "github.com/dgrijalva/jwt-go/v4",
		CurrentModule: "github.com/dgrijalva/jwt-go",
		FixedVersion:  mustVersion(t, "4.0.0-preview1"),
		SameModule:    false,
	}
	assert.Equal(
		t,
		"patchbot: migrate github.com/dgrijalva/jwt-go to github.com/dgrijalva/jwt-go/v4@v4.0.0-preview1",
		commitMessage(crossModule),
	)
}

func Test_CommitUpgrade_AddFailure_ReturnsErrorWithoutCommitting(t *testing.T) {
	calls := stubRunCommand(t, func(call fakeCall) (commandOutput, error) {
		if call.name == "git" && len(call.args) > 0 && call.args[0] == "add" {
			return commandOutput{}, errors.New("add failed")
		}
		return commandOutput{}, nil
	})

	dependency := &UpgradableFinding{
		Module:        "golang.org/x/text",
		CurrentModule: "golang.org/x/text",
		FixedVersion:  mustVersion(t, "0.39.0"),
		SameModule:    true,
	}

	err := commitUpgrade(context.Background(), t.TempDir(), dependency)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "git add failed")
	assert.Len(t, *calls, 1, "commit must not run once add fails")
}

func firstArgOrEmpty(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func writeGoFile(t *testing.T, dir, name, content string) {
	t.Helper()
	err := writeFile(dir, name, content)
	require.NoError(t, err)
}
