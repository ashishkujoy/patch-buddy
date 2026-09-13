package internal

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// canned govulncheck -format=json output covering a same-module fix
// (golang.org/x/text), a cross-module fix (dgrijalva/jwt-go -> its /v4), and
// stdlib gets no scan_level entries here since only OSV+Finding records
// drive classification.
const fakeGovulncheckOutput = `
{"osv":{"id":"GO-2026-5970","summary":"Infinite loop in golang.org/x/text","affected":[{"package":{"name":"golang.org/x/text","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.39.0"}]}]}]}}
{"osv":{"id":"GO-2020-0017","summary":"Authorization bypass in github.com/dgrijalva/jwt-go","affected":[{"package":{"name":"github.com/dgrijalva/jwt-go","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0.0.0-20150717181359-44718f8a89b0"}]}]},{"package":{"name":"github.com/dgrijalva/jwt-go/v4","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.0.0-preview1"}]}]}]}}
{"finding":{"osv":"GO-2026-5970","fixed_version":"v0.39.0","trace":[{"module":"golang.org/x/text","version":"v0.3.0"}]}}
{"finding":{"osv":"GO-2020-0017","trace":[{"module":"github.com/dgrijalva/jwt-go","version":"v3.2.0+incompatible"}]}}
`

func Test_RunVulnerabilityCheck_ClassifiesFakeScannerOutput(t *testing.T) {
	stubRunCommand(t, func(call fakeCall) (commandOutput, error) {
		assert.Equal(t, "govulncheck", call.name)
		return commandOutput{Stdout: fakeGovulncheckOutput}, nil
	})

	err, upgradable, unresolved, stderr := RunVulnerabilityCheck(context.Background(), "/some/workdir")
	require.NoError(t, err)
	assert.Empty(t, stderr)
	assert.Empty(t, unresolved)
	require.Len(t, upgradable, 2)

	byModule := map[string]*UpgradableFinding{}
	for _, u := range upgradable {
		byModule[u.CurrentModule] = u
	}

	textFix := byModule["golang.org/x/text"]
	require.NotNil(t, textFix)
	assert.True(t, textFix.SameModule)
	assert.Equal(t, "0.39.0", textFix.FixedVersion.Original())

	jwtFix := byModule["github.com/dgrijalva/jwt-go"]
	require.NotNil(t, jwtFix)
	assert.False(t, jwtFix.SameModule)
	assert.Equal(t, "github.com/dgrijalva/jwt-go/v4", jwtFix.Module)
	assert.Equal(t, "4.0.0-preview1", jwtFix.FixedVersion.Original())
}

func Test_RunVulnerabilityCheck_PropagatesScanErrorButStillParses(t *testing.T) {
	stubRunCommand(t, func(fakeCall) (commandOutput, error) {
		return commandOutput{Stdout: fakeGovulncheckOutput, Stderr: "scan warning"}, errors.New("exit status 3")
	})

	err, upgradable, _, stderr := RunVulnerabilityCheck(context.Background(), "/some/workdir")
	require.Error(t, err)
	assert.Equal(t, "scan warning", stderr)
	assert.Len(t, upgradable, 2, "partial/valid JSON emitted before a non-zero exit should still be classified")
}
