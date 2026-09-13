package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/ashishkujoy/patchbot/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustVersion(t *testing.T, v string) *semver.Version {
	t.Helper()
	parsed, err := semver.NewVersion(v)
	require.NoError(t, err)
	return parsed
}

func Test_PrintScanSummary_ListsUpgradesAndUnresolved(t *testing.T) {
	var buf bytes.Buffer

	findings := []*internal.UpgradableFinding{
		{Module: "golang.org/x/text", CurrentModule: "golang.org/x/text", FixedVersion: mustVersion(t, "0.39.0"), SameModule: true},
		{Module: "github.com/dgrijalva/jwt-go/v4", CurrentModule: "github.com/dgrijalva/jwt-go", FixedVersion: mustVersion(t, "4.0.0-preview1"), SameModule: false},
	}
	unresolved := []*internal.UnresolvedFinding{
		{Module: "github.com/some/abandoned", Osv: "GO-2020-0000", Summary: "no fix published"},
	}

	printScanSummary(&buf, findings, unresolved)
	out := buf.String()

	assert.Contains(t, out, "2 dependencies need upgrade")
	assert.Contains(t, out, "golang.org/x/text 0.39.0")
	assert.Contains(t, out, "github.com/dgrijalva/jwt-go -> github.com/dgrijalva/jwt-go/v4 4.0.0-preview1 (cross-module fix)")
	assert.Contains(t, out, "1 vulnerabilities have no published fix, needs manual triage")
	assert.Contains(t, out, "github.com/some/abandoned (GO-2020-0000): no fix published")
}

func Test_PrintResults_SeparatesFixedFromNeedsAttention(t *testing.T) {
	var buf bytes.Buffer

	fixed := &internal.UpgradeResult{
		Finding:   &internal.UpgradableFinding{CurrentModule: "golang.org/x/text", FixedVersion: mustVersion(t, "0.39.0")},
		Applied:   true,
		BuildOK:   true,
		Committed: true,
	}
	applyFailed := &internal.UpgradeResult{
		Finding: &internal.UpgradableFinding{CurrentModule: "github.com/dgrijalva/jwt-go", FixedVersion: mustVersion(t, "4.0.0-preview1")},
		Applied: false,
		Err:     errors.New("go get github.com/dgrijalva/jwt-go/v4@v4.0.0-preview1 failed: exit status 1"),
	}
	buildFailed := &internal.UpgradeResult{
		Finding:     &internal.UpgradableFinding{CurrentModule: "github.com/some/breaking", FixedVersion: mustVersion(t, "2.0.0")},
		Applied:     true,
		BuildOK:     false,
		BuildStderr: "undefined: OldFunc",
	}
	commitFailed := &internal.UpgradeResult{
		Finding:   &internal.UpgradableFinding{CurrentModule: "github.com/some/commit-race", FixedVersion: mustVersion(t, "1.2.3")},
		Applied:   true,
		BuildOK:   true,
		Committed: false,
		CommitErr: errors.New("git commit failed: exit status 1"),
	}

	printResults(&buf, []*internal.UpgradeResult{fixed, applyFailed, buildFailed, commitFailed})
	out := buf.String()

	assert.Contains(t, out, "=== Fixed (1) ===")
	assert.Contains(t, out, "golang.org/x/text -> 0.39.0: mechanical fix, build clean, committed")

	assert.Contains(t, out, "=== Needs attention (3) ===")
	assert.Contains(t, out, "[apply failed] github.com/dgrijalva/jwt-go -> 4.0.0-preview1: go get github.com/dgrijalva/jwt-go/v4@v4.0.0-preview1 failed: exit status 1")
	assert.Contains(t, out, "[build failed] github.com/some/breaking -> 2.0.0: breaking change")
	assert.Contains(t, out, "undefined: OldFunc")
	assert.Contains(t, out, "[commit failed] github.com/some/commit-race -> 1.2.3: git commit failed: exit status 1")

	// the mechanical fix must not leak into the needs-attention section
	fixedIdx := strings.Index(out, "=== Fixed")
	attentionIdx := strings.Index(out, "=== Needs attention")
	require.Less(t, fixedIdx, attentionIdx)
	assert.False(t, strings.Contains(out[fixedIdx:attentionIdx], "jwt-go"))
}

func Test_PrintResults_NoResults_PrintsEmptySections(t *testing.T) {
	var buf bytes.Buffer

	printResults(&buf, nil)
	out := buf.String()

	assert.Contains(t, out, "=== Fixed (0) ===")
	assert.Contains(t, out, "=== Needs attention (0) ===")
}
