package internal

import (
	"bytes"
	"os"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
)

func Test_ParseGoVulnerabilityCheckFindings(t *testing.T) {
	buf := readFileAsBuffer(t)

	findings := parseFindings(buf)
	assert.NotEmpty(t, findings)
	assert.Equal(t, 6, len(findings))
	for _, finding := range findings {
		assert.NotEmpty(t, finding.Trace)
	}
}

func Test_MergeFindings(t *testing.T) {
	p1F1V1Finding := Finding{
		Osv:          "GO-2021-0113",
		FixedVersion: "v0.3.7",
		Trace: []trace{
			{
				Module:   "golang.org/x/text",
				Version:  "v0.3.5",
				Pkg:      "golang.org/x/text/language",
				Fn:       "Parse",
				Position: position{},
			},
		},
	}
	p1F2V1Finding := Finding{
		Osv:          "GO-2021-0114",
		FixedVersion: "v0.3.2",
		Trace: []trace{
			{
				Module:   "golang.org/x/text",
				Version:  "v0.3.5",
				Pkg:      "golang.org/x/text/language",
				Fn:       "Stringify",
				Position: position{},
			},
		},
	}
	p1F3V2Finding := Finding{
		Osv:          "GO-2021-0115",
		FixedVersion: "v0.3.8",
		Trace: []trace{
			{
				Module:   "golang.org/x/text",
				Version:  "v0.3.5",
				Pkg:      "golang.org/x/text/language",
				Fn:       "Network",
				Position: position{},
			},
		},
	}
	p2F1V1Finding := Finding{
		Osv:          "GO-2021-0121",
		FixedVersion: "v1.3.1",
		Trace: []trace{
			{
				Module:   "github.com/x/parse",
				Version:  "v0.3.5",
				Pkg:      "github.com/x/parse/language",
				Fn:       "Route",
				Position: position{},
			},
		},
	}

	upgradableFindings := toUpgradableFindings([]Finding{p1F1V1Finding, p1F2V1Finding, p2F1V1Finding, p1F3V2Finding})
	assert.Len(t, upgradableFindings, 2)
	v1, _ := semver.NewVersion("v0.3.8")
	v2, _ := semver.NewVersion("v1.3.1")

	for _, f := range upgradableFindings {
		if f.Module == "golang.org/x/text" {
			assert.Equal(t, v1, f.FixedVersion)
		}
		if f.Module == "github.com/x/parse" {
			assert.Equal(t, v2, f.FixedVersion)
		}
	}

	assert.Equal(t, UpgradableFinding{
		Module:       "golang.org/x/text",
		FixedVersion: v1,
	}, *upgradableFindings[0])
}

func readFileAsBuffer(t *testing.T) bytes.Buffer {
	file, err := os.Open("./test_data.txt")
	assert.NoError(t, err)
	defer func(file *os.File) { _ = file.Close() }(file)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(file)
	assert.NoError(t, err)
	return buf
}
