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

	findings, osvById := parseOutputs(buf)
	assert.NotEmpty(t, findings)
	assert.Equal(t, 6, len(findings))
	for _, finding := range findings {
		assert.NotEmpty(t, finding.Trace)
	}
	assert.NotEmpty(t, osvById)
}

func osvEntryWithSameModuleFix(id, module, fixedVersion string) OsvEntry {
	return OsvEntry{
		Id: id,
		Affected: []osvAffected{
			{
				Package: osvPackage{Name: module, Ecosystem: "Go"},
				Ranges: []osvRange{
					{Type: "SEMVER", Events: []osvEvent{{Introduced: "0"}, {Fixed: fixedVersion}}},
				},
			},
		},
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

	osvById := map[string]OsvEntry{
		"GO-2021-0113": osvEntryWithSameModuleFix("GO-2021-0113", "golang.org/x/text", p1F1V1Finding.FixedVersion),
		"GO-2021-0114": osvEntryWithSameModuleFix("GO-2021-0114", "golang.org/x/text", p1F2V1Finding.FixedVersion),
		"GO-2021-0115": osvEntryWithSameModuleFix("GO-2021-0115", "golang.org/x/text", p1F3V2Finding.FixedVersion),
		"GO-2021-0121": osvEntryWithSameModuleFix("GO-2021-0121", "github.com/x/parse", p2F1V1Finding.FixedVersion),
	}

	upgradableFindings, unresolvedFindings := toUpgradableFindings(
		[]Finding{p1F1V1Finding, p1F2V1Finding, p2F1V1Finding, p1F3V2Finding},
		osvById,
	)
	assert.Empty(t, unresolvedFindings)
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
}

func Test_Classify_SameModuleFixWins(t *testing.T) {
	entry := OsvEntry{
		Id: "GO-2026-0001",
		Affected: []osvAffected{
			{
				Package: osvPackage{Name: "golang.org/x/text", Ecosystem: "Go"},
				Ranges: []osvRange{
					{Type: "SEMVER", Events: []osvEvent{{Introduced: "0"}, {Fixed: "0.39.0"}}},
				},
			},
		},
	}

	target := classify("golang.org/x/text", entry)
	assert.NotNil(t, target)
	assert.True(t, target.SameModule)
	assert.Equal(t, "golang.org/x/text", target.Module)
	assert.Equal(t, "0.39.0", target.FixedVersion.Original())
}

func Test_Classify_CrossModuleFix(t *testing.T) {
	entry := OsvEntry{
		Id: "GO-2020-0017",
		Affected: []osvAffected{
			{
				Package: osvPackage{Name: "github.com/dgrijalva/jwt-go", Ecosystem: "Go"},
				Ranges: []osvRange{
					{Type: "SEMVER", Events: []osvEvent{{Introduced: "0.0.0-20150717181359-44718f8a89b0"}}},
				},
			},
			{
				Package: osvPackage{Name: "github.com/dgrijalva/jwt-go/v4", Ecosystem: "Go"},
				Ranges: []osvRange{
					{Type: "SEMVER", Events: []osvEvent{{Introduced: "0"}, {Fixed: "4.0.0-preview1"}}},
				},
			},
		},
	}

	target := classify("github.com/dgrijalva/jwt-go", entry)
	assert.NotNil(t, target)
	assert.False(t, target.SameModule)
	assert.Equal(t, "github.com/dgrijalva/jwt-go/v4", target.Module, "should prefer the same-base /vN path over an unrelated fork")
	assert.Equal(t, "4.0.0-preview1", target.FixedVersion.Original())
}

func Test_Classify_NoFixAvailable(t *testing.T) {
	entry := OsvEntry{
		Id: "GO-2020-0017",
		Affected: []osvAffected{
			{
				Package: osvPackage{Name: "github.com/some/unfixed-module", Ecosystem: "Go"},
				Ranges: []osvRange{
					{Type: "SEMVER", Events: []osvEvent{{Introduced: "0"}}},
				},
			},
		},
	}

	target := classify("github.com/some/unfixed-module", entry)
	assert.Nil(t, target)
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
