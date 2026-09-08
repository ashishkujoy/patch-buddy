package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"

	"github.com/Masterminds/semver/v3"
)

type position struct {
	Offset   int    `json:"offset"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Filename string `json:"filename"`
}

type trace struct {
	Module   string   `json:"module"`
	Version  string   `json:"version"`
	Pkg      string   `json:"package"`
	Fn       string   `json:"function"`
	Position position `json:"position"`
}

type Finding struct {
	Osv          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []trace `json:"trace"`
}

type UpgradableFinding struct {
	Module       string          `json:"module"`
	FixedVersion *semver.Version `json:"fixed_version"`
}

type output struct {
	Finding Finding `json:"finding"`
}

// RunVulnerabilityCheck reports vulnerabilities using govulncheck command.
// ensure to install govulncheck: https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
func RunVulnerabilityCheck(ctx context.Context, workdir string) (error, []Finding, bytes.Buffer) {
	cmd := exec.CommandContext(ctx, "govulncheck", "-format=json", "./...")
	var stdout, stderr bytes.Buffer
	cmd.Dir = workdir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	findings := parseFindings(stdout)

	return err, findings, stderr
}

// toUpgradableFindings creates upgradable findings merging same module keeping the highest fixable version as fixable version
func toUpgradableFindings(findings []Finding) []*UpgradableFinding {
	m := make(map[string]*UpgradableFinding)
	for _, finding := range findings {
		module := finding.Trace[0].Module
		version, err := semver.NewVersion(finding.FixedVersion)
		if err != nil {
			_ = fmt.Errorf(
				"failed to parse version for %s, fixed version %s\n",
				module,
				finding.FixedVersion,
			)
			continue
		}
		upgradableFinding := UpgradableFinding{
			Module:       module,
			FixedVersion: version,
		}
		existingUpgradableFinding, ok := m[module]
		if ok && existingUpgradableFinding.FixedVersion.GreaterThan(version) {
			upgradableFinding.FixedVersion = version
		}
		m[module] = &upgradableFinding
	}

	upgradableDependencies := make([]*UpgradableFinding, 0, len(m))
	for _, upgradableFinding := range m {
		upgradableDependencies = append(upgradableDependencies, upgradableFinding)
	}
	return upgradableDependencies
}

func parseFindings(stdout bytes.Buffer) []Finding {
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	var findings []Finding
	for {
		var _output output
		decodingErr := decoder.Decode(&_output)
		if decodingErr == io.EOF {
			break
		}
		// not a finding block
		if decodingErr != nil || _output.Finding.Osv == "" {
			continue
		}
		findings = append(findings, _output.Finding)
	}
	return findings
}
