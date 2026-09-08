package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os/exec"
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
