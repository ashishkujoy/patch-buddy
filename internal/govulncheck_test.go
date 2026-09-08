package internal

import (
	"bytes"
	"os"
	"testing"

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

func readFileAsBuffer(t *testing.T) bytes.Buffer {
	file, err := os.Open("./test_data.txt")
	assert.NoError(t, err)
	defer func(file *os.File) { _ = file.Close() }(file)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(file)
	assert.NoError(t, err)
	return buf
}
