package main

import (
	"context"
	"fmt"

	"github.com/ashishkujoy/patchbot/internal"
)

func main() {
	err, findings, stderr := internal.RunVulnerabilityCheck(context.Background(), ".")
	if err != nil {
		panic(err)
	}
	if stderr.Len() != 0 {
		_ = fmt.Errorf("%s", string(stderr.Bytes()))
		return
	}
	fmt.Printf("%d dependencies need upgrade\n", len(findings))
	for _, finding := range findings {
		fmt.Printf("%s %s\n", finding.Module, finding.FixedVersion.Original())
	}
}
