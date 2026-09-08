package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/ashishkujoy/patchbot/internal"
)

func main() {
	workdir := flag.String("workdir", ".", "Directory where patch bot needs to run")
	flag.Parse()
	err, findings, stderr := internal.RunVulnerabilityCheck(context.Background(), *workdir)
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
