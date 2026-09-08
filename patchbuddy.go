package main

import (
	"context"
	"fmt"
	"strings"

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
	for i, finding := range findings {
		fmt.Printf("%s %d %s\n", strings.Repeat("*", 20), i, strings.Repeat("*", 20))
		fmt.Println(finding)
		fmt.Printf("%s %d %s\n", strings.Repeat("*", 20), i, strings.Repeat("*", 20))
	}
}
