// +build ignore

package main

import (
	"fmt"
	"os"
	"github.com/irify/irify-benchmark/internal/runner"
)

func main() {
	data, err := os.ReadFile("/tmp/open-redirect-debug.json")
	if err != nil {
		panic(err)
	}
	conv := &runner.IrifyConverter{}
	if !conv.Detect(data) {
		panic("not irify format")
	}
	fs, err := conv.Convert(data)
	if err != nil {
		panic(err)
	}
	for i, f := range fs.Findings {
		fmt.Printf("Finding #%d: rule=%s\n", i, f.RuleName)
		if f.Flow == nil {
			fmt.Println("  No flow")
			continue
		}
		if f.Flow.Source != nil {
			fmt.Printf("  Source: %s:%d (%s)\n", f.Flow.Source.File, f.Flow.Source.Line, f.Flow.Source.Symbol)
		}
		if f.Flow.Sink != nil {
			fmt.Printf("  Sink:   %s:%d (%s)\n", f.Flow.Sink.File, f.Flow.Sink.Line, f.Flow.Sink.Symbol)
		}
		fmt.Println()
	}
}
