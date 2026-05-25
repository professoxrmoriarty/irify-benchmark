package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/irify/irify-benchmark/internal/reporter"
	"github.com/irify/irify-benchmark/pkg/schema"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <input-json> <output-html>\n", os.Args[0])
		os.Exit(1)
	}

	inputPath := os.Args[1]
	outputPath := os.Args[2]

	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		os.Exit(1)
	}

	var result schema.Result
	if err := json.Unmarshal(data, &result); err != nil {
		fmt.Fprintf(os.Stderr, "parse JSON: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create output: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	rep := &reporter.HTMLReporter{}
	if err := rep.Render(&result, f); err != nil {
		fmt.Fprintf(os.Stderr, "render HTML: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("HTML report generated: %s\n", outputPath)
}
