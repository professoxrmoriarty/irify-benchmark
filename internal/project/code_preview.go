package project

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/irify/irify-benchmark/pkg/schema"
	"gopkg.in/yaml.v3"
)

// PrintCaseWithPreview prints a case as YAML followed by source/sink code previews.
func PrintCaseWithPreview(projectID string, c *schema.Case) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal case: %w", err)
	}
	fmt.Println("# --- Case YAML ---")
	fmt.Print(string(data))

	if c.Expectation != nil && c.Expectation.Flow != nil {
		if c.Expectation.Flow.Source != nil {
			fmt.Println("# --- Source Preview ---")
			if err := printLocationPreview(projectID, c.Expectation.Flow.Source, "source"); err != nil {
				fmt.Printf("  (unable to preview source: %v)\n", err)
			}
		}
		if c.Expectation.Flow.Sink != nil {
			fmt.Println("# --- Sink Preview ---")
			if err := printLocationPreview(projectID, c.Expectation.Flow.Sink, "sink"); err != nil {
				fmt.Printf("  (unable to preview sink: %v)\n", err)
			}
		}
		for i := range c.Expectation.Flow.Sanitizers {
			fmt.Printf("# --- Sanitizer[%d] Preview ---\n", i)
			if err := printLocationPreview(projectID, &c.Expectation.Flow.Sanitizers[i].Location, "sanitizer"); err != nil {
				fmt.Printf("  (unable to preview sanitizer[%d]: %v)\n", i, err)
			}
		}
	}

	return nil
}

func printLocationPreview(projectID string, loc *schema.Location, label string) error {
	if loc == nil || loc.File == "" {
		return fmt.Errorf("no file specified")
	}

	path := filepath.Join("cases", projectID, "src", loc.File)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	if loc.Line < 1 || loc.Line > len(lines) {
		return fmt.Errorf("line %d out of bounds (file has %d lines)", loc.Line, len(lines))
	}

	fmt.Printf("[%s]\n", loc.File)

	// Show target line ± 2 lines.
	start := loc.Line - 2
	if start < 1 {
		start = 1
	}
	end := loc.Line + 2
	if end > len(lines) {
		end = len(lines)
	}

	for i := start; i <= end; i++ {
		prefix := "  "
		if i == loc.Line {
			prefix = "> "
		}
		fmt.Printf("%s%3d | %s\n", prefix, i, lines[i-1])
		if i == loc.Line && loc.Column > 0 {
			// Print a caret under the claimed column.
			marker := strings.Repeat(" ", 6+loc.Column) + "^"
			if loc.Symbol != "" {
				marker += " " + loc.Symbol + " (" + label + ")"
			} else {
				marker += " (" + label + ")"
			}
			fmt.Println(marker)
		}
	}

	return nil
}
