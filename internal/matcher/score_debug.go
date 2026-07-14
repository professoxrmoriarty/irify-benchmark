// +build ignore

package main

import (
	"fmt"
	"github.com/irify/irify-benchmark/internal/matcher"
	"github.com/irify/irify-benchmark/pkg/schema"
)

func main() {
	cases := []schema.Case{
		{
			CaseID: "basic-basic24-001",
			Expectation: &schema.Expectation{
				Type: "must_alert",
				Flow: &schema.Flow{
					Source: &schema.Location{Symbol: "req.getParameter", Line: 38, File: "securibench/micro/basic/Basic24.java"},
					Sink:   &schema.Location{Symbol: "resp.sendRedirect", Line: 41, File: "securibench/micro/basic/Basic24.java"},
				},
			},
			SourceCode: "securibench/micro/basic/Basic24.java",
		},
		{
			CaseID: "sanitizers-sanitizers5-001",
			Expectation: &schema.Expectation{
				Type: "must_alert",
				Flow: &schema.Flow{
					Source: &schema.Location{Symbol: "req.getParameter", Line: 41, File: "securibench/micro/sanitizers/Sanitizers5.java"},
					Sink:   &schema.Location{Symbol: "resp.sendRedirect", Line: 46, File: "securibench/micro/sanitizers/Sanitizers5.java"},
				},
			},
			SourceCode: "securibench/micro/sanitizers/Sanitizers5.java",
		},
	}
	findings := []schema.Finding{
		{
			RuleName: "检测Java URL重定向漏洞",
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "req", Line: 37, File: "src/securibench/micro/basic/Basic24.java"},
				Sink:   &schema.Location{Symbol: "parameter[2].sendRedirect(...)", Line: 41, File: "src/securibench/micro/basic/Basic24.java"},
			},
		},
		{
			RuleName: "检测Java URL重定向漏洞",
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "req", Line: 40, File: "src/securibench/micro/sanitizers/Sanitizers5.java"},
				Sink:   &schema.Location{Symbol: "parameter[1].getParameter", Line: 41, File: "src/securibench/micro/sanitizers/Sanitizers5.java"},
			},
		},
		{
			RuleName: "检测Java URL重定向漏洞",
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "name", Line: 38, File: "src/securibench/micro/sanitizers/Sanitizers5.java"},
				Sink:   &schema.Location{Symbol: "parameter[2].sendRedirect(enc)", Line: 47, File: "src/securibench/micro/sanitizers/Sanitizers5.java"},
			},
		},
	}
	for _, c := range cases {
		fmt.Printf("=== %s ===\n", c.CaseID)
		for j, f := range findings {
			score := matcher.Score(c, f)
			fmt.Printf("  finding %d: Total=%.2f SourceMatch=%v SinkMatch=%v LineDist=%d\n", j, score.Total, score.SourceMatch, score.SinkMatch, score.LineDistance)
		}
	}
}
