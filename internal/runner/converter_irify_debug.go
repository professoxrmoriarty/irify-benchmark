// +build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type irifyReport struct {
	Risks map[string]irifyRisk `json:"Risks"`
}

type irifyRisk struct {
	RuleName      string              `json:"rule_name"`
	DataFlowPaths []irifyDataFlowPath `json:"data_flow_paths"`
}

type irifyDataFlowPath struct {
	Nodes []irifyDataFlowNode `json:"nodes"`
}

type irifyDataFlowNode struct {
	NodeID      string         `json:"node_id"`
	IRCode      string         `json:"ir_code"`
	CodeRange   irifyCodeRange `json:"code_range"`
	IsEntryNode bool           `json:"is_entry_node"`
}

type irifyCodeRange struct {
	StartLine int    `json:"start_line"`
	URL       string `json:"url"`
}

var knownSourcePatterns = []string{
	"getParameter", "getHeader", "getCookies", "getQueryString",
	"getInputStream", "getReader", "getAttribute",
}

func isSourceNode(node *irifyDataFlowNode) bool {
	ir := strings.ToLower(node.IRCode)
	for _, p := range knownSourcePatterns {
		if strings.Contains(ir, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func findSinkNode(nodes []irifyDataFlowNode) *irifyDataFlowNode {
	var candidates []*irifyDataFlowNode
	for i := range nodes {
		node := &nodes[i]
		if node.IsEntryNode {
			continue
		}
		if isSourceNode(node) {
			fmt.Printf("    SKIP source: line=%d ir=%s\n", node.CodeRange.StartLine, node.IRCode[:60])
			continue
		}
		if !strings.Contains(node.IRCode, "(") {
			fmt.Printf("    SKIP no-paren: line=%d ir=%s\n", node.CodeRange.StartLine, node.IRCode[:60])
			continue
		}
		fmt.Printf("    CANDIDATE: line=%d ir=%s\n", node.CodeRange.StartLine, node.IRCode[:60])
		candidates = append(candidates, node)
	}
	if len(candidates) == 0 {
		return nil
	}
	best := candidates[0]
	for _, cand := range candidates[1:] {
		if cand.CodeRange.StartLine > best.CodeRange.StartLine {
			best = cand
		}
	}
	return best
}

func main() {
	data, err := os.ReadFile("/tmp/open-redirect-debug.json")
	if err != nil {
		panic(err)
	}
	var report irifyReport
	if err := json.Unmarshal(data, &report); err != nil {
		panic(err)
	}
	for k, risk := range report.Risks {
		fmt.Printf("Risk %s: %s\n", k, risk.RuleName)
		for _, path := range risk.DataFlowPaths {
			sink := findSinkNode(path.Nodes)
			if sink != nil {
				fmt.Printf("  SELECTED SINK: line=%d ir=%s\n", sink.CodeRange.StartLine, sink.IRCode[:80])
			} else {
				fmt.Println("  NO SINK FOUND")
			}
		}
		fmt.Println()
	}
}
