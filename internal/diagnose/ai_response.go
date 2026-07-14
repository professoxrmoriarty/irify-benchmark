package diagnose

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type AIResponseValidation struct {
	Valid    bool                     `json:"valid"`
	Errors   []string                 `json:"errors,omitempty"`
	Counts   AIResponseValidationStat `json:"counts"`
	Response *AIResponseContract      `json:"response,omitempty"`
}

type AIResponseValidationStat struct {
	RootCauses      int `json:"root_causes"`
	RuleSuggestions int `json:"rule_suggestions"`
	BenchmarkFixes  int `json:"benchmark_fixes"`
	ValidationSteps int `json:"validation_steps"`
	Uncertainties   int `json:"uncertainties"`
}

type AIResponseContract struct {
	RootCauses      []AIRootCause      `json:"root_causes"`
	RuleSuggestions []AIRuleSuggestion `json:"rule_suggestions"`
	BenchmarkFixes  []AIBenchmarkFix   `json:"benchmark_fixes"`
	ValidationPlan  []string           `json:"validation_plan"`
	Uncertainties   []string           `json:"uncertainties"`
}

type AIRootCause struct {
	Category     string   `json:"category"`
	Summary      string   `json:"summary"`
	EvidenceRefs []string `json:"evidence_refs"`
	Confidence   string   `json:"confidence"`
}

type AIRuleSuggestion struct {
	RuleID             string   `json:"rule_id"`
	RuleFile           string   `json:"rule_file"`
	Reason             string   `json:"reason"`
	ReviewOnlyDiff     string   `json:"review_only_diff"`
	ValidationCommands []string `json:"validation_commands"`
}

type AIBenchmarkFix struct {
	Target             string   `json:"target"`
	Reason             string   `json:"reason"`
	CaseIDs            []string `json:"case_ids"`
	ValidationCommands []string `json:"validation_commands"`
}

var fencedJSONPattern = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*?\\})\\s*```")

func ValidateAIResponse(input []byte) AIResponseValidation {
	jsonBytes := extractAIResponseJSON(input)
	var response AIResponseContract
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(jsonBytes, &raw); err != nil {
		return AIResponseValidation{Valid: false, Errors: []string{fmt.Sprintf("invalid JSON response: %v", err)}}
	}
	if err := json.Unmarshal(jsonBytes, &response); err != nil {
		return AIResponseValidation{Valid: false, Errors: []string{fmt.Sprintf("invalid response contract: %v", err)}}
	}

	result := AIResponseValidation{
		Response: &response,
		Counts: AIResponseValidationStat{
			RootCauses:      len(response.RootCauses),
			RuleSuggestions: len(response.RuleSuggestions),
			BenchmarkFixes:  len(response.BenchmarkFixes),
			ValidationSteps: len(response.ValidationPlan),
			Uncertainties:   len(response.Uncertainties),
		},
	}
	for _, field := range []string{"root_causes", "rule_suggestions", "benchmark_fixes", "validation_plan", "uncertainties"} {
		if _, ok := raw[field]; !ok {
			result.Errors = append(result.Errors, fmt.Sprintf("missing required field %q", field))
		}
	}
	for i, item := range response.RuleSuggestions {
		if strings.TrimSpace(item.RuleID) == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("rule_suggestions[%d].rule_id is required", i))
		}
		if strings.TrimSpace(item.RuleFile) == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("rule_suggestions[%d].rule_file is required", i))
		}
		if strings.TrimSpace(item.Reason) == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("rule_suggestions[%d].reason is required", i))
		}
		if strings.TrimSpace(item.ReviewOnlyDiff) == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("rule_suggestions[%d].review_only_diff is required", i))
		}
	}
	result.Valid = len(result.Errors) == 0
	return result
}

func extractAIResponseJSON(input []byte) []byte {
	trimmed := strings.TrimSpace(string(input))
	if match := fencedJSONPattern.FindStringSubmatch(trimmed); len(match) == 2 {
		return []byte(match[1])
	}
	return []byte(trimmed)
}
