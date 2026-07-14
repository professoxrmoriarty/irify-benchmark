package diagnose

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type RuleLookup struct {
	Language string
	CWE      string
	RuleID   string
	RuleName string
}

func MapRuleCandidates(root string, lookup RuleLookup) []RuleCandidate {
	var candidates []RuleCandidate
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".sf" {
			return nil
		}
		contentBytes, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := strings.ToLower(string(contentBytes))
		pathSlash := filepath.ToSlash(path)
		pathLower := strings.ToLower(pathSlash)
		if lookup.Language != "" && !strings.Contains(pathLower, "/"+strings.ToLower(lookup.Language)+"/") {
			return nil
		}

		var reasons []string
		if lookup.RuleID != "" && strings.Contains(content, strings.ToLower(lookup.RuleID)) {
			reasons = append(reasons, "rule_id")
		}
		if lookup.CWE != "" && cweMatchesPath(pathLower, lookup.CWE) {
			reasons = append(reasons, "cwe_directory")
		}
		if lookup.RuleName != "" && strings.Contains(content, strings.ToLower(lookup.RuleName)) {
			reasons = append(reasons, "rule_name")
		}
		if len(reasons) == 0 {
			return nil
		}
		candidates = append(candidates, RuleCandidate{
			Path:         pathSlash,
			MatchReasons: reasons,
			Confidence:   confidenceForReasons(reasons),
		})
		return nil
	})

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Confidence != candidates[j].Confidence {
			return confidenceRank(candidates[i].Confidence) > confidenceRank(candidates[j].Confidence)
		}
		return candidates[i].Path < candidates[j].Path
	})
	return candidates
}

func cweMatchesPath(pathLower, cwe string) bool {
	cweLower := strings.ToLower(strings.ReplaceAll(cwe, "_", "-"))
	number := strings.TrimPrefix(cweLower, "cwe-")
	return strings.Contains(pathLower, cweLower) || strings.Contains(pathLower, "cwe-"+number)
}

func confidenceForReasons(reasons []string) string {
	hasRuleID := false
	hasCWE := false
	for _, reason := range reasons {
		if reason == "rule_id" {
			hasRuleID = true
		}
		if reason == "cwe_directory" {
			hasCWE = true
		}
	}
	if hasRuleID {
		return string(ConfidenceHigh)
	}
	if hasCWE && len(reasons) >= 2 {
		return string(ConfidenceMedium)
	}
	return string(ConfidenceLow)
}

func confidenceRank(conf string) int {
	switch conf {
	case string(ConfidenceHigh):
		return 3
	case string(ConfidenceMedium):
		return 2
	default:
		return 1
	}
}
