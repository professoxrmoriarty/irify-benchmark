package diagnose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMapRuleCandidatesByRuleID(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "java", "cwe-79-xss", "java-servlet-xss.sf")
	if err := os.MkdirAll(filepath.Dir(rulePath), 0755); err != nil {
		t.Fatal(err)
	}
	content := `desc(
	title: "Java Servlet XSS"
	title_zh: "检测Java Servlet XSS漏洞"
	rule_id: "91441632-5409-4bfe-8c54-cb49e21c870d"
)
*.getParameter*(,*) as $source;
`
	if err := os.WriteFile(rulePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	candidates := MapRuleCandidates(dir, RuleLookup{
		Language: "java",
		CWE:      "CWE-79",
		RuleID:   "91441632-5409-4bfe-8c54-cb49e21c870d",
		RuleName: "检测Java Servlet XSS漏洞",
	})

	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].Path != filepath.ToSlash(rulePath) {
		t.Fatalf("candidate path = %q, want %q", candidates[0].Path, filepath.ToSlash(rulePath))
	}
	if candidates[0].Confidence != "high" {
		t.Fatalf("confidence = %q, want high", candidates[0].Confidence)
	}
	if !contains(candidates[0].MatchReasons, "rule_id") {
		t.Fatalf("match reasons missing rule_id: %#v", candidates[0].MatchReasons)
	}
}

func TestMapRuleCandidatesFallsBackToCWEDirectory(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "java", "cwe-22-path-travel", "java-path-travel.sf")
	if err := os.MkdirAll(filepath.Dir(rulePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulePath, []byte(`desc(title_zh: "检测Java路径穿越漏洞")`), 0644); err != nil {
		t.Fatal(err)
	}

	candidates := MapRuleCandidates(dir, RuleLookup{
		Language: "java",
		CWE:      "CWE-22",
		RuleName: "检测Java路径穿越漏洞",
	})

	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].Confidence == "" {
		t.Fatal("expected non-empty confidence")
	}
	if !contains(candidates[0].MatchReasons, "cwe_directory") {
		t.Fatalf("match reasons missing cwe_directory: %#v", candidates[0].MatchReasons)
	}
}

func TestMapRuleCandidatesFiltersByLanguageBeforeCWEFallback(t *testing.T) {
	dir := t.TempDir()
	javaRulePath := filepath.Join(dir, "java", "cwe-79-xss", "java-servlet-xss.sf")
	goRulePath := filepath.Join(dir, "golang", "cwe-79-xss", "go-http-xss.sf")
	for _, rulePath := range []string{javaRulePath, goRulePath} {
		if err := os.MkdirAll(filepath.Dir(rulePath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rulePath, []byte(`desc(title_zh: "检测XSS漏洞")`), 0644); err != nil {
			t.Fatal(err)
		}
	}

	candidates := MapRuleCandidates(dir, RuleLookup{
		Language: "java",
		CWE:      "CWE-79",
		RuleName: "检测XSS漏洞",
	})

	if len(candidates) != 1 {
		t.Fatalf("expected 1 java candidate, got %d: %#v", len(candidates), candidates)
	}
	if candidates[0].Path != filepath.ToSlash(javaRulePath) {
		t.Fatalf("candidate path = %q, want %q", candidates[0].Path, filepath.ToSlash(javaRulePath))
	}
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
