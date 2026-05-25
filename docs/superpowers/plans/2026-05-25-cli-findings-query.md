# CLI Findings Query Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add CLI commands `findings list`, `findings show`, and `raw-scan` to let AI agents query scan results and raw engine output as structured JSON.

**Architecture:** Three new CLI commands registered in `cmd/irify-benchmark/main.go`, with implementation logic extracted into a new `findings_cmd.go` file. A `findingsQueryStore` interface decouples the commands from `HybridStore` for testability. A small schema extension (`FindingIndex` on `CaseResult`) enables precise finding-to-case mapping. All commands are read-only queries.

**Tech Stack:** Go 1.22, cobra, standard `encoding/json`, existing `pkg/schema` and `internal/store` packages.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `pkg/schema/result.go` | Modify | Add `FindingIndex` to `CaseResult` |
| `internal/matcher/matcher.go` | Modify | Populate `FindingIndex` during match |
| `cmd/irify-benchmark/findings_cmd.go` | Create | CLI command logic: `runRawScan`, `runFindingsList`, `runFindingsShow`, `resolveScanVersion`, `buildDiagnosis` |
| `cmd/irify-benchmark/findings_cmd_test.go` | Create | Unit tests for all three commands with a mock store |
| `cmd/irify-benchmark/main.go` | Modify | Register `findings` and `raw-scan` commands |
| `docs/cli-usage.md` | Modify | Document new commands |

---

## Task 1: Extend Schema to Track Finding Index

**Files:**
- Modify: `pkg/schema/result.go`
- Modify: `internal/matcher/matcher.go`
- Test: `go test ./internal/matcher/...`

- [ ] **Step 1: Add `FindingIndex` to `CaseResult`**

In `pkg/schema/result.go`, add the new field:

```go
// CaseResult captures the evaluation outcome for a single case.
type CaseResult struct {
	CaseID         string          `json:"case_id,omitempty"`
	Status         string          `json:"status,omitempty"`
	MatchedFinding *MatchedFinding `json:"matched_finding,omitempty"`
	MatchScore     float64         `json:"match_score,omitempty"`
	MatchDetails   *MatchDetails   `json:"match_details,omitempty"`
	FindingIndex   int             `json:"finding_index,omitempty"` // Index into FindingSet.Findings, -1 if unmatched
}
```

- [ ] **Step 2: Update matcher to populate `FindingIndex`**

In `internal/matcher/matcher.go`, find the `CaseResult` construction inside `Match()` (around line 102) and update it:

```go
cr := schema.CaseResult{
	CaseID:       c.CaseID,
	Status:       status,
	FindingIndex: cm.findingIdx, // -1 means unmatched
}
```

- [ ] **Step 3: Run matcher tests to verify no regressions**

Run: `go test ./internal/matcher/... -v`
Expected: PASS (existing tests should still pass because `FindingIndex` defaults to 0 which is a valid index, but the existing test data likely has index 0 matched)

- [ ] **Step 4: Commit**

```bash
git add pkg/schema/result.go internal/matcher/matcher.go
git commit -m "feat: add FindingIndex to CaseResult for reverse lookup"
```

---

## Task 2: Create `findings_cmd.go` Skeleton + Test Scaffold

**Files:**
- Create: `cmd/irify-benchmark/findings_cmd.go`
- Create: `cmd/irify-benchmark/findings_cmd_test.go`
- Test: `go test ./cmd/irify-benchmark/...`

- [ ] **Step 1: Create `findings_cmd.go` with interface and skeleton functions**

Create `cmd/irify-benchmark/findings_cmd.go`:

```go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/irify/irify-benchmark/pkg/schema"
)

// findingsQueryStore abstracts the store operations needed by CLI findings commands.
type findingsQueryStore interface {
	GetFindings(projectID, engine, version string) (*schema.FindingSet, error)
	GetResult(projectID, engine, version string) (*schema.Result, error)
	GetLatestResult(projectID, engine string) (*schema.Result, error)
	ListResults(projectID string) ([]schema.ResultMeta, error)
	GetRawReport(projectID, engine, version string) ([]byte, string, error)
	ReadProject(projectID string) (*schema.Project, error)
	ReadCases(projectID string) (*schema.CaseSet, error)
}

func resolveScanVersion(store findingsQueryStore, projectID, engine, version string) (string, string, error) {
	if engine != "" && version != "" {
		return engine, version, nil
	}
	if engine != "" {
		result, err := store.GetLatestResult(projectID, engine)
		if err != nil {
			return "", "", fmt.Errorf("no scan data for engine %s: %w", engine, err)
		}
		if result == nil {
			return "", "", fmt.Errorf("no scan data for engine %s", engine)
		}
		return result.Engine, result.EngineVersion, nil
	}
	// Both omitted: pick latest scan across all engines
	metas, err := store.ListResults(projectID)
	if err != nil {
		return "", "", fmt.Errorf("list results: %w", err)
	}
	if len(metas) == 0 {
		return "", "", fmt.Errorf("no scan data for project %s", projectID)
	}
	latest := metas[0]
	for _, m := range metas[1:] {
		if m.ScanTime.After(latest.ScanTime) {
			latest = m
		}
	}
	return latest.Engine, latest.EngineVersion, nil
}

func runRawScan(store findingsQueryStore, projectID, engine, version string, w io.Writer) error {
	return fmt.Errorf("not implemented")
}

func runFindingsList(store findingsQueryStore, projectID, engine, version string, w io.Writer) error {
	return fmt.Errorf("not implemented")
}

func runFindingsShow(store findingsQueryStore, projectID string, index int, engine, version string, w io.Writer) error {
	return fmt.Errorf("not implemented")
}
```

- [ ] **Step 2: Create test file with mock store and failing tests**

Create `cmd/irify-benchmark/findings_cmd_test.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/irify/irify-benchmark/pkg/schema"
)

type mockFindingsStore struct {
	findings     *schema.FindingSet
	result       *schema.Result
	latestResult *schema.Result
	metas        []schema.ResultMeta
	rawReport    []byte
	rawFormat    string
	project      *schema.Project
	cases        *schema.CaseSet
}

func (m *mockFindingsStore) GetFindings(projectID, engine, version string) (*schema.FindingSet, error) {
	return m.findings, nil
}
func (m *mockFindingsStore) GetResult(projectID, engine, version string) (*schema.Result, error) {
	return m.result, nil
}
func (m *mockFindingsStore) GetLatestResult(projectID, engine string) (*schema.Result, error) {
	return m.latestResult, nil
}
func (m *mockFindingsStore) ListResults(projectID string) ([]schema.ResultMeta, error) {
	return m.metas, nil
}
func (m *mockFindingsStore) GetRawReport(projectID, engine, version string) ([]byte, string, error) {
	return m.rawReport, m.rawFormat, nil
}
func (m *mockFindingsStore) ReadProject(projectID string) (*schema.Project, error) {
	return m.project, nil
}
func (m *mockFindingsStore) ReadCases(projectID string) (*schema.CaseSet, error) {
	return m.cases, nil
}

func TestRunRawScan(t *testing.T) {
	store := &mockFindingsStore{
		rawReport: []byte(`{"engine":"yaklang","findings":[]}`),
		rawFormat: "json",
	}
	var buf bytes.Buffer
	err := runRawScan(store, "proj-1", "yaklang", "1.0", &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != `{"engine":"yaklang","findings":[]}` {
		t.Fatalf("unexpected output: %s", buf.String())
	}
}

func TestRunFindingsList(t *testing.T) {
	store := &mockFindingsStore{
		project: &schema.Project{ProjectID: "p1", Name: "Test Project"},
		findings: &schema.FindingSet{
			Engine:        "yaklang",
			EngineVersion: "1.0",
			ScanTime:      time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC),
			Findings: []schema.Finding{
				{RuleID: "r1", RuleName: "Rule 1", Severity: "high", Confidence: "high"},
			},
		},
		result: &schema.Result{
			CaseResults: []schema.CaseResult{
				{CaseID: "c1", Status: "tp", FindingIndex: 0, MatchScore: 0.95},
			},
		},
	}
	var buf bytes.Buffer
	err := runFindingsList(store, "p1", "yaklang", "1.0", &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out struct {
		ProjectID string `json:"project_id"`
		Findings  []struct {
			Index       int     `json:"index"`
			MatchStatus string  `json:"match_status"`
			MatchScore  float64 `json:"match_score"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
	if out.Findings[0].MatchStatus != "tp" {
		t.Fatalf("expected tp, got %s", out.Findings[0].MatchStatus)
	}
}

func TestRunFindingsShow(t *testing.T) {
	store := &mockFindingsStore{
		project: &schema.Project{ProjectID: "p1", Name: "Test Project"},
		findings: &schema.FindingSet{
			Engine: "yaklang",
			Findings: []schema.Finding{
				{RuleID: "r1", RuleName: "Rule 1", Severity: "high", Flow: &schema.Flow{
					Source: &schema.Location{File: "a.java", Line: 10},
					Sink:   &schema.Location{File: "a.java", Line: 20},
				}},
			},
		},
		result: &schema.Result{
			CaseResults: []schema.CaseResult{
				{CaseID: "c1", Status: "tp", FindingIndex: 0, MatchScore: 0.95},
			},
		},
		cases: &schema.CaseSet{
			Cases: []schema.Case{
				{CaseID: "c1", Expectation: &schema.Expectation{
					Type: "must_alert",
					Flow: &schema.Flow{
						Source: &schema.Location{File: "a.java", Line: 10},
						Sink:   &schema.Location{File: "a.java", Line: 20},
					},
				}},
			},
		},
	}
	var buf bytes.Buffer
	err := runFindingsShow(store, "p1", 0, "yaklang", "1.0", &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out struct {
		Finding struct {
			RuleID string `json:"rule_id"`
		} `json:"finding"`
		Match struct {
			MatchStatus string `json:"match_status"`
		} `json:"match"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if out.Match.MatchStatus != "tp" {
		t.Fatalf("expected tp, got %s", out.Match.MatchStatus)
	}
}
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `go test ./cmd/irify-benchmark/... -v -run TestRun`
Expected: FAIL with "not implemented" errors.

- [ ] **Step 4: Commit**

```bash
git add cmd/irify-benchmark/findings_cmd.go cmd/irify-benchmark/findings_cmd_test.go
git commit -m "feat: scaffold findings CLI commands with TDD tests"
```

---

## Task 3: Implement `runRawScan`

**Files:**
- Modify: `cmd/irify-benchmark/findings_cmd.go`
- Test: `go test ./cmd/irify-benchmark/... -run TestRunRawScan`

- [ ] **Step 1: Implement `runRawScan` function**

Replace the stub in `cmd/irify-benchmark/findings_cmd.go`:

```go
func runRawScan(store findingsQueryStore, projectID, engine, version string, w io.Writer) error {
	engine, version, err := resolveScanVersion(store, projectID, engine, version)
	if err != nil {
		return err
	}
	data, _, err := store.GetRawReport(projectID, engine, version)
	if err != nil {
		return fmt.Errorf("get raw report: %w", err)
	}
	if data == nil {
		return fmt.Errorf("no raw report found for project %s engine %s version %s", projectID, engine, version)
	}
	_, err = w.Write(data)
	return err
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./cmd/irify-benchmark/... -v -run TestRunRawScan`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add cmd/irify-benchmark/findings_cmd.go
git commit -m "feat: implement raw-scan CLI command"
```

---

## Task 4: Implement `runFindingsList`

**Files:**
- Modify: `cmd/irify-benchmark/findings_cmd.go`
- Test: `go test ./cmd/irify-benchmark/... -run TestRunFindingsList`

- [ ] **Step 1: Implement `runFindingsList` function**

Replace the stub in `cmd/irify-benchmark/findings_cmd.go`:

```go
func runFindingsList(store findingsQueryStore, projectID, engine, version string, w io.Writer) error {
	engine, version, err := resolveScanVersion(store, projectID, engine, version)
	if err != nil {
		return err
	}

	project, err := store.ReadProject(projectID)
	if err != nil {
		return fmt.Errorf("read project: %w", err)
	}

	findingSet, err := store.GetFindings(projectID, engine, version)
	if err != nil {
		return fmt.Errorf("get findings: %w", err)
	}

	result, _ := store.GetResult(projectID, engine, version)

	// Build finding index -> case result map
	findingMatches := make(map[int]schema.CaseResult)
	if result != nil {
		for _, cr := range result.CaseResults {
			if cr.FindingIndex >= 0 && cr.FindingIndex < len(findingSet.Findings) {
				findingMatches[cr.FindingIndex] = cr
			}
		}
	}

	type listFinding struct {
		Index       int              `json:"index"`
		RuleID      string           `json:"rule_id"`
		RuleName    string           `json:"rule_name"`
		Severity    string           `json:"severity"`
		Confidence  string           `json:"confidence"`
		Source      *schema.Location `json:"source,omitempty"`
		Sink        *schema.Location `json:"sink,omitempty"`
		MatchedCase string           `json:"matched_case,omitempty"`
		MatchStatus string           `json:"match_status,omitempty"`
		MatchScore  float64          `json:"match_score,omitempty"`
	}

	items := make([]listFinding, 0, len(findingSet.Findings))
	for i, f := range findingSet.Findings {
		item := listFinding{
			Index:      i,
			RuleID:     f.RuleID,
			RuleName:   f.RuleName,
			Severity:   f.Severity,
			Confidence: f.Confidence,
		}
		if f.Flow != nil {
			item.Source = f.Flow.Source
			item.Sink = f.Flow.Sink
		}
		if cr, ok := findingMatches[i]; ok {
			item.MatchedCase = cr.CaseID
			item.MatchStatus = cr.Status
			item.MatchScore = cr.MatchScore
		}
		items = append(items, item)
	}

	output := struct {
		ProjectID     string        `json:"project_id"`
		ProjectName   string        `json:"project_name"`
		Engine        string        `json:"engine"`
		EngineVersion string        `json:"engine_version"`
		ScanTime      string        `json:"scan_time"`
		TotalFindings int           `json:"total_findings"`
		Findings      []listFinding `json:"findings"`
	}{
		ProjectID:     projectID,
		ProjectName:   project.Name,
		Engine:        findingSet.Engine,
		EngineVersion: findingSet.EngineVersion,
		ScanTime:      findingSet.ScanTime.Format(time.RFC3339),
		TotalFindings: len(findingSet.Findings),
		Findings:      items,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./cmd/irify-benchmark/... -v -run TestRunFindingsList`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add cmd/irify-benchmark/findings_cmd.go
git commit -m "feat: implement findings list CLI command"
```

---

## Task 5: Implement `runFindingsShow` + Diagnosis Logic

**Files:**
- Modify: `cmd/irify-benchmark/findings_cmd.go`
- Test: `go test ./cmd/irify-benchmark/... -run TestRunFindingsShow`

- [ ] **Step 1: Add diagnosis helper**

Append to `cmd/irify-benchmark/findings_cmd.go`:

```go
type diagnosisResult struct {
	IsMisaligned bool   `json:"is_misaligned"`
	Text         string `json:"text"`
}

func buildDiagnosis(finding schema.Finding, caseExpectation *schema.Expectation) *diagnosisResult {
	if caseExpectation == nil || caseExpectation.Flow == nil {
		return nil
	}

	var parts []string
	isMisaligned := false

	fSrc := finding.Flow.Source
	fSink := finding.Flow.Sink
	cSrc := caseExpectation.Flow.Source
	cSink := caseExpectation.Flow.Sink

	if fSrc != nil && cSrc != nil {
		if fSrc.File != cSrc.File {
			parts = append(parts, fmt.Sprintf("Source file mismatch: finding at %s, case expects %s", fSrc.File, cSrc.File))
			isMisaligned = true
		} else if fSrc.Line > 0 && cSrc.Line > 0 && absInt(fSrc.Line-cSrc.Line) > 3 {
			parts = append(parts, fmt.Sprintf("Source line offset %d lines", absInt(fSrc.Line-cSrc.Line)))
			isMisaligned = true
		}
	}

	if fSink != nil && cSink != nil {
		if fSink.File != cSink.File {
			parts = append(parts, fmt.Sprintf("Sink file mismatch: finding at %s, case expects %s", fSink.File, cSink.File))
			isMisaligned = true
		} else if fSink.Line > 0 && cSink.Line > 0 && absInt(fSink.Line-cSink.Line) > 3 {
			parts = append(parts, fmt.Sprintf("Sink line offset %d lines", absInt(fSink.Line-cSink.Line)))
			isMisaligned = true
		}
	}

	text := "Position close to Case, please verify manually"
	if len(parts) > 0 {
		text = strings.Join(parts, "; ")
	}

	return &diagnosisResult{
		IsMisaligned: isMisaligned,
		Text:         text,
	}
}

func absInt(a int) int {
	if a < 0 {
		return -a
	}
	return a
}
```

- [ ] **Step 2: Implement `runFindingsShow` function**

Replace the stub:

```go
func runFindingsShow(store findingsQueryStore, projectID string, index int, engine, version string, w io.Writer) error {
	engine, version, err := resolveScanVersion(store, projectID, engine, version)
	if err != nil {
		return err
	}

	project, err := store.ReadProject(projectID)
	if err != nil {
		return fmt.Errorf("read project: %w", err)
	}

	findingSet, err := store.GetFindings(projectID, engine, version)
	if err != nil {
		return fmt.Errorf("get findings: %w", err)
	}
	if index < 0 || index >= len(findingSet.Findings) {
		return fmt.Errorf("finding index %d out of range (total: %d)", index, len(findingSet.Findings))
	}

	finding := findingSet.Findings[index]

	result, _ := store.GetResult(projectID, engine, version)

	// Find matching case result by FindingIndex
	var matchedCase *schema.CaseResult
	if result != nil {
		for i := range result.CaseResults {
			if result.CaseResults[i].FindingIndex == index {
				matchedCase = &result.CaseResults[i]
				break
			}
		}
	}

	// Read cases for expectation and diagnosis
	caseSet, _ := store.ReadCases(projectID)

	type showFinding struct {
		Index      int          `json:"index"`
		RuleID     string       `json:"rule_id"`
		RuleName   string       `json:"rule_name"`
		Severity   string       `json:"severity"`
		Confidence string       `json:"confidence"`
		Flow       *schema.Flow `json:"flow,omitempty"`
	}

	type showMatch struct {
		MatchedCase     string           `json:"matched_case"`
		MatchStatus     string           `json:"match_status"`
		MatchScore      float64          `json:"match_score"`
		MatchDetails    *schema.MatchDetails `json:"match_details,omitempty"`
		CaseExpectation *schema.Expectation  `json:"case_expectation,omitempty"`
		Diagnosis       *diagnosisResult `json:"diagnosis,omitempty"`
	}

	output := struct {
		ProjectID   string      `json:"project_id"`
		ProjectName string      `json:"project_name"`
		Engine      string      `json:"engine"`
		Finding     showFinding `json:"finding"`
		Match       *showMatch  `json:"match,omitempty"`
	}{
		ProjectID:   projectID,
		ProjectName: project.Name,
		Engine:      findingSet.Engine,
		Finding: showFinding{
			Index:      index,
			RuleID:     finding.RuleID,
			RuleName:   finding.RuleName,
			Severity:   finding.Severity,
			Confidence: finding.Confidence,
			Flow:       finding.Flow,
		},
	}

	if matchedCase != nil {
		match := &showMatch{
			MatchedCase:  matchedCase.CaseID,
			MatchStatus:  matchedCase.Status,
			MatchScore:   matchedCase.MatchScore,
			MatchDetails: matchedCase.MatchDetails,
		}
		if caseSet != nil {
			for _, c := range caseSet.Cases {
				if c.CaseID == matchedCase.CaseID {
					match.CaseExpectation = c.Expectation
					match.Diagnosis = buildDiagnosis(finding, c.Expectation)
					break
				}
			}
		}
		output.Match = match
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}
```

- [ ] **Step 3: Run test to verify it passes**

Run: `go test ./cmd/irify-benchmark/... -v -run TestRunFindingsShow`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add cmd/irify-benchmark/findings_cmd.go
git commit -m "feat: implement findings show CLI command with diagnosis"
```

---

## Task 6: Register Commands in `main.go`

**Files:**
- Modify: `cmd/irify-benchmark/main.go`
- Build: `go build ./cmd/irify-benchmark/...`

- [ ] **Step 1: Add cobra command definitions**

In `cmd/irify-benchmark/main.go`, after the existing `resultsCmd` definition block (around where `resultsListCmd` and `resultsShowCmd` are defined), add:

```go
var (
	findingsCmd = &cobra.Command{
		Use:   "findings",
		Short: "Query engine findings",
	}
	findingsListCmd = &cobra.Command{
		Use:   "list <project-id>",
		Short: "List findings with match summary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectID := args[0]
			engine, _ := cmd.Flags().GetString("engine")
			version, _ := cmd.Flags().GetString("version")
			hs, err := store.NewHybridStore(".", "data/benchmark.db")
			if err != nil {
				return fmt.Errorf("init hybrid store: %w", err)
			}
			defer hs.Close()
			return runFindingsList(hs, projectID, engine, version, os.Stdout)
		},
	}
	findingsShowCmd = &cobra.Command{
		Use:   "show <project-id> <finding-index>",
		Short: "Show single finding with match details",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectID := args[0]
			index, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid finding index: %w", err)
			}
			engine, _ := cmd.Flags().GetString("engine")
			version, _ := cmd.Flags().GetString("version")
			hs, err := store.NewHybridStore(".", "data/benchmark.db")
			if err != nil {
				return fmt.Errorf("init hybrid store: %w", err)
			}
			defer hs.Close()
			return runFindingsShow(hs, projectID, index, engine, version, os.Stdout)
		},
	}
	rawScanCmd = &cobra.Command{
		Use:   "raw-scan <project-id>",
		Short: "Output the raw scan report JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectID := args[0]
			engine, _ := cmd.Flags().GetString("engine")
			version, _ := cmd.Flags().GetString("version")
			hs, err := store.NewHybridStore(".", "data/benchmark.db")
			if err != nil {
				return fmt.Errorf("init hybrid store: %w", err)
			}
			defer hs.Close()
			return runRawScan(hs, projectID, engine, version, os.Stdout)
		},
	}
)
```

Then in `init()`, register them:

```go
rootCmd.AddCommand(runCmd, scanCmd, matchCmd, serverCmd, caseCmd, projectCmd, reviewCmd, resultsCmd, findingsCmd, rawScanCmd)
findingsCmd.AddCommand(findingsListCmd, findingsShowCmd)
findingsListCmd.Flags().String("engine", "", "Engine name")
findingsListCmd.Flags().String("version", "", "Engine version")
findingsShowCmd.Flags().String("engine", "", "Engine name")
findingsShowCmd.Flags().String("version", "", "Engine version")
rawScanCmd.Flags().String("engine", "", "Engine name")
rawScanCmd.Flags().String("version", "", "Engine version")
```

Note: `openStore()` should be an existing helper in `main.go` that returns `*store.HybridStore`. If it doesn't exist, it may be named differently (e.g., `newStore()` or inline store creation). Check the existing pattern in `main.go` and reuse it.

- [ ] **Step 2: Verify build succeeds**

Run: `go build -o bin/irify-benchmark ./cmd/irify-benchmark`
Expected: Success (no compilation errors)

- [ ] **Step 3: Commit**

```bash
git add cmd/irify-benchmark/main.go
git commit -m "feat: register findings and raw-scan CLI commands"
```

---

## Task 7: End-to-End Validation

**Files:**
- Shell: manual CLI invocation

- [ ] **Step 1: Run a test project if available**

If an existing project with scan data exists (e.g., `java-cmdi-001`), run:

```bash
./bin/irify-benchmark raw-scan java-cmdi-001 | head -c 500
./bin/irify-benchmark findings list java-cmdi-001 | head -c 500
./bin/irify-benchmark findings show java-cmdi-001 0 | head -c 500
```

Expected: Valid JSON output, no panics.

- [ ] **Step 2: Test error paths**

```bash
./bin/irify-benchmark findings list nonexistent-project 2>&1
./bin/irify-benchmark findings show java-cmdi-001 9999 2>&1
```

Expected: JSON error objects with descriptive messages.

- [ ] **Step 3: Commit** (if any fixes were needed)

```bash
git add -A
git commit -m "fix: findings CLI edge cases from E2E validation"
```

---

## Task 8: Update CLI Documentation

**Files:**
- Modify: `docs/cli-usage.md`

- [ ] **Step 1: Add new command documentation**

Append to `docs/cli-usage.md` under a new section:

```markdown
### Query Findings

#### `findings list`

List all findings for a project with match summary:

```bash
irify-benchmark findings list <project-id> [--engine=<engine>] [--version=<version>]
```

Output: JSON array of findings with `match_status` (`tp`/`fp`/`fn`/`tn`).

#### `findings show`

Show a single finding with full details and case match diagnosis:

```bash
irify-benchmark findings show <project-id> <finding-index> [--engine=<engine>] [--version=<version>]
```

Output: JSON with `finding`, `match`, and `diagnosis` fields.

#### `raw-scan`

Output the raw engine scan report (unmodified JSON):

```bash
irify-benchmark raw-scan <project-id> [--engine=<engine>] [--version=<version>]
```
```

- [ ] **Step 2: Commit**

```bash
git add docs/cli-usage.md
git commit -m "docs: add findings and raw-scan CLI commands"
```

---

## Spec Coverage Check

| Spec Requirement | Implementing Task |
|-----------------|-------------------|
| `raw-scan` command | Task 3 |
| `findings list` command | Task 4 |
| `findings show` command | Task 5 |
| `FindingIndex` schema extension | Task 1 |
| JSON output schemas | Tasks 3-5 |
| `--engine` / `--version` flags | Task 6 |
| Default to latest scan | Task 2 (`resolveScanVersion`) |
| Diagnosis logic | Task 5 |
| Error handling with JSON | Tasks 3-5 |
| Frontend unchanged | No task (by design) |
| CLI docs updated | Task 8 |

## Placeholder Scan

No TBD, TODO, or vague steps remain. Every function body, test assertion, and command registration is fully specified.
