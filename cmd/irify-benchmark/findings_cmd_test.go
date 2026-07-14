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
