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
		MatchedCase     string              `json:"matched_case"`
		MatchStatus     string              `json:"match_status"`
		MatchScore      float64             `json:"match_score"`
		MatchDetails    *schema.MatchDetails `json:"match_details,omitempty"`
		CaseExpectation *schema.Expectation  `json:"case_expectation,omitempty"`
		Diagnosis       *diagnosisResult     `json:"diagnosis,omitempty"`
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
