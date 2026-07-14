package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/irify/irify-benchmark/pkg/schema"
)

// SQLiteStore implements runtime storage using SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (or creates) a SQLite database at dbPath and initializes the schema.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	s := &SQLiteStore{db: db}
	if err := s.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) initSchema() error {
	schemaSQL := `
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    engine TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    scan_time TEXT NOT NULL,
    rule_id TEXT,
    rule_name TEXT,
    severity TEXT,
    confidence TEXT,
    source_file TEXT,
    source_line INTEGER,
    source_column INTEGER,
    source_symbol TEXT,
    sink_file TEXT,
    sink_line INTEGER,
    sink_column INTEGER,
    sink_symbol TEXT,
    sanitizer_count INTEGER DEFAULT 0,
    raw_json TEXT
);

CREATE TABLE IF NOT EXISTS case_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    engine TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    case_id TEXT NOT NULL,
    status TEXT NOT NULL,
    match_score REAL,
    source_match INTEGER,
    sink_match INTEGER,
    sanitizer_match INTEGER,
    trace_complete INTEGER,
    line_distance INTEGER,
    matched_finding_id INTEGER REFERENCES findings(id),
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS result_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    engine TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    total_cases INTEGER,
    tp INTEGER,
    fn INTEGER,
    fp INTEGER,
    tn INTEGER,
    recall REAL,
    precision REAL,
    f1 REAL,
    scan_time TEXT,
    UNIQUE(project_id, engine, engine_version)
);

CREATE TABLE IF NOT EXISTS pending_review (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    item_id TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    proposed_case_json TEXT NOT NULL,
    original_finding_json TEXT,
    submitted_at TEXT NOT NULL,
    reviewed_at TEXT,
    reviewer TEXT,
    review_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_engine ON findings(engine, engine_version);
CREATE INDEX IF NOT EXISTS idx_case_results_project ON case_results(project_id, engine, engine_version);
CREATE INDEX IF NOT EXISTS idx_pending_project ON pending_review(project_id, status);

CREATE TABLE IF NOT EXISTS cases_index (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    name TEXT,
    description TEXT,
    language TEXT,
    cwe TEXT,
    framework TEXT,
    tags TEXT,
    source_file TEXT,
    UNIQUE(project_id, case_id)
);
CREATE INDEX IF NOT EXISTS idx_cases_project ON cases_index(project_id);
CREATE INDEX IF NOT EXISTS idx_cases_cwe ON cases_index(cwe);
CREATE INDEX IF NOT EXISTS idx_cases_language ON cases_index(language);
CREATE INDEX IF NOT EXISTS idx_cases_search ON cases_index(name, description, case_id);

CREATE TABLE IF NOT EXISTS raw_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    engine TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'unknown',
    raw_data BLOB NOT NULL,
    stored_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, engine, engine_version)
);
CREATE INDEX IF NOT EXISTS idx_raw_reports_project ON raw_reports(project_id);
`
	_, err := s.db.Exec(schemaSQL)
	return err
}

// SaveFindings persists a set of engine findings for a project.
func (s *SQLiteStore) SaveFindings(projectID string, findings *schema.FindingSet) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(
		"DELETE FROM findings WHERE project_id = ? AND engine = ? AND engine_version = ?",
		projectID, findings.Engine, findings.EngineVersion,
	)
	if err != nil {
		return fmt.Errorf("delete old findings: %w", err)
	}

	stmt, err := tx.Prepare(`
		INSERT INTO findings (
			project_id, engine, engine_version, scan_time,
			rule_id, rule_name, severity, confidence,
			source_file, source_line, source_column, source_symbol,
			sink_file, sink_line, sink_column, sink_symbol,
			sanitizer_count, raw_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	scanTime := findings.ScanTime.Format(time.RFC3339)
	if findings.ScanTime.IsZero() {
		scanTime = time.Now().UTC().Format(time.RFC3339)
	}

	for _, f := range findings.Findings {
		rawJSON, _ := json.Marshal(f)
		sourceFile, sourceLine, sourceColumn, sourceSymbol := "", 0, 0, ""
		sinkFile, sinkLine, sinkColumn, sinkSymbol := "", 0, 0, ""
		sanitizerCount := 0

		if f.Flow != nil {
			if f.Flow.Source != nil {
				sourceFile = f.Flow.Source.File
				sourceLine = f.Flow.Source.Line
				sourceColumn = f.Flow.Source.Column
				sourceSymbol = f.Flow.Source.Symbol
			}
			if f.Flow.Sink != nil {
				sinkFile = f.Flow.Sink.File
				sinkLine = f.Flow.Sink.Line
				sinkColumn = f.Flow.Sink.Column
				sinkSymbol = f.Flow.Sink.Symbol
			}
			sanitizerCount = len(f.Flow.Sanitizers)
		}

		_, err = stmt.Exec(
			projectID, findings.Engine, findings.EngineVersion, scanTime,
			f.RuleID, f.RuleName, f.Severity, f.Confidence,
			sourceFile, sourceLine, sourceColumn, sourceSymbol,
			sinkFile, sinkLine, sinkColumn, sinkSymbol,
			sanitizerCount, string(rawJSON),
		)
		if err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
	}

	return tx.Commit()
}

// GetFindings retrieves engine findings for a specific project, engine, and version.
func (s *SQLiteStore) GetFindings(projectID, engine, version string) (*schema.FindingSet, error) {
	rows, err := s.db.Query(`
		SELECT engine, engine_version, scan_time, raw_json
		FROM findings
		WHERE project_id = ? AND engine = ? AND engine_version = ?
	`, projectID, engine, version)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()

	var findings []schema.Finding
	var scanTimeStr string
	var firstEngine, firstVersion string
	for rows.Next() {
		var rawJSON string
		if err := rows.Scan(&firstEngine, &firstVersion, &scanTimeStr, &rawJSON); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		var f schema.Finding
		if err := json.Unmarshal([]byte(rawJSON), &f); err != nil {
			return nil, fmt.Errorf("unmarshal finding: %w", err)
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	scanTime, _ := time.Parse(time.RFC3339, scanTimeStr)
	return &schema.FindingSet{
		BenchmarkID:   projectID,
		Engine:        firstEngine,
		EngineVersion: firstVersion,
		ScanTime:      scanTime,
		Findings:      findings,
	}, nil
}

// SaveResult persists an evaluation result (case results + summary) for a project.
func (s *SQLiteStore) SaveResult(projectID string, result *schema.Result) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(
		"DELETE FROM case_results WHERE project_id = ? AND engine = ? AND engine_version = ?",
		projectID, result.Engine, result.EngineVersion,
	)
	if err != nil {
		return fmt.Errorf("delete old case results: %w", err)
	}

	_, err = tx.Exec(
		"DELETE FROM result_summaries WHERE project_id = ? AND engine = ? AND engine_version = ?",
		projectID, result.Engine, result.EngineVersion,
	)
	if err != nil {
		return fmt.Errorf("delete old result summary: %w", err)
	}

	caseStmt, err := tx.Prepare(`
		INSERT INTO case_results (
			project_id, engine, engine_version, case_id, status,
			match_score, source_match, sink_match, sanitizer_match,
			trace_complete, line_distance, matched_finding_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare case result insert: %w", err)
	}
	defer caseStmt.Close()

	for _, cr := range result.CaseResults {
		sourceMatch, sinkMatch, sanitizerMatch, traceComplete := 0, 0, 0, 0
		matchScore := 0.0
		lineDistance := 0
		var matchedFindingID interface{} = nil

		if cr.MatchDetails != nil {
			if cr.MatchDetails.SourceMatch {
				sourceMatch = 1
			}
			if cr.MatchDetails.SinkMatch {
				sinkMatch = 1
			}
			if cr.MatchDetails.SanitizerMatch {
				sanitizerMatch = 1
			}
			if cr.MatchDetails.TraceComplete {
				traceComplete = 1
			}
			lineDistance = cr.MatchDetails.LineDistance
		}
		matchScore = cr.MatchScore

		// Persist the matched finding's array index so the findings list
		// command can show which finding matched which case. A negative or
		// zero FindingIndex means no match (leave NULL).
		if cr.FindingIndex >= 0 {
			matchedFindingID = cr.FindingIndex
		}

		_, err = caseStmt.Exec(
			projectID, result.Engine, result.EngineVersion, cr.CaseID, cr.Status,
			matchScore, sourceMatch, sinkMatch, sanitizerMatch,
			traceComplete, lineDistance, matchedFindingID,
		)
		if err != nil {
			return fmt.Errorf("insert case result: %w", err)
		}
	}

	scanTime := result.ScanTime.Format(time.RFC3339)
	if result.ScanTime.IsZero() {
		scanTime = time.Now().UTC().Format(time.RFC3339)
	}
	summary := result.Summary
	if summary == nil {
		summary = &schema.Summary{}
	}

	_, err = tx.Exec(`
		INSERT INTO result_summaries (
			project_id, engine, engine_version, total_cases, tp, fn, fp, tn,
			recall, precision, f1, scan_time
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, projectID, result.Engine, result.EngineVersion,
		summary.TotalCases, summary.TP, summary.FN, summary.FP, summary.TN,
		summary.Recall, summary.Precision, summary.F1, scanTime,
	)
	if err != nil {
		return fmt.Errorf("insert result summary: %w", err)
	}

	return tx.Commit()
}

// GetResult retrieves a full evaluation result for a specific project, engine, and version.
func (s *SQLiteStore) GetResult(projectID, engine, version string) (*schema.Result, error) {
	row := s.db.QueryRow(`
		SELECT total_cases, tp, fn, fp, tn, recall, precision, f1, scan_time
		FROM result_summaries
		WHERE project_id = ? AND engine = ? AND engine_version = ?
	`, projectID, engine, version)

	var summary schema.Summary
	var scanTimeStr string
	err := row.Scan(
		&summary.TotalCases, &summary.TP, &summary.FN, &summary.FP, &summary.TN,
		&summary.Recall, &summary.Precision, &summary.F1, &scanTimeStr,
	)
	if err == sql.ErrNoRows {
		return &schema.Result{BenchmarkID: projectID, Engine: engine, EngineVersion: version}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query result summary: %w", err)
	}

	scanTime, _ := time.Parse(time.RFC3339, scanTimeStr)

	rows, err := s.db.Query(`
		SELECT case_id, status, match_score, source_match, sink_match,
		       sanitizer_match, trace_complete, line_distance, matched_finding_id
		FROM case_results
		WHERE project_id = ? AND engine = ? AND engine_version = ?
	`, projectID, engine, version)
	if err != nil {
		return nil, fmt.Errorf("query case results: %w", err)
	}
	defer rows.Close()

	var caseResults []schema.CaseResult
	for rows.Next() {
		var cr schema.CaseResult
		var sourceMatch, sinkMatch, sanitizerMatch, traceComplete int
		var lineDistance int
		var matchedFindingID sql.NullInt64
		err := rows.Scan(
			&cr.CaseID, &cr.Status, &cr.MatchScore,
			&sourceMatch, &sinkMatch, &sanitizerMatch, &traceComplete, &lineDistance,
			&matchedFindingID,
		)
		if err != nil {
			return nil, fmt.Errorf("scan case result: %w", err)
		}
		if matchedFindingID.Valid {
			cr.FindingIndex = int(matchedFindingID.Int64)
		}
		cr.MatchDetails = &schema.MatchDetails{
			SourceMatch:    sourceMatch == 1,
			SinkMatch:      sinkMatch == 1,
			SanitizerMatch: sanitizerMatch == 1,
			TraceComplete:  traceComplete == 1,
			LineDistance:   lineDistance,
		}
		caseResults = append(caseResults, cr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("case results rows error: %w", err)
	}

	return &schema.Result{
		BenchmarkID:   projectID,
		Engine:        engine,
		EngineVersion: version,
		ScanTime:      scanTime,
		Summary:       &summary,
		CaseResults:   caseResults,
	}, nil
}

// GetLatestResult returns the most recent result for a project and engine.
func (s *SQLiteStore) GetLatestResult(projectID, engine string) (*schema.Result, error) {
	row := s.db.QueryRow(`
		SELECT engine_version FROM result_summaries
		WHERE project_id = ? AND engine = ?
		ORDER BY scan_time DESC LIMIT 1
	`, projectID, engine)
	var version string
	err := row.Scan(&version)
	if err == sql.ErrNoRows {
		return &schema.Result{BenchmarkID: projectID, Engine: engine}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query latest result: %w", err)
	}
	return s.GetResult(projectID, engine, version)
}

// ListResults returns summaries of all stored results for a project.
func (s *SQLiteStore) ListResults(projectID string) ([]schema.ResultMeta, error) {
	rows, err := s.db.Query(`
		SELECT project_id, engine, engine_version, scan_time
		FROM result_summaries
		WHERE project_id = ?
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("query results: %w", err)
	}
	defer rows.Close()

	var results []schema.ResultMeta
	for rows.Next() {
		var r schema.ResultMeta
		var scanTimeStr string
		if err := rows.Scan(&r.ProjectID, &r.Engine, &r.EngineVersion, &scanTimeStr); err != nil {
			return nil, fmt.Errorf("scan result meta: %w", err)
		}
		r.ScanTime, _ = time.Parse(time.RFC3339, scanTimeStr)
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return results, nil
}

// SavePendingItem inserts a pending review item for a project.
func (s *SQLiteStore) SavePendingItem(projectID string, item schema.PendingItem) error {
	proposedCaseJSON, err := json.Marshal(item.ProposedCase)
	if err != nil {
		return fmt.Errorf("marshal proposed case: %w", err)
	}
	originalFindingJSON := []byte("null")
	if item.OriginalFinding != nil {
		originalFindingJSON, err = json.Marshal(item.OriginalFinding)
		if err != nil {
			return fmt.Errorf("marshal original finding: %w", err)
		}
	}

	submittedAt := item.SubmittedAt.Format(time.RFC3339)
	if item.SubmittedAt.IsZero() {
		submittedAt = time.Now().UTC().Format(time.RFC3339)
	}

	_, err = s.db.Exec(`
		INSERT OR IGNORE INTO pending_review (
			project_id, item_id, source, status,
			proposed_case_json, original_finding_json,
			submitted_at, reviewed_at, reviewer, review_notes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, projectID, item.ItemID, item.Source, item.Status,
		string(proposedCaseJSON), string(originalFindingJSON),
		submittedAt, nil, nil, nil,
	)
	if err != nil {
		return fmt.Errorf("insert pending item: %w", err)
	}
	return nil
}

// GetPendingQueue retrieves all pending review items for a project.
func (s *SQLiteStore) GetPendingQueue(projectID string) (*schema.PendingQueue, error) {
	rows, err := s.db.Query(`
		SELECT item_id, source, status, proposed_case_json, original_finding_json,
		       submitted_at, reviewed_at, reviewer, review_notes
		FROM pending_review
		WHERE project_id = ?
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("query pending queue: %w", err)
	}
	defer rows.Close()

	var items []schema.PendingItem
	for rows.Next() {
		var item schema.PendingItem
		var proposedCaseJSON string
		var originalFindingJSON sql.NullString
		var submittedAtStr string
		var reviewedAtStr sql.NullString
		var reviewer, reviewNotes sql.NullString

		err := rows.Scan(
			&item.ItemID, &item.Source, &item.Status,
			&proposedCaseJSON, &originalFindingJSON,
			&submittedAtStr, &reviewedAtStr, &reviewer, &reviewNotes,
		)
		if err != nil {
			return nil, fmt.Errorf("scan pending item: %w", err)
		}

		item.SubmittedAt, _ = time.Parse(time.RFC3339, submittedAtStr)
		if reviewedAtStr.Valid {
			t, _ := time.Parse(time.RFC3339, reviewedAtStr.String)
			item.ReviewedAt = &t
		}
		if reviewer.Valid {
			item.Reviewer = &reviewer.String
		}
		if reviewNotes.Valid {
			item.ReviewNotes = &reviewNotes.String
		}

		if err := json.Unmarshal([]byte(proposedCaseJSON), &item.ProposedCase); err != nil {
			return nil, fmt.Errorf("unmarshal proposed case: %w", err)
		}
		if originalFindingJSON.Valid && originalFindingJSON.String != "null" && originalFindingJSON.String != "" {
			var f schema.Finding
			if err := json.Unmarshal([]byte(originalFindingJSON.String), &f); err != nil {
				return nil, fmt.Errorf("unmarshal original finding: %w", err)
			}
			item.OriginalFinding = &f
		}

		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return &schema.PendingQueue{BenchmarkID: projectID, Items: items}, nil
}

// UpdatePendingItem updates the status and review metadata of a pending item.
func (s *SQLiteStore) UpdatePendingItem(projectID, itemID, status, reviewer, notes string) error {
	reviewedAt := time.Now().UTC().Format(time.RFC3339)

	var reviewerPtr, notesPtr interface{}
	if reviewer != "" {
		reviewerPtr = reviewer
	}
	if notes != "" {
		notesPtr = notes
	}

	_, err := s.db.Exec(`
		UPDATE pending_review
		SET status = ?, reviewed_at = ?, reviewer = ?, review_notes = ?
		WHERE project_id = ? AND item_id = ?
	`, status, reviewedAt, reviewerPtr, notesPtr, projectID, itemID)
	if err != nil {
		return fmt.Errorf("update pending item: %w", err)
	}
	return nil
}

// SyncCasesIndex rebuilds the case index for a project from the provided cases.
func (s *SQLiteStore) SyncCasesIndex(projectID string, cases []schema.Case) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec("DELETE FROM cases_index WHERE project_id = ?", projectID)
	if err != nil {
		return fmt.Errorf("delete old index: %w", err)
	}

	stmt, err := tx.Prepare(`
		INSERT INTO cases_index (project_id, case_id, name, description, language, cwe, framework, tags, source_file)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, c := range cases {
		cwe, framework, tagsStr, sourceFile := "", "", "", ""
		if c.Metadata != nil {
			cwe = c.Metadata.CWE
			framework = c.Metadata.Framework
			if len(c.Metadata.Tags) > 0 {
				tagsJSON, _ := json.Marshal(c.Metadata.Tags)
				tagsStr = string(tagsJSON)
			}
		}
		if c.Expectation != nil && c.Expectation.Flow != nil && c.Expectation.Flow.Source != nil {
			sourceFile = c.Expectation.Flow.Source.File
		}

		_, err = stmt.Exec(projectID, c.CaseID, c.Name, c.Description, c.Language, cwe, framework, tagsStr, sourceFile)
		if err != nil {
			return fmt.Errorf("insert case index: %w", err)
		}
	}

	return tx.Commit()
}

// SearchCases queries the cases_index table with optional filtering.
func (s *SQLiteStore) SearchCases(filter schema.CaseFilter) ([]schema.CaseWithProject, error) {
	var conditions []string
	var args []interface{}

	if filter.ProjectID != "" {
		conditions = append(conditions, "project_id = ?")
		args = append(args, filter.ProjectID)
	}
	if filter.CWE != "" {
		conditions = append(conditions, "cwe = ?")
		args = append(args, filter.CWE)
	}
	if filter.Language != "" {
		conditions = append(conditions, "language = ?")
		args = append(args, filter.Language)
	}
	if filter.Tag != "" {
		conditions = append(conditions, "tags LIKE ?")
		args = append(args, "%"+filter.Tag+"%")
	}
	if filter.Keyword != "" {
		conditions = append(conditions, "(case_id LIKE ? OR name LIKE ? OR description LIKE ?)")
		like := "%" + filter.Keyword + "%"
		args = append(args, like, like, like)
	}

	query := "SELECT project_id, case_id, name, description, language, cwe, framework, tags, source_file FROM cases_index"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY project_id, case_id"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query cases index: %w", err)
	}
	defer rows.Close()

	var results []schema.CaseWithProject
	for rows.Next() {
		var c schema.CaseWithProject
		var cwe, framework, tagsStr, sourceFile string
		err := rows.Scan(&c.Project.ProjectID, &c.CaseID, &c.Name, &c.Description, &c.Language, &cwe, &framework, &tagsStr, &sourceFile)
		if err != nil {
			return nil, fmt.Errorf("scan case index: %w", err)
		}
		if cwe != "" || framework != "" || tagsStr != "" {
			c.Metadata = &schema.Metadata{CWE: cwe, Framework: framework}
			if tagsStr != "" {
				_ = json.Unmarshal([]byte(tagsStr), &c.Metadata.Tags)
			}
		}
		if sourceFile != "" {
			c.Expectation = &schema.Expectation{Flow: &schema.Flow{Source: &schema.Location{File: sourceFile}}}
		}
		results = append(results, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return results, nil
}

// SaveRawReport persists the original engine output bytes for a project scan.
func (s *SQLiteStore) SaveRawReport(projectID, engine, version, format string, data []byte) error {
	_, err := s.db.Exec(`
		INSERT INTO raw_reports (project_id, engine, engine_version, format, raw_data)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(project_id, engine, engine_version) DO UPDATE SET
			format = excluded.format,
			raw_data = excluded.raw_data,
			stored_at = CURRENT_TIMESTAMP
	`, projectID, engine, version, format, data)
	if err != nil {
		return fmt.Errorf("save raw report: %w", err)
	}
	return nil
}

// GetRawReport retrieves the original engine output bytes for a project scan.
func (s *SQLiteStore) GetRawReport(projectID, engine, version string) ([]byte, string, error) {
	var data []byte
	var format string
	err := s.db.QueryRow(`
		SELECT raw_data, format FROM raw_reports
		WHERE project_id = ? AND engine = ? AND engine_version = ?
	`, projectID, engine, version).Scan(&data, &format)
	if err == sql.ErrNoRows {
		return nil, "", fmt.Errorf("raw report not found")
	}
	if err != nil {
		return nil, "", fmt.Errorf("get raw report: %w", err)
	}
	return data, format, nil
}
