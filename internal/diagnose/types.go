package diagnose

import "github.com/irify/irify-benchmark/pkg/schema"

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Category string

const (
	CategoryMatchedTP               Category = "matched_tp"
	CategoryNoSameCWEFinding        Category = "no_same_cwe_finding"
	CategoryCrossCWEOrNoiseRule     Category = "cross_cwe_or_noise_rule"
	CategoryMatcherEndpointSource   Category = "matcher_endpoint_source_mismatch"
	CategorySinkMethodMismatch      Category = "sink_method_mismatch"
	CategoryPathOrPrefixMismatch    Category = "path_or_prefix_mismatch"
	CategoryDuplicateFindingForCase Category = "duplicate_finding_for_same_case"
	CategoryPossibleTruthError      Category = "possible_truth_error"
	CategoryRulePrecisionIssue      Category = "rule_precision_issue"
	CategoryConverterLoss           Category = "converter_loss"
	CategoryUnknown                 Category = "unknown"
)

type Summary struct {
	TP                int `json:"tp"`
	FP                int `json:"fp"`
	FN                int `json:"fn"`
	TN                int `json:"tn"`
	UnmatchedFindings int `json:"unmatched_findings"`
}

type CategorySummary struct {
	Category   Category `json:"category"`
	Count      int      `json:"count"`
	Confidence string   `json:"confidence,omitempty"`
}

type ScoreBreakdown struct {
	FilePath      float64 `json:"file_path"`
	SourceSymbol  float64 `json:"source_symbol"`
	SinkSymbol    float64 `json:"sink_symbol"`
	LineProximity float64 `json:"line_proximity"`
	Total         float64 `json:"total"`
	Threshold     float64 `json:"threshold"`
}

type TraceEvidence struct {
	Kind     string           `json:"kind"`
	Message  string           `json:"message"`
	Location *schema.Location `json:"location,omitempty"`
}

type RuleCandidate struct {
	Path         string   `json:"path"`
	MatchReasons []string `json:"match_reasons"`
	Confidence   string   `json:"confidence"`
}

type EvidenceRef struct {
	ProjectID    string `json:"project_id,omitempty"`
	CaseID       string `json:"case_id,omitempty"`
	FindingIndex int    `json:"finding_index,omitempty"`
}

type DiffHunk struct {
	OldStart int `json:"old_start"`
	OldLines int `json:"old_lines"`
	NewStart int `json:"new_start"`
	NewLines int `json:"new_lines"`
}

type ReviewComment struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

type RuleReviewSuggestion struct {
	SuggestionID         string          `json:"suggestion_id"`
	RulePatchRecommended bool            `json:"rule_patch_recommended"`
	SuggestionType       string          `json:"suggestion_type"`
	Confidence           string          `json:"confidence"`
	RuleID               string          `json:"rule_id,omitempty"`
	RuleName             string          `json:"rule_name,omitempty"`
	RuleFile             string          `json:"rule_file,omitempty"`
	EvidenceRefs         []EvidenceRef   `json:"evidence_refs,omitempty"`
	OriginalSnippet      string          `json:"original_snippet,omitempty"`
	SuggestedSnippet     string          `json:"suggested_snippet,omitempty"`
	DiffHunks            []DiffHunk      `json:"diff_hunks,omitempty"`
	ReviewComments       []ReviewComment `json:"review_comments,omitempty"`
	ValidationCommands   []string        `json:"validation_commands,omitempty"`
}

type CandidateFinding struct {
	Index    int            `json:"index"`
	RuleID   string         `json:"rule_id,omitempty"`
	RuleName string         `json:"rule_name,omitempty"`
	CWE      string         `json:"cwe,omitempty"`
	Severity string         `json:"severity,omitempty"`
	Flow     *schema.Flow   `json:"flow,omitempty"`
	Score    ScoreBreakdown `json:"score_breakdown"`
}

type CaseDiagnosis struct {
	CaseID                string                 `json:"case_id"`
	Status                string                 `json:"status"`
	Category              Category               `json:"category"`
	Confidence            string                 `json:"confidence"`
	ExpectedFlow          *schema.Flow           `json:"expected_flow,omitempty"`
	BestCandidateFinding  *CandidateFinding      `json:"best_candidate_finding,omitempty"`
	ScoreBreakdown        *ScoreBreakdown        `json:"score_breakdown,omitempty"`
	TraceEvidence         []TraceEvidence        `json:"trace_evidence,omitempty"`
	RuleCandidates        []RuleCandidate        `json:"rule_candidates,omitempty"`
	SuggestedNextCommands []string               `json:"suggested_next_commands,omitempty"`
	RuleReviewSuggestions []RuleReviewSuggestion `json:"rule_review_suggestions,omitempty"`
}

type FindingDiagnosis struct {
	FindingIndex          int                    `json:"finding_index"`
	Status                string                 `json:"status"`
	Category              Category               `json:"category"`
	Confidence            string                 `json:"confidence"`
	Finding               schema.Finding         `json:"finding"`
	NearestCases          []string               `json:"nearest_cases,omitempty"`
	ScoreBreakdown        *ScoreBreakdown        `json:"score_breakdown,omitempty"`
	TraceEvidence         []TraceEvidence        `json:"trace_evidence,omitempty"`
	RuleCandidates        []RuleCandidate        `json:"rule_candidates,omitempty"`
	RuleReviewSuggestions []RuleReviewSuggestion `json:"rule_review_suggestions,omitempty"`
}

type RuleSummary struct {
	RuleID      string                 `json:"rule_id,omitempty"`
	RuleName    string                 `json:"rule_name,omitempty"`
	Count       int                    `json:"count"`
	Candidates  []RuleCandidate        `json:"rule_candidates,omitempty"`
	Suggestions []RuleReviewSuggestion `json:"rule_review_suggestions,omitempty"`
}

type Report struct {
	ProjectID        string             `json:"project_id"`
	ProjectName      string             `json:"project_name"`
	Engine           string             `json:"engine"`
	EngineVersion    string             `json:"engine_version"`
	Summary          Summary            `json:"summary"`
	RemediationPlan  *RemediationPlan   `json:"remediation_plan,omitempty"`
	CategorySummary  []CategorySummary  `json:"category_summary,omitempty"`
	CaseDiagnoses    []CaseDiagnosis    `json:"case_diagnoses,omitempty"`
	FindingDiagnoses []FindingDiagnosis `json:"finding_diagnoses,omitempty"`
	RuleSummaries    []RuleSummary      `json:"rule_summaries,omitempty"`
	Warnings         []string           `json:"warnings,omitempty"`
}

type RemediationPlan struct {
	Queues         []RemediationQueue `json:"queues"`
	RuleChangeGate RuleChangeGate     `json:"rule_change_gate"`
}

type RemediationQueue struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Owner       string   `json:"owner"`
	Count       int      `json:"count"`
	Risk        string   `json:"risk"`
	Goal        string   `json:"goal"`
	NextAction  string   `json:"next_action"`
	Categories  []string `json:"categories"`
	CaseIDs     []string `json:"case_ids,omitempty"`
	FindingRefs []int    `json:"finding_refs,omitempty"`
}

type RuleChangeGate struct {
	AllowAutomaticPatch bool     `json:"allow_automatic_patch"`
	RequiredEvidence    []string `json:"required_evidence"`
	ValidationCommands  []string `json:"validation_commands"`
}

type DiagnosticBundle struct {
	ProjectID     string             `json:"project_id"`
	ProjectName   string             `json:"project_name"`
	Engine        string             `json:"engine"`
	EngineVersion string             `json:"engine_version"`
	Summary       Summary            `json:"summary"`
	Categories    []CategorySummary  `json:"categories,omitempty"`
	Priorities    []BundlePriority   `json:"priorities,omitempty"`
	RuleReviews   []BundleRuleReview `json:"rule_reviews,omitempty"`
	Commands      []string           `json:"commands,omitempty"`
	Notes         []string           `json:"notes,omitempty"`
}

type BundlePriority struct {
	Priority     int      `json:"priority"`
	Kind         string   `json:"kind"`
	Category     Category `json:"category"`
	Confidence   string   `json:"confidence"`
	CaseID       string   `json:"case_id,omitempty"`
	FindingIndex *int     `json:"finding_index,omitempty"`
	RuleID       string   `json:"rule_id,omitempty"`
	RuleName     string   `json:"rule_name,omitempty"`
	Reason       string   `json:"reason"`
	NextAction   string   `json:"next_action"`
}

type BundleRuleReview struct {
	SuggestionID         string          `json:"suggestion_id"`
	RulePatchRecommended bool            `json:"rule_patch_recommended"`
	SuggestionType       string          `json:"suggestion_type"`
	Confidence           string          `json:"confidence"`
	RuleID               string          `json:"rule_id,omitempty"`
	RuleName             string          `json:"rule_name,omitempty"`
	RuleFile             string          `json:"rule_file,omitempty"`
	EvidenceRefs         []EvidenceRef   `json:"evidence_refs,omitempty"`
	OriginalSnippet      string          `json:"original_snippet,omitempty"`
	SuggestedSnippet     string          `json:"suggested_snippet,omitempty"`
	ReviewComments       []ReviewComment `json:"review_comments,omitempty"`
	ValidationCommands   []string        `json:"validation_commands,omitempty"`
}
