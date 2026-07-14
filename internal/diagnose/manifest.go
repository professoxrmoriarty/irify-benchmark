package diagnose

import "fmt"

type AgentHandoffManifest struct {
	ProjectID       string                 `json:"project_id"`
	ProjectName     string                 `json:"project_name"`
	Engine          string                 `json:"engine"`
	EngineVersion   string                 `json:"engine_version"`
	Objective       string                 `json:"objective"`
	Summary         Summary                `json:"summary"`
	WorkflowSteps   []AgentWorkflowStep    `json:"workflow_steps"`
	Guardrails      AgentGuardrails        `json:"guardrails"`
	Artifacts       []AgentArtifact        `json:"artifacts"`
	RuleReviewQueue []AgentRuleReviewItem  `json:"rule_review_queue,omitempty"`
	RemediationPlan *RemediationPlan       `json:"remediation_plan,omitempty"`
	Validation      []AgentValidationCheck `json:"validation"`
}

type AgentWorkflowStep struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Goal           string `json:"goal"`
	Command        string `json:"command,omitempty"`
	API            string `json:"api,omitempty"`
	ExpectedOutput string `json:"expected_output"`
}

type AgentGuardrails struct {
	Allowed   []string `json:"allowed"`
	Forbidden []string `json:"forbidden"`
}

type AgentArtifact struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
	API         string `json:"api,omitempty"`
}

type AgentRuleReviewItem struct {
	SuggestionID       string   `json:"suggestion_id"`
	RuleID             string   `json:"rule_id,omitempty"`
	RuleFile           string   `json:"rule_file,omitempty"`
	SuggestionType     string   `json:"suggestion_type"`
	Confidence         string   `json:"confidence"`
	ReviewOnly         bool     `json:"review_only"`
	ValidationCommands []string `json:"validation_commands,omitempty"`
}

type AgentValidationCheck struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

func BuildAgentHandoffManifest(report Report, options DiagnosticBundleOptions) AgentHandoffManifest {
	bundle := BuildDiagnosticBundle(report, options)
	projectID := report.ProjectID
	engine := report.Engine
	if engine == "" {
		engine = "yaklang"
	}

	manifest := AgentHandoffManifest{
		ProjectID:       projectID,
		ProjectName:     report.ProjectName,
		Engine:          engine,
		EngineVersion:   report.EngineVersion,
		Objective:       "Help AI add benchmark projects, run scans, validate TP/FP/FN results, and produce review-only SyntaxFlow rule suggestions.",
		Summary:         report.Summary,
		RemediationPlan: report.RemediationPlan,
		WorkflowSteps: []AgentWorkflowStep{
			{
				ID:             "validate-benchmark",
				Title:          "Validate benchmark inputs",
				Goal:           "Check project metadata, case paths, expected source/sink, CWE, and annotations before scanning.",
				Command:        fmt.Sprintf("irify-benchmark case validate --project %s", projectID),
				ExpectedOutput: "No schema/path/expectation errors before engine results are trusted.",
			},
			{
				ID:             "run-scan",
				Title:          "Run or refresh scanner output",
				Goal:           "Generate current engine findings for the benchmark project.",
				Command:        fmt.Sprintf("irify-benchmark run --project %s --engine %s", projectID, engine),
				ExpectedOutput: "A stored finding set and result summary for the selected engine/version.",
			},
			{
				ID:             "diagnose",
				Title:          "Build diagnostic evidence",
				Goal:           "Classify TP/FN/FP-like findings and collect evidence for matcher, benchmark, or rule causes.",
				Command:        fmt.Sprintf("irify-benchmark diagnose %s --engine %s --format bundle --max-priorities %d --max-rule-reviews %d", projectID, engine, effectiveLimit(options.MaxPriorities, 12), effectiveLimit(options.MaxRuleReviews, 8)),
				API:            fmt.Sprintf("/api/projects/%s/diagnosis?engine=%s&format=bundle&max_priorities=%d&max_rule_reviews=%d", projectID, engine, effectiveLimit(options.MaxPriorities, 12), effectiveLimit(options.MaxRuleReviews, 8)),
				ExpectedOutput: "A compact bundle with priorities, rule review snippets, evidence refs, and validation commands.",
			},
			{
				ID:             "ask-ai",
				Title:          "Ask AI for semantic diagnosis",
				Goal:           "Use prompt guardrails to explain root causes and produce review-only rule diffs.",
				Command:        fmt.Sprintf("irify-benchmark diagnose %s --engine %s --format prompt --max-priorities %d --max-rule-reviews %d", projectID, engine, effectiveLimit(options.MaxPriorities, 12), effectiveLimit(options.MaxRuleReviews, 8)),
				API:            fmt.Sprintf("/api/projects/%s/diagnosis?engine=%s&format=prompt&max_priorities=%d&max_rule_reviews=%d", projectID, engine, effectiveLimit(options.MaxPriorities, 12), effectiveLimit(options.MaxRuleReviews, 8)),
				ExpectedOutput: "A fenced JSON response matching the diagnosis response contract.",
			},
			{
				ID:             "validate-ai-response",
				Title:          "Validate AI response contract",
				Goal:           "Reject malformed AI output before a human reviews suggested rule or benchmark changes.",
				Command:        "irify-benchmark diagnose validate-response --file ai-response.md",
				API:            "/api/diagnosis/validate-response",
				ExpectedOutput: "valid=true plus parsed response payload, or explicit missing-field errors.",
			},
		},
		Guardrails: AgentGuardrails{
			Allowed: []string{
				"Add or edit benchmark project/case metadata after validation.",
				"Run scanner, matcher, diagnosis, prompt, and response validation commands.",
				"Generate SyntaxFlow modification suggestions as review-only diffs.",
				"Explain whether evidence points to matcher, converter, benchmark expectation, or SyntaxFlow rule behavior.",
			},
			Forbidden: []string{
				"Do not modify yaklang/common/syntaxflow/sfbuildin or apply SyntaxFlow patches automatically.",
				"Do not treat unmatched findings as confirmed false positives without review.",
				"Do not weaken rules before proving benchmark/matcher/converter causes are not responsible.",
				"Do not accept AI output that fails the response contract validator.",
			},
		},
		Artifacts: []AgentArtifact{
			{
				Name:        "Full diagnosis JSON",
				Description: "Complete machine-readable TP/FP/FN diagnosis for deep inspection.",
				Command:     fmt.Sprintf("irify-benchmark diagnose %s --engine %s --format json", projectID, engine),
				API:         fmt.Sprintf("/api/projects/%s/diagnosis?engine=%s", projectID, engine),
			},
			{
				Name:        "AI diagnostic bundle",
				Description: "Bounded evidence package for semantic analysis.",
				Command:     fmt.Sprintf("irify-benchmark diagnose %s --engine %s --format bundle", projectID, engine),
				API:         fmt.Sprintf("/api/projects/%s/diagnosis?engine=%s&format=bundle", projectID, engine),
			},
			{
				Name:        "AI prompt",
				Description: "Prompt with guardrails, required response contract, and diagnostic bundle.",
				Command:     fmt.Sprintf("irify-benchmark diagnose %s --engine %s --format prompt", projectID, engine),
				API:         fmt.Sprintf("/api/projects/%s/diagnosis?engine=%s&format=prompt", projectID, engine),
			},
		},
		Validation: []AgentValidationCheck{
			{Name: "Go diagnosis tests", Command: "GOCACHE=/tmp/irify-benchmark-go-build go test ./internal/diagnose ./cmd/irify-benchmark -count=1"},
			{Name: "Frontend build", Command: "cd web && npm run build"},
			{Name: "Response contract", Command: "irify-benchmark diagnose validate-response --file ai-response.md"},
		},
	}

	for _, review := range bundle.RuleReviews {
		manifest.RuleReviewQueue = append(manifest.RuleReviewQueue, AgentRuleReviewItem{
			SuggestionID:       review.SuggestionID,
			RuleID:             review.RuleID,
			RuleFile:           review.RuleFile,
			SuggestionType:     review.SuggestionType,
			Confidence:         review.Confidence,
			ReviewOnly:         true,
			ValidationCommands: review.ValidationCommands,
		})
	}
	return manifest
}

func effectiveLimit(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}
