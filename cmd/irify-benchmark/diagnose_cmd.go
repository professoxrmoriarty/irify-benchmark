package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/irify/irify-benchmark/internal/diagnose"
	"github.com/irify/irify-benchmark/internal/store"
)

var (
	diagnoseFormat         string
	diagnoseMaxPriorities  int
	diagnoseMaxRuleReviews int
	diagnoseResponseFile   string

	diagnoseCmd = &cobra.Command{
		Use:   "diagnose <project-id>",
		Short: "Diagnose benchmark TP/FP/FN causes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiagnoseProject(args[0], engineName, engineVersion, diagnoseFormat, diagnoseBundleOptions(), cmd.OutOrStdout())
		},
	}

	diagnoseValidateResponseCmd = &cobra.Command{
		Use:           "validate-response",
		Short:         "Validate AI response against the diagnosis prompt contract",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			reader := cmd.InOrStdin()
			if diagnoseResponseFile != "" {
				file, err := os.Open(diagnoseResponseFile)
				if err != nil {
					return fmt.Errorf("open response file: %w", err)
				}
				defer file.Close()
				reader = file
			}
			return runValidateAIResponse(reader, cmd.OutOrStdout())
		},
	}
)

func diagnoseBundleOptions() diagnose.DiagnosticBundleOptions {
	return diagnose.DiagnosticBundleOptions{
		MaxPriorities:  diagnoseMaxPriorities,
		MaxRuleReviews: diagnoseMaxRuleReviews,
	}
}

func runDiagnoseProject(projectID, engine, version, format string, bundleOptions diagnose.DiagnosticBundleOptions, w io.Writer) error {
	hs, err := store.NewHybridStore(".", "data/benchmark.db")
	if err != nil {
		return fmt.Errorf("init hybrid store: %w", err)
	}
	defer hs.Close()

	engine, version, err = resolveScanVersion(hs, projectID, engine, version)
	if err != nil {
		return err
	}
	project, err := hs.ReadProject(projectID)
	if err != nil {
		return fmt.Errorf("read project: %w", err)
	}
	caseSet, err := hs.ReadCases(projectID)
	if err != nil {
		return fmt.Errorf("read cases: %w", err)
	}
	findingSet, err := hs.GetFindings(projectID, engine, version)
	if err != nil {
		return fmt.Errorf("get findings: %w", err)
	}
	result, _ := hs.GetResult(projectID, engine, version)
	report := diagnose.BuildReport(diagnose.BuildReportInput{
		ProjectID:     projectID,
		ProjectName:   project.Name,
		Engine:        engine,
		EngineVersion: version,
		Cases:         caseSet.Cases,
		Findings:      findingSet.Findings,
		Result:        result,
		RuleRoot:      filepath.Join("..", "yaklang", "common", "syntaxflow", "sfbuildin", "buildin"),
	})
	return renderDiagnosis(report, format, bundleOptions, w)
}

func renderDiagnosis(report diagnose.Report, format string, bundleOptions diagnose.DiagnosticBundleOptions, w io.Writer) error {
	switch format {
	case "", "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	case "bundle", "ai":
		bundle := diagnose.BuildDiagnosticBundle(report, bundleOptions)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(bundle)
	case "prompt":
		return renderDiagnosisPrompt(report, bundleOptions, w)
	case "manifest", "handoff":
		manifest := diagnose.BuildAgentHandoffManifest(report, bundleOptions)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(manifest)
	case "markdown", "md":
		fmt.Fprintf(w, "# Benchmark Diagnosis\n\n")
		fmt.Fprintf(w, "- Project: `%s` (%s)\n", report.ProjectID, report.ProjectName)
		fmt.Fprintf(w, "- Engine: `%s %s`\n", report.Engine, report.EngineVersion)
		fmt.Fprintf(w, "- Summary: TP=%d FP=%d FN=%d TN=%d Unmatched=%d\n\n",
			report.Summary.TP, report.Summary.FP, report.Summary.FN, report.Summary.TN, report.Summary.UnmatchedFindings)
		fmt.Fprintln(w, "## Categories")
		fmt.Fprintln(w)
		for _, item := range report.CategorySummary {
			fmt.Fprintf(w, "- `%s`: %d\n", item.Category, item.Count)
		}
		return nil
	default:
		return fmt.Errorf("unsupported diagnosis format %q", format)
	}
}

func renderDiagnosisPrompt(report diagnose.Report, bundleOptions diagnose.DiagnosticBundleOptions, w io.Writer) error {
	bundle := diagnose.BuildDiagnosticBundle(report, bundleOptions)
	var bundleJSON bytes.Buffer
	enc := json.NewEncoder(&bundleJSON)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bundle); err != nil {
		return err
	}

	fmt.Fprintln(w, "# IRify Benchmark Diagnosis Task")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "You are diagnosing an IRify benchmark scan result. Use the diagnostic bundle below to explain TP/FP/FN root causes and propose next actions.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "## Guardrails")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "- Do not modify SyntaxFlow rules directly.")
	fmt.Fprintln(w, "- Return rule modification suggestions as review-only diffs.")
	fmt.Fprintln(w, "- Distinguish benchmark matcher/converter issues from real SyntaxFlow rule issues.")
	fmt.Fprintln(w, "- Treat unmatched findings as pending review, not confirmed false positives.")
	fmt.Fprintln(w, "- Cite case IDs, finding indexes, rule IDs, and rule files from the bundle.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "## Required Output")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "1. Root-cause summary grouped by category.")
	fmt.Fprintln(w, "2. Prioritized investigation plan.")
	fmt.Fprintln(w, "3. Rule review suggestions with GitHub-style diff guidance when evidence supports a rule change.")
	fmt.Fprintln(w, "4. Benchmark-side fixes when evidence points to matcher, converter, path, or expectation problems.")
	fmt.Fprintln(w, "5. Validation commands to run after each suggested change.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "## Response Contract")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Return a JSON object inside a fenced `json` block with this shape:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "```json")
	fmt.Fprintln(w, "{")
	fmt.Fprintln(w, `  "root_causes": [`)
	fmt.Fprintln(w, `    {"category": "string", "summary": "string", "evidence_refs": ["case_id or finding_index"], "confidence": "high|medium|low"}`)
	fmt.Fprintln(w, "  ],")
	fmt.Fprintln(w, `  "rule_suggestions": [`)
	fmt.Fprintln(w, `    {"rule_id": "string", "rule_file": "string", "reason": "string", "review_only_diff": "string", "validation_commands": ["string"]}`)
	fmt.Fprintln(w, "  ],")
	fmt.Fprintln(w, `  "benchmark_fixes": [`)
	fmt.Fprintln(w, `    {"target": "matcher|converter|case_expectation|path", "reason": "string", "case_ids": ["string"], "validation_commands": ["string"]}`)
	fmt.Fprintln(w, "  ],")
	fmt.Fprintln(w, `  "validation_plan": ["string"],`)
	fmt.Fprintln(w, `  "uncertainties": ["string"]`)
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w, "```")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "## Diagnostic Bundle")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "```json")
	fmt.Fprint(w, bundleJSON.String())
	fmt.Fprintln(w, "```")
	return nil
}

func runValidateAIResponse(r io.Reader, w io.Writer) error {
	content, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read AI response: %w", err)
	}
	result := diagnose.ValidateAIResponse(content)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return err
	}
	if !result.Valid {
		return fmt.Errorf("AI response does not satisfy diagnosis response contract")
	}
	return nil
}
