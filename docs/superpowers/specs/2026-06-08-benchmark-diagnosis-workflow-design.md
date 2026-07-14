# Benchmark Diagnosis Workflow Design

## Summary

This design extends `irify-benchmark` into an AI-friendly evidence engine for scan result analysis and SyntaxFlow rule improvement. The first implementation phase is CLI-first: AI agents should be able to import projects, run scans, validate results, and understand why true positives, false positives, and false negatives happened through structured CLI output. The Web UI should reuse the same diagnosis data to explain benchmark behavior to human users.

The system will not automatically modify Yaklang SyntaxFlow rules in phase one. It may produce review-style rule suggestions, including a side-by-side diff preview, but those suggestions are advisory and must be backed by benchmark evidence.

## Goals

- Provide deterministic diagnosis for TP, FP, FN, TN, and unmatched findings.
- Make CLI output suitable for AI agents that need to decide whether to fix benchmark data, matcher/converter logic, or Yaklang `.sf` rules.
- Give users a clear Web view of what happened in a benchmark run and why.
- Map benchmark findings and cases back to candidate SyntaxFlow rule files under `yaklang/common/syntaxflow/sfbuildin/buildin/`.
- Generate review-style rule suggestions without applying patches automatically.
- Keep CLI, HTTP API, and Web UI backed by one shared diagnosis module.

## Non-Goals

- Automatically editing `.sf` rules.
- Automatically committing or pushing Yaklang rule changes.
- Replacing AI or human semantic review for sanitizer effectiveness, rule correctness, or patch safety.
- Building a full PR review system for Yaklang.
- Supporting every scanner engine equally in phase one. The first target is Yaklang `--format irify` output.

## Current Context

`irify-benchmark` already has:

- Project and case storage under `cases/{project-id}`.
- SQLite-backed scan findings, results, and pending review data.
- A Yaklang runner that executes `yak code-scan --format irify --with-dataflow-path --memory`.
- An IRify converter that normalizes Yak raw reports into `schema.FindingSet`.
- A matcher that scores expected case flows against findings.
- CLI commands for `run`, `scan`, `match`, `findings list`, `findings show`, and `analyze fp`.
- Web pages for projects, cases, results, findings, and review queue.

The existing analysis is useful but fragmented. Some diagnosis logic is embedded in CLI commands, and Web pages mostly display raw result data. The next step is to move diagnosis into a reusable internal module.

## Architecture

### Shared Diagnosis Module

Add a new internal package:

```text
internal/diagnose/
```

Responsibilities:

- Load project, cases, findings, match results, and raw reports through the store interface.
- Build case-level diagnosis records.
- Build finding-level diagnosis records.
- Classify likely causes of TP/FP/FN/unmatched findings.
- Extract score breakdown and trace evidence.
- Resolve candidate Yaklang `.sf` rule files.
- Generate advisory rule review suggestions.

The module must not depend on Cobra or HTTP handlers. CLI commands and API handlers call it.

### CLI Layer

Add a `diagnose` command group:

```bash
irify-benchmark diagnose <project-id> --engine yaklang --version latest --format json
irify-benchmark diagnose case <project-id> <case-id> --engine yaklang --version latest --format json
irify-benchmark diagnose finding <project-id> <finding-index> --engine yaklang --version latest --format json
irify-benchmark diagnose rule <project-id> --rule-id <rule-id> --engine yaklang --version latest --format markdown
```

The default output should be JSON for AI consumption. Markdown output is for humans and reports.

### HTTP API Layer

Add endpoints that return the same diagnosis structures:

```text
GET /api/projects/{id}/diagnosis?engine=yaklang&version=...
GET /api/projects/{id}/diagnosis/cases/{caseId}?engine=yaklang&version=...
GET /api/projects/{id}/diagnosis/findings/{findingIndex}?engine=yaklang&version=...
GET /api/projects/{id}/diagnosis/rules/{ruleId}?engine=yaklang&version=...
```

The API should not recompute different logic in handlers. It delegates to `internal/diagnose`.

### Web Layer

Add diagnosis-focused pages:

```text
/project/:id/diagnosis
/project/:id/diagnosis/case/:caseId
/project/:id/diagnosis/finding/:findingIndex
/project/:id/rules/:ruleId/review
```

The Web UI should explain benchmark behavior, not merely list findings. It should show:

- TP/FP/FN distribution by CWE, rule, file, and diagnosis category.
- Expected flow vs finding flow.
- Score breakdown and threshold.
- Trace evidence used by the diagnosis engine.
- Candidate `.sf` rule files.
- Rule review suggestions in a GitHub-style side-by-side view.

## Diagnosis Data Model

### Diagnosis Report

```json
{
  "project_id": "securibench-micro-xss",
  "project_name": "Securibench Micro XSS",
  "engine": "yaklang",
  "engine_version": "yak version dev",
  "summary": {
    "tp": 57,
    "fp": 140,
    "fn": 67,
    "tn": 0,
    "unmatched_findings": 140
  },
  "category_summary": [],
  "case_diagnoses": [],
  "finding_diagnoses": [],
  "rule_summaries": []
}
```

### Case Diagnosis

```json
{
  "case_id": "basic-basic1-001",
  "status": "fn",
  "category": "matcher_endpoint_source_mismatch",
  "confidence": "high",
  "expected_flow": {},
  "best_candidate_finding": {},
  "score_breakdown": {
    "file_path": 0.30,
    "source_symbol": 0.00,
    "sink_symbol": 0.25,
    "line_proximity": 0.20,
    "total": 0.75,
    "threshold": 0.80
  },
  "trace_evidence": [],
  "rule_candidates": [],
  "suggested_next_commands": [],
  "rule_review_suggestions": []
}
```

### Finding Diagnosis

```json
{
  "finding_index": 131,
  "status": "unmatched_finding",
  "category": "duplicate_finding_for_same_case",
  "confidence": "medium",
  "finding": {},
  "nearest_cases": [],
  "score_breakdown": {},
  "trace_evidence": [],
  "rule_candidates": [],
  "rule_review_suggestions": []
}
```

### Rule Review Suggestion

```json
{
  "suggestion_id": "rule-suggestion-cwe22-guarded-canonical-path",
  "rule_patch_recommended": true,
  "suggestion_type": "add_guard",
  "confidence": "medium",
  "rule_id": "7b798768-13e1-4dcd-8ab5-99a6f9635605",
  "rule_name": "检测Java路径穿越漏洞",
  "rule_file": "yaklang/common/syntaxflow/sfbuildin/buildin/java/cwe-22-path-travel/java-path-travel.sf",
  "evidence_refs": [
    {
      "project_id": "securibench-micro-path-traversal",
      "case_id": "basic-basic22-safe-001",
      "finding_index": 1
    }
  ],
  "original_snippet": "$sink #{\n    include:` * & $source`,\n}-> as $high;",
  "suggested_snippet": "$sink.getCanonicalPath() as $canonical;\n$canonical.startsWith(* as $safeBase) as $pathGuard;\n$sink #{\n    include:` * & $source`,\n}-> as $taintedSink;\n$taintedSink - $pathGuard as $high;\n$taintedSink & $pathGuard as $low;",
  "diff_hunks": [
    {
      "old_start": 57,
      "old_lines": 3,
      "new_start": 57,
      "new_lines": 8
    }
  ],
  "review_comments": [
    {
      "line": 57,
      "message": "Guarded canonical-path flows should be downgraded instead of reported as high severity."
    }
  ],
  "validation_commands": [
    "irify-benchmark diagnose case securibench-micro-path-traversal basic-basic22-safe-001 --engine yaklang --format json"
  ]
}
```

The suggestion model represents a reviewable proposal, not an applied patch.

## Diagnosis Categories

The first phase should support these categories:

| Category | Meaning | Typical Action |
| --- | --- | --- |
| `matched_tp` | Case is correctly matched by a finding | No fix |
| `no_same_cwe_finding` | No finding exists for the case CWE | Check missing rule or disabled rule |
| `cross_cwe_or_noise_rule` | Finding comes from an unrelated CWE or code-quality rule | Exclude from benchmark scope or rule set |
| `matcher_endpoint_source_mismatch` | Trace contains expected source, but normalized endpoint source differs | Fix converter or matcher before rule |
| `sink_method_mismatch` | Source is close but sink method does not match expected sink | Inspect rule sink coverage |
| `path_or_prefix_mismatch` | Paths differ only by prefix or normalization | Fix case paths or path normalization |
| `duplicate_finding_for_same_case` | Multiple findings compete for one case | Deduplicate or group by vulnerability instance |
| `possible_truth_error` | Finding is plausible but annotation line/symbol seems wrong | Review benchmark case |
| `rule_precision_issue` | Same-CWE rule reports unsafe result on safe or irrelevant flow | Consider tightening `.sf` rule |
| `converter_loss` | Raw report has data that normalized finding lost | Fix converter |
| `unknown` | Available evidence is insufficient for a confident category | Preserve evidence and require AI or human review |

Each category must include evidence strings so AI and users can audit the classification.

## Rule File Mapping

For Yaklang, rule mapping should use multiple signals:

- `rule_id` from the finding.
- `rule_name` from the finding.
- CWE from case metadata.
- CWE directory names under `yaklang/common/syntaxflow/sfbuildin/buildin/{language}/`.
- `desc(... rule_id: "...")` in `.sf` files.
- Rule title and title_zh when rule_id is absent.

The mapping output should include confidence:

```json
{
  "path": "yaklang/common/syntaxflow/sfbuildin/buildin/java/cwe-79-xss/java-servlet-xss.sf",
  "match_reasons": ["rule_id", "cwe_directory", "rule_name"],
  "confidence": "high"
}
```

## Rule Suggestion Strategy

Rule suggestions should be generated conservatively. The diagnosis engine can produce suggestion templates, but AI may enrich them with semantic reasoning before presenting a final recommendation.

Supported suggestion types:

- `add_source`: A case has no finding because the rule does not recognize a source API.
- `add_sink`: A case has no finding because the rule misses a sink API.
- `tighten_sink`: A rule reports too broadly on sink-like calls.
- `add_guard`: A rule needs to recognize a safety guard.
- `add_sanitizer`: A rule should downgrade or suppress flows through known sanitizers.
- `downgrade_guarded`: Guarded flows should move from high to low/audit instead of disappearing.
- `exclude_noise_rule`: A rule is outside the benchmark scope.
- `benchmark_matcher_fix`: Evidence points to benchmark matcher/converter rather than `.sf`.

Rules:

- Every suggestion must reference concrete case/finding evidence.
- Every suggestion must say whether a rule patch is recommended.
- If diagnosis category is `matcher_endpoint_source_mismatch`, `path_or_prefix_mismatch`, or `converter_loss`, `rule_patch_recommended` should default to `false`.
- If diagnosis category is `rule_precision_issue`, `sink_method_mismatch`, `no_same_cwe_finding`, or repeated same-CWE FN, rule suggestions may set `rule_patch_recommended` to `true`.
- Suggested snippets must preserve original rule context and show enough surrounding lines for review.

## GitHub-Style Rule Review UI

The Web rule review page should use the approved direction:

- Left column: current `.sf` rule source snippet.
- Right column: suggested SyntaxFlow snippet.
- Red/green hunk styling for removed and added lines.
- Inline review comments anchored to suggested lines.
- Benchmark evidence panel showing affected cases/findings, category, confidence, and score.
- Validation command panel showing how AI or users should reproduce the case.
- A clear "Suggested only, not applied" label.

The page should not provide an "Apply patch" action in phase one. Acceptable actions:

- Copy suggested snippet.
- Copy validation commands.
- Open related case diagnosis.
- Open related finding diagnosis.
- Mark suggestion as useful/not useful for future review tracking.

## CLI Output Requirements

CLI JSON should be stable, explicit, and machine-readable:

- Use snake_case fields.
- Include project, engine, and version in every top-level response.
- Include raw indexes for findings and case IDs for cases.
- Include candidate rule paths as repository-relative paths.
- Include enough evidence for AI to avoid re-reading every file.
- Include suggested commands as arrays of strings.

Markdown output should be concise and report-oriented:

- Summary table.
- Category breakdown.
- Top rules contributing FP/FN.
- Representative examples.
- Rule review suggestions.
- Suggested next commands.

## Error Handling

- If no scan exists, return a clear error telling the user to run `irify-benchmark run`.
- If engine/version is omitted, resolve the latest result consistently with existing findings commands.
- If raw report is missing, diagnosis should still run from normalized findings but include a warning.
- If rule files cannot be found, include `rule_candidates: []` and a `rule_mapping_failed` warning.
- If a diagnosis category cannot be determined, use `unknown` with low confidence and include available evidence.

## Testing Strategy

Go unit tests:

- Category classification for known scenarios.
- Rule file mapping by `rule_id`, CWE directory, and rule name.
- Score breakdown and trace evidence extraction.
- Rule suggestion gating for benchmark-side vs rule-side issues.

Integration tests:

- Run diagnosis against existing Securibench Micro fixture data.
- Assert that Basic1-style XSS endpoint mismatch is categorized as `matcher_endpoint_source_mismatch`.
- Assert that code-quality findings in XSS benchmark are categorized as `cross_cwe_or_noise_rule`.
- Assert that candidate rule paths resolve under `yaklang/common/syntaxflow/sfbuildin/buildin/`.

Web tests:

- Diagnosis page renders summary and category breakdown.
- Case diagnosis page shows expected flow, candidate finding, and score.
- Rule review page renders side-by-side original and suggested snippets.

## Rollout Plan

1. Extract diagnosis logic into `internal/diagnose`.
2. Add CLI `diagnose` commands with JSON output.
3. Add rule file mapping for Yaklang `.sf` files.
4. Add conservative rule review suggestion generation.
5. Add HTTP API endpoints.
6. Add Web diagnosis overview and detail pages.
7. Add GitHub-style rule review page.
8. Add fixture-based regression tests using existing Securibench Micro data.

## Acceptance Criteria

- AI can run one CLI command and receive a diagnosis report explaining TP/FP/FN causes for a project.
- Users can open the Web UI and understand why benchmark results contain false positives and false negatives.
- A diagnosis for a matcher/converter issue does not recommend changing `.sf` rules by default.
- A rule precision issue can produce a side-by-side SyntaxFlow suggestion with evidence and validation commands.
- CLI and Web display the same diagnosis categories and evidence because they share the same module.
- No `.sf` files are modified automatically.
