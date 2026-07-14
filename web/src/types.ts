export interface Project {
  project_id: string
  name: string
  description: string
  language: string
  framework: string
  source_root: string
}

export interface FileEntry {
  name: string
  type: 'file' | 'directory'
  path: string
  entries?: FileEntry[]
  children?: FileEntry[]
}

export interface Location {
  symbol: string
  line: number
  column: number
  file: string
}

export interface Sanitizer extends Location {
  effective: boolean
}

export interface Flow {
  source: Location | null
  sanitizers: Sanitizer[]
  sink: Location | null
}

export interface Expectation {
  type: string
  flow: Flow | null
}

export interface Metadata {
  cwe: string
  framework: string
  tags: string[]
}

export interface Case {
  case_id: string
  name: string
  description: string
  language: string
  source_code: string
  expectation: Expectation | null
  metadata: Metadata | null
  notes: string
}

export interface CaseWithProject extends Case {
  project: Project
}

export interface Annotation {
  benchmark_id: string
  version: string
  created_at: string
  cases: Case[]
}

export interface MatchDetails {
  source_match: boolean
  sink_match: boolean
  sanitizer_match: boolean
  trace_complete: boolean
  line_distance: number
}

export interface MatchedFinding {
  rule_id: string
  rule_name: string
  severity: string
}

export interface CaseResult {
  case_id: string
  status: string
  matched_finding: MatchedFinding | null
  match_score: number
  match_details: MatchDetails | null
}

export interface Summary {
  total_cases: number
  tp: number
  fn: number
  fp: number
  tn: number
  recall: number
  precision: number
  f1: number
}

export interface Result {
  benchmark_id: string
  engine: string
  engine_version: string
  scan_time: string
  summary: Summary | null
  case_results: CaseResult[]
  pending_review: unknown[]
}

export interface Finding {
  rule_id: string
  rule_name: string
  severity: string
  confidence: string
  flow: Flow | null
}

export interface FindingSet {
  engine: string
  engine_version: string
  scan_time: string
  findings: Finding[]
}

export interface FindingVersion {
  engine: string
  engine_version: string
}

export interface FindingVersionList {
  versions: FindingVersion[]
}

export interface PendingItem {
  item_id: string
  project_id?: string
  source: string
  status: string
  proposed_case: Case | null
  original_finding: Finding | null
  submitted_at: string
  reviewed_at: string | null
  reviewer: string | null
  review_notes: string | null
}

export interface PendingQueue {
  benchmark_id: string
  items: PendingItem[]
}

export interface DiagnosisSummary {
  tp: number
  fp: number
  fn: number
  tn: number
  unmatched_findings: number
}

export interface DiagnosisCategorySummary {
  category: string
  count: number
  confidence?: string
}

export interface ScoreBreakdown {
  file_path: number
  source_symbol: number
  sink_symbol: number
  line_proximity: number
  total: number
  threshold: number
}

export interface TraceEvidence {
  kind: string
  message: string
  location?: Location | null
}

export interface RuleCandidate {
  path: string
  match_reasons: string[]
  confidence: string
}

export interface RuleReviewSuggestion {
  suggestion_id: string
  rule_patch_recommended: boolean
  suggestion_type: string
  confidence: string
  rule_id?: string
  rule_name?: string
  rule_file?: string
  original_snippet?: string
  suggested_snippet?: string
  validation_commands?: string[]
  review_comments?: { line: number; message: string }[]
}

export interface CandidateFinding {
  index: number
  rule_id?: string
  rule_name?: string
  severity?: string
  flow?: Flow | null
  score_breakdown: ScoreBreakdown
}

export interface CaseDiagnosis {
  case_id: string
  status: string
  category: string
  confidence: string
  expected_flow?: Flow | null
  best_candidate_finding?: CandidateFinding | null
  score_breakdown?: ScoreBreakdown | null
  trace_evidence?: TraceEvidence[]
  rule_candidates?: RuleCandidate[]
  suggested_next_commands?: string[]
  rule_review_suggestions?: RuleReviewSuggestion[]
}

export interface FindingDiagnosis {
  finding_index: number
  status: string
  category: string
  confidence: string
  finding: Finding
  nearest_cases?: string[]
  score_breakdown?: ScoreBreakdown | null
  trace_evidence?: TraceEvidence[]
  rule_candidates?: RuleCandidate[]
  rule_review_suggestions?: RuleReviewSuggestion[]
}

export interface RuleSummaryDiagnosis {
  rule_id?: string
  rule_name?: string
  count: number
  rule_candidates?: RuleCandidate[]
  rule_review_suggestions?: RuleReviewSuggestion[]
}

export interface DiagnosisReport {
  project_id: string
  project_name: string
  engine: string
  engine_version: string
  summary: DiagnosisSummary
  remediation_plan?: RemediationPlan
  category_summary?: DiagnosisCategorySummary[]
  case_diagnoses?: CaseDiagnosis[]
  finding_diagnoses?: FindingDiagnosis[]
  rule_summaries?: RuleSummaryDiagnosis[]
  warnings?: string[]
}

export interface RemediationPlan {
  queues: RemediationQueue[]
  rule_change_gate: RuleChangeGate
}

export interface RemediationQueue {
  id: string
  label: string
  owner: string
  count: number
  risk: string
  goal: string
  next_action: string
  categories: string[]
  case_ids?: string[]
  finding_refs?: number[]
}

export interface RuleChangeGate {
  allow_automatic_patch: boolean
  required_evidence: string[]
  validation_commands: string[]
}

export interface AIResponseValidationCounts {
  root_causes: number
  rule_suggestions: number
  benchmark_fixes: number
  validation_steps: number
  uncertainties: number
}

export interface AIRootCause {
  category: string
  summary: string
  evidence_refs: string[]
  confidence: string
}

export interface AIRuleSuggestion {
  rule_id: string
  rule_file: string
  reason: string
  review_only_diff: string
  validation_commands: string[]
}

export interface AIBenchmarkFix {
  target: string
  reason: string
  case_ids: string[]
  validation_commands: string[]
}

export interface AIResponseContract {
  root_causes: AIRootCause[]
  rule_suggestions: AIRuleSuggestion[]
  benchmark_fixes: AIBenchmarkFix[]
  validation_plan: string[]
  uncertainties: string[]
}

export interface AIResponseValidation {
  valid: boolean
  errors?: string[]
  counts: AIResponseValidationCounts
  response?: AIResponseContract
}

export interface AgentWorkflowStep {
  id: string
  title: string
  goal: string
  command?: string
  api?: string
  expected_output: string
}

export interface AgentGuardrails {
  allowed: string[]
  forbidden: string[]
}

export interface AgentArtifact {
  name: string
  description: string
  command?: string
  api?: string
}

export interface AgentRuleReviewItem {
  suggestion_id: string
  rule_id?: string
  rule_file?: string
  suggestion_type: string
  confidence: string
  review_only: boolean
  validation_commands?: string[]
}

export interface AgentValidationCheck {
  name: string
  command: string
}

export interface AgentHandoffManifest {
  project_id: string
  project_name: string
  engine: string
  engine_version: string
  objective: string
  summary: DiagnosisSummary
  workflow_steps: AgentWorkflowStep[]
  guardrails: AgentGuardrails
  artifacts: AgentArtifact[]
  rule_review_queue?: AgentRuleReviewItem[]
  validation: AgentValidationCheck[]
}
