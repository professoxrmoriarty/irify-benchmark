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

export interface PendingItem {
  item_id: string
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
