export type ToolKey = 'irify' | 'code_guard' | 'fortify';

export interface ToolMetric {
  key: ToolKey;
  label: string;
  pending_review_raw: number;
  pending_review_high_raw: number;
  pending_review_high_kept: number;
  pending_review_high_excluded: number;
  pending_review_excluded: number;
  positive_total: number;
  positive_supported: number;
  positive_tp: number;
  positive_relaxed_tp: number;
  positive_fn: number;
  positive_recall: number | null;
  positive_relaxed_recall: number | null;
  warn_total: number;
  warn_supported: number;
  warn_matched: number;
  warn_missed: number;
  warn_overstated: number;
  warn_match_rate: number | null;
  safe_total: number;
  safe_supported: number;
  safe_fp: number;
  safe_severe_fp: number;
  safe_advisory_noise: number;
  safe_tn: number;
  safe_fp_rate: number | null;
  safe_advisory_rate: number | null;
  unsupported_cases: number;
  pending_review_additions: number;
  finding_reviewed_total: number;
  finding_useful_alerts: number;
  finding_confirmed_false_positive: number;
  finding_advisory_noise: number;
  finding_overstated: number;
  finding_pending_manual: number;
  finding_pending_review: number;
  finding_total: number;
  finding_noise_total: number;
  finding_confirmed_fp_rate: number | null;
  finding_noise_rate: number | null;
  finding_pending_rate: number | null;
  finding_audit_load: number | null;
  high_risk_reviewed_total: number;
  high_risk_true_alerts: number;
  high_risk_confirmed_false_positive: number;
  high_risk_overstated: number;
  high_risk_pending_manual: number;
  high_risk_pending_review: number;
  high_risk_total: number;
  high_risk_false_positive_rate: number | null;
  high_risk_overreport_rate: number | null;
  high_risk_pending_rate: number | null;
}

export interface FamilyMetric {
  family: string;
  positiveCases: number;
  safeCases: number;
  tools: Record<ToolKey, Record<string, number>>;
}

export interface Location {
  kind?: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
  api?: string;
  notes?: string;
  symbol?: string;
  source_tool?: string;
  evidence?: string;
  params?: Array<{ name: string; type?: string; annotation?: string }>;
}

export interface CaseItem {
  caseId: string;
  scenarioId: string;
  family: string;
  title: string;
  description: string;
  route: string;
  expectation: 'must_alert' | 'should_warn' | 'must_not_alert' | 'informational_only';
  expectedSeverityBand: string[];
  filePath: string;
  lineStart: number;
  lineEnd: number;
  source: Location;
  sink?: Location | null;
  trace: Location[];
  safeGuards: Array<{ line: number; type: string; description: string; code: string }>;
  ruleType: string;
  aliases: string[];
  irifySupport: 'supported' | 'unsupported';
  ruleCandidates: Array<{ rule_file: string; title_zh: string; title: string; risk: string; rule_id: string }>;
  verificationStatus: Record<ToolKey, string>;
  observedRules: Record<ToolKey, Array<{ rule_name: string; severity: string; line_start: number; evidence: string }>>;
  notes: string[];
}

export interface PendingItem {
  tool: ToolKey;
  toolLabel: string;
  ruleName: string;
  severity: string;
  filePath: string;
  lineStart: number;
  candidateCaseIds: string[];
  evidence: string;
  reason: string;
  owaspCategory: string;
  reviewPriority: 'high' | 'medium';
}

export interface BenchmarkDataset {
  project: string;
  meta: {
    summary: {
      controllers_with_cases: number;
      total_cases: number;
      total_vul_cases: number;
      total_safe_cases: number;
    };
    rule_count: number;
    source_root: string;
    readme_path: string;
  };
  summary: {
    totalCases: number;
    positiveCases: number;
    warnCases: number;
    negativeCases: number;
    supportedCases: number;
    pendingReviewTotals: Record<ToolKey, number>;
    pendingReviewRawTotals: Record<ToolKey, number>;
  };
  pendingReviewPolicy: {
    version: string;
    description: string;
    tools: Record<ToolKey, {
      rawTotal: number;
      rawHighTotal: number;
      keptTotal: number;
      keptHighTotal: number;
      excludedTotal: number;
      excludedHighTotal: number;
      excludedReasons: Record<string, number>;
    }>;
  };
  tools: ToolMetric[];
  families: FamilyMetric[];
  cases: CaseItem[];
  pendingReviewAdditions: PendingItem[];
  statusLegend: Record<string, string>;
}

export interface ProjectIndexEntry {
  projectId: string;
  projectName: string;
  language: string;
  frontendPath: string;
  truthPath: string;
  evaluationPath: string;
  htmlPath: string;
  pendingReviewTotals: Record<ToolKey, number>;
  summary: BenchmarkDataset['summary'];
}

export interface ProjectIndex {
  projects: ProjectIndexEntry[];
  defaultProjectId: string;
}
