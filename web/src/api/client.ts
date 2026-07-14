import { API_BASE } from '../config'
import type {
  AIResponseValidation,
  AgentHandoffManifest,
  Annotation,
  CaseWithProject,
  DiagnosisReport,
  FileEntry,
  FindingSet,
  FindingVersionList,
  PendingQueue,
  Project,
  Result,
} from '../types'

async function fetchJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export async function listProjects() {
  return fetchJSON<Project[]>('/api/projects')
}

export async function getProject(id: string) {
  return fetchJSON<Project>(`/api/projects/${id}`)
}

export async function getProjectFiles(id: string) {
  return fetchJSON<FileEntry>(`/api/projects/${id}/files`)
}

export async function getFileContent(projectId: string, path: string) {
  // Backend already prefixes 'src/' to the path, so strip it if present
  const cleanPath = path.replace(/^src\//, '')
  const res = await fetch(`${API_BASE}/api/projects/${projectId}/files/${cleanPath}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.text()
}

export async function getProjectCases(id: string, keyword?: string, cwe?: string, language?: string, tag?: string) {
  const params = new URLSearchParams()
  if (keyword) params.set('keyword', keyword)
  if (cwe) params.set('cwe', cwe)
  if (language) params.set('language', language)
  if (tag) params.set('tag', tag)
  const qs = params.toString()
  return fetchJSON<Annotation | { cases: CaseWithProject[] }>(`/api/projects/${id}/cases${qs ? '?' + qs : ''}`)
}

export async function getProjectCase(projectId: string, caseId: string): Promise<CaseWithProject | null> {
  const data = await fetchJSON<{ cases: CaseWithProject[] }>(`/api/projects/${projectId}/cases`)
  return data.cases.find((c) => c.case_id === caseId) ?? null
}

export async function listCases(projectId?: string, keyword?: string, cwe?: string, language?: string, tag?: string) {
  const params = new URLSearchParams()
  if (projectId) params.set('project_id', projectId)
  if (keyword) params.set('keyword', keyword)
  if (cwe) params.set('cwe', cwe)
  if (language) params.set('language', language)
  if (tag) params.set('tag', tag)
  const qs = params.toString()
  return fetchJSON<{ cases: CaseWithProject[] }>(`/api/cases${qs ? '?' + qs : ''}`)
}

export async function getProjectResults(id: string) {
  return fetchJSON<Result[]>(`/api/projects/${id}/results`)
}

export function getProjectFindings(id: string): Promise<FindingSet | FindingVersionList>
export function getProjectFindings(id: string, engine: string, version: string): Promise<FindingSet>
export async function getProjectFindings(id: string, engine?: string, version?: string): Promise<FindingSet | FindingVersionList> {
  const params = new URLSearchParams()
  if (engine) params.set('engine', engine)
  if (version) params.set('version', version)
  const qs = params.toString()
  return fetchJSON<FindingSet | FindingVersionList>(`/api/projects/${id}/findings${qs ? '?' + qs : ''}`)
}

export async function getProjectDiagnosis(id: string, engine?: string, version?: string) {
  const params = new URLSearchParams()
  if (engine) params.set('engine', engine)
  if (version) params.set('version', version)
  const qs = params.toString()
  return fetchJSON<DiagnosisReport>(`/api/projects/${id}/diagnosis${qs ? '?' + qs : ''}`)
}

export async function getProjectDiagnosisPrompt(id: string, maxPriorities = 12, maxRuleReviews = 8): Promise<string> {
  const params = new URLSearchParams()
  params.set('engine', 'yaklang')
  params.set('format', 'prompt')
  params.set('max_priorities', String(maxPriorities))
  params.set('max_rule_reviews', String(maxRuleReviews))
  const res = await fetch(`${API_BASE}/api/projects/${id}/diagnosis?${params.toString()}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.text()
}

export async function getProjectAgentManifest(id: string, maxPriorities = 12, maxRuleReviews = 8): Promise<AgentHandoffManifest> {
  const params = new URLSearchParams()
  params.set('engine', 'yaklang')
  params.set('format', 'manifest')
  params.set('max_priorities', String(maxPriorities))
  params.set('max_rule_reviews', String(maxRuleReviews))
  return fetchJSON<AgentHandoffManifest>(`/api/projects/${id}/diagnosis?${params.toString()}`)
}

export async function validateAIResponse(content: string): Promise<AIResponseValidation> {
  const res = await fetch(`${API_BASE}/api/diagnosis/validate-response`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    body: content,
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export async function getPending() {
  return fetchJSON<PendingQueue>('/api/pending')
}

export async function approveItem(itemId: string, reviewer: string = 'user', notes: string = '') {
  const res = await fetch(`${API_BASE}/api/pending/${itemId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reviewer, notes }),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export async function rejectItem(itemId: string, reviewer: string = 'user', reason: string = '') {
  const res = await fetch(`${API_BASE}/api/pending/${itemId}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reviewer, reason }),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}
