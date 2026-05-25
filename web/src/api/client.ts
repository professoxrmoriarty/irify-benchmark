import { API_BASE } from '../config'

async function fetchJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export async function listProjects() {
  return fetchJSON<any[]>('/api/projects')
}

export async function getProject(id: string) {
  return fetchJSON<any>(`/api/projects/${id}`)
}

export async function getProjectFiles(id: string) {
  return fetchJSON<any>(`/api/projects/${id}/files`)
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
  return fetchJSON<any>(`/api/projects/${id}/cases${qs ? '?' + qs : ''}`)
}

export async function listCases(projectId?: string, keyword?: string, cwe?: string, language?: string, tag?: string) {
  const params = new URLSearchParams()
  if (projectId) params.set('project_id', projectId)
  if (keyword) params.set('keyword', keyword)
  if (cwe) params.set('cwe', cwe)
  if (language) params.set('language', language)
  if (tag) params.set('tag', tag)
  const qs = params.toString()
  return fetchJSON<{ cases: any[] }>(`/api/cases${qs ? '?' + qs : ''}`)
}

export async function getProjectResults(id: string) {
  return fetchJSON<any>(`/api/projects/${id}/results`)
}

export async function getProjectFindings(id: string, engine?: string, version?: string) {
  const params = new URLSearchParams()
  if (engine) params.set('engine', engine)
  if (version) params.set('version', version)
  const qs = params.toString()
  return fetchJSON<any>(`/api/projects/${id}/findings${qs ? '?' + qs : ''}`)
}

export async function getPending() {
  return fetchJSON<{items: any[]}>('/api/pending')
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
