import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { listCases, listProjects } from '../api/client'
import type { CaseWithProject, Project } from '../types'

function CaseList() {
  const [cases, setCases] = useState<CaseWithProject[]>([])
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filter states
  const [projectId, setProjectId] = useState('')
  const [keyword, setKeyword] = useState('')
  const [cwe, setCwe] = useState('')
  const [language, setLanguage] = useState('')
  const [tag, setTag] = useState('')

  const navigate = useNavigate()

  // Load projects for filter dropdown
  useEffect(() => {
    listProjects()
      .then((data) => setProjects(data || []))
      .catch(() => setProjects([]))
  }, [])

  // Load cases with filters
  useEffect(() => {
    setLoading(true)
    listCases(projectId || undefined, keyword || undefined, cwe || undefined, language || undefined, tag || undefined)
      .then((data) => {
        setCases(data.cases || [])
        setError(null)
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : String(err))
        setCases([])
      })
      .finally(() => setLoading(false))
  }, [projectId, keyword, cwe, language, tag])

  // Derive unique filter options from loaded data
  const cweOptions = useMemo(() => {
    const set = new Set<string>()
    cases.forEach((c) => {
      if (c.metadata?.cwe) set.add(c.metadata.cwe)
    })
    return Array.from(set).sort()
  }, [cases])

  const langOptions = useMemo(() => {
    const set = new Set<string>()
    cases.forEach((c) => {
      if (c.language) set.add(c.language)
    })
    return Array.from(set).sort()
  }, [cases])

  const tagOptions = useMemo(() => {
    const set = new Set<string>()
    cases.forEach((c) => {
      c.metadata?.tags?.forEach((t) => set.add(t))
    })
    return Array.from(set).sort()
  }, [cases])

  const handleRowClick = (projectId: string, caseId: string) => {
    navigate(`/project/${encodeURIComponent(projectId)}?case=${encodeURIComponent(caseId)}`)
  }

  if (loading && cases.length === 0) return <p>Loading...</p>
  if (error) return <p className="badge badge-fn">Error: {error}</p>

  return (
    <div>
      <h1>Cases</h1>

      <div className="filters">
        <select value={projectId} onChange={(e) => setProjectId(e.target.value)}>
          <option value="">All Projects</option>
          {projects.map((p) => (
            <option key={p.project_id} value={p.project_id}>{p.name}</option>
          ))}
        </select>

        <input
          type="text"
          placeholder="Search ID / Name / Description..."
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
        />

        <select value={cwe} onChange={(e) => setCwe(e.target.value)}>
          <option value="">All CWEs</option>
          {cweOptions.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>

        <select value={language} onChange={(e) => setLanguage(e.target.value)}>
          <option value="">All Languages</option>
          {langOptions.map((l) => (
            <option key={l} value={l}>{l}</option>
          ))}
        </select>

        <select value={tag} onChange={(e) => setTag(e.target.value)}>
          <option value="">All Tags</option>
          {tagOptions.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>

      <table>
        <thead>
          <tr>
            <th>Case ID</th>
            <th>Name</th>
            <th>Description</th>
            <th>Project</th>
            <th>Language</th>
            <th>CWE</th>
            <th>Tags</th>
          </tr>
        </thead>
        <tbody>
          {cases.map((c) => (
            <tr
              key={`${c.project?.project_id || ''}-${c.case_id}`}
              className="clickable-row"
              onClick={() => handleRowClick(c.project?.project_id || '', c.case_id)}
            >
              <td>{c.case_id}</td>
              <td>{c.name || '-'}</td>
              <td>{c.description || '-'}</td>
              <td>{c.project?.name || c.project?.project_id || '-'}</td>
              <td>{c.language || '-'}</td>
              <td>{c.metadata?.cwe || '-'}</td>
              <td>{c.metadata?.tags?.join(', ') || '-'}</td>
            </tr>
          ))}
          {cases.length === 0 && (
            <tr><td colSpan={7}>No cases found</td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

export default CaseList
