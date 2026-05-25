import { useEffect, useState, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getProjectFindings, getProject, getFileContent, listProjects } from '../api/client'
import { CodeViewer } from '../components/CodeViewer'
import type { Finding, Case } from '../types'

interface FindingSet {
  engine: string
  engine_version: string
  scan_time: string
  findings: Finding[]
}

interface CaseSet {
  project_id: string
  version: string
  cases: Case[]
}

export function FindingsPage() {
  const { id } = useParams()
  const [project, setProject] = useState<any>(null)
  const [caseSet, setCaseSet] = useState<CaseSet | null>(null)
  const [findingSet, setFindingSet] = useState<FindingSet | null>(null)
  const [selectedIdx, setSelectedIdx] = useState<number>(0)
  const [fileContent, setFileContent] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [allProjects, setAllProjects] = useState<any[]>([])

  useEffect(() => {
    if (!id) {
      setLoading(true)
      listProjects()
        .then((data) => setAllProjects(data || []))
        .catch((err) => setError(err instanceof Error ? err.message : String(err)))
        .finally(() => setLoading(false))
      return
    }
    setLoading(true)
    Promise.all([
      getProject(id),
      getProjectFindings(id).catch(() => null),
      fetch(`/api/projects/${id}/cases`).then((r) => (r.ok ? r.json() : null)).catch(() => null),
    ])
      .then(([proj, data, caseData]) => {
        setProject(proj)
        setCaseSet(caseData)
        if (data && data.findings) {
          setFindingSet(data as FindingSet)
        } else if (data && data.versions && data.versions.length > 0) {
          const first = data.versions[0]
          return getProjectFindings(id, first.engine, first.engine_version).then((fs: any) => {
            setFindingSet(fs as FindingSet)
          })
        } else {
          setFindingSet(null)
        }
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false))
  }, [id])

  const selectedFinding = findingSet?.findings[selectedIdx]

  // Auto-load file when selection changes
  useEffect(() => {
    if (!id || !selectedFinding) {
      setFileContent('')
      return
    }
    const targetFile = selectedFinding.flow?.source?.file || selectedFinding.flow?.sink?.file
    if (targetFile) {
      getFileContent(id, targetFile)
        .then((content) => setFileContent(content))
        .catch(() => setFileContent(`// Could not load file: ${targetFile}`))
    } else {
      setFileContent('// No file location available for this finding')
    }
  }, [id, selectedFinding])

  const highlights = useMemo(() => {
    if (!selectedFinding) return undefined
    const src = selectedFinding.flow?.source
    const sink = selectedFinding.flow?.sink
    const h: { sourceLines: number[]; sinkLines: number[]; sanitizerLines: number[] } = {
      sourceLines: src?.line ? [src.line] : [],
      sinkLines: sink?.line ? [sink.line] : [],
      sanitizerLines: [],
    }
    return h
  }, [selectedFinding])

  const focusLine = useMemo(() => {
    return selectedFinding?.flow?.source?.line || selectedFinding?.flow?.sink?.line
  }, [selectedFinding])

  // Find nearest case for the selected finding
  const nearestCase = useMemo(() => {
    if (!selectedFinding || !caseSet?.cases) return null
    return findNearestCase(selectedFinding, caseSet.cases)
  }, [selectedFinding, caseSet])

  const diagnosis = useMemo(() => {
    if (!selectedFinding || !nearestCase) return null
    return diagnoseFinding(selectedFinding, nearestCase)
  }, [selectedFinding, nearestCase])

  if (loading) return <p>Loading...</p>
  if (error) return <p className="badge badge-fn">Error: {error}</p>

  // Global findings page: show project selector
  if (!id) {
    return (
      <div style={{ padding: '1rem' }}>
        <h1>Findings</h1>
        <p style={{ color: '#666' }}>Select a project to view engine findings:</p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
          {allProjects.map((p) => (
            <Link
              key={p.project_id}
              to={`/project/${p.project_id}/findings`}
              style={{
                padding: '1rem',
                border: '1px solid #e1e4e8',
                borderRadius: '6px',
                textDecoration: 'none',
                color: '#24292f',
                background: '#fff',
              }}
            >
              <h3 style={{ margin: '0 0 0.5rem' }}>{p.name}</h3>
              <p style={{ margin: 0, color: '#666', fontSize: '0.85rem' }}>{p.description || 'No description'}</p>
            </Link>
          ))}
        </div>
        {allProjects.length === 0 && <p style={{ color: '#666', marginTop: '2rem' }}>No projects found.</p>}
      </div>
    )
  }

  const findings = findingSet?.findings || []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 60px)' }}>
      {/* Header */}
      <div style={{ padding: '0.75rem 1rem', borderBottom: '1px solid #e1e4e8', display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <Link to={`/project/${id}/results`} style={{ color: '#0366d6', textDecoration: 'none' }}>
          ← Back
        </Link>
        <h2 style={{ margin: 0, fontSize: '1.1rem' }}>
          Findings — {project?.name || id}
        </h2>
        {findingSet && (
          <span style={{ color: '#666', fontSize: '0.85rem' }}>
            {findingSet.engine} {findingSet.engine_version} · {findings.length} findings
          </span>
        )}
        {findingSet && (
          <a
            href={`/api/projects/${id}/raw-scan?engine=${encodeURIComponent(findingSet.engine)}&version=${encodeURIComponent(findingSet.engine_version)}`}
            download
            style={{
              marginLeft: 'auto',
              fontSize: '0.8rem',
              padding: '0.3rem 0.6rem',
              background: '#f6f8fa',
              border: '1px solid #d0d7de',
              borderRadius: '4px',
              color: '#24292f',
              textDecoration: 'none',
            }}
          >
            ⬇ Download Raw Scan
          </a>
        )}
      </div>

      {/* Main content */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Left: findings list */}
        <div
          style={{
            width: '420px',
            minWidth: '320px',
            borderRight: '1px solid #e1e4e8',
            overflowY: 'auto',
            background: '#f6f8fa',
          }}
        >
          {findings.length === 0 ? (
            <p style={{ padding: '1rem', color: '#666' }}>No findings found.</p>
          ) : (
            findings.map((f, idx) => {
              const isActive = idx === selectedIdx
              const src = f.flow?.source
              const sink = f.flow?.sink
              return (
                <div
                  key={idx}
                  onClick={() => setSelectedIdx(idx)}
                  style={{
                    padding: '0.6rem 0.75rem',
                    borderBottom: '1px solid #e1e4e8',
                    cursor: 'pointer',
                    background: isActive ? '#dbeafe' : 'transparent',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontWeight: 600,
                        padding: '0.1rem 0.4rem',
                        borderRadius: '3px',
                        textTransform: 'uppercase',
                        background: severityBg(f.severity),
                        color: severityColor(f.severity),
                      }}
                    >
                      {f.severity || '?'}
                    </span>
                    <span style={{ fontSize: '0.85rem', fontWeight: 500, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {f.rule_name}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#586069', fontFamily: 'monospace' }}>
                    {src && (
                      <span>
                        S: {src.file}:{src.line}:{src.column}
                      </span>
                    )}
                    {src && sink && <span style={{ margin: '0 0.4rem' }}>|</span>}
                    {sink && (
                      <span>
                        K: {sink.file}:{sink.line}:{sink.column}
                      </span>
                    )}
                  </div>
                </div>
              )
            })
          )}
        </div>

        {/* Right: code viewer + diagnosis */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Diagnosis banner */}
          {selectedFinding && (
            <div
              style={{
                padding: '0.6rem 1rem',
                borderBottom: '1px solid #e1e4e8',
                background: '#fff',
                fontSize: '0.85rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.3rem' }}>
                <strong>{selectedFinding.rule_name}</strong>
                {selectedFinding.rule_id && (
                  <span style={{ color: '#666', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                    {selectedFinding.rule_id}
                  </span>
                )}
              </div>
              {diagnosis ? (
                <div style={{ color: diagnosis.isMisaligned ? '#d73a49' : '#28a745' }}>
                  {diagnosis.text}
                </div>
              ) : nearestCase ? (
                <div style={{ color: '#586069' }}>
                  最近 Case: {nearestCase.case_id} — {nearestCase.expectation?.flow?.source?.file}:{nearestCase.expectation?.flow?.source?.line}
                </div>
              ) : (
                <div style={{ color: '#586069' }}>没有找到关联的 Case</div>
              )}
            </div>
          )}

          {/* Monaco editor */}
          <div style={{ flex: 1 }}>
            {fileContent ? (
              <CodeViewer
                content={fileContent}
                language={project?.language || 'plaintext'}
                highlights={highlights}
                focusLine={focusLine}
              />
            ) : (
              <div
                style={{
                  height: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#666',
                }}
              >
                Select a finding to view code
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function severityColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'high':
    case 'critical':
      return '#d73a49'
    case 'middle':
    case 'medium':
      return '#e36209'
    case 'low':
      return '#ffd33d'
    case 'info':
      return '#0366d6'
    default:
      return '#6a737d'
  }
}

function severityBg(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'high':
    case 'critical':
      return '#ffeef0'
    case 'middle':
    case 'medium':
      return '#fff5eb'
    case 'low':
      return '#fff8c5'
    case 'info':
      return '#ddf4ff'
    default:
      return '#f6f8fa'
  }
}

function findNearestCase(finding: Finding, cases: Case[]): Case | null {
  const fSrc = finding.flow?.source
  const fSink = finding.flow?.sink
  if (!fSrc && !fSink) return null

  let best: { case: Case; score: number } | null = null
  for (const c of cases) {
    const cSrc = c.expectation?.flow?.source
    const cSink = c.expectation?.flow?.sink
    if (!cSrc && !cSink) continue

    let score = 0
    if (fSrc && cSrc) {
      if (fSrc.file === cSrc.file) score += 100
      if (fSrc.line > 0 && cSrc.line > 0) score -= Math.abs(fSrc.line - cSrc.line)
    }
    if (fSink && cSink) {
      if (fSink.file === cSink.file) score += 100
      if (fSink.line > 0 && cSink.line > 0) score -= Math.abs(fSink.line - cSink.line)
    }
    if (best === null || score > best.score) {
      best = { case: c, score }
    }
  }
  return best?.case || null
}

function diagnoseFinding(finding: Finding, nearestCase: Case): { text: string; isMisaligned: boolean } | null {
  const fSrc = finding.flow?.source
  const fSink = finding.flow?.sink
  const cSrc = nearestCase.expectation?.flow?.source
  const cSink = nearestCase.expectation?.flow?.sink

  const parts: string[] = []
  let isMisaligned = false

  if (fSrc && cSrc) {
    if (fSrc.file !== cSrc.file) {
      parts.push(`Source 文件不匹配: finding 在 ${fSrc.file}，case 期望在 ${cSrc.file}`)
      isMisaligned = true
    } else if (Math.abs(fSrc.line - cSrc.line) > 3) {
      parts.push(`Source 行号偏差 ${Math.abs(fSrc.line - cSrc.line)} 行`)
      isMisaligned = true
    }
  }

  if (fSink && cSink) {
    if (fSink.file !== cSink.file) {
      parts.push(`Sink 文件不匹配: finding 在 ${fSink.file}，case 期望在 ${cSink.file}`)
      isMisaligned = true
    } else if (Math.abs(fSink.line - cSink.line) > 3) {
      parts.push(`Sink 行号偏差 ${Math.abs(fSink.line - cSink.line)} 行`)
      isMisaligned = true
    }
  }

  if (parts.length === 0) {
    return { text: '位置与 Case 接近，请人工确认', isMisaligned: false }
  }

  return { text: parts.join('；'), isMisaligned }
}
