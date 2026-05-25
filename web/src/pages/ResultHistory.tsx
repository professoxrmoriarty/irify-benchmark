import { useEffect, useState } from 'react'
import { useParams, Link, useLocation } from 'react-router-dom'
import { getProjectResults, getProject, listProjects } from '../api/client'
import type { Result, CaseResult } from '../types'

export function ResultHistory() {
  const { id } = useParams()
  const location = useLocation()
  const [project, setProject] = useState<any>(null)
  const [results, setResults] = useState<Result[]>([])
  const [selectedResult, setSelectedResult] = useState<Result | null>(null)
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
    Promise.all([getProject(id), getProjectResults(id)])
      .then(([proj, data]) => {
        setProject(proj)
        const resultList = Array.isArray(data) ? data : [data]
        setResults(resultList)
        if (resultList.length > 0) {
          setSelectedResult(resultList[0])
        }
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <p>Loading...</p>
  if (error) return <p className="badge badge-fn">Error: {error}</p>

  // Global results page: show project selector
  if (!id) {
    return (
      <div style={{ padding: '1rem' }}>
        <h1>Results</h1>
        <p style={{ color: '#666' }}>Select a project to view benchmark results:</p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
          {allProjects.map((p) => (
            <Link
              key={p.project_id}
              to={`/project/${p.project_id}/results`}
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

  const summary = selectedResult?.summary

  return (
    <div style={{ padding: '1rem' }}>
      <div style={{ marginBottom: '1rem' }}>
        <Link to={`/project/${id}`} style={{ color: '#0366d6', textDecoration: 'none' }}>
          ← Back to Project
        </Link>
      </div>
      <h1>Results — {project?.name || id}</h1>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', borderBottom: '1px solid #e1e4e8' }}>
        <Link
          to={`/project/${id}/results`}
          style={{
            padding: '0.5rem 1rem',
            textDecoration: 'none',
            color: location.pathname === `/project/${id}/results` ? '#0366d6' : '#24292f',
            borderBottom: location.pathname === `/project/${id}/results` ? '2px solid #0366d6' : '2px solid transparent',
            fontWeight: location.pathname === `/project/${id}/results` ? 600 : 400,
          }}
        >
          Evaluation
        </Link>
        <Link
          to={`/project/${id}/results/scan`}
          style={{
            padding: '0.5rem 1rem',
            textDecoration: 'none',
            color: location.pathname === `/project/${id}/results/scan` ? '#0366d6' : '#24292f',
            borderBottom: location.pathname === `/project/${id}/results/scan` ? '2px solid #0366d6' : '2px solid transparent',
            fontWeight: location.pathname === `/project/${id}/results/scan` ? 600 : 600,
          }}
        >
          Scan Results
        </Link>
      </div>

      {results.length === 0 ? (
        <p style={{ color: '#666' }}>No results found. Run the benchmark pipeline first.</p>
      ) : (
        <>
          {/* Result selector */}
          {results.length > 1 && (
            <div style={{ marginBottom: '1rem' }}>
              <select
                value={selectedResult?.scan_time || ''}
                onChange={(e) => {
                  const r = results.find((x) => x.scan_time === e.target.value)
                  setSelectedResult(r || null)
                }}
                style={{ padding: '0.4rem', fontSize: '0.9rem' }}
              >
                {results.map((r) => (
                  <option key={r.scan_time} value={r.scan_time}>
                    {r.engine} {r.engine_version} — {new Date(r.scan_time).toLocaleString()}
                  </option>
                ))}
              </select>
            </div>
          )}

          {selectedResult && summary && (
            <>
              {/* Summary cards */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))',
                  gap: '0.75rem',
                  marginBottom: '1.5rem',
                }}
              >
                <MetricCard label="Total Cases" value={summary.total_cases} color="#6a737d" />
                <MetricCard label="TP" value={summary.tp} color="#28a745" />
                <MetricCard label="FN" value={summary.fn} color="#d73a49" />
                <MetricCard label="FP" value={summary.fp} color="#e36209" />
                <MetricCard label="TN" value={summary.tn} color="#0366d6" />
                <MetricCard label="Recall" value={typeof summary.recall === 'number' ? summary.recall.toFixed(2) : '-'} color="#6f42c1" />
                <MetricCard label="Precision" value={typeof summary.precision === 'number' ? summary.precision.toFixed(2) : '-'} color="#6f42c1" />
                <MetricCard label="F1" value={typeof summary.f1 === 'number' ? summary.f1.toFixed(2) : '-'} color="#6f42c1" />
              </div>

              {/* Case results table */}
              <div className="card">
                <h3 style={{ margin: '0 0 0.5rem' }}>Case Results</h3>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #e1e4e8', textAlign: 'left' }}>
                      <th style={{ padding: '0.5rem' }}>Case ID</th>
                      <th style={{ padding: '0.5rem' }}>Status</th>
                      <th style={{ padding: '0.5rem' }}>Matched Rule</th>
                      <th style={{ padding: '0.5rem' }}>Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedResult.case_results.map((cr: CaseResult) => (
                      <tr key={cr.case_id} style={{ borderBottom: '1px solid #e1e4e8' }}>
                        <td style={{ padding: '0.5rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                          {cr.case_id}
                        </td>
                        <td style={{ padding: '0.5rem' }}>
                          <StatusBadge status={cr.status} />
                        </td>
                        <td style={{ padding: '0.5rem' }}>
                          {cr.matched_finding ? (
                            <div>
                              <div style={{ fontWeight: 500 }}>{cr.matched_finding.rule_name}</div>
                              <div style={{ fontSize: '0.75rem', color: '#666' }}>
                                {cr.matched_finding.rule_id}
                              </div>
                            </div>
                          ) : (
                            '-'
                          )}
                        </td>
                        <td style={{ padding: '0.5rem' }}>
                          {cr.match_score > 0 ? cr.match_score.toFixed(2) : '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </div>
  )
}

function MetricCard({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div
      className="card"
      style={{
        textAlign: 'center',
        padding: '0.75rem',
        borderLeft: `4px solid ${color}`,
      }}
    >
      <div style={{ fontSize: '1.5rem', fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: '0.75rem', color: '#666', marginTop: '0.25rem' }}>{label}</div>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    tp: '#28a745',
    fn: '#d73a49',
    fp: '#e36209',
    tn: '#0366d6',
  }
  const color = colors[status] || '#6a737d'
  return (
    <span
      className="badge"
      style={{
        background: color + '20',
        color: color,
        border: `1px solid ${color}40`,
        fontSize: '0.75rem',
        textTransform: 'uppercase',
        fontWeight: 600,
      }}
    >
      {status}
    </span>
  )
}
