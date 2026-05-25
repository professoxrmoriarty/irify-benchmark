import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { listProjects } from '../api/client'

export function Dashboard() {
  const [projects, setProjects] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    listProjects()
      .then((data) => setProjects(data || []))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <p>Loading...</p>
  if (error) return <p className="badge badge-fn">Error: {error}</p>

  return (
    <div className="dashboard">
      <h1>Benchmark Projects</h1>
      <div className="project-grid" style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
        gap: '1rem',
        marginTop: '1rem',
      }}>
        {projects.map((p) => (
          <div key={p.project_id} className="project-card card" style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '0.5rem',
          }}>
            <h3 style={{ margin: 0 }}>{p.name}</h3>
            <p style={{ margin: 0, color: '#666', fontSize: '0.9rem', flex: 1 }}>
              {p.description || 'No description'}
            </p>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <span className="badge" style={{
                background: '#e1ecf4',
                color: '#0366d6',
              }}>{p.language}</span>
              {p.framework && (
                <span className="badge" style={{
                  background: '#f1f8ff',
                  color: '#2188ff',
                }}>{p.framework}</span>
              )}
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
              <Link
                to={`/project/${p.project_id}`}
                style={{
                  flex: 1,
                  padding: '0.4rem 0.8rem',
                  background: '#0366d6',
                  color: '#fff',
                  textDecoration: 'none',
                  borderRadius: '4px',
                  fontSize: '0.9rem',
                  textAlign: 'center',
                }}
              >
                Open Project
              </Link>
              <Link
                to={`/project/${p.project_id}/results`}
                style={{
                  padding: '0.4rem 0.8rem',
                  background: '#f6f8fa',
                  border: '1px solid #d0d7de',
                  color: '#24292f',
                  textDecoration: 'none',
                  borderRadius: '4px',
                  fontSize: '0.9rem',
                  textAlign: 'center',
                }}
              >
                Results
              </Link>
            </div>
          </div>
        ))}
      </div>
      {projects.length === 0 && (
        <p style={{ color: '#666', marginTop: '2rem' }}>No projects found. Create one with the CLI.</p>
      )}
    </div>
  )
}
