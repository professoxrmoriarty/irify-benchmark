import { useEffect, useMemo, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getProject, getProjectCases, getFileContent } from '../api/client'
import { CodeViewer } from '../components/CodeViewer'

export function CaseDetail() {
  const { projectId, caseId } = useParams<{ projectId: string; caseId: string }>()
  const [project, setProject] = useState<any>(null)
  const [caseData, setCaseData] = useState<any>(null)
  const [fileContent, setFileContent] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!projectId || !caseId) return
    setLoading(true)
    Promise.all([
      getProject(projectId),
      getProjectCases(projectId),
    ])
      .then(([proj, data]) => {
        setProject(proj)
        const c = data.cases?.find((x: any) => x.case_id === caseId)
        setCaseData(c || null)
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false))
  }, [projectId, caseId])

  useEffect(() => {
    if (!projectId || !caseData?.source_code) return
    getFileContent(projectId, caseData.source_code)
      .then(setFileContent)
      .catch((err) => setFileContent(`// Error loading file: ${err instanceof Error ? err.message : String(err)}`))
  }, [projectId, caseData])

  const highlights = useMemo(() => {
    if (!caseData?.expectation?.flow) return undefined
    const flow = caseData.expectation.flow
    return {
      sourceLines: flow.source ? [flow.source.line] : [],
      sinkLines: flow.sink ? [flow.sink.line] : [],
      sanitizerLines: flow.sanitizers?.map((s: any) => s.line) || [],
    }
  }, [caseData])

  if (loading) return <p>Loading...</p>
  if (error) return <p className="badge badge-fn">Error: {error}</p>
  if (!caseData) return <p>Case not found</p>

  const flow = caseData.expectation?.flow

  return (
    <div className="case-detail">
      <h2>{caseData.name || caseData.case_id}</h2>
      {caseData.name && <p style={{ color: '#666', marginTop: '-0.5rem' }}>{caseData.case_id}</p>}
      {caseData.description && (
        <div className="card" style={{ background: '#f8f9fa' }}>
          <p style={{ margin: 0 }}>{caseData.description}</p>
        </div>
      )}
      <div className="card">
        <p><strong>Project:</strong> {project?.name || projectId} <span style={{ color: '#888', fontSize: '0.85rem' }}>({project?.language}{project?.framework ? ` / ${project.framework}` : ''})</span></p>
        <p><strong>Language:</strong> {caseData.language}</p>
        <p><strong>Expectation:</strong> {caseData.expectation?.type}</p>
        <p><strong>CWE:</strong> {caseData.metadata?.cwe || '-'}</p>
        <p><strong>Tags:</strong> {caseData.metadata?.tags?.join(', ') || '-'}</p>
        <p><strong>Source File:</strong> {caseData.source_code}</p>
        {caseData.notes && <p><strong>Notes:</strong> {caseData.notes}</p>}
      </div>

      <div className="card">
        <h3>Expected Flow</h3>
        <div className="flow-layout">
          <div className="flow-box source">
            <h4>Source</h4>
            {flow?.source ? (
              <div>
                <div>{flow.source.symbol}</div>
                <div style={{ fontSize: '0.85rem', color: '#666' }}>
                  {flow.source.file}:{flow.source.line}:{flow.source.column}
                </div>
              </div>
            ) : <em>None</em>}
          </div>
          <div className="flow-arrow">→</div>
          <div className="flow-box sanitizer">
            <h4>Sanitizers</h4>
            {flow?.sanitizers && flow.sanitizers.length > 0 ? (
              <ul style={{ margin: 0, paddingLeft: '1.2rem' }}>
                {flow.sanitizers.map((s: any, i: number) => (
                  <li key={i}>
                    {s.symbol} ({s.effective ? 'effective' : 'ineffective'})
                  </li>
                ))}
              </ul>
            ) : <em>None</em>}
          </div>
          <div className="flow-arrow">→</div>
          <div className="flow-box sink">
            <h4>Sink</h4>
            {flow?.sink ? (
              <div>
                <div>{flow.sink.symbol}</div>
                <div style={{ fontSize: '0.85rem', color: '#666' }}>
                  {flow.sink.file}:{flow.sink.line}:{flow.sink.column}
                </div>
              </div>
            ) : <em>None</em>}
          </div>
        </div>
      </div>

      <div className="card" style={{ height: '60vh', padding: 0, overflow: 'hidden' }}>
        <CodeViewer
          content={fileContent}
          language={project?.language || 'plaintext'}
          highlights={highlights}
        />
      </div>

      <Link to={`/project/${projectId}`}>← Back to Project</Link>
    </div>
  )
}
