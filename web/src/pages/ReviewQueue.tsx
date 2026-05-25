import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getPending, approveItem, rejectItem } from '../api/client'

function statusBadgeClass(status: string) {
  switch (status) {
    case 'pending': return 'badge badge-pending'
    case 'approved': return 'badge badge-approved'
    case 'rejected': return 'badge badge-rejected'
    default: return 'badge'
  }
}

function FlowPreview({ flow }: { flow: any }) {
  if (!flow) return <em>No flow</em>
  return (
    <div className="flow-preview">
      <span className="flow-tag source-tag">{flow.source?.symbol || '?'}</span>
      <span> → </span>
      {flow.sanitizers?.length > 0 && (
        <>
          <span className="flow-tag sanitizer-tag">{flow.sanitizers.length} sanitizer(s)</span>
          <span> → </span>
        </>
      )}
      <span className="flow-tag sink-tag">{flow.sink?.symbol || '?'}</span>
    </div>
  )
}

function ReviewQueue() {
  const [items, setItems] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [dialogItem, setDialogItem] = useState<any | null>(null)
  const [dialogAction, setDialogAction] = useState<'approve' | 'reject' | null>(null)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const navigate = useNavigate()

  const load = () => {
    setLoading(true)
    getPending()
      .then((data) => setItems(data.items || []))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
  }, [])

  const handleAction = (item: any, action: 'approve' | 'reject') => {
    setDialogItem(item)
    setDialogAction(action)
  }

  const confirm = async () => {
    if (!dialogItem || !dialogAction) return
    setActionLoading(dialogItem.item_id)
    try {
      if (dialogAction === 'approve') {
        await approveItem(dialogItem.item_id, 'user', '')
      } else {
        await rejectItem(dialogItem.item_id, 'user', '')
      }
      setDialogItem(null)
      setDialogAction(null)
      load()
    } catch (err: any) {
      setError(err.message)
    } finally {
      setActionLoading(null)
    }
  }

  const cancel = () => {
    setDialogItem(null)
    setDialogAction(null)
  }

  if (loading) return <p>Loading...</p>
  if (error) return <p className="badge badge-fn">Error: {error}</p>

  const pending = items.filter((i: any) => i.status === 'pending')
  const decided = items.filter((i: any) => i.status !== 'pending')

  return (
    <div>
      <h1>Review Queue</h1>

      <h2>Pending ({pending.length})</h2>
      {pending.length === 0 ? (
        <p>No pending items</p>
      ) : (
        <table className="review-table">
          <thead>
            <tr>
              <th>ItemID</th>
              <th>Project</th>
              <th>Case</th>
              <th>Flow</th>
              <th>Source</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {pending.map((item: any) => {
              const projectId = item.project_id || ''
              const caseId = item.proposed_case?.case_id || ''
              return (
                <>
                  <tr key={item.item_id}>
                    <td>{item.item_id}</td>
                    <td>{projectId}</td>
                    <td>
                      <span
                        className="case-link"
                        style={{ cursor: 'pointer', color: '#0366d6', textDecoration: 'underline' }}
                        onClick={() => navigate(`/project/${projectId}?review=${encodeURIComponent(item.item_id)}`)}
                      >
                        {caseId || '-'}
                      </span>
                    </td>
                    <td>
                      <FlowPreview flow={item.proposed_case?.expectation?.flow} />
                    </td>
                    <td>{item.source}</td>
                    <td><span className={statusBadgeClass(item.status)}>{item.status}</span></td>
                    <td>
                      <button
                        className="btn btn-secondary"
                        style={{ marginRight: 4 }}
                        onClick={() => navigate(`/project/${projectId}?review=${encodeURIComponent(item.item_id)}`)}
                      >
                        Open Project
                      </button>
                      <button
                        className="btn btn-success"
                        onClick={() => handleAction(item, 'approve')}
                        disabled={actionLoading === item.item_id}
                      >
                        Approve
                      </button>{' '}
                      <button
                        className="btn btn-danger"
                        onClick={() => handleAction(item, 'reject')}
                        disabled={actionLoading === item.item_id}
                      >
                        Reject
                      </button>
                    </td>
                  </tr>
                </>
              )
            })}
          </tbody>
        </table>
      )}

      {decided.length > 0 && (
        <>
          <h2>Decided</h2>
          <table className="review-table">
            <thead>
              <tr>
                <th>ItemID</th>
                <th>Project</th>
                <th>Case</th>
                <th>Status</th>
                <th>ReviewedAt</th>
              </tr>
            </thead>
            <tbody>
              {decided.map((item: any) => (
                <tr key={item.item_id}>
                  <td>{item.item_id}</td>
                  <td>{item.project_id || ''}</td>
                  <td>{item.proposed_case?.case_id || '-'}</td>
                  <td><span className={statusBadgeClass(item.status)}>{item.status}</span></td>
                  <td>{item.reviewed_at ? new Date(item.reviewed_at).toLocaleString() : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {dialogItem && dialogAction && (
        <div className="dialog-overlay" onClick={cancel}>
          <div className="dialog" onClick={(e) => e.stopPropagation()}>
            <h3>{dialogAction === 'approve' ? 'Approve' : 'Reject'} Item</h3>
            <p>
              Are you sure you want to <strong>{dialogAction}</strong> <code>{dialogItem.item_id}</code>?
            </p>
            {dialogItem.proposed_case && (
              <div className="card" style={{ marginBottom: 12, textAlign: 'left' }}>
                <p><strong>Case:</strong> {dialogItem.proposed_case.case_id}</p>
                <p><strong>Expectation:</strong> {dialogItem.proposed_case.expectation?.type}</p>
                <FlowPreview flow={dialogItem.proposed_case.expectation?.flow} />
              </div>
            )}
            <div className="dialog-actions">
              <button className="btn" onClick={cancel}>Cancel</button>
              <button
                className={`btn ${dialogAction === 'approve' ? 'btn-success' : 'btn-danger'}`}
                onClick={confirm}
                disabled={actionLoading === dialogItem.item_id}
              >
                {dialogAction === 'approve' ? 'Approve' : 'Reject'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default ReviewQueue
