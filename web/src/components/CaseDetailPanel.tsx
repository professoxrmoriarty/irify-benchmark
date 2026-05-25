import type { Case, Location, PendingItem } from '../types'

interface CaseDetailPanelProps {
  caseData: Case
  onJumpToLocation: (loc: Location) => void
  onClose: () => void
  pendingItem?: PendingItem | null
  onApprove?: (itemId: string) => void
  onReject?: (itemId: string) => void
  actionLoading?: boolean
}

export function CaseDetailPanel({
  caseData,
  onJumpToLocation,
  onClose,
  pendingItem,
  onApprove,
  onReject,
  actionLoading,
}: CaseDetailPanelProps) {
  const flow = caseData.expectation?.flow

  const handleLocationClick = (loc: Location | null) => {
    if (!loc) return
    onJumpToLocation(loc)
  }

  return (
    <div className="case-detail-panel">
      <div className="case-panel-header">
        <div>
          <div className="case-panel-title">{caseData.name || caseData.case_id}</div>
          {caseData.name && (
            <div className="case-panel-subtitle">{caseData.case_id}</div>
          )}
        </div>
        <button className="case-panel-close" onClick={onClose} aria-label="Close">
          ×
        </button>
      </div>

      <div className="case-panel-section">
        <div className="case-panel-meta">
          <span className="case-panel-meta-item">
            <strong>Expectation:</strong> {caseData.expectation?.type || '-'}
          </span>
          <span className="case-panel-meta-item">
            <strong>CWE:</strong> {caseData.metadata?.cwe || '-'}
          </span>
          <span className="case-panel-meta-item">
            <strong>Language:</strong> {caseData.language || '-'}
          </span>
          <span className="case-panel-meta-item">
            <strong>Tags:</strong> {caseData.metadata?.tags?.join(', ') || '-'}
          </span>
        </div>
      </div>

      {caseData.description && (
        <div className="case-panel-section">
          <div className="case-panel-label">Description</div>
          <div className="case-panel-description">{caseData.description}</div>
        </div>
      )}

      <div className="case-panel-section">
        <div className="case-panel-label">Expected Flow</div>

        <div
          className="case-panel-flow-node case-panel-flow-source"
          onClick={() => handleLocationClick(flow?.source || null)}
          role="button"
          tabIndex={0}
        >
          <div className="case-panel-flow-label">Source</div>
          {flow?.source ? (
            <div>
              <div className="case-panel-flow-symbol">{flow.source.symbol}</div>
              <div className="case-panel-flow-location">
                {flow.source.file}:{flow.source.line}:{flow.source.column}
              </div>
            </div>
          ) : (
            <em>None</em>
          )}
        </div>

        <div className="case-panel-flow-arrow">→</div>

        <div className="case-panel-flow-node case-panel-flow-sanitizer">
          <div className="case-panel-flow-label">Sanitizers</div>
          {flow?.sanitizers && flow.sanitizers.length > 0 ? (
            <ul className="case-panel-sanitizer-list">
              {flow.sanitizers.map((s, i) => (
                <li
                  key={i}
                  className="case-panel-sanitizer-item"
                  onClick={() => handleLocationClick(s)}
                  role="button"
                  tabIndex={0}
                >
                  <span className="case-panel-flow-symbol">{s.symbol}</span>
                  <span className="case-panel-sanitizer-badge">
                    {s.effective ? 'effective' : 'ineffective'}
                  </span>
                  <div className="case-panel-flow-location">
                    {s.file}:{s.line}:{s.column}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <em>None</em>
          )}
        </div>

        <div className="case-panel-flow-arrow">→</div>

        <div
          className="case-panel-flow-node case-panel-flow-sink"
          onClick={() => handleLocationClick(flow?.sink || null)}
          role="button"
          tabIndex={0}
        >
          <div className="case-panel-flow-label">Sink</div>
          {flow?.sink ? (
            <div>
              <div className="case-panel-flow-symbol">{flow.sink.symbol}</div>
              <div className="case-panel-flow-location">
                {flow.sink.file}:{flow.sink.line}:{flow.sink.column}
              </div>
            </div>
          ) : (
            <em>None</em>
          )}
        </div>
      </div>

      {caseData.notes && (
        <div className="case-panel-section">
          <div className="case-panel-label">Notes</div>
          <div className="case-panel-description">{caseData.notes}</div>
        </div>
      )}

      {pendingItem && (
        <div className="case-panel-section">
          <div className="case-panel-label">Review</div>
          <div className="case-panel-review">
            <div className="case-panel-review-info">
              <span className="badge badge-pending">{pendingItem.status}</span>
              <span className="case-panel-review-source">{pendingItem.source}</span>
            </div>
            <div className="case-panel-review-actions">
              <button
                className="btn btn-success"
                onClick={() => onApprove?.(pendingItem.item_id)}
                disabled={actionLoading}
              >
                Approve
              </button>
              <button
                className="btn btn-danger"
                onClick={() => onReject?.(pendingItem.item_id)}
                disabled={actionLoading}
              >
                Reject
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
