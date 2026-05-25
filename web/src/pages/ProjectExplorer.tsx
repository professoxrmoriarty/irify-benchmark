import { useEffect, useMemo, useState } from 'react'
import { useParams, useSearchParams, Link } from 'react-router-dom'
import {
  getProject,
  getProjectFiles,
  getFileContent,
  getProjectCases,
  getPending,
  approveItem,
  rejectItem,
} from '../api/client'
import { FileTree, type FileEntry } from '../components/FileTree'
import { CodeViewer } from '../components/CodeViewer'
import { CaseDetailPanel } from '../components/CaseDetailPanel'
import type { Case, Location, PendingItem } from '../types'
import './ProjectExplorer.css'

export function ProjectExplorer() {
  const { id } = useParams()
  const [searchParams, setSearchParams] = useSearchParams()
  const caseParam = searchParams.get('case')
  const reviewParam = searchParams.get('review')

  const [project, setProject] = useState<any>(null)
  const [files, setFiles] = useState<FileEntry[]>([])
  const [selectedFile, setSelectedFile] = useState<string>('')
  const [fileContent, setFileContent] = useState<string>('')
  const [cases, setCases] = useState<Case[]>([])
  const [selectedCase, setSelectedCase] = useState<Case | null>(null)
  const [selectedReviewItem, setSelectedReviewItem] = useState<PendingItem | null>(null)
  const [isReviewMode, setIsReviewMode] = useState(false)
  const [focusLine, setFocusLine] = useState<number | undefined>(undefined)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [caseError, setCaseError] = useState<string | null>(null)

  const [pendingItems, setPendingItems] = useState<PendingItem[]>([])
  const [actionLoading, setActionLoading] = useState(false)
  const [toast, setToast] = useState<string | null>(null)
  const [newlyApprovedCaseId, setNewlyApprovedCaseId] = useState<string | null>(null)

  // Load project, files, cases
  useEffect(() => {
    if (!id) return
    setLoading(true)
    Promise.all([
      getProject(id),
      getProjectFiles(id),
      getProjectCases(id),
    ])
      .then(([proj, fileTree, caseData]) => {
        setProject(proj)
        const fileList = Array.isArray(fileTree)
          ? fileTree
          : fileTree?.entries || (fileTree ? [fileTree] : [])
        setFiles(fileList)
        const loadedCases = caseData.cases || caseData || []
        setCases(loadedCases)
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false))
  }, [id])

  // Load pending items
  useEffect(() => {
    getPending()
      .then((data) => {
        const items = data.items || []
        const filtered = items.filter(
          (item: any) => item.project_id === id && item.status === 'pending'
        )
        setPendingItems(filtered)
      })
      .catch(() => setPendingItems([]))
  }, [id])

  // Resolve case or review param
  useEffect(() => {
    if (reviewParam) {
      setIsReviewMode(true)
      const item = pendingItems.find((p) => p.item_id === reviewParam)
      if (item && item.proposed_case) {
        setSelectedReviewItem(item)
        setSelectedCase(item.proposed_case)
        setCaseError(null)
      } else {
        setSelectedReviewItem(null)
        setSelectedCase(null)
        setCaseError(`Review item "${reviewParam}" not found`)
      }
    } else if (caseParam) {
      setIsReviewMode(false)
      setSelectedReviewItem(null)
      const matched = cases.find((c) => c.case_id === caseParam)
      if (matched) {
        setSelectedCase(matched)
        setCaseError(null)
      } else {
        setSelectedCase(null)
        setCaseError(`Case "${caseParam}" not found`)
      }
    } else {
      setIsReviewMode(false)
      setSelectedReviewItem(null)
      setSelectedCase(null)
      setCaseError(null)
    }
  }, [caseParam, reviewParam, cases, pendingItems])

  // Auto-load source file when selectedCase changes
  useEffect(() => {
    if (!id || !selectedCase) {
      setFocusLine(undefined)
      return
    }
    const sourceFile = selectedCase.source_code
    if (sourceFile) {
      setSelectedFile(sourceFile)
      getFileContent(id, sourceFile)
        .then((content) => {
          setFileContent(content)
          const sourceLine = selectedCase.expectation?.flow?.source?.line
          if (sourceLine) {
            setFocusLine(sourceLine)
          }
        })
        .catch((err) => {
          setFileContent(
            `// Error loading file: ${err instanceof Error ? err.message : String(err)}`
          )
        })
    }
  }, [id, selectedCase])

  // Clear toast after 3s
  useEffect(() => {
    if (!toast) return
    const timer = setTimeout(() => setToast(null), 3000)
    return () => clearTimeout(timer)
  }, [toast])

  const handleSelectFile = async (path: string) => {
    if (!id) return
    setSelectedFile(path)
    try {
      const content = await getFileContent(id, path)
      setFileContent(content)
    } catch (err) {
      setFileContent(
        `// Error loading file: ${err instanceof Error ? err.message : String(err)}`
      )
    }
  }

  const highlights = useMemo(() => {
    if (!selectedCase?.expectation?.flow || !selectedFile) return undefined
    const flow = selectedCase.expectation.flow
    return {
      sourceLines: flow.source?.file === selectedFile ? [flow.source.line] : [],
      sinkLines: flow.sink?.file === selectedFile ? [flow.sink.line] : [],
      sanitizerLines:
        flow.sanitizers?.filter((s) => s.file === selectedFile).map((s) => s.line) || [],
    }
  }, [selectedCase, selectedFile])

  const handleJumpToLocation = async (loc: Location) => {
    if (!id) return
    if (loc.file !== selectedFile) {
      await handleSelectFile(loc.file)
    }
    if (loc.line) {
      setFocusLine(loc.line)
    }
  }

  const handleClosePanel = () => {
    setSearchParams({})
  }

  const handleSelectCase = (caseId: string) => {
    setSearchParams({ case: caseId })
  }

  const handleSelectReviewItem = (itemId: string) => {
    setSearchParams({ review: itemId })
  }

  const currentPendingItem = useMemo(() => {
    if (!selectedCase) return null
    return (
      pendingItems.find((p) => p.proposed_case?.case_id === selectedCase.case_id) || null
    )
  }, [selectedCase, pendingItems])

  const goToNextPending = (currentItemId: string) => {
    const currentIndex = pendingItems.findIndex((p) => p.item_id === currentItemId)
    const nextItem = pendingItems[currentIndex + 1]
    if (nextItem) {
      setSearchParams({ review: nextItem.item_id })
    } else {
      setSearchParams({})
      setToast('Review queue complete')
    }
  }

  const handleApprove = async (itemId: string) => {
    setActionLoading(true)
    try {
      await approveItem(itemId, 'user', '')
      setPendingItems((prev) => prev.filter((p) => p.item_id !== itemId))

      // Reload cases to reflect the newly approved case
      if (id) {
        const caseData = await getProjectCases(id)
        const loadedCases = caseData.cases || caseData || []
        setCases(loadedCases)
      }

      // Find which case was just approved for visual feedback
      const approvedItem = pendingItems.find((p) => p.item_id === itemId)
      if (approvedItem?.proposed_case) {
        setNewlyApprovedCaseId(approvedItem.proposed_case.case_id)
        setTimeout(() => setNewlyApprovedCaseId(null), 2500)
      }

      setToast('Approved and added to cases')
      goToNextPending(itemId)
    } catch (err: any) {
      setToast(`Error: ${err.message}`)
    } finally {
      setActionLoading(false)
    }
  }

  const handleReject = async (itemId: string) => {
    setActionLoading(true)
    try {
      await rejectItem(itemId, 'user', '')
      setPendingItems((prev) => prev.filter((p) => p.item_id !== itemId))
      setToast('Rejected')
      goToNextPending(itemId)
    } catch (err: any) {
      setToast(`Error: ${err.message}`)
    } finally {
      setActionLoading(false)
    }
  }

  if (loading) return <p>Loading...</p>
  if (error) return <p className="badge badge-fn">Error: {error}</p>

  return (
    <div className="project-explorer">
      <div className="sidebar">
        <div>
          <h3>{project?.name || id}</h3>
          <div style={{ fontSize: '0.8rem', color: '#666', marginBottom: 8 }}>
            {project?.language} {project?.framework ? `· ${project.framework}` : ''}
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: 8 }}>
            <Link
              to={`/project/${id}/findings`}
              style={{
                fontSize: '0.75rem',
                padding: '0.2rem 0.5rem',
                background: '#e1ecf4',
                color: '#0366d6',
                textDecoration: 'none',
                borderRadius: '4px',
              }}
            >
              Findings
            </Link>
            <Link
              to={`/project/${id}/results`}
              style={{
                fontSize: '0.75rem',
                padding: '0.2rem 0.5rem',
                background: '#e1ecf4',
                color: '#0366d6',
                textDecoration: 'none',
                borderRadius: '4px',
              }}
            >
              Results
            </Link>
          </div>
        </div>
        <div className="file-tree-section">
          <FileTree entries={files} onSelectFile={handleSelectFile} selectedPath={selectedFile} />
        </div>
        <div className="case-list">
          <h4>Cases ({cases.length})</h4>
          {caseError && !isReviewMode && <div className="case-error">{caseError}</div>}
          {cases.map((c) => (
            <div
              key={c.case_id}
              className={`case-item ${
                selectedCase?.case_id === c.case_id && !isReviewMode ? 'case-item-active' : ''
              } ${newlyApprovedCaseId === c.case_id ? 'case-item-new' : ''}`}
              onClick={() => handleSelectCase(c.case_id)}
              role="button"
              tabIndex={0}
            >
              {c.case_id}
            </div>
          ))}
        </div>
        {pendingItems.length > 0 && (
          <div className="review-list">
            <h4>Review Queue ({pendingItems.length})</h4>
            {caseError && isReviewMode && <div className="case-error">{caseError}</div>}
            {pendingItems.map((item) => (
              <div
                key={item.item_id}
                className={`review-item ${
                  selectedReviewItem?.item_id === item.item_id ? 'review-item-active' : ''
                }`}
                onClick={() => item.item_id && handleSelectReviewItem(item.item_id)}
                role="button"
                tabIndex={0}
              >
                <div className="review-item-id">{item.item_id}</div>
                <div className="review-item-case">{item.proposed_case?.case_id || '-'}</div>
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="editor-area">
        {selectedFile ? (
          <CodeViewer
            content={fileContent}
            language={project?.language || 'plaintext'}
            highlights={highlights}
            focusLine={focusLine}
          />
        ) : (
          <div className="empty-state">Select a file to view</div>
        )}
      </div>
      {selectedCase && (
        <div className="case-panel">
          {isReviewMode && (
            <div className="case-panel-review-banner">
              <span className="badge badge-pending">Review Mode</span>
              <span className="case-panel-review-id">{selectedReviewItem?.item_id}</span>
            </div>
          )}
          <CaseDetailPanel
            caseData={selectedCase}
            onJumpToLocation={handleJumpToLocation}
            onClose={handleClosePanel}
            pendingItem={isReviewMode ? selectedReviewItem : currentPendingItem}
            onApprove={isReviewMode ? handleApprove : undefined}
            onReject={isReviewMode ? handleReject : undefined}
            actionLoading={actionLoading}
          />
        </div>
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  )
}
