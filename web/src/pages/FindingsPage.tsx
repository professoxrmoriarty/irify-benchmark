import { useEffect, useState } from 'react'
import { PageShell } from '@/design-system/PageShell'
import { LoadingState } from '@/design-system/LoadingState'
import { ErrorState } from '@/design-system/ErrorState'
import { EmptyState } from '@/design-system/EmptyState'
import { StatusBadge } from '@/design-system/StatusBadge'
import { FilterBar } from '@/components/FilterBar'
import { CodeBlock } from '@/components/CodeBlock'
import { Card, CardContent } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { listProjects, getProjectFindings } from '@/api/client'
import type { Finding, FindingVersion, Project } from '@/types'

export function FindingsPage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [projectId, setProjectId] = useState<string>('')
  const [versions, setVersions] = useState<FindingVersion[]>([])
  const [selectedVersion, setSelectedVersion] = useState<string>('') // "engine|version"
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)

  // Load project list once, default to the first project with scan data.
  useEffect(() => {
    async function loadProjects() {
      try {
        const list = await listProjects()
        setProjects(list)
        if (list.length > 0) {
          // Prefer the first project that actually has scan results; fall back to the first.
          const withResults = await Promise.all(
            list.map((p) =>
              getProjectFindings(p.project_id)
                .then((r) => ('versions' in r && r.versions.length > 0 ? p.project_id : ''))
                .catch(() => '')
            )
          )
          const first = withResults.find((id) => id) || list[0].project_id
          setProjectId(first)
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err))
      } finally {
        setLoading(false)
      }
    }
    loadProjects()
  }, [])

  // When the project changes, fetch its available scan versions.
  useEffect(() => {
    if (!projectId) {
      setVersions([])
      setSelectedVersion('')
      setFindings([])
      return
    }
    let cancelled = false
    async function loadVersions() {
      try {
        const result = await getProjectFindings(projectId)
        if (cancelled) return
        if ('versions' in result) {
          const v = result.versions
          setVersions(v)
          // Auto-select the latest version (sorted by scan_time desc server-side).
          if (v.length > 0) {
            setSelectedVersion(`${v[0].engine}|${v[0].engine_version}`)
          } else {
            setSelectedVersion('')
            setFindings([])
          }
        } else {
          // Should not happen without engine/version, but guard anyway.
          setVersions([])
          setFindings(result.findings)
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err))
      }
    }
    loadVersions()
    return () => {
      cancelled = true
    }
  }, [projectId])

  // When a version is selected, fetch the findings for that engine+version.
  useEffect(() => {
    if (!projectId || !selectedVersion) {
      setFindings([])
      return
    }
    const [engine, version] = selectedVersion.split('|', 2)
    let cancelled = false
    async function loadFindings() {
      try {
        const result = await getProjectFindings(projectId, engine, version)
        if (cancelled) return
        if ('findings' in result) {
          setFindings(result.findings)
        } else {
          setFindings([])
        }
        setError(null)
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err))
      }
    }
    loadFindings()
    return () => {
      cancelled = true
    }
  }, [projectId, selectedVersion])

  const filtered = findings.filter((f) =>
    f.rule_name.toLowerCase().includes(filter.toLowerCase())
  )

  return (
    <PageShell title="结果">
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <Select value={projectId} onValueChange={setProjectId}>
            <SelectTrigger size="sm" className="min-w-[12rem]">
              <SelectValue placeholder="选择项目" />
            </SelectTrigger>
            <SelectContent>
              {projects.map((p) => (
                <SelectItem key={p.project_id} value={p.project_id}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {versions.length > 0 && (
            <Select value={selectedVersion} onValueChange={setSelectedVersion}>
              <SelectTrigger size="sm" className="min-w-[14rem]">
                <SelectValue placeholder="选择扫描版本" />
              </SelectTrigger>
              <SelectContent>
                {versions.map((v, idx) => (
                  <SelectItem
                    key={`${v.engine}-${v.engine_version}-${idx}`}
                    value={`${v.engine}|${v.engine_version}`}
                  >
                    {v.engine} · {v.engine_version}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>

        {filtered.length > 0 && (
          <FilterBar value={filter} onChange={setFilter} placeholder="搜索结果" />
        )}

        {loading && <LoadingState />}
        {error && <ErrorState message={error} />}
        {!loading && !error && !projectId && (
          <EmptyState message="请先选择一个项目" />
        )}
        {!loading && !error && projectId && versions.length === 0 && (
          <EmptyState message="该项目暂无扫描结果，请先运行 irify-benchmark run" />
        )}
        {!loading && !error && versions.length > 0 && (
          <div className="space-y-3">
            {filtered.length === 0 ? (
              <EmptyState message="没有匹配的结果" />
            ) : (
              filtered.map((f, index) => {
                const id = `${f.rule_id}-${index}`
                return (
                  <Card key={id}>
                    <CardContent className="p-4">
                      <div
                        className="flex cursor-pointer items-center justify-between"
                        onClick={() => setExpanded(expanded === id ? null : id)}
                      >
                        <div>
                          <div className="font-medium text-text-primary">{f.rule_name}</div>
                          <div className="text-xs text-text-muted">
                            {f.flow?.source?.file || '未知位置'}:{f.flow?.source?.line || 0}
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-xs">置信度 {f.confidence}</span>
                          <StatusBadge
                            status={f.severity === 'high' ? 'danger' : 'warning'}
                          />
                        </div>
                      </div>
                      {expanded === id && (
                        <div className="mt-4 border-t border-border pt-4">
                          <CodeBlock code={JSON.stringify(f.flow, null, 2)} language="json" />
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )
              })
            )}
          </div>
        )}
      </div>
    </PageShell>
  )
}