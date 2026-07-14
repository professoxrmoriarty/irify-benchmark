import { useEffect, useState } from 'react'
import { PageShell } from '@/design-system/PageShell'
import { LoadingState } from '@/design-system/LoadingState'
import { ErrorState } from '@/design-system/ErrorState'
import { EmptyState } from '@/design-system/EmptyState'
import { StatusBadge } from '@/design-system/StatusBadge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { listProjects, getProjectDiagnosis, getProjectFindings } from '@/api/client'
import type { DiagnosisReport, DiagnosisCategorySummary, Project } from '@/types'

const statusMap: Record<string, 'success' | 'warning' | 'danger' | 'neutral'> = {
  false_negative: 'warning',
  false_positive: 'danger',
  rule_defect: 'warning',
  data_issue: 'neutral',
}

const labelMap: Record<string, string> = {
  false_negative: '漏报',
  false_positive: '误报',
  rule_defect: '规则缺陷',
  data_issue: '数据问题',
}

export default function DiagnosisOverview() {
  const [projects, setProjects] = useState<Project[]>([])
  const [projectId, setProjectId] = useState<string>('')
  const [report, setReport] = useState<DiagnosisReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Load project list once, default to the first project that has scan data.
  useEffect(() => {
    async function loadProjects() {
      try {
        const list = await listProjects()
        setProjects(list)
        if (list.length > 0) {
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

  // Load diagnosis whenever the selected project changes.
  // The diagnosis endpoint auto-resolves the latest scan version when engine/version are omitted.
  useEffect(() => {
    if (!projectId) {
      setReport(null)
      return
    }
    let cancelled = false
    async function loadDiagnosis() {
      try {
        const data = await getProjectDiagnosis(projectId)
        if (cancelled) return
        setReport(data)
        setError(null)
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err))
          setReport(null)
        }
      }
    }
    loadDiagnosis()
    return () => {
      cancelled = true
    }
  }, [projectId])

  const categories = report?.category_summary || []

  return (
    <PageShell title="诊断">
      <div className="space-y-6">
        <div className="flex items-center gap-3">
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
        </div>

        {loading && <LoadingState />}
        {error && <ErrorState message={error} />}
        {!loading && !error && !projectId && (
          <EmptyState message="请先选择一个项目" />
        )}
        {!loading && !error && projectId && !report && (
          <EmptyState message="该项目暂无诊断数据，请先运行 irify-benchmark run" />
        )}
        {!loading && !error && report && (
          <>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {categories.map((c: DiagnosisCategorySummary) => (
                <Card key={c.category}>
                  <CardHeader>
                    <CardTitle className="text-base font-medium">
                      {labelMap[c.category] || c.category}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-between">
                      <span className="text-3xl font-semibold">{c.count}</span>
                      <StatusBadge status={statusMap[c.category] || 'neutral'} />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
            <Card>
              <CardHeader>
                <CardTitle className="text-base font-medium">TOP 问题</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 text-sm text-text-secondary">
                  {report?.case_diagnoses?.slice(0, 5).map((d, idx) => (
                    <div
                      key={idx}
                      className="flex justify-between border-b border-border pb-2 last:border-0"
                    >
                      <span>{d.case_id}</span>
                      <span className="text-text-muted">{d.category || '未分类'}</span>
                    </div>
                  )) || <div className="text-text-muted">暂无问题</div>}
                </div>
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </PageShell>
  )
}