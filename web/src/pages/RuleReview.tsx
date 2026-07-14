import { useEffect, useState } from 'react'
import { PageShell } from '@/design-system/PageShell'
import { LoadingState } from '@/design-system/LoadingState'
import { ErrorState } from '@/design-system/ErrorState'
import { EmptyState } from '@/design-system/EmptyState'
import { DiffViewer } from '@/components/DiffViewer'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Drawer,
  DrawerContent,
  DrawerHeader,
  DrawerTitle,
  DrawerTrigger,
} from '@/components/ui/drawer'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { listProjects, getProjectDiagnosis, getProjectFindings } from '@/api/client'
import type { DiagnosisReport, Project, RuleReviewSuggestion } from '@/types'

const suggestionTypeLabel: Record<string, string> = {
  add_source: '补充 source',
  add_sink: '补充 sink',
  tighten_sink: '收紧 sink',
  add_guard: '新增 guard',
  add_sanitizer: '新增 sanitizer',
  downgrade_guarded: '降级已防护流',
  exclude_noise_rule: '排除噪声规则',
  benchmark_matcher_fix: '修复 matcher/converter',
}

export default function RuleReview() {
  const [projects, setProjects] = useState<Project[]>([])
  const [projectId, setProjectId] = useState<string>('')
  const [report, setReport] = useState<DiagnosisReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [dismissed, setDismissed] = useState<Set<string>>(new Set())
  const [openId, setOpenId] = useState<string | null>(null)

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
        setDismissed(new Set())
        setOpenId(null)
        setError(null)
      } catch (err) {
        if (cancelled) {
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

  // Collect every rule review suggestion across rule_summaries and case_diagnoses.
  const suggestions: RuleReviewSuggestion[] = []
  for (const r of report?.rule_summaries || []) {
    for (const s of r.rule_review_suggestions || []) suggestions.push(s)
  }
  for (const c of report?.case_diagnoses || []) {
    for (const s of c.rule_review_suggestions || []) suggestions.push(s)
  }
  // Deduplicate by suggestion_id (a suggestion may surface from both case and rule summaries).
  const seen = new Set<string>()
  const unique = suggestions.filter((s) => {
    const id = s.suggestion_id
    if (seen.has(id)) return false
    seen.add(id)
    return true
  })
  const items = unique.filter((s) => !dismissed.has(s.suggestion_id))

  function handleDismiss(id: string) {
    setDismissed((prev) => new Set(prev).add(id))
    setOpenId(null)
  }

  return (
    <PageShell title="规则审阅">
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
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
          {items.length > 0 && (
            <span className="text-xs text-text-muted">
              {items.length} 条建议 · 仅建议，未自动应用
            </span>
          )}
        </div>

        {loading && <LoadingState />}
        {error && <ErrorState message={error} />}
        {!loading && !error && !projectId && <EmptyState message="请先选择一个项目" />}
        {!loading && !error && projectId && !report && (
          <EmptyState message="该项目暂无诊断数据，请先运行 irify-benchmark run" />
        )}
        {!loading && !error && report && items.length === 0 && (
          <EmptyState message="暂无规则审阅建议" />
        )}
        {!loading && !error && report && items.length > 0 && (
          <div className="space-y-3">
            {items.map((s) => (
              <Card key={s.suggestion_id}>
                <CardHeader>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <CardTitle className="text-base font-medium">
                      {s.rule_name || s.rule_id || '未知规则'}
                    </CardTitle>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">
                        {suggestionTypeLabel[s.suggestion_type] || s.suggestion_type}
                      </Badge>
                      <Badge
                        variant={s.rule_patch_recommended ? 'default' : 'secondary'}
                      >
                        {s.rule_patch_recommended ? '建议改规则' : '非规则问题'}
                      </Badge>
                      <span className="text-xs text-text-muted">
                        置信度 {s.confidence}
                      </span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  {s.rule_file && (
                    <div className="text-xs text-text-muted">
                      规则文件：<code className="text-text-secondary">{s.rule_file}</code>
                    </div>
                  )}
                  <Drawer
                    open={openId === s.suggestion_id}
                    onOpenChange={(o) => setOpenId(o ? s.suggestion_id : null)}
                  >
                    <DrawerTrigger asChild>
                      <Button variant="outline">查看 diff</Button>
                    </DrawerTrigger>
                    <DrawerContent className="max-h-[85vh]">
                      <DrawerHeader>
                        <DrawerTitle>{s.rule_name || s.rule_id}</DrawerTitle>
                      </DrawerHeader>
                      <div className="overflow-auto px-4 pb-2">
                        <DiffViewer
                          oldValue={s.original_snippet || ''}
                          newValue={s.suggested_snippet || ''}
                          oldFileName={s.rule_file || 'original.sf'}
                          newFileName={s.rule_file || 'suggested.sf'}
                        />
                      </div>
                      {(s.review_comments?.length ?? 0) > 0 && (
                        <div className="space-y-1 px-4 py-2 text-sm">
                          <div className="font-medium text-text-primary">审阅意见</div>
                          {s.review_comments!.map((c, i) => (
                            <div key={i} className="text-text-secondary">
                              <span className="text-text-muted">L{c.line}：</span>
                              {c.message}
                            </div>
                          ))}
                        </div>
                      )}
                      {(s.validation_commands?.length ?? 0) > 0 && (
                        <div className="space-y-1 px-4 py-2 text-sm">
                          <div className="font-medium text-text-primary">验证命令</div>
                          {s.validation_commands!.map((cmd, i) => (
                            <div key={i} className="text-text-secondary">
                              <code className="text-text-muted">{cmd}</code>
                            </div>
                          ))}
                        </div>
                      )}
                      <div className="flex justify-end gap-2 p-4">
                        <Button variant="outline" onClick={() => handleDismiss(s.suggestion_id)}>
                          不采用
                        </Button>
                        <Button onClick={() => handleDismiss(s.suggestion_id)}>
                          标记已审阅
                        </Button>
                      </div>
                    </DrawerContent>
                  </Drawer>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </PageShell>
  )
}