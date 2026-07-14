import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { PageShell } from '@/design-system/PageShell'
import { MetricCard } from '@/design-system/MetricCard'
import { StatusBadge } from '@/design-system/StatusBadge'
import { EmptyState } from '@/design-system/EmptyState'
import { LoadingState } from '@/design-system/LoadingState'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { listProjects, listCases, getPending, getProjectResults } from '@/api/client'
import type { Result } from '@/types'

function CollapsibleSection({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  return (
    <Card>
      <CardHeader className="pb-0">
        <button
          type="button"
          onClick={() => setOpen(!open)}
          className="flex w-full items-center justify-between py-2"
        >
          <CardTitle className="text-base font-medium">{title}</CardTitle>
          {open ? <ChevronUp className="h-4 w-4" aria-hidden="true" /> : <ChevronDown className="h-4 w-4" aria-hidden="true" />}
        </button>
      </CardHeader>
      {open && <CardContent>{children}</CardContent>}
    </Card>
  )
}

interface DashboardData {
  projectCount: number
  caseCount: number
  pendingCount: number
  passRate: number | null
  recentRuns: Result[]
  loading: boolean
  error: string | null
}

function useDashboardData(): DashboardData {
  const [data, setData] = useState<DashboardData>({
    projectCount: 0,
    caseCount: 0,
    pendingCount: 0,
    passRate: null,
    recentRuns: [],
    loading: true,
    error: null,
  })

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const [projects, casesRes, pendingRes] = await Promise.all([
          listProjects(),
          listCases(),
          getPending(),
        ])

        const resultsArrays = (
          await Promise.all(
            projects.map((p) => getProjectResults(p.project_id).catch(() => null as Result[] | null))
          )
        ).filter((arr): arr is Result[] => arr != null)

        const latestPerProject: Result[] = []
        for (const results of resultsArrays) {
          if (results.length === 0) continue
          const sorted = [...results].sort(
            (a, b) => new Date(b.scan_time).getTime() - new Date(a.scan_time).getTime()
          )
          latestPerProject.push(sorted[0])
        }

        const totalCases = latestPerProject.reduce(
          (sum, r) => sum + (r.summary?.total_cases ?? 0),
          0
        )
        const totalTP = latestPerProject.reduce((sum, r) => sum + (r.summary?.tp ?? 0), 0)
        const passRate = totalCases > 0 ? Math.round((totalTP / totalCases) * 1000) / 10 : null

        const recentRuns = latestPerProject
          .sort((a, b) => new Date(b.scan_time).getTime() - new Date(a.scan_time).getTime())
          .slice(0, 5)

        if (!cancelled) {
          setData({
            projectCount: projects.length,
            caseCount: casesRes.cases.length,
            pendingCount: pendingRes.items?.length ?? 0,
            passRate,
            recentRuns,
            loading: false,
            error: null,
          })
        }
      } catch (err) {
        if (!cancelled) {
          setData((prev) => ({
            ...prev,
            loading: false,
            error: err instanceof Error ? err.message : String(err),
          }))
        }
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [])

  return data
}

export function Dashboard() {
  const { projectCount, caseCount, pendingCount, passRate, recentRuns, loading, error } = useDashboardData()

  const metrics = useMemo(
    () => [
      { title: '项目数', value: projectCount },
      { title: '用例数', value: caseCount },
      { title: '通过率', value: passRate == null ? '-' : `${passRate}%` },
      { title: '待审核', value: pendingCount },
    ],
    [projectCount, caseCount, passRate, pendingCount]
  )

  const qualityGatePass = passRate == null || passRate >= 80

  return (
    <PageShell title="工作台">
      {loading && <LoadingState />}
      {error && <div className="text-sm text-danger">加载数据失败：{error}</div>}
      {!loading && !error && (
        <div className="space-y-6">
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25 }}
            className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4"
          >
            {metrics.map((m) => (
              <MetricCard key={m.title} {...m} />
            ))}
          </motion.div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-base font-medium">质量门</CardTitle>
              </CardHeader>
              <CardContent className="flex items-center gap-3">
                <StatusBadge status={qualityGatePass ? 'success' : 'warning'} />
                <span className="text-sm">
                  {passRate == null
                    ? '暂无扫描结果，无法判定质量门'
                    : qualityGatePass
                    ? '当前批次达到通过标准'
                    : `当前通过率 ${passRate}% 低于 80% 阈值`}
                </span>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-base font-medium">最近运行</CardTitle>
              </CardHeader>
              <CardContent>
                {recentRuns.length === 0 ? (
                  <EmptyState message="暂无运行记录" />
                ) : (
                  <ul className="space-y-3">
                    {recentRuns.map((r) => {
                      const tp = r.summary?.tp ?? 0
                      const fn = r.summary?.fn ?? 0
                      const fp = r.summary?.fp ?? 0
                      return (
                        <li key={`${r.benchmark_id}-${r.scan_time}`} className="text-sm">
                          <Link
                            to="/history"
                            className="flex items-center justify-between rounded-md p-2 hover:bg-muted"
                          >
                            <span className="font-medium text-text-primary">
                              {r.engine} {r.engine_version}
                            </span>
                            <span className="text-xs text-text-muted">
                              TP {tp} / FN {fn} / FP {fp}
                            </span>
                          </Link>
                          <div className="px-2 text-xs text-text-muted">
                            {new Date(r.scan_time).toLocaleString('zh-CN')}
                          </div>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>

          <CollapsibleSection title="覆盖率">
            <div className="text-sm text-text-muted">覆盖率详情折叠展示</div>
          </CollapsibleSection>
          <CollapsibleSection title="根因分布">
            <div className="text-sm text-text-muted">根因分布详情折叠展示</div>
          </CollapsibleSection>
        </div>
      )}
    </PageShell>
  )
}
