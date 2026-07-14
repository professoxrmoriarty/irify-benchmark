import { useEffect, useState } from 'react'
import { PageShell } from '@/design-system/PageShell'
import { LoadingState } from '@/design-system/LoadingState'
import { ErrorState } from '@/design-system/ErrorState'
import { EmptyState } from '@/design-system/EmptyState'
import { Timeline } from '@/components/Timeline'
import { listProjects, getProjectResults } from '@/api/client'
import type { Project, Result } from '@/types'

interface RunItem {
  project: Project
  result: Result
}

export function ResultHistory() {
  const [items, setItems] = useState<RunItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function load() {
      try {
        const projects = await listProjects()
        if (projects.length === 0) {
          setItems([])
          return
        }
        const results = await Promise.all(
          projects.map((p) =>
            getProjectResults(p.project_id)
              .then((runs) => (runs || []).map((r) => ({ project: p, result: r })))
              .catch(() => [] as RunItem[])
          )
        )
        const all = results
          .flat()
          .sort((a, b) => new Date(b.result.scan_time).getTime() - new Date(a.result.scan_time).getTime())
        setItems(all)
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err))
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  const timelineItems = items.map((item) => {
    const r = item.result
    const tp = r.summary?.tp ?? 0
    const fn = r.summary?.fn ?? 0
    const fp = r.summary?.fp ?? 0
    const total = r.summary?.total_cases ?? 0
    const passRate = total > 0 ? Math.round((tp / total) * 1000) / 10 : 0
    const status = fn === 0 && fp === 0 ? 'success' : fn > tp || fp > tp ? 'danger' : 'warning'
    return {
      id: `${r.benchmark_id}-${r.scan_time}`,
      title: `${item.project.name} · ${r.engine} ${r.engine_version}`,
      description: `TP ${tp} / FN ${fn} / FP ${fp} · 通过率 ${passRate}%`,
      time: new Date(r.scan_time).toLocaleString('zh-CN'),
      status: status as 'success' | 'warning' | 'danger' | 'neutral',
    }
  })

  return (
    <PageShell title="运行历史">
      {loading && <LoadingState />}
      {error && <ErrorState message={error} />}
      {!loading && !error && (
        <>
          {timelineItems.length === 0 ? (
            <EmptyState message="暂无运行记录" />
          ) : (
            <Timeline items={timelineItems} />
          )}
        </>
      )}
    </PageShell>
  )
}
