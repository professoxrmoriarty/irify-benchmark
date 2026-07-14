import { useEffect, useState } from 'react'
import { PageShell } from '@/design-system/PageShell'
import { LoadingState } from '@/design-system/LoadingState'
import { ErrorState } from '@/design-system/ErrorState'
import { StatusBadge } from '@/design-system/StatusBadge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { listProjects, getProjectFindings } from '@/api/client'
import type { FindingSet } from '@/types'

type RuleStat = {
  rule_id: string
  rule_name: string
  count: number
}

export function RuleFeedbackBoard() {
  const [rules, setRules] = useState<RuleStat[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => {
    async function load() {
      try {
        const projects = await listProjects()
        if (projects.length === 0) {
          setRules([])
          return
        }
        const result = await getProjectFindings(projects[0].project_id)
        if ('findings' in result) {
          const counts = new Map<string, RuleStat>()
          for (const f of (result as FindingSet).findings) {
            const existing = counts.get(f.rule_id)
            if (existing) {
              existing.count += 1
            } else {
              counts.set(f.rule_id, { rule_id: f.rule_id, rule_name: f.rule_name, count: 1 })
            }
          }
          setRules(Array.from(counts.values()))
        } else {
          setRules([])
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err))
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  return (
    <PageShell title="规则反馈">
      {loading && <LoadingState />}
      {error && <ErrorState message={error} />}
      {!loading && !error && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {rules.map((rule) => (
            <Card key={rule.rule_id}>
              <CardHeader>
                <CardTitle className="text-base font-medium">{rule.rule_name}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="mb-4 flex items-center justify-between">
                  <div>
                    <div className="text-xs text-text-muted">命中次数</div>
                    <div className="text-2xl font-semibold text-text-primary">{rule.count}</div>
                  </div>
                  <StatusBadge status={rule.count > 5 ? 'success' : 'warning'} />
                </div>
                <button
                  type="button"
                  onClick={() => setExpanded(expanded === rule.rule_id ? null : rule.rule_id)}
                  className="flex items-center text-xs text-primary"
                >
                  反馈历史
                  {expanded === rule.rule_id ? (
                    <ChevronUp className="ml-1 h-3 w-3" aria-hidden="true" />
                  ) : (
                    <ChevronDown className="ml-1 h-3 w-3" aria-hidden="true" />
                  )}
                </button>
                {expanded === rule.rule_id && (
                  <div className="mt-3 text-xs text-text-muted">反馈详情列表占位</div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </PageShell>
  )
}
