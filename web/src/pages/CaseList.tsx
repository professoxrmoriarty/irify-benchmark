import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { PageShell } from '@/design-system/PageShell'
import { LoadingState } from '@/design-system/LoadingState'
import { ErrorState } from '@/design-system/ErrorState'
import { FilterBar } from '@/components/FilterBar'
import { StatusBadge } from '@/design-system/StatusBadge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { listCases } from '@/api/client'
import type { CaseWithProject } from '@/types'
import { Plus } from 'lucide-react'

export default function CaseList() {
  const navigate = useNavigate()
  const [cases, setCases] = useState<CaseWithProject[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    listCases()
      .then((data) => setCases(data.cases))
      .catch((err) => setError(errorMessage(err)))
      .finally(() => setLoading(false))
  }, [])

  const filtered = cases.filter((c) => c.name?.toLowerCase().includes(filter.toLowerCase()))

  return (
    <PageShell
      title="用例"
      actions={
        <Button>
          <Plus className="mr-1 h-4 w-4" aria-hidden="true" /> 新增
        </Button>
      }
    >
      <div className="space-y-4">
        <FilterBar value={filter} onChange={setFilter} placeholder="搜索用例" />
        {loading && <LoadingState />}
        {error && <ErrorState message={error} />}
        {!loading && !error && (
          <div className="space-y-3">
            {filtered.map((c) => (
              <Card
                key={c.case_id}
                className="cursor-pointer transition-shadow hover:shadow-md"
                onClick={() => navigate(`/cases/${c.case_id}`)}
              >
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base font-medium">{c.name}</CardTitle>
                    <StatusBadge status={c.expectation ? 'success' : 'warning'} />
                  </div>
                </CardHeader>
                <CardContent className="flex gap-2 text-xs text-text-muted">
                  <span>{c.language}</span>
                  <span>·</span>
                  <span>{c.project?.name}</span>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </PageShell>
  )
}

function errorMessage(err: unknown) {
  return err instanceof Error ? err.message : String(err)
}
