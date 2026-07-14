import { useEffect, useState } from 'react'
import { PageShell } from '@/design-system/PageShell'
import { LoadingState } from '@/design-system/LoadingState'
import { ErrorState } from '@/design-system/ErrorState'
import { StatusBadge } from '@/design-system/StatusBadge'
import { FilterBar } from '@/components/FilterBar'
import { EmptyState } from '@/design-system/EmptyState'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { getPending, approveItem, rejectItem } from '@/api/client'
import type { PendingItem } from '@/types'

export default function ReviewQueue() {
  const [items, setItems] = useState<PendingItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    getPending()
      .then((data) => setItems(data.items || []))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false))
  }, [])

  async function handleApprove(itemId: string) {
    await approveItem(itemId)
    setItems((prev) => prev.filter((i) => i.item_id !== itemId))
  }

  async function handleReject(itemId: string) {
    await rejectItem(itemId)
    setItems((prev) => prev.filter((i) => i.item_id !== itemId))
  }

  const filtered = items.filter((i) =>
    i.source.toLowerCase().includes(filter.toLowerCase())
  )

  return (
    <PageShell title="待审核">
      <div className="space-y-4">
        <FilterBar value={filter} onChange={setFilter} placeholder="搜索待审核项" />
        {loading && <LoadingState />}
        {error && <ErrorState message={error} />}
        {!loading && !error && filtered.length === 0 && <EmptyState message="暂无待审核项" />}
        {!loading && !error && filtered.length > 0 && (
          <div className="space-y-3">
            {filtered.map((item) => (
              <Card key={item.item_id}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-medium text-text-primary">{item.source}</div>
                      <div className="text-xs text-text-muted">
                        {item.status} · 提交于 {new Date(item.submitted_at).toLocaleDateString('zh-CN')}
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <StatusBadge status="neutral" />
                      <Button size="sm" variant="outline" onClick={() => handleReject(item.item_id)}>
                        驳回
                      </Button>
                      <Button size="sm" onClick={() => handleApprove(item.item_id)}>
                        确认
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </PageShell>
  )
}
