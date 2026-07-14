import { Inbox } from 'lucide-react'

export function EmptyState({ message = '暂无数据' }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-text-muted">
      <Inbox className="mb-3 h-10 w-10 opacity-40" aria-hidden="true" />
      <p className="text-sm">{message}</p>
    </div>
  )
}
