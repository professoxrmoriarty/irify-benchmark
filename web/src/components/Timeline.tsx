interface TimelineItem {
  id: string
  title: string
  time: string
  description?: string
  status: 'success' | 'warning' | 'danger' | 'neutral'
}

const statusDot: Record<TimelineItem['status'], string> = {
  success: 'bg-emerald-500',
  warning: 'bg-amber-500',
  danger: 'bg-red-500',
  neutral: 'bg-slate-300',
}

export function Timeline({ items }: { items: TimelineItem[] }) {
  return (
    <div className="space-y-0">
      {items.map((item, index) => (
        <div key={item.id} className="relative flex gap-4 pb-6 last:pb-0">
          {index !== items.length - 1 && (
            <div className="absolute left-[7px] top-4 h-full w-px bg-border" />
          )}
          <div
            className={`relative z-10 mt-1.5 h-3.5 w-3.5 rounded-full ${statusDot[item.status]}`}
            aria-hidden="true"
          />
          <div className="flex-1">
            <div className="text-sm font-medium text-text-primary">{item.title}</div>
            {item.description && (
              <div className="text-xs text-text-secondary">{item.description}</div>
            )}
            <div className="text-xs text-text-muted">{item.time}</div>
          </div>
        </div>
      ))}
    </div>
  )
}
