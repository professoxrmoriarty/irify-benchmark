import { Badge } from '@/components/ui/badge'

type Status = 'success' | 'warning' | 'danger' | 'info' | 'neutral'

const statusMap: Record<Status, { label: string; className: string }> = {
  success: { label: '通过', className: 'bg-emerald-50 text-emerald-700 hover:bg-emerald-50' },
  warning: { label: '警告', className: 'bg-amber-50 text-amber-700 hover:bg-amber-50' },
  danger: { label: '失败', className: 'bg-red-50 text-red-700 hover:bg-red-50' },
  info: { label: '运行中', className: 'bg-sky-50 text-sky-700 hover:bg-sky-50' },
  neutral: { label: '待处理', className: 'bg-slate-100 text-slate-700 hover:bg-slate-100' },
}

export function StatusBadge({ status, className }: { status: Status; className?: string }) {
  const config = statusMap[status]
  return <Badge className={`${config.className}${className ? ` ${className}` : ''}`}>{config.label}</Badge>
}
