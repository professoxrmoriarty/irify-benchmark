import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

interface MetricCardProps {
  title: string
  value: string | number
  trend?: { value: string; positive: boolean }
}

export function MetricCard({ title, value, trend }: MetricCardProps) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-text-muted">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-semibold text-text-primary">{value}</div>
        {trend && (
          <div className={`mt-1 text-xs ${trend.positive ? 'text-success' : 'text-danger'}`}>
            {trend.value}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
