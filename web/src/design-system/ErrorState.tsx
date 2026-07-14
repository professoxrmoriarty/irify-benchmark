import { Button } from '@/components/ui/button'

export function ErrorState({ message = '加载失败', onRetry }: { message?: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-text-muted" role="alert">
      <p className="mb-3 text-sm">{message}</p>
      {onRetry && <Button onClick={onRetry}>重试</Button>}
    </div>
  )
}
