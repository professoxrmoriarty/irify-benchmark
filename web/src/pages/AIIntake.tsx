import { useState } from 'react'
import { PageShell } from '@/design-system/PageShell'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent } from '@/components/ui/card'

export function AIIntake() {
  const [input, setInput] = useState('')
  const [history, setHistory] = useState<string[]>([])

  const submit = () => {
    if (!input.trim()) return
    setHistory([input, ...history])
    setInput('')
  }

  return (
    <PageShell title="AI 辅助">
      <div className="space-y-4">
        <div className="flex gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="输入问题"
            onKeyDown={(e) => e.key === 'Enter' && submit()}
          />
          <Button onClick={submit}>提交</Button>
        </div>
        <div className="space-y-2">
          {history.map((item, idx) => (
            <Card key={idx}>
              <CardContent className="p-3 text-sm text-text-secondary">{item}</CardContent>
            </Card>
          ))}
        </div>
      </div>
    </PageShell>
  )
}
