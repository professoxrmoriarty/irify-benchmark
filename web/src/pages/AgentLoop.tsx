import { PageShell } from '@/design-system/PageShell'
import { StatusBadge } from '@/design-system/StatusBadge'
import { Timeline } from '@/components/Timeline'
import { Card, CardContent } from '@/components/ui/card'
import {
  Drawer,
  DrawerContent,
  DrawerHeader,
  DrawerTitle,
  DrawerTrigger,
} from '@/components/ui/drawer'

const runs = [
  { id: 'a1', name: 'Agent Run #7', status: 'info' as const },
  { id: 'a2', name: 'Agent Run #6', status: 'success' as const },
]

const steps = [
  { id: 's1', title: '分析项目结构', time: '2 分钟前', status: 'success' as const },
  { id: 's2', title: '生成测试用例', time: '1 分钟前', status: 'success' as const },
]

export function AgentLoop() {
  return (
    <PageShell title="Agent 运行">
      <div className="space-y-3">
        {runs.map((run) => (
          <Card key={run.id}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="font-medium text-text-primary">{run.name}</div>
                <Drawer>
                  <DrawerTrigger asChild>
                    <button type="button" className="text-sm text-primary">
                      查看步骤
                    </button>
                  </DrawerTrigger>
                  <DrawerContent>
                    <DrawerHeader>
                      <DrawerTitle>{run.name}</DrawerTitle>
                    </DrawerHeader>
                    <div className="p-4">
                      <Timeline items={steps} />
                    </div>
                  </DrawerContent>
                </Drawer>
              </div>
              <div className="mt-2">
                <StatusBadge status={run.status} />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </PageShell>
  )
}
