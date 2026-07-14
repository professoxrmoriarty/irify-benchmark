import { useState } from 'react'
import { Link } from 'react-router-dom'
import { PageShell } from '@/design-system/PageShell'
import { StatusBadge } from '@/design-system/StatusBadge'
import { LoadingState } from '@/design-system/LoadingState'
import { ErrorState } from '@/design-system/ErrorState'
import { FilterBar } from '@/components/FilterBar'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { useProjectCases, useProjectFiles, useProjects } from '@/api/swr'
import type { Project } from '@/types'
import { Plus, FolderOpen, Files, GitBranch } from 'lucide-react'

function ProjectCard({ project }: { project: Project }) {
  const { data: files } = useProjectFiles(project.project_id)
  const { data: cases } = useProjectCases(project.project_id)
  const fileCount = files?.children?.length ?? 0
  const caseCount = cases?.cases?.length ?? 0

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base font-medium">{project.name}</CardTitle>
          <StatusBadge status="success" />
        </div>
        <div className="text-xs text-text-muted">{project.language || '未知语言'}</div>
      </CardHeader>
      <CardContent>
        <div className="mb-3 flex gap-4 text-sm">
          <span className="flex items-center gap-1 text-text-muted">
            <Files className="h-3.5 w-3.5" aria-hidden="true" />
            {fileCount} 文件
          </span>
          <span className="flex items-center gap-1 text-text-muted">
            <GitBranch className="h-3.5 w-3.5" aria-hidden="true" />
            {caseCount} 用例
          </span>
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button variant="ghost" size="sm" className="h-auto p-0 text-primary">
              <FolderOpen className="mr-1 h-4 w-4" aria-hidden="true" /> 查看详情
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>{project.name}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 text-sm text-text-secondary">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-xs text-text-muted">语言</div>
                  <div>{project.language || '未知'}</div>
                </div>
                <div>
                  <div className="text-xs text-text-muted">状态</div>
                  <div>ready</div>
                </div>
                <div>
                  <div className="text-xs text-text-muted">文件</div>
                  <div>{fileCount}</div>
                </div>
                <div>
                  <div className="text-xs text-text-muted">用例</div>
                  <div>{caseCount}</div>
                </div>
              </div>
              <div className="flex gap-2">
                <Button asChild size="sm">
                  <Link to={`/cases?project=${project.project_id}`}>查看用例</Link>
                </Button>
                <Button asChild variant="outline" size="sm">
                  <Link to={`/findings?project=${project.project_id}`}>查看结果</Link>
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  )
}

export function ProjectExplorer() {
  const { data: projects, error, isLoading, mutate } = useProjects()
  const [filter, setFilter] = useState('')

  const filtered = projects
    ? projects.filter((p) => p.name?.toLowerCase().includes(filter.toLowerCase()))
    : []

  return (
    <PageShell
      title="项目"
      actions={
        <>
          <Button variant="outline">导入</Button>
          <Button>
            <Plus className="mr-1 h-4 w-4" aria-hidden="true" /> 新建项目
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FilterBar value={filter} onChange={setFilter} placeholder="搜索项目" />
        {isLoading && <LoadingState />}
        {error && <ErrorState message="加载项目失败" onRetry={() => mutate()} />}
        {!isLoading && !error && (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            {filtered.map((project) => (
              <ProjectCard key={project.project_id} project={project} />
            ))}
          </div>
        )}
      </div>
    </PageShell>
  )
}
