import { useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { PageShell } from '@/design-system/PageShell'
import { LoadingState } from '@/design-system/LoadingState'
import { ErrorState } from '@/design-system/ErrorState'
import { HighlightedCode, type CodeHighlight } from '@/components/HighlightedCode'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { getFileContent, getProjectCase, listCases } from '@/api/client'
import type { CaseWithProject, Expectation, Flow } from '@/types'

export function CaseDetail() {
  const { id } = useParams()
  const [caseItem, setCaseItem] = useState<CaseWithProject | null>(null)
  const [sourceCode, setSourceCode] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    let cancelled = false
    setLoading(true)
    setError(null)

    async function load() {
      try {
        const list = await listCases()
        const summary = list.cases.find((c) => c.case_id === id)
        if (!summary || !summary.project?.project_id) {
          if (!cancelled) setError('未找到该用例')
          return
        }

        const projectId = summary.project.project_id
        const full = await getProjectCase(projectId, id as string)
        if (!full) {
          if (!cancelled) setError('未找到该用例')
          return
        }
        const merged: CaseWithProject = { ...full, project: summary.project }
        if (!cancelled) setCaseItem(merged)

        const sourcePath = full.expectation?.flow?.source?.file ?? full.expectation?.flow?.sink?.file
        if (full.source_code) {
          if (!cancelled) setSourceCode(full.source_code)
        } else if (sourcePath) {
          try {
            const text = await getFileContent(projectId, sourcePath)
            if (!cancelled) setSourceCode(text)
          } catch {
            if (!cancelled) setSourceCode('')
          }
        } else {
          if (!cancelled) setSourceCode('')
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err))
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    return () => {
      cancelled = true
    }
  }, [id])

  const highlights = useMemo<CodeHighlight[]>(() => {
    if (!caseItem?.expectation?.flow) return []
    const flow: Flow = caseItem.expectation.flow
    const list: CodeHighlight[] = []
    if (flow.source?.line) {
      list.push({ line: flow.source.line, type: 'source', label: 'source' })
    }
    if (flow.sink?.line) {
      list.push({ line: flow.sink.line, type: 'sink', label: 'sink' })
    }
    for (const s of flow.sanitizers ?? []) {
      if (s.line) {
        list.push({ line: s.line, type: 'sanitizer', label: 'sanitizer' })
      }
    }
    return list
  }, [caseItem])

  const expectationBadges = useMemo(() => {
    if (!caseItem?.expectation) return null
    const exp: Expectation = caseItem.expectation
    const flow = exp.flow
    return (
      <div className="flex flex-wrap gap-2">
        {exp.type && <Badge variant="secondary">type: {exp.type}</Badge>}
        {flow?.source && (
          <Badge variant="outline" className="border-amber-300 text-amber-700">
            source: {flow.source.symbol} (L{flow.source.line})
          </Badge>
        )}
        {flow?.sink && (
          <Badge variant="outline" className="border-rose-300 text-rose-700">
            sink: {flow.sink.symbol} (L{flow.sink.line})
          </Badge>
        )}
        {flow?.sanitizers?.map((s, idx) => (
          <Badge key={idx} variant="outline" className="border-blue-300 text-blue-700">
            sanitizer: {s.symbol} (L{s.line})
          </Badge>
        ))}
      </div>
    )
  }, [caseItem])

  return (
    <PageShell title={caseItem ? caseItem.name : `用例 ${id}`}>
      {loading && <LoadingState />}
      {error && <ErrorState message={error} />}
      {!loading && !error && caseItem && (
        <Tabs defaultValue="code">
          <TabsList>
            <TabsTrigger value="code">代码</TabsTrigger>
            <TabsTrigger value="expected">期望结果</TabsTrigger>
            <TabsTrigger value="meta">元信息</TabsTrigger>
          </TabsList>
          <TabsContent value="code" className="space-y-3 pt-4">
            {expectationBadges}
            <HighlightedCode
              code={sourceCode ?? ''}
              language={caseItem.language}
              highlights={highlights}
            />
          </TabsContent>
          <TabsContent value="expected" className="space-y-3 pt-4 text-sm text-text-secondary">
            {expectationBadges}
            {caseItem.expectation ? (
              <pre className="overflow-auto rounded-lg border border-border bg-surface p-4 text-xs">
                {JSON.stringify(caseItem.expectation, null, 2)}
              </pre>
            ) : (
              <p>暂无期望结果</p>
            )}
          </TabsContent>
          <TabsContent value="meta" className="pt-4 text-sm text-text-secondary">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="text-xs text-text-muted">语言</div>
                <div>{caseItem.language}</div>
              </div>
              <div>
                <div className="text-xs text-text-muted">项目</div>
                <div>{caseItem.project?.name}</div>
              </div>
              <div>
                <div className="text-xs text-text-muted">CWE</div>
                <div>{caseItem.metadata?.cwe || '无'}</div>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      )}
    </PageShell>
  )
}
