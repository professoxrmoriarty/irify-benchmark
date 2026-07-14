import { useEffect, useMemo, useState } from 'react'
import { codeToTokens } from 'shiki'
import type { TokensResult } from 'shiki'

export interface CodeHighlight {
  line: number
  type: 'source' | 'sink' | 'sanitizer'
  label?: string
}

interface HighlightedCodeProps {
  code: string
  language?: string
  highlights?: CodeHighlight[]
}

export function HighlightedCode({ code, language = 'text', highlights = [] }: HighlightedCodeProps) {
  const [result, setResult] = useState<TokensResult | null>(null)

  useEffect(() => {
    let cancelled = false
    codeToTokens(code || '', {
      lang: (language || 'text') as never,
      theme: 'github-light',
    })
      .then((res) => {
        if (!cancelled) setResult(res)
      })
      .catch(() => {
        if (!cancelled) setResult(null)
      })
    return () => {
      cancelled = true
    }
  }, [code, language])

  const highlightMap = useMemo(() => {
    const map = new Map<number, CodeHighlight>()
    for (const h of highlights) {
      if (h.line > 0) map.set(h.line, h)
    }
    return map
  }, [highlights])

  const lines = useMemo(() => {
    if (result?.tokens) return result.tokens
    return (code || '').split('\n').map((line) => [{ content: line, color: '#24292e', fontStyle: 0 }])
  }, [result, code])

  return (
    <div className="overflow-auto rounded-lg border border-border bg-surface text-xs">
      <div className="min-w-full font-mono leading-5">
        {lines.map((tokens, idx) => {
          const lineNumber = idx + 1
          const highlight = highlightMap.get(lineNumber)
          const rowClass =
            highlight?.type === 'source'
              ? 'bg-amber-50/80 border-l-2 border-l-amber-400'
              : highlight?.type === 'sink'
              ? 'bg-rose-50/80 border-l-2 border-l-rose-400'
              : highlight?.type === 'sanitizer'
              ? 'bg-blue-50/80 border-l-2 border-l-blue-400'
              : 'border-l-2 border-l-transparent hover:bg-muted/30'

          return (
            <div key={lineNumber} className={`flex ${rowClass}`}>
              <div className="sticky left-0 w-12 flex-shrink-0 select-none border-r border-border bg-surface px-2 py-0.5 text-right text-text-muted">
                {lineNumber}
              </div>
              <div className="flex flex-1 items-start gap-2 px-3 py-0.5 whitespace-pre">
                <span>
                  {tokens.map((token, tidx) => (
                    <span
                      key={tidx}
                      style={{
                        color: (token as { color?: string }).color,
                        fontStyle: (token.fontStyle ?? 0) & 1 ? 'italic' : 'normal',
                        fontWeight: (token.fontStyle ?? 0) & 2 ? 'bold' : 'normal',
                        textDecoration: (token.fontStyle ?? 0) & 4 ? 'underline' : 'none',
                      }}
                    >
                      {token.content}
                    </span>
                  ))}
                </span>
                {highlight && (
                  <span
                    className={`mt-0.5 flex-shrink-0 rounded px-1.5 py-0 text-[10px] font-medium ${
                      highlight.type === 'source'
                        ? 'bg-amber-100 text-amber-700'
                        : highlight.type === 'sink'
                        ? 'bg-rose-100 text-rose-700'
                        : 'bg-blue-100 text-blue-700'
                    }`}
                  >
                    {highlight.label || highlight.type}
                  </span>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
