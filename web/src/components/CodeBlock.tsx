import { useEffect, useState } from 'react'
import { codeToHtml } from 'shiki'

interface CodeBlockProps {
  code: string
  language?: string
}

export function CodeBlock({ code, language = 'text' }: CodeBlockProps) {
  const [html, setHtml] = useState('')

  useEffect(() => {
    let cancelled = false
    codeToHtml(code || '', {
      lang: language || 'text',
      theme: 'github-light',
    })
      .then((result) => {
        if (!cancelled) setHtml(result)
      })
      .catch(() => {
        if (!cancelled) {
          const escaped = (code || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
          setHtml(`<pre class="shiki" style="background-color:#ffffff;padding:1rem"><code>${escaped}</code></pre>`)
        }
      })
    return () => {
      cancelled = true
    }
  }, [code, language])

  return (
    <div
      className="overflow-auto rounded-lg border border-border bg-surface p-4 text-xs"
      dangerouslySetInnerHTML={{ __html: html }}
    />
  )
}
