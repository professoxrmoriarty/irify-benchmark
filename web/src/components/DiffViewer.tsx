import { useEffect, useState } from 'react'
import { createTwoFilesPatch } from 'diff'
import * as Diff2Html from 'diff2html'
import 'diff2html/bundles/css/diff2html.min.css'

interface DiffViewerProps {
  oldValue: string
  newValue: string
  oldFileName?: string
  newFileName?: string
}

export function DiffViewer({ oldValue, newValue, oldFileName = 'a', newFileName = 'b' }: DiffViewerProps) {
  const [html, setHtml] = useState('')

  useEffect(() => {
    const patch = createTwoFilesPatch(oldFileName, newFileName, oldValue, newValue)
    Promise.resolve(
      Diff2Html.html(patch, {
        drawFileList: false,
        matching: 'lines',
        outputFormat: 'side-by-side',
      })
    ).then(setHtml)
  }, [oldValue, newValue, oldFileName, newFileName])

  return (
    <div
      className="overflow-auto rounded-lg border border-border bg-surface"
      dangerouslySetInnerHTML={{ __html: html }}
    />
  )
}
