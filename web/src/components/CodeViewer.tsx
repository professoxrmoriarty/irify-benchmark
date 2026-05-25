import { useEffect, useRef } from 'react'
import Editor from '@monaco-editor/react'

interface CodeViewerProps {
  content: string
  language: string
  highlights?: {
    sourceLines?: number[]
    sinkLines?: number[]
    sanitizerLines?: number[]
  }
  focusLine?: number
}

export function CodeViewer({ content, language, highlights, focusLine }: CodeViewerProps) {
  const editorRef = useRef<any>(null)
  const monacoRef = useRef<any>(null)
  const decorationIdsRef = useRef<string[]>([])

  const applyDecorations = (editor: any, monaco: any) => {
    const decorations: any[] = []
    highlights?.sourceLines?.forEach((line) => {
      decorations.push({
        range: new monaco.Range(line, 1, line, 1),
        options: {
          isWholeLine: true,
          className: 'highlight-source',
          glyphMarginClassName: 'glyph-source',
        },
      })
    })
    highlights?.sinkLines?.forEach((line) => {
      decorations.push({
        range: new monaco.Range(line, 1, line, 1),
        options: {
          isWholeLine: true,
          className: 'highlight-sink',
          glyphMarginClassName: 'glyph-sink',
        },
      })
    })
    highlights?.sanitizerLines?.forEach((line) => {
      decorations.push({
        range: new monaco.Range(line, 1, line, 1),
        options: {
          isWholeLine: true,
          className: 'highlight-sanitizer',
          glyphMarginClassName: 'glyph-sanitizer',
        },
      })
    })

    decorationIdsRef.current = editor.deltaDecorations(decorationIdsRef.current, decorations)
  }

  const handleEditorDidMount = (editor: any, monaco: any) => {
    editorRef.current = editor
    monacoRef.current = monaco
    applyDecorations(editor, monaco)

    const allLines = [
      ...(highlights?.sourceLines || []),
      ...(highlights?.sinkLines || []),
      ...(highlights?.sanitizerLines || []),
    ]
    if (allLines.length > 0) {
      const firstLine = Math.min(...allLines)
      editor.revealLineInCenter(firstLine)
    }
  }

  // Re-apply decorations when highlights or content change
  useEffect(() => {
    if (editorRef.current && monacoRef.current) {
      const timer = setTimeout(() => {
        applyDecorations(editorRef.current, monacoRef.current)
      }, 100)
      return () => clearTimeout(timer)
    }
  }, [highlights, content])

  // Scroll to focus line when it or content changes
  useEffect(() => {
    if (editorRef.current && focusLine) {
      const timer = setTimeout(() => {
        editorRef.current?.revealLineInCenter(focusLine)
      }, 50)
      return () => clearTimeout(timer)
    }
  }, [focusLine, content])

  // Map common language names to Monaco language ids
  const languageMap: Record<string, string> = {
    java: 'java',
    javascript: 'javascript',
    js: 'javascript',
    typescript: 'typescript',
    ts: 'typescript',
    php: 'php',
    python: 'python',
    py: 'python',
    go: 'go',
    golang: 'go',
    c: 'c',
    cpp: 'cpp',
    'c++': 'cpp',
    csharp: 'csharp',
    'c#': 'csharp',
    ruby: 'ruby',
    rust: 'rust',
    html: 'html',
    xml: 'xml',
    yaml: 'yaml',
    json: 'json',
    sql: 'sql',
    shell: 'shell',
    bash: 'shell',
  }

  const monacoLang = languageMap[language?.toLowerCase()] || language?.toLowerCase() || 'plaintext'

  return (
    <Editor
      height="100%"
      language={monacoLang}
      value={content}
      options={{
        readOnly: true,
        minimap: { enabled: true },
        glyphMargin: true,
        scrollBeyondLastLine: false,
        automaticLayout: true,
      }}
      onMount={handleEditorDidMount}
    />
  )
}
