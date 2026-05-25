import { useState } from 'react'
import './FileTree.css'

export interface FileEntry {
  name: string
  type: 'file' | 'directory'
  path: string
  children?: FileEntry[]
}

interface FileTreeProps {
  entries: FileEntry[]
  onSelectFile: (path: string) => void
  selectedPath?: string
}

function TreeNode({
  entry,
  onSelectFile,
  selectedPath,
}: {
  entry: FileEntry
  onSelectFile: (path: string) => void
  selectedPath?: string
}) {
  const [open, setOpen] = useState(true)
  const isSelected = selectedPath === entry.path

  const handleClick = () => {
    if (entry.type === 'directory') {
      setOpen(!open)
    } else {
      onSelectFile(entry.path)
    }
  }

  return (
    <li>
      <div
        className={`file-tree-item ${isSelected ? 'selected' : ''}`}
        onClick={handleClick}
      >
        <span className="file-tree-toggle">
          {entry.type === 'directory' ? (open ? '▼' : '▶') : ''}
        </span>
        <span className="file-tree-icon">
          {entry.type === 'directory' ? (open ? '📂' : '📁') : '📄'}
        </span>
        <span className="file-tree-label">{entry.name}</span>
      </div>
      {entry.type === 'directory' && open && entry.children && entry.children.length > 0 && (
        <ul>
          {entry.children.map((child) => (
            <TreeNode
              key={child.path}
              entry={child}
              onSelectFile={onSelectFile}
              selectedPath={selectedPath}
            />
          ))}
        </ul>
      )}
    </li>
  )
}

export function FileTree({ entries, onSelectFile, selectedPath }: FileTreeProps) {
  return (
    <div className="file-tree">
      <ul>
        {entries.map((entry) => (
          <TreeNode
            key={entry.path}
            entry={entry}
            onSelectFile={onSelectFile}
            selectedPath={selectedPath}
          />
        ))}
      </ul>
    </div>
  )
}
