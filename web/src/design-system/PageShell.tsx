import type { ReactNode } from 'react'

interface PageTab {
  value: string
  label: string
}

interface PageShellProps {
  title: string
  actions?: ReactNode
  tabs?: PageTab[]
  activeTab?: string
  onTabChange?: (value: string) => void
  children: ReactNode
}

export function PageShell({ title, actions, tabs, activeTab, onTabChange, children }: PageShellProps) {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-text-primary">{title}</h1>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </div>
      {tabs && (
        <nav className="flex gap-1 border-b border-border pb-1">
          {tabs.map((tab) => (
            <button
              key={tab.value}
              onClick={() => onTabChange?.(tab.value)}
              className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                activeTab === tab.value
                  ? 'bg-secondary text-text-primary'
                  : 'text-text-muted hover:bg-muted hover:text-text-secondary'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      )}
      <div className="rounded-xl border border-border bg-surface p-4 shadow-sm">{children}</div>
    </div>
  )
}
