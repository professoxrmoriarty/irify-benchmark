import { NavLink, Outlet } from 'react-router-dom'
import { LayoutGrid, FolderOpen, Files, GitBranch, History } from 'lucide-react'

const navItems = [
  { to: '/', label: '工作台', icon: LayoutGrid, end: true },
  { to: '/projects', label: '项目', icon: FolderOpen },
  { to: '/cases', label: '用例', icon: Files },
  { to: '/history', label: '运行', icon: History },
  { to: '/review', label: '审核', icon: GitBranch },
]

export function AppShell() {
  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b border-border bg-surface/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-7xl items-center px-4">
          <div className="mr-6 text-base font-semibold text-primary">IRIFY · 测评</div>
          <nav className="flex items-center gap-1">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-secondary text-text-primary'
                      : 'text-text-muted hover:bg-muted hover:text-text-secondary'
                  }`
                }
              >
                <item.icon className="h-4 w-4" aria-hidden="true" />
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-7xl p-4">
        <Outlet />
      </main>
    </div>
  )
}
