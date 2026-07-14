import { Input } from '@/components/ui/input'
import { Search } from 'lucide-react'

interface FilterBarProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  children?: React.ReactNode
}

export function FilterBar({ value, onChange, placeholder = '搜索', children }: FilterBarProps) {
  return (
    <div className="flex items-center gap-3">
      <div className="relative flex-1">
        <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-text-muted" aria-hidden="true" />
        <Input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className="pl-9"
        />
      </div>
      {children}
    </div>
  )
}
