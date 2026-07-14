import { Routes, Route } from 'react-router-dom'
import { AppShell } from '@/design-system/AppShell'
import { Dashboard } from '@/pages/Dashboard'
import { ProjectExplorer } from '@/pages/ProjectExplorer'
import { ResultHistory } from '@/pages/ResultHistory'
import DiagnosisOverview from '@/pages/DiagnosisOverview'
import CaseList from '@/pages/CaseList'
import { CaseDetail } from '@/pages/CaseDetail'
import { FindingsPage } from '@/pages/FindingsPage'
import ReviewQueue from '@/pages/ReviewQueue'
import { RuleFeedbackBoard } from '@/pages/RuleFeedbackBoard'
import RuleReview from '@/pages/RuleReview'
import { AIIntake } from '@/pages/AIIntake'
import { AgentLoop } from '@/pages/AgentLoop'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<AppShell />}>
        <Route index element={<Dashboard />} />
        <Route path="projects" element={<ProjectExplorer />} />
        <Route path="history" element={<ResultHistory />} />
        <Route path="diagnosis" element={<DiagnosisOverview />} />
        <Route path="cases" element={<CaseList />} />
        <Route path="cases/:id" element={<CaseDetail />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="review" element={<ReviewQueue />} />
        <Route path="rule-feedback" element={<RuleFeedbackBoard />} />
        <Route path="rule-review" element={<RuleReview />} />
        <Route path="ai" element={<AIIntake />} />
        <Route path="agent" element={<AgentLoop />} />
      </Route>
    </Routes>
  )
}
