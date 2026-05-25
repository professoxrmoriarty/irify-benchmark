import { Routes, Route, NavLink } from 'react-router-dom'
import { Dashboard } from './pages/Dashboard'
import { ProjectExplorer } from './pages/ProjectExplorer'
import { ResultHistory } from './pages/ResultHistory'
import { FindingsPage } from './pages/FindingsPage'

import ReviewQueue from './pages/ReviewQueue'
import CaseList from './pages/CaseList'

function App() {
  return (
    <div>
      <nav className="navbar">
        <div className="nav-brand">IRify Benchmark</div>
        <ul className="nav-links">
          <li><NavLink to="/" end>Projects</NavLink></li>
          <li><NavLink to="/cases">Cases</NavLink></li>
          <li><NavLink to="/review">Review</NavLink></li>
          <li><NavLink to="/results">Results</NavLink></li>
        </ul>
      </nav>
      <main>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/project/:id" element={<ProjectExplorer />} />
          <Route path="/cases" element={<CaseList />} />
          <Route path="/review" element={<ReviewQueue />} />
          <Route path="/results" element={<ResultHistory />} />
          <Route path="/project/:id/results" element={<ResultHistory />} />
          <Route path="/project/:id/results/scan" element={<FindingsPage />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
