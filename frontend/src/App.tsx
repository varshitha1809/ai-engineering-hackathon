import { BrowserRouter, Link, Route, Routes } from 'react-router-dom'
import AppShell from './components/AppShell'
import Analyze from './pages/Analyze'
import AnalysisDetail from './pages/AnalysisDetail'
import Campaigns from './pages/Campaigns'
import Cases from './pages/Cases'
import Dashboard from './pages/Dashboard'
import Evidence from './pages/Evidence'
import Lab from './pages/Lab'
import Landing from './pages/Landing'
import ModelPage from './pages/ModelPage'
import Picker from './pages/Picker'
import Reconstruction from './pages/Reconstruction'
import Settings from './pages/Settings'

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/app" element={<AppShell />}>
        <Route index element={<Dashboard />} />
        <Route path="analyze" element={<Analyze />} />
        <Route path="forensics" element={<Picker target="forensics" />} />
        <Route path="analyses/:id" element={<AnalysisDetail />} />
        <Route path="evidence" element={<Picker target="evidence" />} />
        <Route path="evidence/:id" element={<Evidence />} />
        <Route path="reconstruction" element={<Picker target="reconstruction" />} />
        <Route path="reconstruction/:id" element={<Reconstruction />} />
        <Route path="campaigns" element={<Campaigns />} />
        <Route path="campaigns/:id" element={<Campaigns />} />
        <Route path="lab" element={<Lab />} />
        <Route path="lab/:runId" element={<Lab />} />
        <Route path="model" element={<ModelPage />} />
        <Route path="cases" element={<Cases />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<NotFound />} />
      </Route>
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}

function NotFound() {
  return <div className="state" style={{ margin: 40 }}><b>Page not found</b><p><Link to="/app">Back to the dashboard</Link></p></div>
}

export default function App() {
  return <BrowserRouter><AppRoutes /></BrowserRouter>
}
