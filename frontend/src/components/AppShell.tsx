import { useEffect, useState } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { Logo } from '../pages/Landing'
import { get } from '../lib/api'
import { IconCog, IconDB, IconDNA, IconFlask, IconFlow, IconFolder, IconGrid, IconMail, IconMenu, IconNodes, IconSearch } from './icons'

const NAV = [
  { group: 'Operate', items: [
    { to: '/app', label: 'Overview', Icon: IconGrid, end: true },
    { to: '/app/analyze', label: 'Analyze email', Icon: IconMail },
    { to: '/app/cases', label: 'Cases & reports', Icon: IconFolder },
  ] },
  { group: 'Investigate', items: [
    { to: '/app/forensics', label: 'Threat forensics', Icon: IconDNA },
    { to: '/app/evidence', label: 'Evidence explorer', Icon: IconSearch },
    { to: '/app/reconstruction', label: 'Attack reconstruction', Icon: IconFlow },
    { to: '/app/campaigns', label: 'Campaign intelligence', Icon: IconNodes },
  ] },
  { group: 'Measure', items: [
    { to: '/app/lab', label: 'Robustness lab', Icon: IconFlask },
    { to: '/app/model', label: 'Dataset & model', Icon: IconDB },
    { to: '/app/settings', label: 'Settings & status', Icon: IconCog },
  ] },
]

interface Health { api: string; database: string; model: { status: string; version: string; error: string } }

export default function AppShell() {
  const [open, setOpen] = useState(false)
  const [health, setHealth] = useState<Health | null>(null)
  const [down, setDown] = useState(false)
  const loc = useLocation()
  useEffect(() => setOpen(false), [loc.pathname])
  useEffect(() => {
    const load = () => get<Health>('/health').then(h => { setHealth(h); setDown(false) }).catch(() => setDown(true))
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [])

  return (
    <div className="shell">
      <aside className={`sidebar ${open ? 'open' : ''}`} aria-label="Application navigation">
        <Link to="/" className="brand"><Logo /><b>PHISHDNA <span>AI</span></b></Link>
        {NAV.map(g => (
          <div key={g.group}>
            <div className="nav-group">{g.group}</div>
            {g.items.map(i => (
              <NavLink key={i.to} to={i.to} end={i.end} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
                <i.Icon />{i.label}
              </NavLink>
            ))}
          </div>
        ))}
        <div style={{ marginTop: 'auto', padding: '16px 8px 4px' }} className="tiny dim">
          Local-first build. Mailbox and SIEM actions are local sandbox records unless a connector is configured.
        </div>
      </aside>
      <div className="main">
        <div className="topbar">
          <div className="row">
            <button className="btn sm menu-btn" onClick={() => setOpen(o => !o)} aria-label="Toggle navigation"><IconMenu width={16} /></button>
            <span className="tiny dim mono" style={{ letterSpacing: '.12em' }}>PHISHDNA / ANALYST WORKBENCH</span>
          </div>
          <div className="row">
            {down && <span className="pill crit" role="alert"><span className="dot" />API unreachable</span>}
            {health && !down && (
              <>
                <span className={`pill ${health.database === 'ok' ? 'good' : 'crit'}`}><span className="dot" />DB {health.database}</span>
                <Link to="/app/model" className={`pill ${health.model.status === 'loaded' ? 'good' : 'crit'}`} style={{ textDecoration: 'none' }}
                  title={health.model.error || health.model.version}>
                  <span className="dot" />Model {health.model.status === 'loaded' ? health.model.version.replace('textclf-', '') : health.model.status}
                </Link>
              </>
            )}
            <Link to="/app/analyze" className="btn primary sm">New analysis</Link>
          </div>
        </div>
        <main className="page"><Outlet /></main>
      </div>
    </div>
  )
}
