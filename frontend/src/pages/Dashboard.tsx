import { Link, useNavigate } from 'react-router-dom'
import { Histogram } from '../components/charts'
import { DataLabel, Empty, ErrorState, Loading, PageHead, PriorityPill, Stat, VerdictBadge } from '../components/ui'
import { get, type Verdict } from '../lib/api'
import { fmtDate, human, pct, useApi } from '../lib/hooks'

interface Summary {
  totals: Record<string, number>; verdicts: Record<string, number>; data_labels: Record<string, number>; sources: Record<string, number>
  risk_histogram: number[]; case_states: Record<string, number>
  alerts: { case_id: string; priority: string; priority_score: number; status: string; id: string; subject: string; from_addr: string; verdict: Verdict; verdict_label: string; risk_score: number; created_at: string; data_label: string }[]
  campaigns: { id: string; label: string; severity: string; severity_score: number; member_count: number; low_and_slow: number; last_seen: string }[]
  top_indicators: { id: number; type: string; display_value: string; reputation: string | null; messages: number }[]
  triage: { queue_volume: number; messages_in_campaigns: number; campaign_clusters: number; duplicate_alert_collapse: number; median_minutes_to_resolve: number | null; resolved_cases: number; feedback: Record<string, number> }
  coverage: { headers_present_share: number }; model: { status: string; version: string }
  benchmark: { id: string; finished_at: string; overall: any; counts: any; data_label: string } | null
}

export default function Dashboard() {
  const s = useApi(() => get<Summary>('/dashboard/summary'), [], 20000)
  const nav = useNavigate()
  if (s.loading && !s.data) return <Loading what="Loading live investigation statistics" />
  if (s.error) return <ErrorState error={s.error} retry={s.reload} />
  const d = s.data!
  const t = d.totals
  return (
    <>
      <PageHead eyebrow="Overview" title="Threat overview"
        desc="Every number on this page is a live query over analyses persisted in the local database — nothing is pre-filled."
        actions={<><Link to="/app/analyze" className="btn primary">Analyze an email</Link><button className="btn" onClick={s.reload}>Refresh</button></>} />
      {t.analyses === 0 ? (
        <Empty title="No analyses yet">
          Submit an email on the <Link to="/app/analyze">Analyze</Link> page, or import the labelled local sample set there to populate campaigns.
        </Empty>
      ) : (
        <>
          <div className="grid g4">
            <Stat label="Messages analysed" value={t.analyses} sub={Object.entries(d.data_labels).map(([k, v]) => `${v} ${k === 'user' ? 'real' : k}`).join(' · ')} onClick={() => nav('/app/cases?tab=history')} />
            <Stat label="High risk (phishing / AI manipulation)" value={t.high_risk} sub={`${t.needs_review} more need review`} onClick={() => nav('/app/cases')} />
            <Stat label="Open cases" value={t.open_cases} sub={Object.entries(d.case_states).map(([k, v]) => `${v} ${human(k)}`).join(' · ') || 'none'} onClick={() => nav('/app/cases')} />
            <Stat label="Campaign clusters" value={t.campaigns} sub={`${t.low_and_slow} low-and-slow`} onClick={() => nav('/app/campaigns')} />
          </div>

          <div className="grid g3" style={{ marginTop: 16 }}>
            <div className="card span2">
              <div className="card-head"><h3>Prioritised alerts</h3><span className="tiny dim">sorted by priority, then impact-weighted score</span></div>
              {d.alerts.length === 0 ? <Empty title="Queue is clear">No unresolved cases.</Empty> : (
                <div className="table-wrap"><table className="t">
                  <thead><tr><th>Priority</th><th>Verdict</th><th>Subject</th><th>Risk</th><th>Received</th></tr></thead>
                  <tbody>{d.alerts.map(a => (
                    <tr key={a.id} className="clickable" onClick={() => nav(`/app/analyses/${a.id}`)}>
                      <td><PriorityPill p={a.priority} /></td><td><VerdictBadge verdict={a.verdict} /></td>
                      <td><div>{a.subject || '(no subject)'}</div><div className="tiny dim">{a.from_addr || 'sender unknown'} · <DataLabel label={a.data_label} /></div></td>
                      <td className="num">{a.risk_score}</td><td className="small dim">{fmtDate(a.created_at)}</td>
                    </tr>))}</tbody></table></div>
              )}
            </div>
            <div className="card">
              <div className="card-head"><h3>Risk distribution</h3></div>
              <Histogram bins={d.risk_histogram} label="Risk score distribution of analysed messages" onPick={() => nav('/app/cases?tab=history')} />
              <div className="tiny dim" style={{ marginTop: 6 }}>Policy risk score bins (0–100). 35 = review threshold, 65 = likely-phishing threshold.</div>
            </div>
          </div>

          <div className="grid g3" style={{ marginTop: 16 }}>
            <div className="card">
              <div className="card-head"><h3>Active campaigns</h3><Link to="/app/campaigns" className="small">All →</Link></div>
              {d.campaigns.length === 0 ? <Empty title="No related messages yet">Clusters form only from shared evidence.</Empty> : (
                <div className="stack">{d.campaigns.map(c => (
                  <Link key={c.id} to={`/app/campaigns/${c.id}`} className="finding" style={{ textDecoration: 'none' }}>
                    <div className="row between"><b className="small">{c.label}</b><span className={`pill ${c.severity === 'critical' || c.severity === 'high' ? 'crit' : 'warn'}`}>{c.severity}</span></div>
                    <div className="tiny dim">{c.id} · {c.member_count} messages {c.low_and_slow ? '· low-and-slow' : ''}</div>
                  </Link>))}</div>
              )}
            </div>
            <div className="card">
              <div className="card-head"><h3>Repeated indicators</h3></div>
              {d.top_indicators.length === 0 ? <Empty title="None repeated">No URL, domain, hash or Reply-To seen in ≥2 messages.</Empty> : (
                <div className="stack">{d.top_indicators.map(i => (
                  <div key={i.id} className="row between small">
                    <span style={{ wordBreak: 'break-all' }}><span className="label-tag">{human(i.type)}</span> {i.display_value}</span>
                    <span className="num dim">{i.messages}×{i.reputation && i.reputation !== 'unknown' ? ` · ${i.reputation}` : ''}</span>
                  </div>))}</div>
              )}
            </div>
            <div className="card">
              <div className="card-head"><h3>Model & triage health</h3></div>
              <dl className="kv">
                <dt>Text model</dt><dd>{d.model.status === 'loaded' ? <span className="pill good"><span className="dot" />{d.model.version}</span> : <span className="pill crit">{d.model.status}</span>}</dd>
                <dt>Header coverage</dt><dd>{pct(d.coverage.headers_present_share, 0)} of analyses had headers</dd>
                <dt>Duplicate collapse</dt><dd>{d.triage.messages_in_campaigns} messages → {d.triage.campaign_clusters} clusters</dd>
                <dt>Resolution time</dt><dd>{d.triage.median_minutes_to_resolve !== null ? `${d.triage.median_minutes_to_resolve} min median (${d.triage.resolved_cases} cases)` : 'no resolved cases yet'}</dd>
                <dt>Analyst feedback</dt><dd>{Object.entries(d.triage.feedback).map(([k, v]) => `${v} ${human(k)}`).join(' · ') || 'none yet'}</dd>
                <dt>Last benchmark</dt><dd>{d.benchmark ? <Link to={`/app/lab/${d.benchmark.id}`}>hybrid F1 {pct(d.benchmark.overall?.hybrid?.f1)} · {fmtDate(d.benchmark.finished_at)}</Link> : <Link to="/app/lab">not run yet</Link>}</dd>
              </dl>
            </div>
          </div>
        </>
      )}
    </>
  )
}
