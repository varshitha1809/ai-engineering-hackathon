import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { DataLabel, Empty, ErrorState, Loading, PageHead, PriorityPill, Tabs, VerdictBadge, useToast } from '../components/ui'
import { download, get, type AnalysisRow, type Verdict } from '../lib/api'
import { fmtDate, human, useApi } from '../lib/hooks'

export default function Cases() {
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') ?? 'queue'
  return (
    <>
      <PageHead eyebrow="Investigations" title="Cases, history & reports"
        desc="The analyst queue (priority-sorted), every persisted analysis, the feedback/review queue and the audit trail." />
      <Tabs value={tab} onChange={t => setParams({ tab: t })} tabs={[{ id: 'queue', label: 'Analyst queue' }, { id: 'history', label: 'Investigation history' },
        { id: 'feedback', label: 'Feedback & review queue' }, { id: 'audit', label: 'Audit trail' }]} />
      {tab === 'queue' && <Queue />}
      {tab === 'history' && <History />}
      {tab === 'feedback' && <Feedback />}
      {tab === 'audit' && <Audit />}
    </>
  )
}

function Queue() {
  const [status, setStatus] = useState('')
  const [prio, setPrio] = useState('')
  const q = useApi(() => get<{ items: any[]; counts: Record<string, number> }>(`/cases?${status ? `status=${status}&` : ''}${prio ? `priority=${prio}` : ''}`), [status, prio])
  const nav = useNavigate()
  return (
    <div className="stack">
      <div className="row">
        <select className="input" style={{ maxWidth: 200 }} value={status} onChange={e => setStatus(e.target.value)} aria-label="Filter by status">
          <option value="">All statuses</option>{['open', 'in_review', 'escalated', 'resolved'].map(s => <option key={s} value={s}>{human(s)}</option>)}</select>
        <select className="input" style={{ maxWidth: 160 }} value={prio} onChange={e => setPrio(e.target.value)} aria-label="Filter by priority">
          <option value="">All priorities</option>{['P1', 'P2', 'P3', 'P4'].map(s => <option key={s}>{s}</option>)}</select>
        {q.data && <span className="small dim">{Object.entries(q.data.counts).map(([k, v]) => `${v} ${human(k)}`).join(' · ')}</span>}
      </div>
      {q.loading && !q.data ? <Loading /> : q.error ? <ErrorState error={q.error} retry={q.reload} /> : q.data!.items.length === 0 ? <Empty title="No cases">Cases open automatically for every verdict other than “no strong indicators”.</Empty> : (
        <div className="table-wrap"><table className="t">
          <thead><tr><th>Priority</th><th>Case</th><th>Verdict</th><th>Subject</th><th>Status</th><th>Assignee</th><th>Local state</th><th>Updated</th></tr></thead>
          <tbody>{q.data!.items.map(c => (
            <tr key={c.id} className="clickable" onClick={() => nav(`/app/analyses/${c.analysis_id}`)}>
              <td><PriorityPill p={c.priority} /></td><td className="mono tiny">{c.id}</td><td><VerdictBadge verdict={c.verdict as Verdict} /></td>
              <td><div className="small">{c.subject || '(no subject)'}</div><div className="tiny dim">{c.from_addr} · <DataLabel label={c.data_label} />{c.in_campaigns ? ' · in campaign' : ''}</div></td>
              <td><span className="pill">{human(c.status)}</span></td><td className="small">{c.assignee ?? '—'}</td><td className="small">{c.local_state}</td><td className="tiny">{fmtDate(c.updated_at)}</td>
            </tr>))}</tbody></table></div>
      )}
    </div>
  )
}

function History() {
  const [q, setQ] = useState('')
  const [verdict, setVerdict] = useState('')
  const [label, setLabel] = useState('')
  const [page, setPage] = useState(0)
  const list = useApi(() => get<{ total: number; items: AnalysisRow[] }>(`/analyses?limit=50&offset=${page * 50}${q ? `&q=${encodeURIComponent(q)}` : ''}${verdict ? `&verdict=${verdict}` : ''}${label ? `&data_label=${encodeURIComponent(label)}` : ''}`), [q, verdict, label, page])
  const nav = useNavigate()
  const toast = useToast()
  return (
    <div className="stack">
      <div className="row">
        <input className="input" style={{ maxWidth: 280 }} placeholder="Search subject, sender, ID" value={q} onChange={e => { setQ(e.target.value); setPage(0) }} aria-label="Search" />
        <select className="input" style={{ maxWidth: 240 }} value={verdict} onChange={e => { setVerdict(e.target.value); setPage(0) }} aria-label="Verdict">
          <option value="">All verdicts</option>{['LIKELY_PHISHING', 'AI_INJECTION_SUSPECTED', 'SUSPICIOUS_REVIEW', 'NO_STRONG_INDICATORS', 'INSUFFICIENT_EVIDENCE'].map(v => <option key={v}>{v}</option>)}</select>
        <select className="input" style={{ maxWidth: 220 }} value={label} onChange={e => { setLabel(e.target.value); setPage(0) }} aria-label="Data label">
          <option value="">Any provenance</option><option value="user">real submissions</option><option value="local sample data">local sample data</option></select>
      </div>
      {list.loading && !list.data ? <Loading /> : list.error ? <ErrorState error={list.error} retry={list.reload} /> : list.data!.items.length === 0 ? <Empty title="No analyses match" /> : (<>
        <div className="table-wrap"><table className="t">
          <thead><tr><th>Analysed</th><th>Verdict</th><th>Subject / sender</th><th>Risk</th><th>Source</th><th>Model</th><th>Report</th></tr></thead>
          <tbody>{list.data!.items.map(a => (
            <tr key={a.id} className="clickable" onClick={() => nav(`/app/analyses/${a.id}`)}>
              <td className="tiny">{fmtDate(a.created_at)}</td><td><VerdictBadge verdict={a.verdict} /></td>
              <td><div className="small">{a.subject || '(no subject)'}</div><div className="tiny dim">{a.from_addr || '—'} · <DataLabel label={a.data_label} /></div></td>
              <td className="num">{a.risk_score}</td><td className="small">{a.input_source}{a.batch_id ? ` · ${a.batch_id}` : ''}</td><td className="mono tiny">{a.model_version?.replace('textclf-', '')}</td>
              <td onClick={e => e.stopPropagation()}><button className="btn sm" onClick={() => download(`/analyses/${a.id}/report?format=md`, `${a.id}-report.md`).catch(e => toast.show(e.message, 'error'))}>.md</button></td>
            </tr>))}</tbody></table></div>
        <div className="row between small"><span className="dim">{list.data!.total} total</span>
          <span className="row"><button className="btn sm" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Previous</button><button className="btn sm" disabled={(page + 1) * 50 >= list.data!.total} onClick={() => setPage(p => p + 1)}>Next</button></span></div>
      </>)}
      {toast.node}
    </div>
  )
}

function Feedback() {
  const f = useApi(() => get<{ items: any[]; summary: { total: number; model_disagreements: number; note: string } }>('/feedback'), [])
  const nav = useNavigate()
  const toast = useToast()
  if (f.loading && !f.data) return <Loading />
  if (f.error) return <ErrorState error={f.error} retry={f.reload} />
  return (
    <div className="stack">
      <div className="row between"><span className="small muted">{f.data!.summary.total} feedback records · {f.data!.summary.model_disagreements} disagree with the original verdict. {f.data!.summary.note}</span>
        <button className="btn sm" onClick={() => download('/feedback?format=csv', 'review_queue.csv').catch(e => toast.show(e.message, 'error'))}>Export review queue (CSV)</button></div>
      {f.data!.items.length === 0 ? <Empty title="No analyst feedback yet">Use “Report as phishing” or “Mark benign” on a case.</Empty> : (
        <div className="table-wrap"><table className="t"><thead><tr><th>When</th><th>Label</th><th>Original verdict</th><th>Subject</th><th>Reviewer</th><th>Retraining</th></tr></thead>
          <tbody>{f.data!.items.map(x => <tr key={x.id} className="clickable" onClick={() => nav(`/app/analyses/${x.analysis_id}`)}><td className="tiny">{fmtDate(x.created_at)}</td><td><span className={`pill ${x.label === 'confirmed_phishing' ? 'crit' : x.label === 'unresolved' ? '' : 'good'}`}>{human(x.label)}</span></td>
            <td className="small">{x.original_verdict} ({x.original_risk_score})</td><td className="small">{x.subject}</td><td className="small">{x.reviewer}</td><td className="small">{x.retraining_status}</td></tr>)}</tbody></table></div>
      )}
      {toast.node}
    </div>
  )
}

function Audit() {
  const a = useApi(() => get<any[]>('/audit?limit=300'), [])
  if (a.loading && !a.data) return <Loading />
  if (a.error) return <ErrorState error={a.error} retry={a.reload} />
  return a.data!.length === 0 ? <Empty title="No audit events" /> : (
    <div className="table-wrap"><table className="t"><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>Outcome</th><th>Detail (redacted)</th></tr></thead>
      <tbody>{a.data!.map(e => <tr key={e.id}><td className="tiny">{fmtDate(e.ts)}</td><td className="mono tiny">{e.action}</td><td className="small">{e.actor}</td><td className="mono tiny">{e.target_type}:{e.target_id}</td><td className="small">{e.outcome}</td><td className="tiny">{e.detail}</td></tr>)}</tbody></table></div>
  )
}
