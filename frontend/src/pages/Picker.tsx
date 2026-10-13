import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { DataLabel, Empty, ErrorState, Loading, PageHead, VerdictBadge } from '../components/ui'
import { get, type AnalysisRow } from '../lib/api'
import { fmtDate, useApi } from '../lib/hooks'

const META = {
  forensics: { eyebrow: 'Signature 1', title: 'Threat forensics', desc: 'Pick an analysis to inspect its verdict, risk breakdown, sender/header checks, URLs, attachments and hidden content.', path: (id: string) => `/app/analyses/${id}` },
  evidence: { eyebrow: 'Evidence', title: 'Evidence explorer', desc: 'Pick an analysis to browse every source-linked finding and highlight it in the original content.', path: (id: string) => `/app/evidence/${id}` },
  reconstruction: { eyebrow: 'Signature 2', title: 'Attack reconstruction', desc: 'Pick an analysis to open its evidence-backed attack graph and timeline.', path: (id: string) => `/app/reconstruction/${id}` },
}

export default function Picker({ target }: { target: keyof typeof META }) {
  const m = META[target]
  const [q, setQ] = useState('')
  const [verdict, setVerdict] = useState('')
  const list = useApi(() => get<{ total: number; items: AnalysisRow[] }>(`/analyses?limit=100${q ? `&q=${encodeURIComponent(q)}` : ''}${verdict ? `&verdict=${verdict}` : ''}`), [q, verdict])
  const nav = useNavigate()
  return (
    <>
      <PageHead eyebrow={m.eyebrow} title={m.title} desc={m.desc} />
      <div className="row" style={{ marginBottom: 14 }}>
        <input className="input" style={{ maxWidth: 320 }} placeholder="Search subject, sender or ID" value={q} onChange={e => setQ(e.target.value)} aria-label="Search analyses" />
        <select className="input" style={{ maxWidth: 260 }} value={verdict} onChange={e => setVerdict(e.target.value)} aria-label="Filter by verdict">
          <option value="">All verdicts</option>
          {['LIKELY_PHISHING', 'AI_INJECTION_SUSPECTED', 'SUSPICIOUS_REVIEW', 'NO_STRONG_INDICATORS', 'INSUFFICIENT_EVIDENCE'].map(v => <option key={v} value={v}>{v}</option>)}
        </select>
      </div>
      {list.loading && !list.data ? <Loading /> : list.error ? <ErrorState error={list.error} retry={list.reload} /> :
        list.data!.items.length === 0 ? <Empty title="No analyses found"><Link to="/app/analyze">Analyze an email</Link> first.</Empty> : (
          <div className="table-wrap"><table className="t">
            <thead><tr><th>Verdict</th><th>Subject / sender</th><th>Risk</th><th>Analysed</th><th>ID</th></tr></thead>
            <tbody>{list.data!.items.map(a => (
              <tr key={a.id} className="clickable" onClick={() => nav(m.path(a.id))}>
                <td><VerdictBadge verdict={a.verdict} /></td>
                <td><div>{a.subject || '(no subject)'}</div><div className="tiny dim">{a.from_addr || 'sender unknown'} · <DataLabel label={a.data_label} /></div></td>
                <td className="num">{a.risk_score}</td><td className="small dim">{fmtDate(a.created_at)}</td><td className="mono tiny">{a.id}</td>
              </tr>))}</tbody></table></div>
        )}
    </>
  )
}
