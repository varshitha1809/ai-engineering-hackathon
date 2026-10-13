import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ForceGraph, type FGEdge, type FGNode } from '../components/ForceGraph'
import { DataLabel, Empty, ErrorState, Loading, PageHead, VerdictBadge, useToast } from '../components/ui'
import { download, get, type Campaign, type CampaignEdge, type Verdict } from '../lib/api'
import { fmtDate, human, useApi } from '../lib/hooks'

const VCOLOR: Record<string, string> = { LIKELY_PHISHING: '#ff6b6b', AI_INJECTION_SUSPECTED: '#f08a4b', SUSPICIOUS_REVIEW: '#e8b341', NO_STRONG_INDICATORS: '#7cf25a', INSUFFICIENT_EVIDENCE: '#8fb3ff' }

interface GraphRes { nodes: { id: string; subject: string; from_addr: string; verdict: Verdict; risk_score: number; campaign_id: string | null }[]; edges: CampaignEdge[] }
interface Detail extends Campaign {
  members: { id: string; created_at: string; email_date: string | null; subject: string; from_addr: string; reply_to_addr: string; verdict: Verdict; risk_score: number; data_label: string }[]
  edges: CampaignEdge[]; shared_indicators: { type: string; display_value: string; reputation: string | null; reputation_source: string | null; members: number }[]
}

export default function Campaigns() {
  const { id } = useParams()
  const nav = useNavigate()
  const [minS, setMinS] = useState(0.5)
  const [sev, setSev] = useState('')
  const [lowSlow, setLowSlow] = useState(false)
  const [sel, setSel] = useState<string | null>(null)
  const list = useApi(() => get<{ items: Campaign[]; weak_edges_not_clustered: number; rule: string }>(`/campaigns${sev ? `?severity=${sev}` : ''}${lowSlow ? `${sev ? '&' : '?'}low_and_slow=true` : ''}`), [sev, lowSlow])
  const graph = useApi(() => get<GraphRes>(`/graph?min_strength=${minS}${id ? `&campaign=${id}` : ''}`), [minS, id])
  const detail = useApi(() => (id ? get<Detail>(`/campaigns/${id}`) : Promise.resolve(null)), [id])
  const toast = useToast()

  const { nodes, edges } = useMemo(() => {
    const g = graph.data
    if (!g) return { nodes: [] as FGNode[], edges: [] as FGEdge[] }
    return {
      nodes: g.nodes.map(n => ({ id: n.id, label: n.subject || n.id, color: VCOLOR[n.verdict] ?? '#999', size: 6 + n.risk_score / 12, ring: n.campaign_id ? 'rgba(124,242,90,.6)' : undefined })),
      edges: g.edges.map(e => ({ id: String(e.id), source: e.src, target: e.dst, width: 0.8 + e.strength * 3,
        color: e.strength >= 0.8 ? 'rgba(124,242,90,.75)' : e.strength >= 0.5 ? 'rgba(232,179,65,.65)' : 'rgba(200,200,200,.3)', dashed: e.strength < 0.5,
        label: `${human(e.edge_type)} (${e.strength}) — ${e.explanation}` })),
    }
  }, [graph.data])
  const selEdge = graph.data?.edges.find(e => String(e.id) === sel)
  const selNode = graph.data?.nodes.find(n => n.id === sel)
  const exp = (fmt: string) => id && download(`/campaigns/${id}/export?format=${fmt}`, `${id}.${fmt === 'stix' ? 'stix.json' : fmt}`).then(() => toast.show(`Exported ${id} as ${fmt.toUpperCase()} (local file — nothing was shared externally)`)).catch(e => toast.show(e.message, 'error'))

  return (
    <>
      <PageHead eyebrow="Signature 3 · campaign DNA" title={id ? `Campaign ${id}` : 'Campaign intelligence'}
        desc="Messages are linked only by concrete shared evidence — URL, attachment hash, Reply-To, bank reference, phone, non-common domain, near-duplicate body or the same impersonated profile. Generic words never create a link, and no attacker attribution is made."
        actions={id ? <><button className="btn sm" onClick={() => exp('json')}>Export JSON</button><button className="btn sm" onClick={() => exp('csv')}>CSV</button><button className="btn sm" onClick={() => exp('stix')}>STIX 2.1</button><Link className="btn sm" to="/app/campaigns">All campaigns</Link></> : undefined} />

      <div className="grid g3">
        <div className="stack">
          <div className="card stack">
            <div className="row">
              <select className="input" value={sev} onChange={e => setSev(e.target.value)} aria-label="Filter severity" style={{ flex: 1 }}>
                <option value="">All severities</option>{['critical', 'high', 'medium', 'low'].map(s => <option key={s}>{s}</option>)}
              </select>
              <label className="row small" style={{ gap: 6 }}><input type="checkbox" checked={lowSlow} onChange={e => setLowSlow(e.target.checked)} /> low-and-slow</label>
            </div>
            {list.loading && !list.data ? <Loading /> : list.error ? <ErrorState error={list.error} retry={list.reload} /> :
              list.data!.items.length === 0 ? <Empty title="No campaign clusters">Clusters appear when ≥2 retained messages share moderate/strong evidence. Import the local sample set on the Analyze page to see one.</Empty> :
                list.data!.items.map(c => (
                  <Link key={c.id} to={`/app/campaigns/${c.id}`} className={`finding ${id === c.id ? 'active' : ''}`} style={{ textDecoration: 'none' }}>
                    <div className="row between"><b className="small">{c.label}</b><span className={`pill ${c.severity === 'critical' || c.severity === 'high' ? 'crit' : 'warn'}`}>{c.severity} {c.severity_score}</span></div>
                    <div className="tiny dim">{c.id} · {c.member_count} messages · {fmtDate(c.first_seen)} → {fmtDate(c.last_seen)}</div>
                    {c.low_and_slow ? <div className="tiny" style={{ color: 'var(--warning)' }}>low-and-slow: {c.summary_json.low_and_slow_reason}</div> : null}
                  </Link>))}
            {list.data && <div className="tiny dim">{list.data.rule} {list.data.weak_edges_not_clustered} weak relationship(s) are shown in the graph but do not merge clusters.</div>}
          </div>
        </div>

        <div className="card span2">
          <div className="card-head">
            <h3>{id ? 'Cluster graph' : 'Relationship graph'}</h3>
            <label className="row small">Min. strength
              <input type="range" min={0} max={0.95} step={0.05} value={minS} onChange={e => setMinS(Number(e.target.value))} aria-label="Minimum relationship strength" />
              <span className="num">{minS.toFixed(2)}</span></label>
          </div>
          <div className="row tiny" style={{ gap: 14, marginBottom: 6 }}>
            <span><i style={{ display: 'inline-block', width: 18, height: 3, background: 'rgba(124,242,90,.75)' }} /> strong ≥0.8</span>
            <span><i style={{ display: 'inline-block', width: 18, height: 3, background: 'rgba(232,179,65,.65)' }} /> moderate ≥0.5</span>
            <span><i style={{ display: 'inline-block', width: 18, borderTop: '2px dashed rgba(200,200,200,.5)' }} /> weak (not clustered)</span>
            <span>node colour = verdict, size = risk</span>
          </div>
          {graph.error ? <ErrorState error={graph.error} retry={graph.reload} /> : graph.loading && !graph.data ? <Loading /> :
            nodes.length === 0 ? <Empty title="No relationships at this strength">Lower the minimum strength or analyse more messages.</Empty> :
              <ForceGraph nodes={nodes} edges={edges} height={430} selected={sel} onNode={x => setSel(x)} onEdge={x => setSel(x)} />}
          {selEdge && (
            <div className="finding" style={{ cursor: 'default', marginTop: 10 }}>
              <div className="row between"><b className="small">{human(selEdge.edge_type)}: {selEdge.src} ↔ {selEdge.dst}</b><span className="pill">{selEdge.strength_label} {selEdge.strength}</span></div>
              <div className="small">{selEdge.explanation}</div>
              <div className="mono tiny">{selEdge.evidence_json.map(x => `${x.indicator_type}: ${x.value}`).join(' · ')}</div>
            </div>)}
          {selNode && (
            <div className="finding" style={{ marginTop: 10 }} onClick={() => nav(`/app/analyses/${selNode.id}`)} role="button">
              <div className="row between"><b className="small">{selNode.subject || selNode.id}</b><VerdictBadge verdict={selNode.verdict} /></div>
              <div className="tiny dim">{selNode.from_addr} · risk {selNode.risk_score} · {selNode.campaign_id ?? 'not in a cluster'} — click to open</div>
            </div>)}
        </div>
      </div>

      {id && (detail.loading && !detail.data ? <Loading /> : detail.error ? <ErrorState error={detail.error} /> : detail.data && <CampaignDetail d={detail.data} />)}
      {toast.node}
    </>
  )
}

function CampaignDetail({ d }: { d: Detail }) {
  const nav = useNavigate()
  const s = d.summary_json
  const times = d.members.map(m => new Date(m.email_date ?? m.created_at).getTime())
  const t0 = Math.min(...times), t1 = Math.max(...times)
  return (
    <div className="grid g2" style={{ marginTop: 16 }}>
      <div className="card">
        <div className="card-head"><h3>Members & timeline</h3><span className="tiny dim">Date header when present, otherwise local receipt time</span></div>
        <div style={{ position: 'relative', height: 34, margin: '6px 8px 14px', borderBottom: '1px solid var(--line-2)' }}>
          {d.members.map((m, i) => {
            const x = t1 > t0 ? ((times[i] - t0) / (t1 - t0)) * 100 : 50
            return <span key={m.id} title={`${m.subject} · ${fmtDate(m.email_date ?? m.created_at)}`} onClick={() => nav(`/app/analyses/${m.id}`)}
              style={{ position: 'absolute', left: `calc(${x}% - 6px)`, top: 12, width: 12, height: 12, borderRadius: 999, cursor: 'pointer', background: VCOLOR[m.verdict], border: '2px solid var(--bg)' }} />
          })}
          <span className="tiny dim" style={{ position: 'absolute', left: 0, bottom: -18 }}>{fmtDate(new Date(t0).toISOString())}</span>
          <span className="tiny dim" style={{ position: 'absolute', right: 0, bottom: -18 }}>{fmtDate(new Date(t1).toISOString())}</span>
        </div>
        <div className="table-wrap" style={{ marginTop: 22 }}><table className="t"><thead><tr><th>Message</th><th>Verdict</th><th>Risk</th><th>Date</th></tr></thead>
          <tbody>{d.members.map(m => <tr key={m.id} className="clickable" onClick={() => nav(`/app/analyses/${m.id}`)}>
            <td><div className="small">{m.subject}</div><div className="tiny dim">{m.from_addr}{m.reply_to_addr ? ` · reply-to ${m.reply_to_addr}` : ''} · <DataLabel label={m.data_label} /></div></td>
            <td><VerdictBadge verdict={m.verdict} /></td><td className="num">{m.risk_score}</td><td className="tiny">{fmtDate(m.email_date ?? m.created_at)}</td></tr>)}</tbody></table></div>
      </div>
      <div className="stack">
        <div className="card">
          <div className="card-head"><h3>Why these messages are related</h3></div>
          <div className="table-wrap"><table className="t"><thead><tr><th>Relationship</th><th>Strength</th><th>Evidence</th></tr></thead>
            <tbody>{d.edges.map(e => <tr key={e.id}><td className="small">{human(e.edge_type)}<div className="tiny dim">{e.src} ↔ {e.dst}</div></td><td><span className="pill">{e.strength_label} {e.strength}</span></td>
              <td className="mono tiny" style={{ wordBreak: 'break-all' }}>{e.evidence_json.map(x => `${x.indicator_type}: ${x.value}`).join(' · ')}</td></tr>)}</tbody></table></div>
        </div>
        <div className="card">
          <div className="card-head"><h3>Severity basis</h3><span className="pill crit">{d.severity} {d.severity_score}</span></div>
          <dl className="kv">
            <dt>Worst member risk</dt><dd>{s.max_member_risk} (mean {s.mean_member_risk})</dd><dt>Strongest edge</dt><dd>{s.max_edge_strength}</dd>
            <dt>High-impact request</dt><dd>{s.high_impact ? 'yes' : 'no'} {s.requested_actions.length ? `(${s.requested_actions.map(human).join(', ')})` : ''}</dd>
            <dt>Tactics seen</dt><dd>{s.tactics.map(human).join(', ') || '—'}</dd><dt>Span</dt><dd>{s.span_days} day(s)</dd>
            <dt>Shared indicators</dt><dd>{d.shared_indicators.map(i => <div key={i.type + i.display_value} className="mono tiny">{i.type}: {i.display_value} ({i.members} msgs{i.reputation && i.reputation !== 'unknown' ? `, ${i.reputation}` : ''})</div>)}</dd>
          </dl>
          <p className="tiny dim">Severity = 0.45×worst member risk + 25×strongest edge + size term (log₂, capped) + 12 if a high-impact request is present. Member scores are not summed. {s.attribution_note}</p>
        </div>
      </div>
    </div>
  )
}
