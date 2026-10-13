import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ForceGraph, type FGEdge, type FGNode } from '../components/ForceGraph'
import { ErrorState, Loading, PageHead, Tabs, VerdictBadge } from '../components/ui'
import { get, type Analysis } from '../lib/api'
import { useApi } from '../lib/hooks'

const KIND: Record<string, { col: number; color: string; label: string }> = {
  sender_claim: { col: 0, color: '#8fb3ff', label: 'Sender claim' },
  signal: { col: 1, color: '#e8b341', label: 'Observed signal' },
  tactic: { col: 2, color: '#f08a4b', label: 'Tactic' },
  requested_action: { col: 3, color: '#ff6b6b', label: 'Requested action' },
  objective: { col: 4, color: '#c7a6ff', label: 'Possible objective (inferred)' },
}

export default function Reconstruction() {
  const { id = '' } = useParams()
  const a = useApi(() => get<Analysis>(`/analyses/${id}`), [id])
  const [sel, setSel] = useState<string | null>(null)
  const [view, setView] = useState('graph')
  if (a.loading && !a.data) return <Loading what="Loading reconstruction" />
  if (a.error) return <ErrorState error={a.error} retry={a.reload} />
  const d = a.data!
  const r = d.reconstruction
  const fmap = Object.fromEntries(d.findings.map(f => [f.finding_id, f]))
  const nodes: FGNode[] = r.nodes.map(n => ({ id: n.id, label: n.label, color: KIND[n.kind]?.color ?? '#999', column: KIND[n.kind]?.col ?? 2,
    size: n.kind === 'sender_claim' ? 12 : n.kind === 'objective' ? 11 : 9, dashed: n.status !== 'observed' }))
  const edges: FGEdge[] = r.edges.map((e, i) => ({ id: `e${i}`, source: e.source, target: e.target, width: 1.6, color: 'rgba(170,255,160,.35)',
    dashed: e.status !== 'observed', label: `${e.relation} [${e.evidence.join(', ')}]` }))
  const selNode = r.nodes.find(n => n.id === sel)
  const selEdge = sel?.startsWith('e') ? r.edges[Number(sel.slice(1))] : undefined
  const ev = selNode?.evidence ?? selEdge?.evidence ?? []
  return (
    <>
      <PageHead eyebrow={`Signature 2 · attack reconstruction · ${d.id}`} title={d.parsed?.subject || '(no subject)'}
        desc="Sender claim → observed signals → tactics → requested action → possible objective. Solid = observed in the message; dashed = inference. Click any node or edge to see the findings it rests on."
        actions={<><VerdictBadge verdict={d.verdict} label={d.verdict_label} /><Link className="btn" to={`/app/evidence/${d.id}`}>Evidence explorer</Link><Link className="btn" to={`/app/analyses/${d.id}`}>Forensics</Link></>} />

      <div className="card" style={{ marginBottom: 16 }}>
        <p style={{ margin: 0 }}>{r.narrative}</p>
        <p className="tiny dim" style={{ margin: '8px 0 0' }}>{r.caveat}</p>
      </div>

      <Tabs value={view} onChange={setView} tabs={[{ id: 'graph', label: 'Evidence graph' }, { id: 'timeline', label: 'Timeline' }]} />
      <div className="grid g3">
        <div className="card span2">
          {view === 'graph' ? (<>
            <div className="row small" style={{ gap: 14, marginBottom: 8 }}>
              {Object.entries(KIND).map(([k, v]) => <span key={k} className="row" style={{ gap: 6 }}><i style={{ width: 10, height: 10, borderRadius: 999, background: v.color, display: 'inline-block' }} />{v.label}</span>)}
            </div>
            {r.nodes.length <= 1 ? <div className="state">Insufficient evidence for an attack graph — only the sender claim is available.</div> :
              <ForceGraph nodes={nodes} edges={edges} height={460} columns={5} selected={sel} onNode={setSel} onEdge={setSel} />}
          </>) : (
            <ol className="stack" style={{ listStyle: 'none', padding: 0, margin: 0 }}>
              {r.timeline.map((s, i) => (
                <li key={i} style={{ borderLeft: `2px ${s.status === 'inferred' ? 'dashed' : 'solid'} var(--line-2)`, paddingLeft: 16 }}>
                  <div className="row between"><b>{s.stage}</b><span className={`pill ${s.status === 'inferred' ? 'warn' : s.status === 'unavailable' ? '' : 'info'}`}>{s.status}</span></div>
                  {s.items.map((it, j) => (
                    <div key={j} className="small" style={{ margin: '6px 0' }}>
                      {it.label} {it.evidence.length > 0 && <span className="mono tiny dim">[{it.evidence.join(', ')}]</span>}
                      {it.detail && <div className="tiny dim mono" style={{ wordBreak: 'break-word' }}>{it.detail}</div>}
                    </div>))}
                </li>))}
            </ol>
          )}
        </div>
        <div className="stack">
          <div className="card">
            <div className="card-head"><h3>{selNode ? selNode.label : selEdge ? selEdge.relation : 'Select a node or edge'}</h3>{(selNode || selEdge) && <span className={`pill ${(selNode?.status ?? selEdge?.status) === 'observed' ? 'info' : 'warn'}`}>{selNode?.status ?? selEdge?.status}</span>}</div>
            {selNode?.detail && <div className="mono tiny" style={{ marginBottom: 8, wordBreak: 'break-word' }}>{selNode.detail}</div>}
            {ev.length ? <div className="stack">{ev.map(fid => fmap[fid] && (
              <Link key={fid} to={`/app/evidence/${d.id}`} className="finding" style={{ textDecoration: 'none' }}>
                <b className="small">{fid} · {fmap[fid].title}</b>
                <div className="mono tiny" style={{ wordBreak: 'break-word' }}>{fmap[fid].observed_value}</div>
                <div className="tiny dim">{fmap[fid].source_location} · {fmap[fid].method} · {fmap[fid].status}</div>
              </Link>))}</div> : <div className="small dim">{selNode || selEdge ? 'This element is the sender claim from the From header.' : 'Every element cites the findings that support it.'}</div>}
          </div>
          <div className="card">
            <div className="card-head"><h3>Verification steps</h3></div>
            <p className="tiny dim" style={{ marginTop: 0 }}>What would resolve the uncertainty — not “remove X and it is safe”.</p>
            {r.verification_steps.length ? <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>{r.verification_steps.map((v, i) => <li key={i} style={{ marginBottom: 6 }}>{v.step} <span className="mono tiny dim">[{v.resolves_uncertainty_in.join(', ')}]</span></li>)}</ul> : <div className="small dim">No specific verification needed.</div>}
          </div>
          <div className="card">
            <div className="card-head"><h3>MITRE mapping</h3></div>
            {r.attack_mapping.length ? r.attack_mapping.map(m => <div key={m.id} className="small"><span className="mono accent" style={{ color: 'var(--accent)' }}>{m.id}</span> {m.name}</div>)
              : <div className="small dim">No technique mapping is justified by the evidence.</div>}
            <div className="tiny dim" style={{ marginTop: 6 }}>Mapped only from observed finding categories.</div>
          </div>
        </div>
      </div>
    </>
  )
}
