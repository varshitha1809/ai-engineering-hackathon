import { useMemo, useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ErrorState, Loading, PageHead, VerdictBadge } from '../components/ui'
import { get, type Analysis, type Finding } from '../lib/api'
import { human, useApi } from '../lib/hooks'

export default function Evidence() {
  const { id = '' } = useParams()
  const a = useApi(() => get<Analysis>(`/analyses/${id}`), [id])
  const [sel, setSel] = useState<string | null>(null)
  const [comp, setComp] = useState('')
  const [status, setStatus] = useState('')
  const d = a.data
  const findings = useMemo(() => (d?.findings ?? []).filter(f => (!comp || f.component === comp) && (!status || f.status === status)), [d, comp, status])
  if (a.loading && !d) return <Loading what="Loading evidence" />
  if (a.error) return <ErrorState error={a.error} retry={a.reload} />
  const an = d!
  const active = an.findings.find(f => f.finding_id === sel) ?? null
  const comps = [...new Set(an.findings.map(f => f.component))]
  const pick = (fid: string) => {
    setSel(fid)
    setTimeout(() => document.getElementById(`mark-${fid}`)?.scrollIntoView({ block: 'center', behavior: 'smooth' }), 30)
  }
  return (
    <>
      <PageHead eyebrow={`Evidence explorer · ${an.id}`} title={an.parsed?.subject || '(no subject)'}
        desc={<>Every finding with its source location, method and version. Click a finding to highlight the exact excerpt; click a highlight to open its finding. <b>Observed</b> = fact in the message; <b>inferred</b> = interpretation built on cited findings.</>}
        actions={<><VerdictBadge verdict={an.verdict} label={an.verdict_label} /><Link className="btn" to={`/app/analyses/${an.id}`}>Forensics</Link><Link className="btn" to={`/app/reconstruction/${an.id}`}>Reconstruction</Link></>} />
      <div className="grid g2">
        <div className="card stack">
          <div className="row">
            <select className="input" style={{ maxWidth: 220 }} value={comp} onChange={e => setComp(e.target.value)} aria-label="Filter by layer">
              <option value="">All layers ({an.findings.length})</option>{comps.map(c => <option key={c} value={c}>{human(c)}</option>)}
            </select>
            <select className="input" style={{ maxWidth: 180 }} value={status} onChange={e => setStatus(e.target.value)} aria-label="Filter by status">
              <option value="">Any status</option><option value="observed">observed</option><option value="inferred">inferred</option><option value="unavailable">unavailable</option>
            </select>
          </div>
          <div className="stack" style={{ maxHeight: 680, overflow: 'auto', paddingRight: 4 }}>
            {findings.map(f => (
              <div key={f.finding_id} className={`finding ${sel === f.finding_id ? 'active' : ''}`} onClick={() => pick(f.finding_id)} role="button" tabIndex={0}
                onKeyDown={e => e.key === 'Enter' && pick(f.finding_id)}>
                <div className="row between">
                  <b className="small">{f.finding_id} · {f.title}</b>
                  <span className={`pill ${f.status === 'observed' ? 'info' : f.status === 'inferred' ? 'warn' : ''}`}>{f.status}</span>
                </div>
                <div className="tiny dim mono">{human(f.component)} · {f.source_location} · {f.method} {f.version} · strength {f.confidence}{f.span ? ' · highlighted' : ''}</div>
              </div>
            ))}
            {findings.length === 0 && <div className="small dim">No findings match the filters.</div>}
          </div>
        </div>
        <div className="stack">
          {active && (
            <div className="card">
              <div className="card-head"><h3>{active.finding_id} · {active.title}</h3><span className="pill">{active.severity}</span></div>
              <dl className="kv">
                <dt>Category</dt><dd className="mono tiny">{active.category}</dd>
                <dt>Observed value</dt><dd className="mono tiny">{active.observed_value || '—'}</dd>
                <dt>Source location</dt><dd className="mono tiny">{active.source_location}</dd>
                <dt>Method / version</dt><dd>{active.method} · {active.version}</dd>
                <dt>Strength</dt><dd>{active.confidence} <span className="dim tiny">(evidence strength, not a probability)</span></dd>
                <dt>Status</dt><dd>{active.status}</dd>
                <dt>Recorded</dt><dd className="tiny">{active.timestamp}</dd>
                <dt>Explanation</dt><dd className="small">{active.explanation}</dd>
                {active.related_finding_ids.length > 0 && <><dt>Built on</dt><dd>{active.related_finding_ids.map(r => <button key={r} className="btn sm" style={{ marginRight: 4 }} onClick={() => pick(r)}>{r}</button>)}</dd></>}
                {active.related_indicator_ids.length > 0 && <><dt>Indicators</dt><dd className="small">{active.related_indicator_ids.map(i => an.indicators.find(x => x.id === i)?.display_value ?? `#${i}`).join(', ')}</dd></>}
              </dl>
            </div>
          )}
          <div className="card">
            <div className="card-head"><h3>Source view</h3><span className="tiny dim">subject + visible body (retained copy)</span></div>
            <div className="small muted">Subject</div>
            <div className="source-view" style={{ marginBottom: 10 }}>{highlight(an.parsed?.subject || '', 'subject', an.findings, sel, pick)}</div>
            <div className="small muted">Body</div>
            <div className="source-view">{an.body_text ? highlight(an.body_text, 'body', an.findings, sel, pick) : '(no visible body retained)'}</div>
            <p className="tiny dim">Findings in headers, URLs, attachments or hidden HTML have no body span — their location is shown in the finding detail.</p>
          </div>
        </div>
      </div>
    </>
  )
}

function highlight(text: string, field: 'subject' | 'body', findings: Finding[], sel: string | null, pick: (id: string) => void): ReactNode {
  const spans = findings.filter(f => f.span && f.span.field === field && f.span.end > f.span.start && f.span.end <= text.length)
    .map(f => ({ s: f.span!.start, e: f.span!.end, id: f.finding_id }))
    .sort((a, b) => a.s - b.s || b.e - a.e)
  const out: ReactNode[] = []
  let pos = 0
  for (const sp of spans) {
    if (sp.s < pos) continue // overlapping spans: first one wins, the rest stay selectable from the list
    if (sp.s > pos) out.push(text.slice(pos, sp.s))
    const ids = spans.filter(o => o.s < sp.e && o.e > sp.s).map(o => o.id)
    out.push(<mark key={sp.id} id={`mark-${sp.id}`} className={`ev ${ids.includes(sel ?? '') ? 'active' : ''}`} title={ids.join(', ')}
      onClick={() => pick(ids.includes(sel ?? '') ? sel! : sp.id)}>{text.slice(sp.s, sp.e)}</mark>)
    ids.forEach(i => i !== sp.id && out.push(<span key={`a-${i}-${sp.id}`} id={`mark-${i}`} />))
    pos = sp.e
  }
  out.push(text.slice(pos))
  return out
}
