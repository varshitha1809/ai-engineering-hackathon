import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { CaseActions } from '../components/CaseActions'
import { IconDownload } from '../components/icons'
import { DataLabel, ErrorState, Loading, PageHead, PriorityPill, RiskMeter, StatusPill, Tabs, VerdictBadge, useToast } from '../components/ui'
import { del, download, get, post, type Analysis, type Finding } from '../lib/api'
import { fmtDate, human, useApi } from '../lib/hooks'

const GROUP_LABEL: Record<string, string> = {
  text_model: 'Trained text model', intent: 'Intent & tactics (rules)', identity: 'Sender identity & auth', url: 'Links',
  attachment: 'Attachments', reputation: 'Threat intelligence', evasion: 'Hidden content & evasion', context: 'Thread & relationships',
  ai_injection: 'AI-assistant instructions',
}

export default function AnalysisDetail() {
  const { id = '' } = useParams()
  const a = useApi(() => get<Analysis>(`/analyses/${id}`), [id])
  const [tab, setTab] = useState('overview')
  const toast = useToast()
  const nav = useNavigate()
  if (a.loading && !a.data) return <Loading what="Loading analysis" />
  if (a.error) return <ErrorState error={a.error} retry={a.reload} />
  const d = a.data!
  const p = d.parsed || {}
  const rescore = async () => {
    try {
      const r = await post<any>(`/analyses/${id}/rescore`)
      toast.show(r.status === 'rescored' ? `Re-scored: ${r.before.verdict} (${r.before.risk_score}) → ${r.after.verdict} (${r.after.risk_score})` : r.detail)
      a.reload()
    } catch (e) { toast.show(String((e as Error).message), 'error') }
  }
  const remove = async () => {
    if (!confirm('Delete this analysis, its evidence and retained raw content? This cannot be undone.')) return
    try { await del(`/analyses/${id}`); nav('/app/cases?tab=history') } catch (e) { toast.show(String((e as Error).message), 'error') }
  }
  const exp = (fmt: string) => download(`/analyses/${id}/report?format=${fmt}`, `${id}-report.${fmt === 'md' ? 'md' : fmt}`).catch(e => toast.show(e.message, 'error'))
  const findings = d.findings
  const byComp = (c: string) => findings.filter(f => f.component === c)
  return (
    <>
      <PageHead eyebrow={`Threat forensics · ${d.id}`} title={p.subject || '(no subject)'}
        desc={<>{p.from_addr ? <>From <b>{p.from_display || p.from_addr}</b> &lt;{p.from_addr}&gt;</> : 'Sender unknown (no headers)'} · analysed {fmtDate(d.created_at)} · <DataLabel label={d.data_label} /></>}
        actions={<>
          <Link className="btn" to={`/app/evidence/${id}`}>Evidence explorer</Link>
          <Link className="btn" to={`/app/reconstruction/${id}`}>Attack reconstruction</Link>
        </>} />

      <div className="grid g3">
        <div className="card" style={{ display: 'flex', gap: 18, alignItems: 'center' }}>
          <RiskMeter score={d.risk_score} />
          <div className="stack" style={{ gap: 8 }}>
            <VerdictBadge verdict={d.verdict} label={d.verdict_label} large />
            <span className="tiny dim">{d.score_semantics}</span>
            {d.original.verdict !== d.verdict && <span className="tiny">Originally: {d.original.verdict} ({d.original.risk_score})</span>}
          </div>
        </div>
        <div className="card">
          <div className="small muted">Uncertainty</div>
          <div style={{ fontSize: 22, margin: '4px 0 8px', textTransform: 'capitalize' }}>{d.uncertainty.level}</div>
          <ul className="small" style={{ margin: 0, paddingLeft: 18, color: 'var(--text-2)' }}>
            {d.uncertainty.reasons.length ? d.uncertainty.reasons.map(r => <li key={r}>{r}</li>) : <li>No uncertainty factors flagged.</li>}
          </ul>
        </div>
        <div className="card">
          <div className="small muted">Impact & priority</div>
          <div className="row" style={{ margin: '6px 0' }}><PriorityPill p={d.impact.priority} /><span className="small">{d.impact.rationale}</span></div>
          <div className="small muted">Requested actions: {Object.keys(d.actions).map(human).join(', ') || 'none extracted'}</div>
          <div className="small muted">Tactics: {Object.keys(d.tactics).map(human).join(', ') || 'none'}</div>
          <div className="small muted">Local state: <b>{d.local_state}</b></div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="row between">
          <p style={{ margin: 0, maxWidth: 900 }}>{d.explanation?.user}</p>
          <div className="row">
            <button className="btn sm" onClick={() => exp('md')}><IconDownload width={14} />Report (.md)</button>
            <button className="btn sm" onClick={() => exp('json')}>JSON</button>
            <button className="btn sm" onClick={() => exp('csv')}>Findings CSV</button>
            <button className="btn sm" onClick={rescore} disabled={!d.raw_retained} title={d.raw_retained ? 'Re-run current model & rules on the retained content' : 'raw content not retained'}>Re-score</button>
            <button className="btn sm danger" onClick={remove}>Delete</button>
          </div>
        </div>
      </div>

      <div style={{ marginTop: 18 }}>
        <Tabs value={tab} onChange={setTab} tabs={[
          { id: 'overview', label: 'Risk breakdown' }, { id: 'sender', label: `Sender & headers (${byComp('identity').length})` },
          { id: 'urls', label: `URLs (${p.url_count ?? 0})` }, { id: 'attachments', label: `Attachments (${(p.attachments || []).length})` },
          { id: 'hidden', label: `Hidden content & AI view (${byComp('ai_injection').length + byComp('evasion').length})` },
          { id: 'intel', label: `Intel & related (${d.related_edges.length})` }, { id: 'case', label: 'Case & response' },
          { id: 'stages', label: 'Stages & versions' }]} />
      </div>

      {tab === 'overview' && <Overview d={d} />}
      {tab === 'sender' && <Sender d={d} />}
      {tab === 'urls' && <Urls d={d} />}
      {tab === 'attachments' && <Attachments d={d} />}
      {tab === 'hidden' && <Hidden d={d} />}
      {tab === 'intel' && <Intel d={d} />}
      {tab === 'case' && <CaseActions analysis={d} onChange={a.reload} />}
      {tab === 'stages' && <Stages d={d} />}
      {toast.node}
    </>
  )
}

export function FindingList({ items, empty }: { items: Finding[]; empty: string }) {
  if (!items.length) return <div className="small dim">{empty}</div>
  return (
    <div className="stack">
      {items.map(f => (
        <div key={f.finding_id} className="finding" style={{ cursor: 'default' }}>
          <div className="row between">
            <b className="small">{f.finding_id} · {f.title}</b>
            <span className="row" style={{ gap: 6 }}>
              <span className={`pill ${f.status === 'observed' ? 'info' : f.status === 'inferred' ? 'warn' : ''}`}>{f.status}</span>
              <span className="pill">{f.method}</span>
            </span>
          </div>
          {f.observed_value && <div className="mono tiny" style={{ marginTop: 6, color: 'var(--text)', wordBreak: 'break-word' }}>{f.observed_value}</div>}
          <div className="tiny dim" style={{ marginTop: 6 }}>{f.explanation} <span className="mono">[{f.source_location} · {f.version} · strength {f.confidence}]</span></div>
        </div>
      ))}
    </div>
  )
}

function Overview({ d }: { d: Analysis }) {
  const groups = Object.entries(d.strengths).sort((a, b) => b[1] - a[1])
  return (
    <div className="grid g2">
      <div className="card">
        <div className="card-head"><h3>Evidence groups</h3><span className="tiny dim">strength 0–1 · weight in fusion</span></div>
        <div className="stack">
          {groups.map(([g, v]) => {
            const w = d.explanation?.analyst.group_strengths.find(x => x.group === g)?.weight
            const strong = d.decision.strong_groups.includes(g)
            return (
              <div key={g} title={`${GROUP_LABEL[g] ?? g}: strength ${v} × weight ${w}`}>
                <div className="row between small"><span>{GROUP_LABEL[g] ?? g} {strong && <span className="pill crit" style={{ marginLeft: 6 }}>strong</span>}</span><span className="num dim">{v.toFixed(2)} × {w}</span></div>
                <div className="bar-track"><i style={{ width: `${v * 100}%`, background: g === 'text_model' ? 'var(--series-baseline)' : undefined }} /></div>
              </div>)
          })}
        </div>
        <div className="tiny dim" style={{ marginTop: 10 }}>{d.explanation?.analyst.note}</div>
      </div>
      <div className="stack">
        <div className="card">
          <div className="card-head"><h3>Why this verdict</h3></div>
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>{d.decision.decision_reasons.map(r => <li key={r}>{r}</li>)}</ul>
          {d.decision.flags.length > 0 && <div className="small" style={{ marginTop: 8 }}>Flags: {d.decision.flags.join(', ')}</div>}
        </div>
        <div className="card">
          <div className="card-head"><h3>Trained model contribution</h3>{d.model && <span className="tiny dim">{d.model.model_version}</span>}</div>
          {d.model ? (<>
            <div className="small">Score <b>{d.model.score.toFixed(3)}</b> vs tuned threshold {d.model.threshold.toFixed(3)} · {d.model.latency_ms} ms</div>
            <div className="tiny dim" style={{ margin: '4px 0 8px' }}>{d.model.explanation_method}</div>
            <div className="stack" style={{ gap: 4 }}>{d.model.top_contributions.map(c => (
              <div key={c.feature + c.type} className="row between small">
                <span className="mono">“{c.feature.trim()}” <span className="dim">({c.type})</span></span>
                <span className="num" style={{ color: c.contribution > 0 ? 'var(--warning)' : 'var(--good)' }}>{c.contribution > 0 ? '+' : ''}{c.contribution.toFixed(3)}</span>
              </div>))}</div>
          </>) : <div className="small" style={{ color: '#ffb3b3' }}>Text model did not run for this analysis — see stage status. The verdict accounts for the missing layer.</div>}
        </div>
        <div className="card">
          <div className="card-head"><h3>Recommended response</h3></div>
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>{d.recommendations.map((r, i) => <li key={i}>{r.text}{r.evidence?.length ? <span className="mono tiny dim"> [{r.evidence.join(', ')}]</span> : null}</li>)}</ul>
        </div>
      </div>
    </div>
  )
}

function Sender({ d }: { d: Analysis }) {
  const p = d.parsed || {}
  return (
    <div className="grid g2">
      <div className="card">
        <div className="card-head"><h3>Parsed identity</h3><span className="tiny dim">{p.headers_present ? 'from message headers' : 'no header block'}</span></div>
        <dl className="kv">
          <dt>Display name</dt><dd>{p.from_display || '—'}</dd><dt>From</dt><dd>{p.from_addr || '—'}</dd>
          <dt>Reply-To</dt><dd>{p.reply_to_addr || '—'}</dd><dt>Return-Path domain</dt><dd>{p.return_path_domain || '—'}</dd>
          <dt>To</dt><dd>{(p.to || []).join(', ') || '—'}</dd><dt>Date</dt><dd>{p.date || '—'}</dd>
          <dt>Message-ID</dt><dd className="mono tiny">{p.message_id || '—'}</dd><dt>In-Reply-To</dt><dd className="mono tiny">{p.in_reply_to || '—'}</dd>
          <dt>Received hops</dt><dd>{p.received_hops ?? '—'}</dd>
          <dt>Auth results</dt><dd>{(p.authentication_results || []).length ? (p.authentication_results as string[]).map((x, i) => <div key={i} className="mono tiny">{x}</div>) : <span className="pill">unavailable — not a pass</span>}</dd>
        </dl>
      </div>
      <div className="card">
        <div className="card-head"><h3>Identity, authentication & thread findings</h3></div>
        <FindingList items={d.findings.filter(f => f.component === 'identity' || f.category.startsWith('auth.') || f.category.startsWith('identity.') || f.category.startsWith('context.'))} empty="No identity findings." />
      </div>
    </div>
  )
}

function Urls({ d }: { d: Analysis }) {
  const urlF = d.findings.filter(f => f.component === 'url' || f.category.startsWith('url.'))
  const urlInds = d.indicators.filter(i => i.type === 'url' || i.type === 'domain')
  return (
    <div className="grid g2">
      <div className="card">
        <div className="card-head"><h3>URL inventory</h3><span className="tiny dim">static analysis only — no URL is fetched</span></div>
        {urlInds.length ? <div className="table-wrap"><table className="t"><thead><tr><th>Type</th><th>Value</th><th>Location</th><th>Reputation</th></tr></thead>
          <tbody>{urlInds.map(i => <tr key={i.id + i.location}><td>{i.type}</td><td className="mono tiny" style={{ wordBreak: 'break-all' }}>{i.display_value}</td><td className="tiny">{i.location}</td><td className="tiny">{i.reputation && i.reputation !== 'unknown' ? `${i.reputation} (${i.reputation_source})` : 'unknown'}</td></tr>)}</tbody></table></div>
          : <div className="small dim">No URLs in this message.</div>}
      </div>
      <div className="card"><div className="card-head"><h3>URL findings</h3></div><FindingList items={urlF} empty="No URL findings." /></div>
    </div>
  )
}

function Attachments({ d }: { d: Analysis }) {
  const atts = (d.parsed?.attachments || []) as any[]
  return (
    <div className="grid g2">
      <div className="card">
        <div className="card-head"><h3>Attachment static triage</h3><span className="tiny dim">never opened or executed</span></div>
        {atts.length ? <div className="table-wrap"><table className="t"><thead><tr><th>File</th><th>Declared / detected</th><th>Size</th><th>SHA-256</th><th>Text</th></tr></thead>
          <tbody>{atts.map(x => <tr key={x.index}><td>{x.filename}</td><td className="tiny">{x.declared_type}<br />{x.detected_type}</td><td className="num tiny">{x.size}</td><td className="mono tiny" style={{ wordBreak: 'break-all' }}>{x.sha256}</td><td><StatusPill status={x.text_extraction_status} /></td></tr>)}</tbody></table></div>
          : <div className="small dim">No attachments.</div>}
      </div>
      <div className="card"><div className="card-head"><h3>Attachment findings</h3></div><FindingList items={d.findings.filter(f => f.category.startsWith('attachment.'))} empty="No attachment findings." /></div>
    </div>
  )
}

function Hidden({ d }: { d: Analysis }) {
  const inj = d.findings.filter(f => f.component === 'ai_injection')
  const hid = d.findings.filter(f => f.component === 'evasion')
  return (
    <div className="grid g2">
      <div className="card">
        <div className="card-head"><h3>What the person sees</h3><span className="tiny dim">visible text (hidden HTML removed)</span></div>
        <pre className="source-view">{d.body_text || '(no visible text retained)'}</pre>
      </div>
      <div className="card">
        <div className="card-head"><h3>What an AI assistant could also read</h3><span className="tiny dim">shown as inert evidence — never followed</span></div>
        {hid.length === 0 && inj.length === 0 ? <div className="small dim">No hidden content, comments, Unicode tricks or AI-directed instructions were found{d.parsed?.html_present ? '' : ' (message has no HTML part)'}.</div> : (
          <div className="stack">
            {inj.map(f => (
              <div key={f.finding_id} className="finding" style={{ borderColor: f.confidence >= 0.6 ? 'rgba(240,138,75,.5)' : undefined }}>
                <div className="row between"><b className="small">{f.finding_id} · {f.title}</b><span className={`pill ${f.confidence >= 0.6 ? 'serious' : ''}`}>{f.status} · {f.confidence}</span></div>
                <pre className="source-view" style={{ marginTop: 8, maxHeight: 160 }}>{f.observed_value}</pre>
                <div className="tiny dim">{f.explanation} [{f.source_location}]</div>
              </div>))}
            <FindingList items={hid} empty="" />
          </div>
        )}
      </div>
    </div>
  )
}

function Intel({ d }: { d: Analysis }) {
  const ti = d.threat_intel
  return (
    <div className="grid g2">
      <div className="card">
        <div className="card-head"><h3>Threat-intelligence lookups</h3><span className="tiny dim">providers: {(ti?.stats?.providers || []).join(', ') || '—'}</span></div>
        <p className="tiny dim">“unknown” means no record — it is not a clean verdict. External providers run only when configured.</p>
        {ti?.results?.length ? <div className="table-wrap"><table className="t"><thead><tr><th>Indicator</th><th>Provider</th><th>Verdict</th><th>Source</th></tr></thead>
          <tbody>{ti.results.map((r, i) => <tr key={i}><td className="mono tiny" style={{ wordBreak: 'break-all' }}>{r.indicator_type}: {r.value.length > 60 ? r.value.slice(0, 60) + '…' : r.value}</td><td>{r.provider}</td>
            <td><span className={`pill ${r.verdict === 'malicious' ? 'crit' : r.verdict === 'suspicious' ? 'warn' : ''}`}>{r.verdict}</span></td><td className="tiny">{r.source} {r.detail}</td></tr>)}</tbody></table></div>
          : <div className="small dim">No lookups recorded.</div>}
      </div>
      <div className="card">
        <div className="card-head"><h3>Related messages</h3>{d.campaigns.map(c => <Link key={c.id} to={`/app/campaigns/${c.id}`} className="pill warn" style={{ textDecoration: 'none' }}>{c.id} · {c.member_count} msgs</Link>)}</div>
        {d.related_edges.length ? <div className="stack">{d.related_edges.map(e => (
          <Link key={e.id} to={`/app/analyses/${e.other}`} className="finding" style={{ textDecoration: 'none' }}>
            <div className="row between"><b className="small">{human(e.edge_type)} → {e.other}</b><span className={`pill ${e.strength_label === 'strong' ? 'crit' : e.strength_label === 'moderate' ? 'warn' : ''}`}>{e.strength_label} {e.strength}</span></div>
            <div className="tiny dim">{e.explanation}</div>
            <div className="mono tiny">{e.evidence_json.map(x => `${x.indicator_type}: ${x.value}`).join(' · ')}</div>
          </Link>))}</div> : <div className="small dim">No relationships to other retained messages.</div>}
      </div>
    </div>
  )
}

function Stages({ d }: { d: Analysis }) {
  return (
    <div className="grid g2">
      <div className="card">
        <div className="card-head"><h3>Pipeline stages</h3><span className="tiny dim">{d.latency_ms} ms end-to-end</span></div>
        <div className="table-wrap"><table className="t"><thead><tr><th>Stage</th><th>Status</th><th>Detail</th></tr></thead>
          <tbody>{Object.entries(d.stage_status).map(([k, v]) => <tr key={k}><td>{human(k)}</td><td><StatusPill status={v.status} /></td><td className="tiny">{v.detail ?? ''}{v.ms !== undefined ? ` ${v.ms} ms` : ''}</td></tr>)}</tbody></table></div>
        <div style={{ marginTop: 12 }}><FindingList items={d.findings.filter(f => f.status === 'unavailable')} empty="All layers ran." /></div>
      </div>
      <div className="card">
        <div className="card-head"><h3>Versions & audit receipt</h3></div>
        <dl className="kv"><dt>Model</dt><dd className="mono tiny">{d.versions.model}</dd><dt>Rules</dt><dd className="mono tiny">{d.versions.rules}</dd>
          <dt>Fusion</dt><dd className="mono tiny">{d.versions.fusion}</dd><dt>Raw sha256</dt><dd className="mono tiny">{d.parsed?.raw_sha256}</dd>
          <dt>Raw retained</dt><dd>{d.raw_retained ? 'yes (deletable)' : 'no'}</dd></dl>
        <div className="small muted" style={{ margin: '12px 0 6px' }}>Decision history (original prediction is immutable)</div>
        <div className="table-wrap"><table className="t"><thead><tr><th>When</th><th>Reason</th><th>Verdict</th><th>Risk</th></tr></thead>
          <tbody>{d.history.map(h => <tr key={h.id}><td className="tiny">{fmtDate(h.created_at)}</td><td className="tiny">{h.reason}</td><td className="tiny">{h.verdict}</td><td className="num">{h.risk_score}</td></tr>)}</tbody></table></div>
        <p className="tiny dim">This is an audit receipt, not a cryptographically signed proof.</p>
      </div>
    </div>
  )
}
