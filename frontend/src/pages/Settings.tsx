import { useState } from 'react'
import { Empty, ErrorState, Loading, PageHead, StatusPill, Tabs, useToast } from '../components/ui'
import { del, get, patch, post } from '../lib/api'
import { fmtDate, human, useApi } from '../lib/hooks'

export default function Settings() {
  const [tab, setTab] = useState('status')
  return (
    <>
      <PageHead eyebrow="System" title="Settings & status" desc="Live health of the API, model, database and optional integrations, plus trusted sender/vendor profiles and the local IOC store. Secrets are never displayed." />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: 'status', label: 'Health & integrations' }, { id: 'profiles', label: 'Sender / vendor profiles' }, { id: 'iocs', label: 'Local IOC store' }, { id: 'config', label: 'Configuration' }]} />
      {tab === 'status' && <Status />}
      {tab === 'profiles' && <Profiles />}
      {tab === 'iocs' && <Iocs />}
      {tab === 'config' && <Config />}
    </>
  )
}

function Status() {
  const s = useApi(() => get<any>('/system/status'), [], 10000)
  if (s.loading && !s.data) return <Loading />
  if (s.error) return <ErrorState error={s.error} retry={s.reload} />
  const d = s.data
  return (
    <div className="grid g2">
      <div className="card">
        <div className="card-head"><h3>Core services</h3><button className="btn sm" onClick={s.reload}>Refresh</button></div>
        <dl className="kv">
          <dt>API</dt><dd><StatusPill status={d.api} /></dd><dt>Database</dt><dd><StatusPill status={d.database} /></dd>
          <dt>Text model</dt><dd><StatusPill status={d.model.status} /> <span className="mono tiny">{d.model.version}</span>{d.model.error && <div className="small" style={{ color: '#ffb3b3' }}>{d.model.error}</div>}</dd>
          <dt>Rules / fusion</dt><dd className="mono tiny">{d.rules_version} · {d.fusion_version}</dd>
          <dt>Latency</dt><dd>{d.latency_ms.n ? `p50 ${d.latency_ms.p50} ms · p95 ${d.latency_ms.p95} ms (${d.latency_ms.n} analyses, ${d.latency_ms.scope})` : 'no analyses since server start'}</dd>
          <dt>Stage failures</dt><dd>{Object.keys(d.stage_failures_last_500).length ? Object.entries(d.stage_failures_last_500).map(([k, v]) => `${k}: ${v}`).join(' · ') : 'none in the last 500 analyses'}</dd>
          <dt>Timeouts</dt><dd>{d.timeouts}</dd>
          <dt>Last benchmark</dt><dd>{d.last_benchmark ? <>{d.last_benchmark.id} <StatusPill status={d.last_benchmark.status} /> {d.last_benchmark.progress}/{d.last_benchmark.total}</> : 'none'}</dd>
          <dt>Server started</dt><dd className="small">{fmtDate(d.started_at)}</dd>
        </dl>
      </div>
      <div className="card">
        <div className="card-head"><h3>Integrations</h3></div>
        <div className="stack">{d.integrations.map((i: any) => (
          <div key={i.name} className="row between"><span className="small"><b>{i.name}</b><div className="tiny dim">{i.detail}</div></span><StatusPill status={i.status} /></div>))}</div>
        <p className="tiny dim">“Not connected” integrations never report actions as performed. Local response actions are recorded as sandbox state only.</p>
      </div>
    </div>
  )
}

function Profiles() {
  const p = useApi(() => get<any[]>('/profiles'), [])
  const [form, setForm] = useState({ kind: 'vendor', name: '', emails: '', domains: '', notes: '' })
  const [err, setErr] = useState<string | null>(null)
  const toast = useToast()
  const add = async () => {
    setErr(null)
    try {
      await post('/profiles', { ...form, emails: form.emails.split(',').map(s => s.trim()).filter(Boolean), domains: form.domains.split(',').map(s => s.trim()).filter(Boolean) })
      setForm({ kind: 'vendor', name: '', emails: '', domains: '', notes: '' }); p.reload(); toast.show('Profile saved. New analyses will check impersonation against it.')
    } catch (e) { setErr((e as Error).message) }
  }
  return (
    <div className="grid g3">
      <div className="card stack">
        <h3>Add profile</h3>
        <label className="field">Type<select className="input" value={form.kind} onChange={e => setForm({ ...form, kind: e.target.value })}><option value="vendor">Vendor</option><option value="vip">VIP / executive</option></select></label>
        <label className="field">Name (display name to protect)<input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></label>
        <label className="field">Known addresses (comma separated)<input className="input" value={form.emails} onChange={e => setForm({ ...form, emails: e.target.value })} /></label>
        <label className="field">Known domains<input className="input" value={form.domains} onChange={e => setForm({ ...form, domains: e.target.value })} /></label>
        <label className="field">Notes<input className="input" value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} /></label>
        <button className="btn primary" onClick={add} disabled={form.name.length < 2}>Save profile</button>
        {err && <ErrorState error={err} />}
      </div>
      <div className="card span2">
        <div className="card-head"><h3>Profiles</h3></div>
        {p.loading && !p.data ? <Loading /> : p.error ? <ErrorState error={p.error} /> : p.data!.length === 0 ? <Empty title="No profiles">Profiles enable VIP/vendor impersonation and Reply-To-on-record checks.</Empty> : (
          <div className="table-wrap"><table className="t"><thead><tr><th>Type</th><th>Name</th><th>Addresses</th><th>Domains</th><th>Provenance</th><th /></tr></thead>
            <tbody>{p.data!.map(x => <tr key={x.id}><td>{x.kind}</td><td>{x.name}</td><td className="tiny mono">{(x.emails_json || []).join(', ')}</td><td className="tiny mono">{(x.domains_json || []).join(', ')}</td><td><span className="label-tag">{x.data_label}</span></td>
              <td><button className="btn sm danger" onClick={() => del(`/profiles/${x.id}`).then(p.reload)}>Remove</button></td></tr>)}</tbody></table></div>
        )}
      </div>
      {toast.node}
    </div>
  )
}

function Iocs() {
  const [q, setQ] = useState('')
  const [review, setReview] = useState('')
  const list = useApi(() => get<{ items: any[]; providers: any[] }>(`/indicators?limit=300${q ? `&q=${encodeURIComponent(q)}` : ''}${review ? `&review_status=${review}` : ''}`), [q, review])
  const [form, setForm] = useState({ type: 'domain', value: '', reputation: 'malicious', source: 'analyst (local)', notes: '' })
  const [res, setRes] = useState<any>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const submit = async () => {
    setBusy(true); setErr(null)
    try { setRes(await post('/indicators', form)); list.reload() } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }
  const reviewIoc = async (id: number, status: string) => {
    try { setRes(await patch(`/indicators/${id}`, { review_status: status })); list.reload() } catch (e) { setErr((e as Error).message) }
  }
  return (
    <div className="stack">
      <div className="grid g3">
        <div className="card stack">
          <h3>Set local reputation</h3>
          <p className="tiny dim" style={{ marginTop: 0 }}>Retained analyses that contain the indicator are re-scored immediately (time-of-click re-score) and before/after verdicts are shown.</p>
          <label className="field">Type<select className="input" value={form.type} onChange={e => setForm({ ...form, type: e.target.value })}>
            {['domain', 'url', 'sha256', 'sender_address', 'reply_to_address', 'sender_domain'].map(t => <option key={t}>{t}</option>)}</select></label>
          <label className="field">Value<input className="input" value={form.value} onChange={e => setForm({ ...form, value: e.target.value })} /></label>
          <label className="field">Reputation<select className="input" value={form.reputation} onChange={e => setForm({ ...form, reputation: e.target.value })}>{['malicious', 'suspicious', 'clean', 'unknown'].map(t => <option key={t}>{t}</option>)}</select></label>
          <label className="field">Source<input className="input" value={form.source} onChange={e => setForm({ ...form, source: e.target.value })} /></label>
          <button className="btn primary" onClick={submit} disabled={busy || form.value.length < 3}>{busy ? <span className="spinner" /> : null}Save & re-score</button>
          {err && <ErrorState error={err} />}
        </div>
        <div className="card span2">
          <div className="card-head"><h3>Re-score result</h3></div>
          {!res ? <div className="small dim">Results of the last reputation change appear here.</div> : (<>
            <div className="small">Indicator #{res.indicator.id} {res.indicator.type} <b>{res.indicator.display_value}</b> → {res.indicator.reputation} ({res.indicator.review_status}) · {res.rescored.length} retained message(s) re-analysed</div>
            {res.rescored.length > 0 && <div className="table-wrap" style={{ marginTop: 8 }}><table className="t"><thead><tr><th>Analysis</th><th>Before</th><th>After</th><th>Changed</th></tr></thead>
              <tbody>{res.rescored.map((r: any) => <tr key={r.id}><td className="mono tiny">{r.id}</td><td className="small">{r.before ? `${r.before.verdict} (${r.before.risk_score})` : r.detail}</td><td className="small">{r.after ? `${r.after.verdict} (${r.after.risk_score})` : '—'}</td><td>{r.changed ? <span className="pill warn">changed</span> : 'no'}</td></tr>)}</tbody></table></div>}
          </>)}
        </div>
      </div>
      <div className="card">
        <div className="card-head"><h3>Indicators</h3>
          <div className="row"><input className="input" style={{ width: 220 }} placeholder="Search" value={q} onChange={e => setQ(e.target.value)} aria-label="Search indicators" />
            <select className="input" style={{ width: 200 }} value={review} onChange={e => setReview(e.target.value)} aria-label="Review status"><option value="">Any review status</option><option value="pending_review">pending review</option><option value="approved">approved</option><option value="rejected">rejected</option></select></div></div>
        {list.loading && !list.data ? <Loading /> : list.error ? <ErrorState error={list.error} /> : list.data!.items.length === 0 ? <Empty title="No indicators" /> : (
          <div className="table-wrap" style={{ maxHeight: 520, overflow: 'auto' }}><table className="t"><thead><tr><th>Type</th><th>Value</th><th>Messages</th><th>Reputation</th><th>Review</th><th>First seen (local)</th><th /></tr></thead>
            <tbody>{list.data!.items.map(i => <tr key={i.id}><td className="small">{human(i.type)}</td><td className="mono tiny" style={{ wordBreak: 'break-all', maxWidth: 360 }}>{i.display_value}</td><td className="num">{i.messages}</td>
              <td className="small">{i.reputation ?? 'unknown'}{i.reputation_source ? <div className="tiny dim">{i.reputation_source}</div> : null}</td><td className="small">{human(i.review_status ?? 'none')}</td><td className="tiny">{fmtDate(i.first_seen_local)}</td>
              <td>{i.review_status === 'pending_review' && <span className="row"><button className="btn sm" onClick={() => reviewIoc(i.id, 'approved')}>Approve</button><button className="btn sm danger" onClick={() => reviewIoc(i.id, 'rejected')}>Reject</button></span>}</td></tr>)}</tbody></table></div>
        )}
      </div>
    </div>
  )
}

function Config() {
  const c = useApi(() => get<any>('/settings'), [])
  if (c.loading && !c.data) return <Loading />
  if (c.error) return <ErrorState error={c.error} />
  const d = c.data
  return (
    <div className="grid g2">
      <div className="card">
        <div className="card-head"><h3>Runtime configuration</h3><span className="tiny dim">read-only — edit .env and restart</span></div>
        <dl className="kv">
          <dt>Org domains</dt><dd className="mono tiny">{d.org_domains.join(', ')}</dd><dt>Trusted authserv-ids</dt><dd className="mono tiny">{d.trusted_authserv_ids.join(', ') || 'none — all uploaded auth results are “unverified”'}</dd>
          <dt>Retain raw content</dt><dd>{String(d.retain_raw)} (delete any analysis from its page)</dd><dt>Max email size</dt><dd>{(d.max_email_bytes / 1048576).toFixed(1)} MB</dd>
          <dt>Batch limit</dt><dd>{d.max_batch_items}</dd><dt>Rate limit</dt><dd>{d.rate_limit_per_min}/min on analyze/benchmark endpoints</dd>
          <dt>API key required</dt><dd>{String(d.api_key_required)}</dd><dt>External lookups</dt><dd>{String(d.external_lookups_enabled)} (VirusTotal key present: {String(d.virustotal_key_present)})</dd>
        </dl>
        <p className="tiny dim">{d.env_help}</p>
      </div>
      <div className="card">
        <div className="card-head"><h3>Risk-fusion policy</h3></div>
        <div className="table-wrap"><table className="t"><thead><tr><th>Evidence group</th><th>Weight</th></tr></thead><tbody>{Object.entries(d.fusion_weights).map(([k, v]) => <tr key={k}><td>{human(k)}</td><td className="num">{String(v)}</td></tr>)}</tbody></table></div>
        <div className="small" style={{ marginTop: 10 }}>{Object.entries(d.verdict_policy).map(([k, v]) => <div key={k}>{human(k)}: <b>{String(v)}</b></div>)}</div>
        <p className="tiny dim">Try alternative thresholds safely with Decision replay in the Robustness lab.</p>
      </div>
    </div>
  )
}
