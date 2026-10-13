import { useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { IconUpload } from '../components/icons'
import { ErrorState, PageHead, Tabs, VerdictBadge, useToast } from '../components/ui'
import { get, post, type Analysis, type Verdict } from '../lib/api'

const MAX = 5 * 1024 * 1024

export default function Analyze() {
  const [tab, setTab] = useState('paste')
  return (
    <>
      <PageHead eyebrow="Ingest" title="Analyze an email"
        desc="Paste raw text (with or without headers), upload an .eml, or submit a batch. The backend parses, runs the trained model and every forensic layer, then persists the evidence." />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: 'paste', label: 'Paste text' }, { id: 'upload', label: 'Upload .eml' },
        { id: 'batch', label: 'Batch (.eml / CSV)' }, { id: 'samples', label: 'Local sample set' }]} />
      {tab === 'paste' && <PasteForm />}
      {tab === 'upload' && <UploadForm />}
      {tab === 'batch' && <BatchForm />}
      {tab === 'samples' && <Samples />}
    </>
  )
}

function useSubmit() {
  const nav = useNavigate()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const ctrl = useRef<{ cancelled: boolean } | null>(null)
  const run = async (fd: FormData) => {
    setBusy(true); setError(null)
    const token = { cancelled: false }
    ctrl.current = token
    try {
      const r = await post<Analysis>('/analyze', fd)
      if (!token.cancelled) nav(`/app/analyses/${r.id}`)
    } catch (e) {
      if (!token.cancelled) setError(e instanceof Error ? e.message : String(e))
    } finally {
      if (!token.cancelled) setBusy(false)
    }
  }
  const cancel = () => { if (ctrl.current) ctrl.current.cancelled = true; setBusy(false) }
  return { busy, error, run, cancel, setError }
}

function PasteForm() {
  const [text, setText] = useState('')
  const [subject, setSubject] = useState('')
  const [sender, setSender] = useState('')
  const s = useSubmit()
  const hasHeaders = /^(from|subject|to|date|received|return-path|message-id):/im.test(text.trimStart().split(/\r?\n\r?\n/)[0] ?? '')
  const bytes = new Blob([text]).size
  const submit = () => {
    if (!text.trim()) return s.setError('Paste the email text first.')
    if (bytes > MAX) return s.setError('Text exceeds the 5 MB limit.')
    const fd = new FormData()
    fd.append('text', text)
    if (subject) fd.append('subject', subject)
    if (sender) fd.append('sender', sender)
    s.run(fd)
  }
  return (
    <div className="grid g3">
      <div className="card span2 stack">
        <label className="field">Email content
          <textarea className="input" value={text} onChange={e => setText(e.target.value)} aria-label="Email content"
            placeholder={'Paste the full raw message (headers + body) for identity checks,\nor just the body text.'} />
        </label>
        <div className="row between small">
          <span className="dim">{bytes.toLocaleString()} bytes · {hasHeaders ? <span className="accent" style={{ color: 'var(--accent)' }}>header block detected — parsed as RFC-822</span> : 'no header block — body-only analysis (identity checks will be unavailable)'}</span>
          <div className="row">
            {s.busy && <button className="btn sm" onClick={s.cancel}>Cancel</button>}
            <button className="btn primary" onClick={submit} disabled={s.busy}>{s.busy ? <><span className="spinner" /> Analyzing…</> : 'Run analysis'}</button>
          </div>
        </div>
        {s.error && <ErrorState error={s.error} />}
      </div>
      <div className="card stack">
        <h3>Optional context</h3>
        <p className="small muted">Used only when the pasted text has no header block.</p>
        <label className="field">Subject<input className="input" value={subject} onChange={e => setSubject(e.target.value)} maxLength={300} /></label>
        <label className="field">Sender (e.g. "Name" &lt;a@b.com&gt;)<input className="input" value={sender} onChange={e => setSender(e.target.value)} maxLength={300} /></label>
        <div className="tiny dim">Content is treated strictly as untrusted data. URLs are never fetched and attachments never executed.</div>
      </div>
    </div>
  )
}

function UploadForm() {
  const [file, setFile] = useState<File | null>(null)
  const [drag, setDrag] = useState(false)
  const s = useSubmit()
  const pick = (f: File | undefined) => {
    s.setError(null)
    if (!f) return
    if (!/\.(eml|txt)$/i.test(f.name)) return s.setError(`Unsupported file type: ${f.name}. Upload .eml or .txt (.msg is not supported).`)
    if (f.size > MAX) return s.setError(`${f.name} is larger than 5 MB.`)
    setFile(f)
  }
  return (
    <div className="card stack" style={{ maxWidth: 760 }}>
      <label className={`dropzone ${drag ? 'drag' : ''}`} onDragOver={e => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)}
        onDrop={e => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files[0]) }}>
        <input type="file" accept=".eml,.txt,message/rfc822" className="sr-only" aria-label="Choose .eml file" onChange={e => pick(e.target.files?.[0])} />
        <IconUpload width={28} style={{ color: 'var(--accent)' }} />
        <div style={{ marginTop: 8 }}>{file ? <b>{file.name}</b> : 'Drop an .eml file here or click to choose'}</div>
        <div className="tiny dim">{file ? `${(file.size / 1024).toFixed(1)} KB` : 'Max 5 MB · MIME, quoted-printable and base64 parts are decoded safely'}</div>
      </label>
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        {s.busy && <button className="btn sm" onClick={s.cancel}>Cancel</button>}
        <button className="btn primary" disabled={!file || s.busy} onClick={() => { const fd = new FormData(); fd.append('file', file!); s.run(fd) }}>
          {s.busy ? <><span className="spinner" /> Analyzing…</> : 'Upload & analyze'}</button>
      </div>
      {s.error && <ErrorState error={s.error} />}
    </div>
  )
}

interface BatchRes { batch_id: string; summary: { total: number; ok: number; failed: number; verdicts: Record<string, number> }; results: { name: string; status: string; id?: string; verdict?: Verdict; risk_score?: number; error?: string }[] }

function BatchForm() {
  const [files, setFiles] = useState<File[]>([])
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState<BatchRes | null>(null)
  const [error, setError] = useState<string | null>(null)
  const go = async () => {
    setBusy(true); setError(null); setRes(null)
    const fd = new FormData()
    files.forEach(f => fd.append('files', f))
    try { setRes(await post<BatchRes>('/analyze/batch', fd)) } catch (e) { setError(e instanceof Error ? e.message : String(e)) } finally { setBusy(false) }
  }
  return (
    <div className="stack">
      <div className="card stack" style={{ maxWidth: 760 }}>
        <label className="dropzone">
          <input type="file" multiple accept=".eml,.txt,.csv" className="sr-only" aria-label="Choose batch files" onChange={e => setFiles(Array.from(e.target.files ?? []))} />
          <IconUpload width={26} style={{ color: 'var(--accent)' }} />
          <div style={{ marginTop: 8 }}>{files.length ? `${files.length} file(s) selected` : 'Choose several .eml files and/or a CSV (columns: body, optional subject, sender)'}</div>
          <div className="tiny dim">Up to 50 messages per batch; each message is isolated — one parse failure does not stop the others.</div>
        </label>
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          <button className="btn primary" disabled={!files.length || busy} onClick={go}>{busy ? <><span className="spinner" /> Processing…</> : 'Analyze batch'}</button>
        </div>
        {error && <ErrorState error={error} />}
      </div>
      {res && <BatchTable res={res} />}
    </div>
  )
}

function BatchTable({ res }: { res: BatchRes }) {
  const nav = useNavigate()
  return (
    <div className="card">
      <div className="card-head"><h3>Batch {res.batch_id}</h3><span className="small dim">{res.summary.ok} ok · {res.summary.failed} failed</span></div>
      <div className="table-wrap"><table className="t"><thead><tr><th>Message</th><th>Status</th><th>Verdict</th><th>Risk</th></tr></thead>
        <tbody>{res.results.map((r, i) => (
          <tr key={i} className={r.id ? 'clickable' : ''} onClick={() => r.id && nav(`/app/analyses/${r.id}`)}>
            <td>{r.name}</td><td>{r.status === 'ok' ? <span className="pill good">ok</span> : <span className="pill crit" title={r.error}>failed</span>}</td>
            <td>{r.verdict ? <VerdictBadge verdict={r.verdict} /> : <span className="small" style={{ color: '#ffb3b3' }}>{r.error}</span>}</td>
            <td className="num">{r.risk_score ?? '—'}</td></tr>))}</tbody></table></div>
    </div>
  )
}

function Samples() {
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState<{ results: { file: string; id: string; verdict: Verdict; risk_score: number }[]; campaigns: { id: string; label: string; member_count: number }[]; profiles_added: number } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [preview, setPreview] = useState<{ file: string; subject: string; raw: string }[] | null>(null)
  const toast = useToast()
  const nav = useNavigate()
  const seed = async () => {
    setBusy(true); setError(null)
    try {
      const r = await post<any>('/demo/seed')
      setRes(r); toast.show(`Imported ${r.results.length} local sample messages; ${r.campaigns.length} campaign cluster(s) formed from shared evidence.`)
    } catch (e) { setError(e instanceof Error ? e.message : String(e)) } finally { setBusy(false) }
  }
  return (
    <div className="stack">
      <div className="card stack">
        <h3>Labelled local sample set</h3>
        <p className="small muted">15 synthetic, sanitised messages (reserved <code>.test</code>/<code>.example</code> domains) for the campaign demo: a credential-phishing wave sharing one URL, a slow vendor-impersonation run reusing a Reply-To, two zero-link CEO-impersonation messages, a shared attachment hash, a hidden-instruction email and unrelated benign mail. Two demo profiles and two demo IOCs are added. Everything is tagged <span className="label-tag">local sample data</span>.</p>
        <div className="row">
          <button className="btn primary" onClick={seed} disabled={busy}>{busy ? <><span className="spinner" /> Importing & analysing…</> : 'Import sample set'}</button>
          <button className="btn" onClick={() => get<any>('/demo/samples').then(r => setPreview(r.samples)).catch(e => setError(String(e.message ?? e)))}>Preview raw messages</button>
        </div>
        {error && <ErrorState error={error} />}
      </div>
      {res && (
        <div className="card">
          <div className="card-head"><h3>Imported</h3><Link to="/app/campaigns" className="btn sm">Open campaign intelligence →</Link></div>
          <div className="table-wrap"><table className="t"><thead><tr><th>File</th><th>Verdict</th><th>Risk</th></tr></thead>
            <tbody>{res.results.map(r => <tr key={r.id} className="clickable" onClick={() => nav(`/app/analyses/${r.id}`)}><td>{r.file}</td><td><VerdictBadge verdict={r.verdict} /></td><td className="num">{r.risk_score}</td></tr>)}</tbody></table></div>
        </div>
      )}
      {preview && (
        <div className="card stack">
          <h3>Raw sample messages</h3>
          {preview.map(p => <details key={p.file}><summary className="small">{p.file} — {p.subject}</summary><pre className="source-view">{p.raw}</pre></details>)}
        </div>
      )}
      {toast.node}
    </div>
  )
}
