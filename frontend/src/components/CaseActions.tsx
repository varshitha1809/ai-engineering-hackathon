import { useState } from 'react'
import { patch, type Analysis } from '../lib/api'
import { fmtDate } from '../lib/hooks'
import { ErrorState, PriorityPill, useToast } from './ui'

/** Analyst response actions on the local case store (persisted + audited). */
export function CaseActions({ analysis, onChange }: { analysis: Analysis; onChange: () => void }) {
  const c = analysis.case
  const [note, setNote] = useState('')
  const [assignee, setAssignee] = useState(c?.assignee ?? '')
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [awareness, setAwareness] = useState<{ tactic: string; tip: string }[]>([])
  const toast = useToast()
  if (!c) return (
    <div className="card small muted">No case was opened because the verdict was “no strong indicators”. Feedback can still be recorded from the Cases page if needed.</div>
  )
  const act = async (body: Record<string, unknown>, label: string) => {
    if (body.action === 'quarantine' && !confirm('Quarantine is a high-impact action. Confirm you reviewed the evidence. (This updates the local record only.)')) return
    setBusy(label); setError(null)
    try {
      const r = await patch<any>(`/cases/${c.id}`, { ...body, confirm: body.action === 'quarantine' ? true : undefined })
      toast.show(r.messages?.join(' · ') || 'Case updated')
      setAwareness(r.awareness ?? [])
      setNote('')
      onChange()
    } catch (e) { setError((e as Error).message) } finally { setBusy(null) }
  }
  const B = ({ a, label, cls = '' }: { a: Record<string, unknown>; label: string; cls?: string }) => (
    <button className={`btn sm ${cls}`} disabled={!!busy} onClick={() => act({ ...a, note: note || undefined }, label)}>{busy === label ? <span className="spinner" /> : null}{label}</button>
  )
  return (
    <div className="grid g2">
      <div className="card stack">
        <div className="card-head"><h3>Case {c.id}</h3><span className="row"><PriorityPill p={c.priority} /><span className="pill">{c.status}</span></span></div>
        <div className="small muted">Response actions change <b>local records only</b> (sandbox). No mailbox, recipient or external system is touched.</div>
        <div className="row">
          <B a={{ action: 'report_phishing' }} label="Report as phishing" cls="danger" />
          <B a={{ action: 'mark_benign' }} label="Mark benign / false positive" />
          <B a={{ action: 'escalate' }} label="Escalate" />
          <B a={{ action: 'resolve', feedback_label: 'unresolved' }} label="Resolve (unresolved)" />
          <B a={{ action: 'reopen' }} label="Reopen" />
        </div>
        <div className="row">
          <B a={{ action: 'quarantine' }} label="Quarantine (local)" cls="danger" />
          <B a={{ action: 'release' }} label="Release (local)" />
          <B a={{ action: 'banner' }} label="Warning banner (local)" />
        </div>
        <div className="row">
          <input className="input" style={{ maxWidth: 220 }} placeholder="Assignee" value={assignee} onChange={e => setAssignee(e.target.value)} aria-label="Assignee" />
          <button className="btn sm" disabled={!!busy} onClick={() => act({ action: 'assign', assignee }, 'Assign')}>Assign</button>
        </div>
        <label className="field">Analyst note
          <textarea className="input" style={{ minHeight: 80 }} value={note} onChange={e => setNote(e.target.value)} maxLength={2000} />
        </label>
        <div><button className="btn sm" disabled={!note || !!busy} onClick={() => act({}, 'Add note')}>Add note</button></div>
        {error && <ErrorState error={error} />}
        {awareness.length > 0 && (
          <div className="card flat"><b className="small">Awareness tip</b>{awareness.map(a => <p key={a.tactic} className="small muted" style={{ margin: '6px 0 0' }}><b>{a.tactic}:</b> {a.tip}</p>)}</div>
        )}
      </div>
      <div className="card stack">
        <h3>Notes & feedback</h3>
        {(c.notes_json || []).length === 0 && analysis.feedback.length === 0 && <div className="small dim">No notes or feedback yet.</div>}
        {(c.notes_json || []).map((n, i) => <div key={i} className="finding" style={{ cursor: 'default' }}><div className="tiny dim">{fmtDate(n.ts)} · {n.author}</div><div className="small">{n.text}</div></div>)}
        {analysis.feedback.map(f => <div key={f.id} className="small">Feedback <b>{f.label}</b> by {f.reviewer} · {fmtDate(f.created_at)} <span className="dim">(original verdict {f.original_verdict} kept)</span></div>)}
      </div>
      {toast.node}
    </div>
  )
}
