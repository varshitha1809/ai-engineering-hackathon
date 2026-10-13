import { useEffect, useState, type ReactNode } from 'react'
import type { Verdict } from '../lib/api'
import { IconAlert, IconBot, IconCheck, IconInfo, IconQuestion, IconShield } from './icons'

export const VERDICT_META: Record<Verdict, { cls: string; color: string; Icon: typeof IconAlert; short: string }> = {
  LIKELY_PHISHING: { cls: 'crit', color: 'var(--critical)', Icon: IconAlert, short: 'High risk' },
  AI_INJECTION_SUSPECTED: { cls: 'serious', color: 'var(--serious)', Icon: IconBot, short: 'AI manipulation' },
  SUSPICIOUS_REVIEW: { cls: 'warn', color: 'var(--warning)', Icon: IconQuestion, short: 'Needs review' },
  NO_STRONG_INDICATORS: { cls: 'good', color: 'var(--good)', Icon: IconShield, short: 'No strong indicators' },
  INSUFFICIENT_EVIDENCE: { cls: 'info', color: 'var(--info)', Icon: IconInfo, short: 'Insufficient evidence' },
}

export function VerdictBadge({ verdict, label, large }: { verdict: Verdict; label?: string; large?: boolean }) {
  const m = VERDICT_META[verdict] ?? VERDICT_META.INSUFFICIENT_EVIDENCE
  if (!large) return <span className={`pill ${m.cls}`}><m.Icon />{label ?? m.short}</span>
  return (
    <span className="verdict" style={{ color: m.color, borderColor: m.color, background: 'rgba(0,0,0,.25)' }}>
      <m.Icon />{label ?? m.short}
    </span>
  )
}

export function StatusPill({ status }: { status: string }) {
  const map: Record<string, [string, typeof IconAlert]> = {
    ok: ['good', IconCheck], loaded: ['good', IconCheck], completed: ['good', IconCheck], connected: ['good', IconCheck],
    failed: ['crit', IconAlert], error: ['crit', IconAlert], missing: ['crit', IconAlert],
    running: ['info', IconInfo], queued: ['info', IconInfo], partial: ['warn', IconAlert],
    unavailable: ['', IconInfo], skipped: ['', IconInfo], not_applicable: ['', IconInfo], 'not configured': ['', IconInfo],
    'not connected': ['', IconInfo], 'not enabled': ['', IconInfo],
  }
  const [cls, Icon] = map[status] ?? ['', IconInfo]
  return <span className={`pill ${cls}`}><Icon />{status.replace(/_/g, ' ')}</span>
}

export const PriorityPill = ({ p }: { p: string }) => (
  <span className={`pill ${p === 'P1' ? 'crit' : p === 'P2' ? 'serious' : p === 'P3' ? 'warn' : ''}`}>{p}</span>
)

export const DataLabel = ({ label }: { label: string }) => (
  <span className="label-tag" title="Provenance of this record">{label === 'user' ? 'real submission' : label}</span>
)

export function Loading({ what = 'Loading' }: { what?: string }) {
  return <div className="state" role="status"><span className="spinner" /> <span style={{ marginLeft: 8 }}>{what}…</span></div>
}
export function ErrorState({ error, retry }: { error: string; retry?: () => void }) {
  return (
    <div className="state error" role="alert">
      <div className="row" style={{ justifyContent: 'center' }}><IconAlert width={18} /> <b>Request failed</b></div>
      <p className="small">{error}</p>
      {retry && <button className="btn sm" onClick={retry}>Retry</button>}
    </div>
  )
}
export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="state"><b style={{ color: 'var(--text)' }}>{title}</b><div className="small" style={{ marginTop: 6 }}>{children}</div></div>
}

export function PageHead({ eyebrow, title, desc, actions }: { eyebrow: string; title: string; desc?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        {desc && <p>{desc}</p>}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  )
}

export function Stat({ label, value, sub, onClick, hint }: { label: string; value: ReactNode; sub?: ReactNode; onClick?: () => void; hint?: string }) {
  return (
    <div className={`card ${onClick ? 'link' : ''}`} onClick={onClick} role={onClick ? 'button' : undefined} tabIndex={onClick ? 0 : undefined}
      onKeyDown={e => { if (onClick && (e.key === 'Enter' || e.key === ' ')) onClick() }} title={hint}>
      <div className="small muted">{label}</div>
      <div className="num" style={{ fontSize: 34, letterSpacing: '-.04em', marginTop: 4, fontWeight: 400 }}>{value}</div>
      {sub && <div className="small dim" style={{ marginTop: 2 }}>{sub}</div>}
    </div>
  )
}

export function RiskMeter({ score, size = 132 }: { score: number; size?: number }) {
  const r = size / 2 - 10
  const c = Math.PI * r
  const color = score >= 65 ? 'var(--critical)' : score >= 35 ? 'var(--warning)' : 'var(--good)'
  return (
    <svg width={size} height={size / 2 + 18} viewBox={`0 0 ${size} ${size / 2 + 18}`} role="img" aria-label={`Risk score ${score} of 100`}>
      <path d={`M10 ${size / 2} A ${r} ${r} 0 0 1 ${size - 10} ${size / 2}`} stroke="var(--surface-3)" strokeWidth="10" fill="none" strokeLinecap="round" />
      <path d={`M10 ${size / 2} A ${r} ${r} 0 0 1 ${size - 10} ${size / 2}`} stroke={color} strokeWidth="10" fill="none" strokeLinecap="round"
        strokeDasharray={`${(c * score) / 100} ${c}`} />
      <text x={size / 2} y={size / 2 + 2} textAnchor="middle" fill="var(--text)" fontSize="30" style={{ letterSpacing: '-.04em' }}>{Math.round(score)}</text>
      <text x={size / 2} y={size / 2 + 16} textAnchor="middle" fill="var(--text-3)" fontSize="10">risk score / 100</text>
    </svg>
  )
}

export function Toast({ msg, kind = 'info', onDone }: { msg: string; kind?: 'info' | 'error'; onDone: () => void }) {
  useEffect(() => { const t = setTimeout(onDone, 6000); return () => clearTimeout(t) }, [onDone])
  return <div className="toast" role="status" style={kind === 'error' ? { borderColor: 'var(--critical)' } : undefined}>{msg}</div>
}

export function useToast() {
  const [t, setT] = useState<{ msg: string; kind?: 'info' | 'error' } | null>(null)
  const node = t ? <Toast msg={t.msg} kind={t.kind} onDone={() => setT(null)} /> : null
  return { show: (msg: string, kind?: 'info' | 'error') => setT({ msg, kind }), node }
}

export function Tabs({ tabs, value, onChange }: { tabs: { id: string; label: ReactNode }[]; value: string; onChange: (id: string) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map(t => (
        <button key={t.id} role="tab" aria-selected={value === t.id} className={`tab ${value === t.id ? 'active' : ''}`} onClick={() => onChange(t.id)}>{t.label}</button>
      ))}
    </div>
  )
}
