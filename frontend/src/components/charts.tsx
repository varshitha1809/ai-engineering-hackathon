// Small SVG charts built to the dataviz method: thin marks with 4px rounded data-ends, recessive axes,
// legend for 2 series + direct labels, per-mark hover tooltip, and a table view for every chart.
// Series colours were validated against the dark surface (baseline #5b8def, hybrid #45ab30).
import { useState, type ReactNode } from 'react'

interface Tip { x: number; y: number; html: ReactNode }

function useTip() {
  const [tip, setTip] = useState<Tip | null>(null)
  const on = (e: React.MouseEvent, html: ReactNode) => {
    const box = (e.currentTarget as Element).closest('.viz')!.getBoundingClientRect()
    setTip({ x: e.clientX - box.left, y: e.clientY - box.top, html })
  }
  const node = tip && (
    <div style={{ position: 'absolute', left: Math.min(tip.x + 12, 9999), top: tip.y - 10, pointerEvents: 'none', zIndex: 5,
      background: 'var(--surface-3)', border: '1px solid var(--line-2)', borderRadius: 8, padding: '6px 9px', fontSize: 12,
      whiteSpace: 'nowrap', boxShadow: '0 6px 24px #0008' }}>{tip.html}</div>
  )
  return { on, off: () => setTip(null), node }
}

function TableToggle({ table, children }: { table: ReactNode; children: ReactNode }) {
  const [t, setT] = useState(false)
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button className="btn sm" onClick={() => setT(!t)} aria-pressed={t}>{t ? 'Chart view' : 'Table view'}</button>
      </div>
      {t ? <div className="table-wrap" style={{ marginTop: 8 }}>{table}</div> : children}
    </div>
  )
}

const SERIES = [
  { key: 'baseline', label: 'Baseline (text model only)', color: 'var(--series-baseline)' },
  { key: 'hybrid', label: 'Hybrid pipeline', color: 'var(--series-hybrid)' },
] as const

export function Legend2() {
  return (
    <div className="row small" style={{ gap: 16 }}>
      {SERIES.map(s => <span key={s.key} className="row" style={{ gap: 6 }}><i style={{ width: 10, height: 10, borderRadius: 3, background: s.color, display: 'inline-block' }} />{s.label}</span>)}
    </div>
  )
}

/** Grouped vertical bars: one group per metric, two series (baseline vs hybrid). Values 0..1. */
export function CompareBars({ groups }: { groups: { label: string; baseline: number | null; hybrid: number | null; note?: string }[] }) {
  const tip = useTip()
  const W = 560, H = 220, pad = { l: 34, r: 8, t: 18, b: 30 }
  const gw = (W - pad.l - pad.r) / groups.length
  const bw = Math.min(34, gw / 3)
  const y = (v: number) => pad.t + (1 - v) * (H - pad.t - pad.b)
  const table = (
    <table className="t"><thead><tr><th>Metric</th><th>Baseline</th><th>Hybrid</th></tr></thead>
      <tbody>{groups.map(g => <tr key={g.label}><td>{g.label}</td><td className="num">{fmt(g.baseline)}</td><td className="num">{fmt(g.hybrid)}</td></tr>)}</tbody></table>
  )
  return (
    <TableToggle table={table}>
      <div className="viz" style={{ position: 'relative' }}>
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Baseline versus hybrid metrics">
          {[0, .25, .5, .75, 1].map(v => (
            <g key={v}><line x1={pad.l} x2={W - pad.r} y1={y(v)} y2={y(v)} stroke="var(--line)" />
              <text x={pad.l - 6} y={y(v) + 3} textAnchor="end" fontSize="10" fill="var(--text-3)">{v * 100}%</text></g>
          ))}
          {groups.map((g, i) => {
            const cx = pad.l + gw * i + gw / 2
            return (
              <g key={g.label}>
                {SERIES.map((s, j) => {
                  const v = g[s.key]
                  if (v === null || v === undefined) return null
                  const x = cx + (j === 0 ? -bw - 1 : 1)
                  const h = Math.max(1, (H - pad.t - pad.b) * v)
                  return (
                    <g key={s.key} onMouseMove={e => tip.on(e, <><b>{g.label}</b> · {s.label}: {fmt(v)}{g.note ? <div className="dim">{g.note}</div> : null}</>)} onMouseLeave={tip.off}>
                      <rect x={x - 4} y={pad.t} width={bw + 8} height={H - pad.t - pad.b} fill="transparent" />
                      <path d={roundTop(x, y(v), bw, h)} fill={s.color} />
                      <text x={x + bw / 2} y={y(v) - 4} textAnchor="middle" fontSize="10" fill="var(--text-2)">{fmt(v)}</text>
                    </g>
                  )
                })}
                <text x={cx} y={H - 10} textAnchor="middle" fontSize="11.5" fill="var(--text-2)">{g.label}</text>
              </g>
            )
          })}
        </svg>
        {tip.node}
      </div>
    </TableToggle>
  )
}

function roundTop(x: number, top: number, w: number, h: number) {
  const r = Math.min(4, w / 2, h)
  const b = top + h
  return `M${x},${b} V${top + r} Q${x},${top} ${x + r},${top} H${x + w - r} Q${x + w},${top} ${x + w},${top + r} V${b} Z`
}
const fmt = (v: number | null | undefined) => (v === null || v === undefined ? '—' : `${(v * 100).toFixed(1)}%`)

/** Single-series histogram (counts), clickable bins. */
export function Histogram({ bins, onPick, label }: { bins: number[]; onPick?: (i: number) => void; label: string }) {
  const tip = useTip()
  const W = 520, H = 170, pad = { l: 28, r: 6, t: 12, b: 26 }
  const max = Math.max(1, ...bins)
  const bw = (W - pad.l - pad.r) / bins.length
  const table = (
    <table className="t"><thead><tr><th>Risk range</th><th>Messages</th></tr></thead>
      <tbody>{bins.map((b, i) => <tr key={i}><td>{i * 10}–{i * 10 + 9}</td><td className="num">{b}</td></tr>)}</tbody></table>
  )
  return (
    <TableToggle table={table}>
      <div className="viz" style={{ position: 'relative' }}>
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={label}>
          {[0, .5, 1].map(f => (
            <g key={f}><line x1={pad.l} x2={W - pad.r} y1={pad.t + (1 - f) * (H - pad.t - pad.b)} y2={pad.t + (1 - f) * (H - pad.t - pad.b)} stroke="var(--line)" />
              <text x={pad.l - 5} y={pad.t + (1 - f) * (H - pad.t - pad.b) + 3} fontSize="10" textAnchor="end" fill="var(--text-3)">{Math.round(max * f)}</text></g>
          ))}
          {bins.map((b, i) => {
            const h = ((H - pad.t - pad.b) * b) / max
            const x = pad.l + i * bw + 1
            return (
              <g key={i} style={{ cursor: onPick ? 'pointer' : 'default' }} onClick={() => onPick?.(i)}
                onMouseMove={e => tip.on(e, <>Risk {i * 10}–{i * 10 + 9}: <b>{b}</b> message(s)</>)} onMouseLeave={tip.off}>
                <rect x={x} y={pad.t} width={bw - 2} height={H - pad.t - pad.b} fill="transparent" />
                {b > 0 && <path d={roundTop(x, H - pad.b - h, bw - 2, h)} fill={i >= 7 ? 'var(--critical)' : i >= 4 ? 'var(--warning)' : 'var(--series-hybrid)'} />}
              </g>
            )
          })}
          {[0, 35, 65, 100].map(v => <text key={v} x={pad.l + (v / 100) * (W - pad.l - pad.r)} y={H - 8} fontSize="10" fill="var(--text-3)" textAnchor="middle">{v}</text>)}
        </svg>
        {tip.node}
      </div>
    </TableToggle>
  )
}

/** 2×2 confusion matrix; cell shade = share of n (single green ramp), counts always printed. */
export function Confusion({ m, title }: { m: { tp: number; fp: number; tn: number; fn: number }; title: string }) {
  const n = m.tp + m.fp + m.tn + m.fn || 1
  const cell = (v: number, lab: string, good: boolean) => (
    <div title={`${lab}: ${v} (${((v / n) * 100).toFixed(1)}% of ${n})`} style={{
      padding: '14px 10px', borderRadius: 10, textAlign: 'center', border: '1px solid var(--line)',
      background: `rgba(${good ? '69,171,48' : '255,107,107'}, ${0.08 + 0.5 * (v / n)})` }}>
      <div className="num" style={{ fontSize: 24 }}>{v}</div><div className="tiny muted">{lab}</div>
    </div>
  )
  return (
    <div>
      <div className="small muted" style={{ marginBottom: 6 }}>{title}</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr 1fr', gap: 6, alignItems: 'center' }}>
        <span /> <span className="tiny dim" style={{ textAlign: 'center' }}>predicted malicious</span><span className="tiny dim" style={{ textAlign: 'center' }}>predicted benign</span>
        <span className="tiny dim">actual malicious</span>{cell(m.tp, 'true positive', true)}{cell(m.fn, 'false negative', false)}
        <span className="tiny dim">actual benign</span>{cell(m.fp, 'false positive', false)}{cell(m.tn, 'true negative', true)}
      </div>
    </div>
  )
}

/** Category × layer heat matrix (values 0..1), single-hue sequential ramp + printed values. */
export function HeatMatrix({ rows, cols, value, rowLabel = 'Category' }: { rows: string[]; cols: string[]; value: (r: string, c: string) => number; rowLabel?: string }) {
  return (
    <div className="table-wrap">
      <table className="t">
        <thead><tr><th>{rowLabel}</th>{cols.map(c => <th key={c} style={{ textAlign: 'center' }}>{c.replace(/_/g, ' ')}</th>)}</tr></thead>
        <tbody>{rows.map(r => (
          <tr key={r}><td>{r.replace(/_/g, ' ')}</td>{cols.map(c => {
            const v = value(r, c)
            return <td key={c} className="num" style={{ textAlign: 'center', background: `rgba(69,171,48,${(v * 0.6).toFixed(3)})`, color: v > 0.55 ? '#f4fff0' : 'var(--text-2)' }}
              title={`${r} · ${c}: ${(v * 100).toFixed(0)}% of items`}>{v ? `${Math.round(v * 100)}%` : '·'}</td>
          })}</tr>
        ))}</tbody>
      </table>
    </div>
  )
}

/** Horizontal paired bars per row (e.g. per-category flag rate, baseline vs hybrid). */
export function PairedRows({ rows }: { rows: { label: string; sub?: string; baseline: number | null; hybrid: number | null }[] }) {
  const tip = useTip()
  const table = (
    <table className="t"><thead><tr><th>Row</th><th>Baseline</th><th>Hybrid</th></tr></thead>
      <tbody>{rows.map(r => <tr key={r.label}><td>{r.label} <span className="dim">{r.sub}</span></td><td className="num">{fmt(r.baseline)}</td><td className="num">{fmt(r.hybrid)}</td></tr>)}</tbody></table>
  )
  return (
    <TableToggle table={table}>
      <div className="viz stack" style={{ position: 'relative', gap: 12, marginTop: 8 }}>
        {rows.map(r => (
          <div key={r.label}>
            <div className="row between small"><span>{r.label} <span className="dim">{r.sub}</span></span></div>
            {SERIES.map(s => {
              const v = r[s.key]
              return (
                <div key={s.key} className="row" style={{ gap: 8, marginTop: 3 }} onMouseMove={e => tip.on(e, <>{r.label} · {s.label}: <b>{fmt(v)}</b></>)} onMouseLeave={tip.off}>
                  <div style={{ flex: 1, height: 8, background: 'var(--surface-3)', borderRadius: 4, overflow: 'hidden' }}>
                    <div style={{ width: `${(v ?? 0) * 100}%`, height: '100%', background: s.color, borderRadius: 4 }} />
                  </div>
                  <span className="num tiny muted" style={{ width: 44, textAlign: 'right' }}>{fmt(v)}</span>
                </div>
              )
            })}
          </div>
        ))}
        {tip.node}
      </div>
    </TableToggle>
  )
}
