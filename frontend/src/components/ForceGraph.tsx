import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type SimulationNodeDatum } from 'd3-force'
import { useEffect, useMemo, useState } from 'react'

export interface FGNode { id: string; label: string; color: string; ring?: string; size?: number; group?: string; dashed?: boolean; column?: number }
export interface FGEdge { id: string; source: string; target: string; width: number; color: string; dashed?: boolean; label?: string }
type SimNode = FGNode & SimulationNodeDatum

/** Static-after-settle force layout rendered as SVG. Nodes and edges are clickable/keyboard-focusable. */
export function ForceGraph({ nodes, edges, height = 460, onNode, onEdge, selected, columns }: {
  nodes: FGNode[]; edges: FGEdge[]; height?: number; selected?: string | null
  onNode?: (id: string) => void; onEdge?: (id: string) => void; columns?: number
}) {
  const W = 900
  const [pos, setPos] = useState<Record<string, { x: number; y: number }>>({})
  const key = useMemo(() => nodes.map(n => n.id).join('|') + '#' + edges.map(e => e.id).join('|'), [nodes, edges])

  useEffect(() => {
    const sim: SimNode[] = nodes.map(n => ({ ...n }))
    const links = edges.map(e => ({ source: e.source, target: e.target }))
    const s = forceSimulation(sim)
      .force('link', forceLink(links).id((d: any) => d.id).distance(columns ? 110 : 90).strength(columns ? 0.15 : 0.6))
      .force('charge', forceManyBody().strength(-260))
      .force('collide', forceCollide(34))
      .force('center', forceCenter(W / 2, height / 2))
      .force('y', forceY(height / 2).strength(0.06))
    if (columns) s.force('x', forceX((d: any) => 80 + ((d.column ?? 0) / Math.max(1, columns - 1)) * (W - 160)).strength(1))
    else s.force('x', forceX(W / 2).strength(0.04))
    s.stop()
    for (let i = 0; i < 320; i++) s.tick()
    const p: Record<string, { x: number; y: number }> = {}
    sim.forEach(n => { p[n.id] = { x: Math.max(30, Math.min(W - 30, n.x ?? 0)), y: Math.max(24, Math.min(height - 24, n.y ?? 0)) } })
    setPos(p)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, height, columns])

  return (
    <svg viewBox={`0 0 ${W} ${height}`} width="100%" role="img" aria-label="Relationship graph" style={{ display: 'block' }}>
      <defs>
        <radialGradient id="fg-glow"><stop offset="0" stopColor="rgba(124,242,90,.35)" /><stop offset="1" stopColor="rgba(124,242,90,0)" /></radialGradient>
      </defs>
      {edges.map(e => {
        const a = pos[e.source], b = pos[e.target]
        if (!a || !b) return null
        const active = selected === e.id
        return (
          <g key={e.id} style={{ cursor: onEdge ? 'pointer' : 'default' }} onClick={() => onEdge?.(e.id)} tabIndex={onEdge ? 0 : undefined}
            onKeyDown={ev => ev.key === 'Enter' && onEdge?.(e.id)} aria-label={e.label}>
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="transparent" strokeWidth={14} />
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={active ? 'var(--accent)' : e.color} strokeWidth={active ? e.width + 1.5 : e.width}
              strokeDasharray={e.dashed ? '5 5' : undefined} opacity={active ? 1 : 0.75}><title>{e.label}</title></line>
          </g>
        )
      })}
      {nodes.map(n => {
        const p = pos[n.id]
        if (!p) return null
        const r = n.size ?? 9
        const active = selected === n.id
        return (
          <g key={n.id} transform={`translate(${p.x},${p.y})`} style={{ cursor: onNode ? 'pointer' : 'default' }} onClick={() => onNode?.(n.id)}
            tabIndex={onNode ? 0 : undefined} onKeyDown={ev => ev.key === 'Enter' && onNode?.(n.id)} aria-label={n.label}>
            {active && <circle r={r + 16} fill="url(#fg-glow)" />}
            <circle r={r} fill={n.color} stroke={active ? 'var(--accent)' : n.ring ?? 'var(--bg)'} strokeWidth={2}
              strokeDasharray={n.dashed ? '3 3' : undefined} />
            <text y={r + 13} textAnchor="middle" fontSize="10.5" fill="var(--text-2)" style={{ pointerEvents: 'none' }}>
              {n.label.length > 26 ? n.label.slice(0, 25) + '…' : n.label}
            </text>
            <title>{n.label}</title>
          </g>
        )
      })}
    </svg>
  )
}
