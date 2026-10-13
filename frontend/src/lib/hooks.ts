import { useCallback, useEffect, useRef, useState } from 'react'

export interface Loadable<T> { data: T | null; error: string | null; loading: boolean; reload: () => void }

/** Fetch on mount / when deps change; exposes loading, error and reload. */
export function useApi<T>(fn: () => Promise<T>, deps: unknown[] = [], pollMs?: number | ((d: T | null) => number | null)): Loadable<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)
  const fnRef = useRef(fn)
  fnRef.current = fn
  const reload = useCallback(() => setTick(t => t + 1), [])

  useEffect(() => {
    let alive = true
    setLoading(true)
    fnRef.current()
      .then(d => { if (alive) { setData(d); setError(null) } })
      .catch(e => { if (alive) setError(e instanceof Error ? e.message : String(e)) })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])

  useEffect(() => {
    const ms = typeof pollMs === 'function' ? pollMs(data) : pollMs
    if (!ms) return
    const t = setTimeout(() => setTick(x => x + 1), ms)
    return () => clearTimeout(t)
  }, [data, pollMs])

  return { data, error, loading, reload }
}

/** Adds the `in` class when an element scrolls into view (landing-page reveal animation). */
export function useReveal<T extends HTMLElement>() {
  const ref = useRef<T | null>(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (typeof IntersectionObserver === 'undefined') { el.classList.add('in'); return }
    const io = new IntersectionObserver(es => es.forEach(e => e.isIntersecting && e.target.classList.add('in')), { threshold: 0.12 })
    io.observe(el)
    return () => io.disconnect()
  }, [])
  return ref
}

export const fmtDate = (s?: string | null) => (s ? new Date(s).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—')
export const pct = (v?: number | null, d = 1) => (v === null || v === undefined ? '—' : `${(v * 100).toFixed(d)}%`)
export const human = (s: string) => s.replace(/_/g, ' ')
