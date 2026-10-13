import { useEffect, useRef } from 'react'

/** Green particle cloud in the style of the reference recording. Shape "helix" draws a rotating DNA double
 *  helix (PHISHDNA), "sphere" the glowing orb used by the closing CTA. Pauses off-screen; static under reduced motion. */
export function ParticleField({ shape = 'helix', height = 520, density = 1 }: { shape?: 'helix' | 'sphere'; height?: number; density?: number }) {
  const ref = useRef<HTMLCanvasElement | null>(null)
  useEffect(() => {
    const cv = ref.current
    if (!cv) return
    const ctx = cv.getContext('2d')
    if (!ctx) return
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    let w = 0, h = 0
    const resize = () => {
      w = cv.clientWidth; h = cv.clientHeight
      cv.width = w * dpr; cv.height = h * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    resize()
    const N = Math.round((shape === 'helix' ? 1500 : 1300) * density)
    const rnd = (a: number, b: number) => a + Math.random() * (b - a)
    const pts = Array.from({ length: N }, (_, i) => {
      if (shape === 'helix') {
        const strand = i % 3 // 0,1 strands, 2 rungs/halo
        return { t: rnd(0, 1), strand, j: rnd(-1, 1), k: rnd(-1, 1), s: rnd(0.4, 1.6), f: rnd(0, Math.PI * 2) }
      }
      const u = rnd(-1, 1), th = rnd(0, Math.PI * 2), rr = Math.cbrt(rnd(0.55, 1))
      return { t: u, strand: 0, j: th, k: rr, s: rnd(0.4, 1.5), f: rnd(0, Math.PI * 2) }
    })
    let raf = 0, visible = true
    const t0 = performance.now()
    const io = typeof IntersectionObserver !== 'undefined' ? new IntersectionObserver(([e]) => { visible = e.isIntersecting }) : null
    io?.observe(cv)
    const draw = (now: number) => {
      const time = reduce ? 0 : (now - t0) / 1000
      ctx.clearRect(0, 0, w, h)
      ctx.globalCompositeOperation = 'lighter'
      for (const p of pts) {
        let x: number, y: number, z: number
        if (shape === 'helix') {
          const L = Math.min(w * 0.95, 1100)
          const ang = p.t * Math.PI * 4.2 + time * 0.55
          const R = Math.min(h * 0.26, 120)
          const along = (p.t - 0.5) * L
          if (p.strand < 2) {
            const a = ang + (p.strand ? Math.PI : 0)
            x = along + p.j * 6; y = Math.sin(a) * R + p.k * 7; z = Math.cos(a)
          } else {
            const a = ang
            const mix = (Math.sin(p.f * 3) + 1) / 2 // rung between strands
            const y1 = Math.sin(a) * R, y2 = Math.sin(a + Math.PI) * R
            x = along + p.j * 22; y = y1 + (y2 - y1) * mix + p.k * 18; z = Math.cos(a) * (1 - 2 * mix)
          }
          // tilt the helix like the recording's diagonal cloud
          const rot = -0.32
          const X = x * Math.cos(rot) - y * Math.sin(rot), Y = x * Math.sin(rot) + y * Math.cos(rot)
          x = w * 0.58 + X; y = h * 0.5 + Y
        } else {
          const th = p.j + time * 0.25, phi = Math.acos(p.t)
          const R = Math.min(w, h) * 0.34 * p.k
          const sx = R * Math.sin(phi) * Math.cos(th), sz = R * Math.sin(phi) * Math.sin(th)
          x = w / 2 + sx; y = h / 2 + R * Math.cos(phi) * 0.98; z = sz / (R || 1)
        }
        const tw = 0.55 + 0.45 * Math.sin(time * 2 + p.f)
        const depth = (z + 1) / 2
        const a = (0.18 + 0.7 * depth) * tw
        const size = p.s * (0.6 + depth)
        ctx.fillStyle = depth > 0.75 && p.s > 1.3 ? `rgba(225,255,200,${a})` : `rgba(${90 + depth * 60},${200 + depth * 50},${60 + depth * 30},${a})`
        ctx.fillRect(x, y, size, size)
      }
      ctx.globalCompositeOperation = 'source-over'
      if (!reduce) raf = requestAnimationFrame(loop)
    }
    const loop = (now: number) => { if (visible) draw(now); else raf = requestAnimationFrame(loop) }
    raf = requestAnimationFrame(draw)
    window.addEventListener('resize', resize)
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize); io?.disconnect() }
  }, [shape, density])
  return <canvas ref={ref} aria-hidden="true" style={{ width: '100%', height, display: 'block' }} />
}
