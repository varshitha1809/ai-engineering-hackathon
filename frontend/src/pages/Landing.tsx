import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { ParticleField } from '../components/ParticleField'
import { IconArrow, IconShield } from '../components/icons'
import { get } from '../lib/api'
import { useReveal } from '../lib/hooks'
import './landing.css'

const SIGNATURES = [
  { idx: '1.0', title: 'Dual-audience forensics', hl: 'Human + AI-assistant view',
    body: 'Compares what a person sees with what an AI email assistant would read — hidden HTML, comments, zero-width tricks — while a trained classifier and identity, URL and attachment checks score the message.',
    to: '/app/analyze' },
  { idx: '2.0', title: 'Evidence-linked reconstruction', hl: 'Every claim cites a source',
    body: 'Sender claim → observed signals → tactics → requested action → possible objective. Observed facts and inferences are labelled separately, and thin evidence says “insufficient evidence”.',
    to: '/app/reconstruction' },
  { idx: '3.0', title: 'Campaign DNA correlation', hl: 'Shared indicators, not shared words',
    body: 'Links messages only through concrete evidence — the same URL, attachment hash, Reply-To, bank reference or near-duplicate body — and shows why on every edge.',
    to: '/app/campaigns' },
  { idx: '4.0', title: 'Adaptive robustness lab', hl: 'Measured, not claimed',
    body: 'Runs the real pipeline on a labelled benchmark with validated evasive variants, compares text-only baseline against the hybrid, and opens every miss and false alarm.',
    to: '/app/lab' },
]
const PIPELINE = [
  { idx: '1.0', t: 'Parse & normalise', d: 'Safe MIME parsing, header canonicalisation, URL & attachment inventory, Unicode-evasion map. Nothing is executed or fetched.' },
  { idx: '2.0', t: 'Trained text model', d: 'TF-IDF word + character n-grams with a linear SVM, trained on MeAJOR + Nazario and loaded from a hashed artifact.', featured: true },
  { idx: '3.0', t: 'Forensic rules', d: 'Identity, authentication, lookalike, BEC intent, URL, attachment and AI-injection detectors with source-linked evidence.' },
  { idx: '4.0', t: 'Risk fusion', d: 'Correlation-aware weighted fusion into a 0–100 policy risk score, explicit uncertainty and an impact-aware priority.' },
  { idx: '5.0', t: 'Investigate & correlate', d: 'Reconstruction graph, campaign clustering, analyst cases, local response actions and exportable reports.' },
]

export default function Landing() {
  const [active, setActive] = useState('home')
  const [metrics, setMetrics] = useState<{ f1?: number; recall?: number; fpr?: number; n?: number; ext?: number; p50?: number; version?: string } | null | 'unavailable'>(null)
  const sliderRef = useRef<HTMLDivElement | null>(null)
  const [slide, setSlide] = useState(0)
  const r1 = useReveal<HTMLDivElement>(), r2 = useReveal<HTMLDivElement>(), r3 = useReveal<HTMLDivElement>(), r4 = useReveal<HTMLDivElement>()

  useEffect(() => {
    get<any>('/model').then(m => {
      const e = m.evaluation?.evaluation_sets
      if (!e) return setMetrics('unavailable')
      setMetrics({ f1: e.combined_test?.f1, recall: e.combined_test?.recall, fpr: e.combined_test?.fpr, n: e.combined_test?.n,
        ext: e.spamassassin_external?.f1, p50: m.evaluation?.latency_ms_single_email?.p50, version: m.model?.model_version })
    }).catch(() => setMetrics('unavailable'))
  }, [])

  useEffect(() => {
    const ids = ['home', 'signatures', 'pipeline', 'start']
    const io = typeof IntersectionObserver !== 'undefined' ? new IntersectionObserver(es => {
      es.forEach(e => e.isIntersecting && setActive(e.target.id))
    }, { threshold: 0.45 }) : null
    ids.forEach(id => { const el = document.getElementById(id); if (el && io) io.observe(el) })
    return () => io?.disconnect()
  }, [])

  const go = (i: number) => {
    const el = sliderRef.current
    if (!el) return
    const n = Math.max(0, Math.min(SIGNATURES.length - 1, i))
    const card = el.children[n] as HTMLElement | undefined
    if (card) el.scrollTo({ left: card.offsetLeft - el.offsetLeft, behavior: 'smooth' })
    setSlide(n)
  }

  return (
    <div className="landing">
      <header className="l-top">
        <Link to="/" className="brand"><Logo /><b>PHISHDNA <span>AI</span></b></Link>
        <Link to="/app" className="btn primary">Launch dashboard</Link>
      </header>

      {/* ---------------------------------------------------------------- hero */}
      <section id="home" className="l-hero">
        <div className="l-hero-art"><ParticleField shape="helix" height={620} /></div>
        <div className="l-wrap l-hero-copy">
          <span className="eyebrow">AI-driven phishing &amp; social-engineering detection</span>
          <h1 className="display l-h1">Phishing,<br />decoded to<br />its DNA</h1>
        </div>
        <div className="l-wrap l-hero-foot">
          <a href="#signatures" className="l-scroll"><span aria-hidden>↓</span> Scroll to learn more</a>
          <p>PHISHDNA AI inspects what a person sees <em>and</em> what an AI assistant would read, explains every risk decision with
            linked evidence, connects related emails into campaigns, and measures its own robustness on reproducible tests.</p>
        </div>
      </section>

      {/* ---------------------------------------------------------------- signatures carousel */}
      <section id="signatures" className="l-section l-offer">
        <div className="l-glow" />
        <div className="l-wrap l-offer-grid reveal" ref={r1}>
          <div>
            <span className="eyebrow">Signature capabilities</span>
            <h2 className="display l-h2">Four <span className="fade">signatures</span></h2>
            <p className="l-keep"><span className="accent">→</span> Keep scrolling to learn more</p>
            <div className="row" style={{ marginTop: 26 }}>
              <button className="btn sm" onClick={() => go(slide - 1)} aria-label="Previous signature">←</button>
              <button className="btn sm" onClick={() => go(slide + 1)} aria-label="Next signature">→</button>
            </div>
          </div>
          <div>
            <div className="l-slider" ref={sliderRef} onScroll={e => {
              const el = e.currentTarget
              const w = (el.children[0] as HTMLElement | undefined)?.offsetWidth ?? 1
              setSlide(Math.round(el.scrollLeft / (w + 18)))
            }}>
              {SIGNATURES.map(s => (
                <Link to={s.to} key={s.idx} className="card l-sig noise">
                  <div className="row between"><Glyph idx={s.idx} /><span className="index-tag">{s.idx}</span></div>
                  <h3>{s.title}</h3>
                  <div className="l-hl">{s.hl}</div>
                  <p>{s.body}</p>
                  <span className="row small accent" style={{ gap: 8 }}>Open in app <span className="arrow-dot"><IconArrow /></span></span>
                </Link>
              ))}
            </div>
            <div className="l-pager" role="tablist" aria-label="Signature slides">
              {SIGNATURES.map((s, i) => <button key={s.idx} aria-label={`Show ${s.title}`} className={i === slide ? 'on' : ''} onClick={() => go(i)} />)}
            </div>
          </div>
        </div>
      </section>

      {/* ---------------------------------------------------------------- pipeline (featured-card grid) */}
      <section id="pipeline" className="l-section l-solutions">
        <div className="l-wrap reveal" ref={r2}>
          <h2 className="display l-h2 center">Evidence-driven<br />email <IconShield className="l-inline-icon" /> security</h2>
          <div className="l-cards">
            {PIPELINE.map(p => (
              <div key={p.idx} className={`card l-pcard ${p.featured ? 'featured noise' : ''}`}>
                <div className="row between"><span className="index-tag">{p.idx}</span><span className={`arrow-dot ${p.featured ? 'white' : ''}`}><IconArrow /></span></div>
                <h3>{p.t}</h3>
                <p className="small">{p.d}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ---------------------------------------------------------------- measured results */}
      <section className="l-section l-metrics">
        <div className="l-wrap reveal" ref={r3}>
          <span className="eyebrow">Measured, not claimed</span>
          <div className="l-metric-row">
            {metrics === null && <p className="muted">Loading the latest held-out evaluation…</p>}
            {metrics === 'unavailable' && <p className="muted">Evaluation results are unavailable — start the backend or run <code>python scripts/evaluate_model.py</code>.</p>}
            {metrics && metrics !== 'unavailable' && (<>
              <Metric v={fmtPct(metrics.f1)} l={`F1 on ${metrics.n?.toLocaleString()} held-out test emails`} />
              <Metric v={fmtPct(metrics.recall)} l="recall (malicious caught)" />
              <Metric v={fmtPct(metrics.fpr)} l="false-positive rate" />
              <Metric v={fmtPct(metrics.ext)} l="F1 on an unseen corpus (SpamAssassin) — shows domain shift" />
              <Metric v={metrics.p50 ? `${metrics.p50} ms` : '—'} l="median model latency" />
            </>)}
          </div>
          <p className="small dim">Text model only, measured by <code>scripts/evaluate_model.py</code> on the untouched test split ({metrics && metrics !== 'unavailable' ? metrics.version : 'model'}). Results apply to these datasets and do not prove protection against every real-world attack.</p>
        </div>
      </section>

      {/* ---------------------------------------------------------------- CTA */}
      <section id="start" className="l-section l-cta">
        <div className="l-cta-orb"><ParticleField shape="sphere" height={360} density={0.8} /></div>
        <div className="l-wrap reveal center" ref={r4}>
          <h2 className="display l-h2">Analyze an email<br />today <span className="accent">⌁</span></h2>
          <p className="muted" style={{ maxWidth: 520, margin: '14px auto 26px' }}>Paste a message or upload an .eml — get a verdict, linked evidence and an attack reconstruction in seconds. Runs fully local.</p>
          <Link to="/app/analyze" className="toggle-cta">Start an analysis <span className="knob" /></Link>
        </div>
      </section>

      {/* ---------------------------------------------------------------- footer */}
      <footer className="l-footer">
        <div className="l-wrap l-foot-grid">
          <div>
            <div className="l-foot-brand">PHISHDNA —</div>
            <div className="l-foot-sub">evidence-driven<br />email <IconShield className="l-inline-icon sm" /> security</div>
          </div>
          <div>
            <span className="eyebrow">Signatures</span>
            <ul>{SIGNATURES.map(s => <li key={s.idx}><Link to={s.to}>{s.title}</Link></li>)}</ul>
          </div>
          <div>
            <span className="eyebrow">Explore</span>
            <ul><li><Link to="/app">Dashboard</Link></li><li><Link to="/app/model">Dataset &amp; model</Link></li><li><Link to="/app/settings">System status</Link></li></ul>
          </div>
        </div>
        <div className="l-wrap l-foot-base"><span>PHISHDNA AI · hackathon build · local-first</span><span>Datasets: MeAJOR &amp; Phishing Email Curated Datasets (CC-BY-4.0)</span></div>
      </footer>

      {/* ---------------------------------------------------------------- floating pill nav */}
      <nav className="l-pillnav" aria-label="Page sections">
        {[['home', 'Home'], ['signatures', 'Signatures'], ['pipeline', 'Pipeline'], ['start', 'Get started']].map(([id, l]) => (
          <a key={id} href={`#${id}`} className={active === id ? 'on' : ''}>{active === id && <i className="dot" />}{l}{id === 'signatures' && <span className="accent"> ✛</span>}</a>
        ))}
        <Link to="/app" className="pill-app">App</Link>
      </nav>
    </div>
  )
}

const fmtPct = (v?: number) => (v === undefined || v === null ? '—' : `${(v * 100).toFixed(1)}%`)
const Metric = ({ v, l }: { v: string; l: string }) => <div className="l-metric"><div className="num">{v}</div><div className="small muted">{l}</div></div>

export function Logo({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 3l11 4.2v7.6C27 22 22.4 27 16 29 9.6 27 5 22 5 14.8V7.2z" fill="rgba(124,242,90,.08)" stroke="#7cf25a" strokeWidth="1.8" />
      <path d="M12 9.5c4 3 4 9.5 8 13M20 9.5c-4 3-4 9.5-8 13M12.6 12.6h6.8M12.6 19.4h6.8M13.6 16h4.8" stroke="#7cf25a" strokeWidth="1.5" fill="none" strokeLinecap="round" />
    </svg>
  )
}

function Glyph({ idx }: { idx: string }) {
  const paths: Record<string, string> = {
    '1.0': 'M4 7h16v11H4z M4 8l8 5 8-5 M17 3v3 M19 4.5h-4',
    '2.0': 'M5 5h4v4H5z M15 15h4v4h-4z M15 5h4v4h-4z M9 7h6 M17 9v6',
    '3.0': 'M6 6m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0 M18 6m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0 M12 18m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0 M7.5 7.5l3.5 8.5 M16.5 7.5L13 16 M8 6h8',
    '4.0': 'M9 3h6 M10 3v6L5 19h14l-5-10V3 M7.5 14h9',
  }
  return <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="1.4" strokeLinecap="round" aria-hidden><path d={paths[idx]} /></svg>
}
