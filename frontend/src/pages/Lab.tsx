import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { CompareBars, Confusion, HeatMatrix, Legend2, PairedRows } from '../components/charts'
import { IconPlay } from '../components/icons'
import { Empty, ErrorState, Loading, PageHead, StatusPill, Tabs, VerdictBadge } from '../components/ui'
import { get, post, type EvalRun, type Metrics, type Verdict } from '../lib/api'
import { fmtDate, human, pct, useApi } from '../lib/hooks'

export default function Lab() {
  const { runId } = useParams()
  const nav = useNavigate()
  const [suite, setSuite] = useState('fixtures')
  const [variants, setVariants] = useState(true)
  const [splits, setSplits] = useState<string[]>(['dev', 'holdout'])
  const [sample, setSample] = useState(600)
  const [starting, setStarting] = useState(false)
  const [startErr, setStartErr] = useState<string | null>(null)
  const runs = useApi(() => get<EvalRun[]>('/evaluations'), [], d => (d?.some(r => r.status === 'running' || r.status === 'queued') ? 1500 : null))
  const activeId = runId ?? runs.data?.find(r => r.status === 'completed')?.id
  const run = useApi(() => (activeId ? get<EvalRun>(`/evaluations/${activeId}`) : Promise.resolve(null)), [activeId],
    d => (d && (d.status === 'running' || d.status === 'queued') ? 1200 : null))

  const start = async () => {
    setStarting(true); setStartErr(null)
    try {
      const r = await post<{ id: string }>('/evaluations/run', { suite, variants, splits, dataset_sample: sample })
      nav(`/app/lab/${r.id}`); runs.reload()
    } catch (e) { setStartErr((e as Error).message) } finally { setStarting(false) }
  }
  const running = runs.data?.some(r => r.status === 'running' || r.status === 'queued')
  return (
    <>
      <PageHead eyebrow="Signature 4 · robustness lab" title="Adaptive robustness lab"
        desc="Runs the real pipeline on a fixed labelled benchmark and on validated, sanitised variants, and compares the text-only baseline with the hybrid on identical inputs. Results apply to this benchmark only." />
      <div className="grid g3">
        <div className="card stack">
          <h3>Run a benchmark</h3>
          <label className="field">Suite
            <select className="input" value={suite} onChange={e => setSuite(e.target.value)}>
              <option value="fixtures">Forensic fixtures (synthetic, headers/HTML/attachments)</option>
              <option value="dataset_holdout">ML held-out sample (MeAJOR/Nazario test split, body text)</option>
            </select></label>
          {suite === 'fixtures' ? (<>
            <label className="row small"><input type="checkbox" checked={variants} onChange={e => setVariants(e.target.checked)} /> include validated variants (case/punctuation, zero-width, homoglyph, word-split, paraphrase, HTML visibility, polished rewrite)</label>
            <div className="row small">Splits:
              {['dev', 'holdout'].map(s => <label key={s} className="row" style={{ gap: 4 }}><input type="checkbox" checked={splits.includes(s)} onChange={e => setSplits(e.target.checked ? [...splits, s] : splits.filter(x => x !== s))} />{s}</label>)}
            </div>
          </>) : (
            <label className="field">Sample size (stratified)<input className="input" type="number" min={50} max={5000} value={sample} onChange={e => setSample(Number(e.target.value))} /></label>
          )}
          <button className="btn primary" onClick={start} disabled={starting || running || (suite === 'fixtures' && splits.length === 0)}>
            {starting ? <span className="spinner" /> : <IconPlay width={14} />} {running ? 'A run is in progress…' : 'Run benchmark'}</button>
          {startErr && <ErrorState error={startErr} />}
        </div>
        <div className="card span2">
          <div className="card-head"><h3>Run history</h3></div>
          {runs.loading && !runs.data ? <Loading /> : runs.error ? <ErrorState error={runs.error} retry={runs.reload} /> : runs.data!.length === 0 ? <Empty title="No runs yet">Start one on the left.</Empty> : (
            <div className="table-wrap" style={{ maxHeight: 260, overflow: 'auto' }}><table className="t">
              <thead><tr><th>Run</th><th>Suite</th><th>Status</th><th>Items</th><th>Hybrid F1</th><th>Baseline F1</th><th>Started</th></tr></thead>
              <tbody>{runs.data!.map(r => (
                <tr key={r.id} className="clickable" onClick={() => nav(`/app/lab/${r.id}`)} style={r.id === activeId ? { background: 'var(--accent-soft)' } : undefined}>
                  <td className="mono tiny">{r.id}</td><td className="small">{r.suite}{r.params_json?.variants === false ? ' (no variants)' : ''}</td><td><StatusPill status={r.status} /></td>
                  <td className="num">{r.progress}/{r.total}</td><td className="num">{pct(r.summary?.overall?.hybrid?.f1)}</td><td className="num">{pct(r.summary?.overall?.baseline?.f1)}</td>
                  <td className="tiny">{fmtDate(r.started_at)}</td></tr>))}</tbody></table></div>
          )}
        </div>
      </div>
      <div style={{ marginTop: 18 }}>
        {!activeId ? null : run.loading && !run.data ? <Loading what="Loading run" /> : run.error ? <ErrorState error={run.error} retry={run.reload} /> : run.data && <RunView r={run.data} />}
      </div>
      <Replay />
    </>
  )
}

function RunView({ r }: { r: EvalRun }) {
  const [tab, setTab] = useState('summary')
  if (r.status === 'running' || r.status === 'queued') {
    const p = r.total ? r.progress / r.total : 0
    return <div className="card"><div className="row between"><b>Running {r.id}</b><span className="num small">{r.progress}/{r.total || '…'} items</span></div>
      <div className="progress" style={{ marginTop: 10 }} role="progressbar" aria-valuenow={Math.round(p * 100)}><i style={{ width: `${p * 100}%` }} /></div>
      <p className="tiny dim">Each item is parsed and analysed by the real pipeline (model + all rule layers); nothing is pre-computed.</p></div>
  }
  if (r.status === 'failed') return <ErrorState error={r.error ?? 'run failed'} />
  const m = r.metrics_json
  const o = m.overall as { baseline: Metrics | null; hybrid: Metrics }
  const split = m.by_split?.holdout ? 'holdout' : Object.keys(m.by_split ?? {})[0]
  const prim = (split ? m.by_split[split] : o) as { baseline: Metrics | null; hybrid: Metrics }
  const g = (b: Metrics | null, h: Metrics) => [
    { label: 'Precision', baseline: b?.precision ?? null, hybrid: h.precision }, { label: 'Recall', baseline: b?.recall ?? null, hybrid: h.recall },
    { label: 'F1', baseline: b?.f1 ?? null, hybrid: h.f1 }, { label: 'False-positive rate', baseline: b?.fpr ?? null, hybrid: h.fpr, note: 'lower is better' },
    ...(h.pr_auc !== undefined ? [{ label: 'PR-AUC', baseline: b?.pr_auc ?? null, hybrid: h.pr_auc ?? null, note: 'baseline: model score · hybrid: risk score/100' }] : []),
  ]
  return (
    <div className="stack">
      <div className="card">
        <div className="row between">
          <div><b>{r.id}</b> <span className="dim small">· {r.suite} · {m.counts.items} items ({m.counts.base_cases} base, {m.counts.variants} variants) · model {r.model_version} · {r.rules_version} · {r.fusion_version}</span></div>
          <span className="label-tag">{m.data_label}</span>
        </div>
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[{ id: 'summary', label: 'Baseline vs hybrid' }, { id: 'categories', label: 'Categories & variants' },
        { id: 'ablation', label: 'Ablation & coverage' }, { id: 'failures', label: `Failures (${m.failures.hybrid_false_negatives.length + m.failures.hybrid_false_positives.length})` }, { id: 'limits', label: 'Limitations' }]} />
      {tab === 'summary' && (
        <div className="grid g2">
          <div className="card">
            <div className="card-head"><h3>{split ? `${split} split` : 'All items'} — primary result</h3><Legend2 /></div>
            <CompareBars groups={g(prim.baseline, prim.hybrid)} />
            <div className="tiny dim">n = {prim.hybrid.n} labelled items ({prim.hybrid.positives} malicious). Flag = {m.flag_definition.join(' | ')}. Baseline = trained text model ≥ {m.threshold_text_model.toFixed(3)}.</div>
          </div>
          <div className="card stack">
            <div className="grid g2">
              {prim.baseline && <Confusion m={prim.baseline} title="Baseline (text model)" />}
              <Confusion m={prim.hybrid} title="Hybrid pipeline" />
            </div>
            <div className="table-wrap"><table className="t"><thead><tr><th>Subset</th><th>n</th><th>Baseline F1</th><th>Hybrid F1</th><th>Hybrid FPR</th></tr></thead>
              <tbody>{[['all items', o], ...Object.entries(m.by_split ?? {}), ['originals only', m.originals_only], ...(m.variants_only ? [['variants only', m.variants_only]] : [])].map(([k, v]: any) => (
                <tr key={k}><td>{k}</td><td className="num">{v.hybrid.n}</td><td className="num">{pct(v.baseline?.f1)}</td><td className="num">{pct(v.hybrid.f1)}</td><td className="num">{pct(v.hybrid.fpr)}</td></tr>))}</tbody></table></div>
            <div className="small muted">Latency: hybrid p50 {m.latency_ms.hybrid_p50} ms / p95 {m.latency_ms.hybrid_p95} ms · model p50 {m.latency_ms.model_p50 ?? '—'} ms / p95 {m.latency_ms.model_p95 ?? '—'} ms</div>
          </div>
          {m.disagreements.baseline_missed_hybrid_caught.length > 0 && (
            <div className="card span2">
              <div className="card-head"><h3>Missed by the baseline, caught by an additional signal</h3><span className="tiny dim">{m.disagreements.baseline_missed_hybrid_caught.length} item(s) in this run</span></div>
              <FailureList items={m.disagreements.baseline_missed_hybrid_caught.slice(0, 6)} runId={r.id} />
            </div>)}
        </div>
      )}
      {tab === 'categories' && (
        <div className="grid g2">
          <div className="card"><div className="card-head"><h3>Per category</h3><Legend2 /></div>
            <PairedRows rows={Object.entries(m.per_category).map(([k, v]: any) => ({ label: human(k), sub: `${v.metric} · n=${v.n}`, baseline: v.baseline_flag_rate, hybrid: v.hybrid_flag_rate }))} />
            <div className="tiny dim" style={{ marginTop: 8 }}>For malicious categories the bar is recall; for legitimate mail it is the false-positive rate (lower is better).</div></div>
          <div className="card"><div className="card-head"><h3>Per transformation (robustness)</h3></div>
            <div className="table-wrap"><table className="t"><thead><tr><th>Variant</th><th>n</th><th>Baseline recall</th><th>Hybrid recall</th><th>Baseline FPR</th><th>Hybrid FPR</th></tr></thead>
              <tbody>{Object.entries(m.per_transform).map(([k, v]: any) => <tr key={k}><td>{human(k)}</td><td className="num">{v.n}</td><td className="num">{pct(v.baseline_recall)}</td><td className="num">{pct(v.hybrid_recall)}</td><td className="num">{pct(v.baseline_fpr)}</td><td className="num">{pct(v.hybrid_fpr)}</td></tr>)}</tbody></table></div>
            {m.dropped_variants?.length > 0 && <div className="tiny dim">{m.dropped_variants.length} variant(s) failed label validation and were dropped.</div>}
            {m.unlabelled_ambiguous?.n > 0 && <div className="small" style={{ marginTop: 10 }}>Ambiguous (unlabelled) items: {Object.entries(m.unlabelled_ambiguous.verdicts).map(([k, v]) => `${v} ${k}`).join(', ')} — not forced into metrics.</div>}
          </div>
        </div>
      )}
      {tab === 'ablation' && (
        <div className="grid g2">
          <div className="card"><div className="card-head"><h3>Ablation — remove one layer</h3><span className="tiny dim">policy re-applied to stored layer outputs</span></div>
            <div className="table-wrap"><table className="t"><thead><tr><th>Configuration</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th>FN</th><th>FP</th></tr></thead>
              <tbody>{Object.entries(m.ablation).map(([k, v]: any) => <tr key={k} style={k === 'full hybrid' ? { background: 'var(--accent-soft)' } : undefined}><td>{k}</td><td className="num">{pct(v.precision)}</td><td className="num">{pct(v.recall)}</td><td className="num">{pct(v.f1)}</td><td className="num">{pct(v.fpr)}</td><td className="num">{v.fn}</td><td className="num">{v.fp}</td></tr>)}</tbody></table></div></div>
          <div className="card"><div className="card-head"><h3>Attack-coverage matrix</h3></div>
            <p className="tiny dim" style={{ marginTop: 0 }}>{m.coverage_matrix.definition}</p>
            <HeatMatrix rows={Object.keys(m.coverage_matrix.rows)} cols={Object.keys(Object.values(m.coverage_matrix.rows)[0] as object)} value={(rw, c) => m.coverage_matrix.rows[rw][c]} /></div>
        </div>
      )}
      {tab === 'failures' && (
        <div className="grid g2">
          <div className="card"><div className="card-head"><h3>Missed attacks (hybrid false negatives)</h3><span className="tiny dim">baseline FN: {m.failures.baseline_false_negatives}</span></div>
            {m.failures.hybrid_false_negatives.length ? <FailureList items={m.failures.hybrid_false_negatives} runId={r.id} /> : <Empty title="No missed attacks in this run">Every labelled malicious item was flagged by the hybrid pipeline on this benchmark.</Empty>}</div>
          <div className="card"><div className="card-head"><h3>False alarms (hybrid false positives)</h3><span className="tiny dim">baseline FP: {m.failures.baseline_false_positives}</span></div>
            {m.failures.hybrid_false_positives.length ? <FailureList items={m.failures.hybrid_false_positives} runId={r.id} /> : <Empty title="No false alarms in this run" />}</div>
        </div>
      )}
      {tab === 'limits' && (
        <div className="card">
          <h3>Limitations of this run</h3>
          <ul className="small">{(m.limitations ?? []).map((l: string) => <li key={l}>{l}</li>)}
            <li>Metrics are computed from the predictions stored for this run ({r.id}); no value is entered by hand.</li>
            <li>Passing this benchmark does not prove protection against all real-world phishing.</li></ul>
        </div>
      )}
    </div>
  )
}

function FailureList({ items, runId }: { items: any[]; runId: string }) {
  const [open, setOpen] = useState<string | null>(null)
  return (
    <div className="stack">
      {items.map(f => (
        <div key={f.item_id} className="finding" onClick={() => setOpen(open === f.item_id ? null : f.item_id)}>
          <div className="row between"><b className="small">{f.item_id}</b><span className="row" style={{ gap: 6 }}><VerdictBadge verdict={f.hybrid_verdict as Verdict} /><span className="pill">risk {f.hybrid_score}</span></span></div>
          <div className="tiny dim">{human(f.category)} · {human(f.transform)} · label {f.label === 1 ? 'malicious' : 'benign'} · baseline score {f.baseline_score?.toFixed(3) ?? '—'} · {f.subject}</div>
          {open === f.item_id && <ItemDetail runId={runId} itemId={f.item_id} explanation={f.explanation} />}
        </div>
      ))}
    </div>
  )
}

function ItemDetail({ runId, itemId, explanation }: { runId: string; itemId: string; explanation: string }) {
  const it = useApi(() => get<any>(`/evaluations/${runId}/items/${encodeURIComponent(itemId)}`), [runId, itemId])
  if (it.loading) return <Loading />
  if (it.error) return <ErrorState error={it.error} />
  const d = it.data.detail_json
  return (
    <div style={{ marginTop: 8 }} onClick={e => e.stopPropagation()}>
      <p className="small">{explanation}</p>
      <div className="small muted">Decision: {d.decision_reasons.join('; ')}</div>
      <div className="small muted">Variant validation: {d.validation}</div>
      {it.data.base_case_notes && <div className="small muted">Case note: {it.data.base_case_notes}</div>}
      <div className="stack" style={{ marginTop: 6 }}>{d.top_findings.map((f: any) => <div key={f.finding_id} className="tiny"><b>{f.finding_id}</b> {f.title} <span className="dim">({f.component}, {f.status}, {f.confidence})</span> <span className="mono dim">{f.observed_value.slice(0, 120)}</span></div>)}</div>
      <div className="tiny dim">Versions: model/rules/fusion as recorded on the run.</div>
    </div>
  )
}

function Replay() {
  const [likely, setLikely] = useState(65)
  const [review, setReview] = useState(35)
  const [disabled, setDisabled] = useState<string[]>([])
  const [mode, setMode] = useState('policy')
  const [res, setRes] = useState<any>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const go = async () => {
    setBusy(true); setErr(null)
    try { setRes(await post('/replay', { mode, likely_threshold: likely, review_threshold: review, disabled_layers: disabled })) } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }
  const layers = ['text_model', 'intent', 'identity', 'url', 'attachment', 'evasion', 'context', 'ai_injection', 'reputation']
  return (
    <div className="card" style={{ marginTop: 18 }}>
      <div className="card-head"><h3>Decision replay (shadow mode)</h3><span className="tiny dim">applies to retained analyses; stored verdicts are not modified</span></div>
      <div className="row">
        <select className="input" style={{ maxWidth: 300 }} value={mode} onChange={e => setMode(e.target.value)} aria-label="Replay mode">
          <option value="policy">Policy what-if (stored layer outputs)</option><option value="reanalyze">Re-run current model + rules on retained raw content</option>
        </select>
        {mode === 'policy' && <>
          <label className="row small">Likely ≥ <input className="input" type="number" style={{ width: 80 }} value={likely} onChange={e => setLikely(Number(e.target.value))} /></label>
          <label className="row small">Review ≥ <input className="input" type="number" style={{ width: 80 }} value={review} onChange={e => setReview(Number(e.target.value))} /></label>
        </>}
        <button className="btn primary" onClick={go} disabled={busy}>{busy ? <span className="spinner" /> : null}Replay</button>
      </div>
      {mode === 'policy' && <div className="row small" style={{ marginTop: 8 }}>Disable layers: {layers.map(l => <label key={l} className="row" style={{ gap: 4 }}><input type="checkbox" checked={disabled.includes(l)} onChange={e => setDisabled(e.target.checked ? [...disabled, l] : disabled.filter(x => x !== l))} />{human(l)}</label>)}</div>}
      {err && <ErrorState error={err} />}
      {res && (
        <div style={{ marginTop: 12 }}>
          <div className="small">{res.evaluated} analyses evaluated · <b>{res.changed.length} decision(s) would change</b> · {res.unchanged} unchanged{res.skipped_no_data ? ` · ${res.skipped_no_data} skipped (no retained data)` : ''}</div>
          {res.changed.length > 0 && <div className="table-wrap" style={{ marginTop: 8 }}><table className="t"><thead><tr><th>Analysis</th><th>Before</th><th>After</th></tr></thead>
            <tbody>{res.changed.map((c: any) => <tr key={c.id}><td><Link to={`/app/analyses/${c.id}`}>{c.subject || c.id}</Link></td><td className="small">{c.before.verdict} ({c.before.risk_score})</td><td className="small">{c.after.verdict} ({c.after.risk_score})</td></tr>)}</tbody></table></div>}
        </div>
      )}
    </div>
  )
}
