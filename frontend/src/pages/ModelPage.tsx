import { CompareBars, Confusion, Legend2 } from '../components/charts'
import { ErrorState, Loading, PageHead, StatusPill } from '../components/ui'
import { get } from '../lib/api'
import { fmtDate, pct, useApi } from '../lib/hooks'

export default function ModelPage() {
  const m = useApi(() => get<any>('/model'), [])
  if (m.loading && !m.data) return <Loading what="Loading dataset and model workspace" />
  if (m.error) return <ErrorState error={m.error} retry={m.reload} />
  const d = m.data
  const mod = d.model
  const ev = d.evaluation
  const sets = ev?.evaluation_sets ?? {}
  const dp = d.dataset_profile
  return (
    <>
      <PageHead eyebrow="ML pipeline" title="Dataset & model workspace"
        desc="Acquisition → preprocessing & de-duplication → training → saved artifact → live inference. Every figure below is read from files written by the training and evaluation scripts." />
      <div className="grid g3">
        <div className="card">
          <div className="card-head"><h3>Loaded artifact</h3><StatusPill status={mod.status} /></div>
          {mod.status !== 'loaded' && <ErrorState error={mod.error || 'model not loaded'} />}
          <dl className="kv">
            <dt>Version</dt><dd className="mono tiny">{mod.model_version ?? '—'}</dd><dt>Classifier</dt><dd>{mod.classifier} (C={mod.C})</dd>
            <dt>Features</dt><dd className="small">{mod.features}</dd><dt>n features</dt><dd className="num">{mod.n_features?.toLocaleString()}</dd>
            <dt>Training pool</dt><dd>{mod.training_pool} · {mod.train_rows?.toLocaleString()} rows</dd>
            <dt>Threshold</dt><dd>{mod.decision_threshold} <span className="tiny dim">({mod.threshold_selection})</span></dd>
            <dt>Calibration</dt><dd className="small">{mod.calibration?.method}; val Brier {mod.calibration?.val_brier}, ECE {mod.calibration?.val_ece_10bin}</dd>
            <dt>SHA-256</dt><dd className="mono tiny" style={{ wordBreak: 'break-all' }}>{mod.artifact_sha256}</dd>
            <dt>Trained</dt><dd className="small">{fmtDate(mod.created_at)} · run {mod.run_id}</dd><dt>scikit-learn</dt><dd>{mod.sklearn_version}</dd>
          </dl>
        </div>
        <div className="card span2">
          <div className="card-head"><h3>Held-out test evaluation</h3><span className="tiny dim">{ev ? `${ev.run_id} · ${fmtDate(ev.created_at)}` : 'not run'}</span></div>
          {!ev ? <ErrorState error="No evaluation found - run python scripts/evaluate_model.py" /> : (<>
            <div className="table-wrap"><table className="t">
              <thead><tr><th>Evaluation set</th><th>n</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th>PR-AUC</th><th>ROC-AUC</th><th>Brier</th><th>ECE</th></tr></thead>
              <tbody>{Object.entries(sets).map(([k, v]: any) => v.status === 'unavailable' ? <tr key={k}><td>{k}</td><td colSpan={9}>unavailable</td></tr> : (
                <tr key={k}><td>{k}</td><td className="num">{v.n.toLocaleString()}</td><td className="num">{pct(v.precision)}</td><td className="num">{pct(v.recall)}</td><td className="num">{pct(v.f1)}</td><td className="num">{pct(v.fpr, 2)}</td><td className="num">{v.pr_auc ?? '—'}</td><td className="num">{v.roc_auc ?? '—'}</td><td className="num">{v.brier}</td><td className="num">{v.ece_10bin ?? '—'}</td></tr>))}</tbody></table></div>
            <div className="grid g3" style={{ marginTop: 14 }}>
              {sets.meajor_test?.confusion_matrix && <Confusion m={sets.meajor_test.confusion_matrix} title="MeAJOR test" />}
              {sets.nazario_5_test?.confusion_matrix && <Confusion m={sets.nazario_5_test.confusion_matrix} title="Nazario_5 test (phishing vs legitimate)" />}
              {sets.spamassassin_external?.confusion_matrix && <Confusion m={sets.spamassassin_external.confusion_matrix} title="SpamAssassin (unseen corpus, spam/ham)" />}
            </div>
            <div className="small muted" style={{ marginTop: 10 }}>Single-email latency: p50 {ev.latency_ms_single_email?.p50} ms · p95 {ev.latency_ms_single_email?.p95} ms (n={ev.latency_ms_single_email?.n}).</div>
            <ul className="tiny dim">{ev.notes?.map((n: string) => <li key={n}>{n}</li>)}</ul>
          </>)}
        </div>
      </div>

      {sets.meajor_test?.per_source && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-head"><h3>Per-source breakdown (MeAJOR test)</h3><span className="tiny dim">checks for source/time shift</span></div>
          <div className="table-wrap"><table className="t"><thead><tr><th>Source</th><th>n</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th></tr></thead>
            <tbody>{Object.entries(sets.meajor_test.per_source).map(([k, v]: any) => <tr key={k}><td>{k}</td><td className="num">{v.n}</td><td className="num">{pct(v.precision)}</td><td className="num">{pct(v.recall)}</td><td className="num">{pct(v.f1)}</td><td className="num">{pct(v.fpr, 2)}</td></tr>)}</tbody></table></div>
        </div>
      )}

      <div className="grid g2" style={{ marginTop: 16 }}>
        <div className="card">
          <div className="card-head"><h3>Model selection (validation only)</h3><Legend2 /></div>
          <p className="tiny dim" style={{ marginTop: 0 }}>Selection rule: {mod.selection_rule}. Bars compare candidates on the two validation sets (blue = MeAJOR val F1, green = Nazario_5 val F1).</p>
          <CompareBars groups={(d.candidates ?? []).map((c: any) => ({ label: `${c.pool === 'meajor_only' ? 'M' : 'M+N'} ${c.classifier === 'logreg' ? 'LR' : 'SVM'} C=${c.C}`, baseline: c.val.meajor.f1, hybrid: c.val.nazario_5.f1, note: `fit ${c.fit_seconds}s` }))} />
          <div className="tiny dim">M = MeAJOR only, M+N = MeAJOR + Nazario_5. Colours here reuse the two validated series slots.</div>
        </div>
        <div className="card">
          <div className="card-head"><h3>Datasets</h3></div>
          <dl className="kv">
            <dt>MeAJOR</dt><dd className="small">{dp.meajor?.rows?.toLocaleString()} rows ({dp.meajor_format}) · {dp.meajor?.license}<br /><span className="dim">{dp.meajor?.label_semantics}</span></dd>
            <dt>Sources</dt><dd className="small">{Object.entries(dp.meajor?.source_counts ?? {}).map(([k, v]) => `${k}: ${v}`).join(' · ')}</dd>
            <dt>Supplementary</dt><dd className="small">{Object.entries(dp.supplementary ?? {}).map(([k, v]: any) => <div key={k}><b>{k}</b> — {v.rows ?? '—'} rows, role <i>{v.role}</i>; {v.label_semantics}</div>)}</dd>
            <dt>De-duplication</dt><dd className="small">{dp.deduplication && `${dp.deduplication.exact_duplicate_rows} exact dup rows, ${dp.deduplication.near_duplicate_unions} near-dup unions (MinHash, Jaccard ≥ ${dp.deduplication.jaccard_threshold}); ${dp.deduplication.rows_before_collapse} → ${dp.deduplication.rows_after_collapse} rows; ${dp.deduplication.label_conflict_rows_dropped} label-conflict rows dropped`}</dd>
            <dt>Cross-overlap</dt><dd className="small">{Object.entries(dp.cross_dataset_overlap ?? {}).map(([k, v]: any) => `${k}: ${v.exact_overlap_with_meajor} exact with MeAJOR`).join(' · ')}</dd>
            <dt>Splits</dt><dd className="small">group-aware stratified 70/15/15, seed {dp.seed}; duplicate groups never cross splits</dd>
          </dl>
        </div>
      </div>

      <div className="grid g2" style={{ marginTop: 16 }}>
        <div className="card">
          <div className="card-head"><h3>Download manifest</h3></div>
          <div className="table-wrap"><table className="t"><thead><tr><th>File</th><th>Status</th><th>Bytes</th><th>MD5 verified</th></tr></thead>
            <tbody>{(d.download_manifest ?? []).map((x: any, i: number) => <tr key={i}><td className="small">{x.name}</td><td><StatusPill status={x.status === 'cached' ? 'ok' : x.status} /></td><td className="num tiny">{x.bytes?.toLocaleString() ?? '—'}</td><td className="small">{x.md5_verified ? 'yes' : x.error ?? '—'}</td></tr>)}</tbody></table></div>
        </div>
        <div className="card">
          <div className="card-head"><h3>What is ML vs rules</h3></div>
          <div className="small"><b>Trained model:</b> {d.feature_usage.ml_trained.join('; ')}</div>
          <div className="small" style={{ marginTop: 6 }}><b>Deterministic rules:</b> {d.feature_usage.deterministic_rules.join(' · ')}</div>
          <div className="small" style={{ marginTop: 6, color: 'var(--warning)' }}>{d.feature_usage.not_trained_on}</div>
          <div className="small muted" style={{ marginTop: 12 }}>Reproduce:</div>
          <pre className="source-view" style={{ maxHeight: 180 }}>{Object.values(d.commands).join('\n')}</pre>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-head"><h3>Training runs</h3></div>
        <div className="table-wrap"><table className="t"><thead><tr><th>Run</th><th>Created</th><th>Model</th><th>Pool</th><th>Threshold</th><th>Mode</th></tr></thead>
          <tbody>{(d.training_runs ?? []).slice().reverse().map((r: any) => <tr key={r.run_id}><td className="mono tiny">{r.run_id}</td><td className="tiny">{fmtDate(r.created_at)}</td><td className="small">{r.classifier} C={r.C}</td><td className="small">{r.training_pool}</td><td className="num">{r.decision_threshold}</td><td className="small">{r.quick_mode ? 'quick' : 'full'}</td></tr>)}</tbody></table></div>
      </div>
    </>
  )
}
