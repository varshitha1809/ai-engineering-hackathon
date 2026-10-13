# PHISHDNA AI — Implementation Log

This log records what was actually done, the commands run and the results observed.
Nothing in this file is aspirational: an item is checked only after it was run/verified.

## 0. Reference inspection (Phase 1)

| Reference | How it was inspected | Key takeaways |
|---|---|---|
| `PHISHDNA_AI_Refined_Claude_Implementation_Spec.docx` | Full `word/document.xml` text extracted with Python `zipfile` (546 paragraphs incl. tables) | 4 signature capabilities, feature inventory §4.1–4.6, ML procedure §5, verdict policy §6.2, evidence schema §6.4, API contract §8.1, data model §8.2, tests §10.1, gates G1–G7, DoD §12.1 |
| `WhatsApp Video 2026-10-12 at 11.41.43 PM.mp4` (20.6 s, 1920×1080) | 24 frames extracted with OpenCV, contact sheets + full-res crops | Near-black canvas with deep green radial glows; large light-weight grotesk display type; `[ OUR SERVICES ]` bracketed green mono eyebrows; green particle-cloud graphics; glassy dark-green cards with `[ 1.0 ]` indices and round green arrow buttons; bright "featured" noisy green card; horizontal card carousel with pill pager; floating pill bottom nav (`• Home  Services  Product  About us`); "Contact us Today" particle sphere with toggle-pill CTA; footer with large gradient wordmark |
| `WhatsApp Image 2026-10-12 at 11.43.39 PM.jpeg` (architecture) | Viewed directly | 6 layers: React+TS frontend (public landing + analyst app) → FastAPI backend (API layer, Email Processing, Analysis Engine, Threat Intelligence, Investigation Services, Evaluation & Monitoring) → scikit-learn pipeline (acquire → preprocess/dedupe → TF-IDF+LR → artifacts → live inference) → SQLite/Postgres (emails & analyses, indicators & campaigns, investigation history, model artifacts & results) → optional external TI with graceful local fallback → 4 signature features |

Workspace at start: only the three reference files; no existing code, no git repo.
Environment: Windows 11, Python 3.11.9 (scikit-learn 1.9.1, pandas 3.0.2, FastAPI 0.116.1), Node 24.15 / npm 11.12, 12 cores, 15.7 GB RAM. No ffmpeg (OpenCV used instead).

## Phase checklist

- [x] Phase 1 — Inspection, requirements checklist, repository layout
- [x] Phase 2 — Dataset acquisition, profiling, preprocessing, training, evaluation
- [x] Phase 3 — Backend: parsing, detectors, ML inference, risk fusion, persistence
- [x] Phase 4 — Attack reconstruction & evidence provenance
- [x] Phase 5 — Campaign intelligence, IOC store, cases & feedback
- [x] Phase 6 — Robustness lab
- [x] Phase 7 — Frontend (video-matched landing + analyst application)
- [x] Phase 8 — Tests, end-to-end verification, production build, docs

## Progress entries

### Phase 2 — ML pipeline
* `python scripts/download_datasets.py --supplementary` → MeAJOR parquet 86,278,230 B (MD5 ok, 108,685×20), CEAS_08, Enron,
  Nazario, Nazario_5, SpamAssassin — all MD5-verified against Zenodo's published checksums. Licences: CC-BY-4.0 (API metadata).
* Finding: the MeAJOR file contains only TREC-05/06/07 rows (label 1 = TREC spam). Nazario_5 added for genuine phishing labels.
* `python scripts/preprocess_dataset.py` → 111,712 → 99,057 rows (5,032 exact dups, 7,643 near-dup unions, 20 conflict rows dropped).
* `python scripts/train_model.py` → 8 candidates; selected LinearSVC C=0.5 on MeAJOR+Nazario_5 (val mean F1 0.9806),
  sigmoid-calibrated, threshold 0.5211, artifact 10.4 MB, sha256 e1a96bef….
* `python scripts/evaluate_model.py` → MeAJOR test F1 0.9838 / FPR 1.29%; Nazario_5 test F1 0.9749; SpamAssassin external F1 0.880 / FPR 5.63%.

### Phases 3–6 — backend, reconstruction, campaigns, lab
Files: `backend/app/{config,db,state,security,main}.py`, `email_processing/*`, `analysis/{evidence,context,fusion,model}.py`,
`analysis/detectors/*`, `threat_intel/providers.py`, `investigation/reconstruction.py`,
`services/{engine,campaigns,indicators,audit}.py`, `evaluation/{benchmark,variants}.py`,
`api/{analysis,cases,intel,evaluations,system,demo}.py`; `scripts/build_benchmark.py`, `scripts/build_demo_fixtures.py`.

Issues found and fixed during development (using dev data only):
* Homoglyph detector flagged digit-only tokens (empty script set) — fixed; regression test `test_digits_are_not_homoglyphs`.
* Freemail → different-freemail Reply-To was under-weighted (0.5 → 0.6).
* Dev benchmark misses: org domain used as a sender subdomain was not detected; "sign in to view" was not recognised — two general rules added.
* Paraphrase variants with no table term were wrongly reported as "validation failed" — now "not applicable".
* Campaign labels kept a stale member count; low-and-slow definition changed to "most members below 65, spanning ≥ 1 day";
  malicious `domain` IOCs now also match sender/Reply-To domains.
* Policy change after the **dev** run (before any holdout run): uncorroborated text-model evidence below the existing 0.85
  strong-score constant no longer routes to review (dev FPR 0.24 → 0.12, dev recall unchanged at 1.0).
* The test suite found evidence excerpts leaking full bank-account numbers → excerpts now mask account numbers/IBANs.

### Phase 7 — frontend
React 19 + TypeScript + Vite 6, react-router 7.18.4, d3-force, self-hosted Inter Tight + JetBrains Mono. `npm audit`: 0 vulnerabilities
(react-router upgraded from 6.30 and vitest to 5.0.4 to clear advisories). Chart colours validated with the dataviz validator
(baseline #5b8def / hybrid #45ab30 on the dark surface; all checks pass). Eleven app pages plus the landing page.

### Phase 8 — verification (actual results)
* `python -m pytest backend/tests -q` → **67 passed**.
* `cd frontend && npm test` → **8 passed**; `npx tsc -b` → no errors; `npx eslint src` → 0 errors, 2 fast-refresh warnings;
  `npm run build` → success (JS 430 kB / 130 kB gzip).
* Live server on a fresh DB, journey over HTTP: pasted vendor bank-change BEC → LIKELY_PHISHING 85.2 with 3 verification steps;
  hidden-instruction .eml → AI_INJECTION_SUSPECTED; sample-set import → 5 evidence-backed clusters (shared URL, shared Reply-To
  [low-and-slow], same impersonated CEO profile, shared attachment hash, near-duplicate pair); fixtures benchmark
  EVAL-261013-041713-7945 (308 items) holdout hybrid F1 0.982 vs baseline 0.648; ML sample benchmark EVAL-261013-041727-2540
  hybrid F1 0.969 vs baseline 0.977; case report → in_review + IOC review queue; Markdown report exported
  (`data/reports/sample_analyst_report.md`).
* Headless-Chrome screenshots at 1440 px of landing, overview, forensics, evidence, reconstruction, campaign, lab and model pages
  were reviewed. Mobile: narrow-screen CSS fixes applied, but headless Chrome on Windows would not render below ~500 px, so the
  390 px phone layout is **not visually verified**.

## Final requirement checklist (DOCX §1–12 + architecture image)

Legend: ✅ implemented and tested · 🟡 partially implemented (explanation) · ❌ not implemented (blocker)

| # | Requirement | Status | Evidence / note |
|---|---|---|---|
| 1 | Real dataset download, MD5, manifest, CSV fallback path | ✅ | `download_datasets.py`; fallback coded but not exercised (Parquet succeeded) |
| 2 | Schema/label/licence/provenance/overlap review, profile JSON | ✅ | `dataset_profile.json`, ML_PIPELINE §1 |
| 3 | Exact + near-dup dedupe, group-aware split, seeds | ✅ | duplicate groups never cross splits |
| 4 | TF-IDF + LR / linear SVM, validation selection, saved full pipeline | ✅ | `train_model.py`, svm.md, artifact + sha |
| 5 | Backend loads artifact; tamper/missing handling | ✅ | `test_ml_fusion.py` |
| 6 | Held-out P/R/F1/FPR/CM/per-class/PR-AUC/calibration/latency | ✅ | `models/evaluation_latest.json` |
| 7 | Hybrid vs text-only on identical held-out samples | ✅ | robustness lab (fixtures + ML test sample) |
| 8 | Trained structured/hybrid ML model | 🟡 | not trained: structured fields describe anonymised URLs and are absent from Nazario_5; hybrid = documented rule-weighted fusion |
| 9 | Paste + .eml + batch (.eml/CSV) ingestion with validation | ✅ | `test_api.py` |
| 10 | MIME/header canonicalisation; raw stored separately | ✅ | parser + `raw_inputs` |
| 11 | Unicode/entity normalisation with offset map | ✅ | `test_parser.py` |
| 12 | Attachment static triage (hash, magic, mismatch, no execution) | ✅ | tests |
| 13 | OCR / QR / image lures | ❌ | no OCR/QR dependency; disclosed per attachment as unavailable |
| 14 | Auth parsing; untrusted results; pass ≠ benign | ✅ | tests |
| 15 | Impersonation, lookalike/punycode, VIP/vendor profiles | ✅ | tests |
| 16 | Zero-link BEC, payroll, gift cards, MFA, data requests | ✅ | tests + benchmark |
| 17 | Sender behaviour baseline (style deviation) | 🟡 | first-contact and Reply-To-on-record checks only; no stylometric baseline |
| 18 | Thread/quoted-context consistency | ✅ | reply-without-thread; new payment details above quote |
| 19 | Callback/phone lures | ✅ | `test_callback_lure` |
| 20 | Multilingual coverage/fairness | 🟡 | English only; heuristic OOD → INSUFFICIENT; no fairness claim |
| 21 | URL extraction, anchor mismatch, lexical/lookalike checks | ✅ | tests |
| 22 | Reputation adapters with timeout/cache/rate limit + local fallback | 🟡 | local provider tested; VirusTotal adapter unit-tested but not live-tested (no key) |
| 23 | Safe page/brand rendering | 🟡 | deliberately not implemented (no isolated renderer); UI states "live page analysis unavailable" |
| 24 | Time-of-click re-score with before/after | ✅ | `test_demo_seed_builds_justified_campaigns_and_rescore` |
| 25 | IOC store with provenance, expiry, review queue, history | ✅ | `indicators`, `indicator_history` |
| 26 | Campaign clustering, near-dup, boilerplate handling, no generic-word edges | ✅ | `test_campaigns_safety.py` |
| 27 | Low-and-slow detection | ✅ | demo vendor run flagged |
| 28 | Domain age / CT enrichment | ❌ | no permitted service configured; never invented |
| 29 | ATT&CK mapping; JSON/CSV/STIX export | ✅ | MISP/TAXII/SIEM adapters not built ("not connected") |
| 30 | Risk fusion, no double counting, uncertainty/OOD routing | ✅ | tests |
| 31 | Optional LLM cascade | 🟡 | not used; deterministic grounded explanations |
| 32 | Impact-aware priority queue | ✅ | P1–P4 + priority score |
| 33 | Dual-audience explanation, case summary, audit receipt | ✅ | receipt is not cryptographically signed (stated in UI) |
| 34 | Analyst actions incl. local quarantine/release/banner | ✅ | `test_case_actions_feedback_and_audit_persist` |
| 35 | Triage measures | ✅ | dashboard triage block |
| 36 | Awareness feedback after report | ✅ | tactic tips on report |
| 37 | Live dashboard and model/system health | ✅ | `test_dashboard_counts_are_live` |
| 38 | Auth/session protection | 🟡 | optional API key + rate limiting; no user accounts/roles |
| 39 | Gmail/Graph/IMAP, SIEM/SOAR connectors | ❌ | need OAuth/credentials; UI shows "not connected" |
| 40 | Reproducible deployment | 🟡 | README, `.env.example`, pinned deps, health endpoint; no Docker Compose |
| 41 | Signature 1 acceptance demo | ✅ | live run |
| 42 | Signature 2 acceptance | ✅ | provenance + insufficient-story tests |
| 43 | Signature 3 acceptance | ✅ | demo seed test |
| 44 | Signature 4 acceptance | ✅ | live run + UI |
| 45 | Replay against new threshold/rules/model; shadow mode | ✅ | `/replay` policy + reanalyze modes |
| 46 | Attack-coverage matrix | ✅ | benchmark metrics + UI |
| 47 | Frontend: pages, video-matched design, loading/empty/error states | ✅ | build + screenshots + vitest; phone layout not visually verified |
| 48 | Security controls | ✅ | docs/SECURITY.md table |

## Outstanding constraints
* OCR/QR, domain age/CT, live threat intelligence and mailbox/SIEM connectors need dependencies or credentials that are not available; all are shown as unavailable.
* The benchmark is synthetic and written by the same author as the rules; results apply to it only.
* The SpamAssassin domain-shift result (F1 0.88) and false positives on notification-style mail are real model weaknesses.
