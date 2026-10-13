# PHISHDNA AI — Architecture

Implements the supplied architecture image layer by layer. Services are modules inside one FastAPI process (the spec allows
this); boundaries follow the diagram.

```
Frontend (React + TS, Vite)                      frontend/src
  public landing  ─┐  analyst app (11 pages) ──── typed client lib/api.ts ──► /api/v1/*
                   ▼
Backend (FastAPI)                                backend/app
  API layer ............ main.py, security.py (API key, rate limit), api/*.py (pydantic validation)
  Email processing ..... email_processing/parser.py (MIME, limits), html_inspector.py, normalizer.py, urls.py
  Analysis engine ...... analysis/model.py (trained model), detectors/*.py (forensic rules), fusion.py, evidence.py
  Threat intelligence .. threat_intel/providers.py (local IOC + optional VirusTotal), services/indicators.py
  Investigation ........ investigation/reconstruction.py, services/campaigns.py, api/cases.py, report export
  Evaluation/monitoring  evaluation/benchmark.py + variants.py, api/system.py (health, status, dashboard)
                   ▼
ML pipeline (scikit-learn)                       scripts/download → preprocess → train → evaluate; models/
                   ▼
Data & storage (SQLite, WAL)                     backend/app/db.py
  analyses, findings, raw_inputs (separate, deletable), indicators(+history), analysis_indicators,
  campaigns, campaign_members, campaign_edges, cases, feedback, profiles, evaluation_runs/items,
  analysis_versions, audit_events
                   ▼
External integrations (optional)                 VirusTotal adapter (off by default); Gmail/Graph/SIEM: "not connected"
```

## End-to-end flow (verified)
`POST /api/v1/analyze` → validation (type/size) → `parse_input` (limits, defects recorded) → detectors in order
(social engineering → identity/auth/thread → URLs → attachments → hidden content/AI injection) → trained model
(`TextModel.predict`, sha-verified artifact) → TI lookups (local IOC store; VT only if enabled) → related-message correlation
(candidate edges against retained messages) → fusion → uncertainty, impact & priority → reconstruction graph + explanations →
persistence (analysis, findings with provenance, raw input, indicators, case, version history, audit) → campaign edges and
cluster rebuild. Every stage writes `stage_status`; failures become `unavailable` findings and feed the verdict policy.

## Evidence record
`analysis/evidence.py::Finding` = spec §6.4: `finding_id, analysis_id, category, component, severity, observed_value
(masked excerpt), source_location, method (model|rule|provider), version, confidence (evidence strength), status
(observed|inferred|unavailable), timestamp, explanation, related_indicator_ids, related_finding_ids, span, tags`.

## Risk fusion (`analysis/fusion.py`, version fusion-1.0.0)
* Group strength = strongest finding + 15% of the second (correlated findings in one group cannot stack).
* Content groups (text model, intent) are correlated: `content = max(a,b) + 0.5·min(a,b)` of weighted strengths.
* Other groups: weighted noisy-OR. Weights: text 0.55, intent 0.6, identity 0.55, url 0.55, attachment 0.65,
  reputation 0.95, evasion 0.35, context 0.35, ai_injection 0.7. Output = 0–100 **policy risk score** (not a probability).
* Verdict order: parse failure → INSUFFICIENT; AI-injection strength ≥ 0.6 → AI_INJECTION_SUSPECTED; malicious reputation →
  LIKELY; score ≥ 65 and ≥ 2 strong groups → LIKELY; score ≥ 65 with one strong group → REVIEW (single-source decisions are not
  automatic); score ≥ 35 but only uncorroborated text-model evidence below 0.85 → NO_STRONG + uncertainty note; score ≥ 35 →
  REVIEW; high-impact request with unverified identity → REVIEW; model unavailable and no other evidence → INSUFFICIENT;
  < 8 words → INSUFFICIENT; likely non-English → INSUFFICIENT; else NO_STRONG_INDICATORS (never shown as "safe").
* Passing authentication results never reduce risk; uploaded Authentication-Results are "unverified" unless the authserv-id is
  configured as trusted.
* The model threshold (0.5211) was tuned on validation. Policy constants were fixed before the benchmark; one policy change
  (uncorroborated text-only evidence) was adopted after the **dev** split run and before the first holdout run.

## Campaign correlation (`services/campaigns.py`)
Edges only from concrete evidence: shared URL (0.95), attachment SHA-256 (0.95), bank reference hash (0.9), Reply-To address
(0.85), non-common link domain (0.75), phone hash (0.7), Reply-To domain (0.6), same impersonated profile (0.6), near-duplicate
body (Jaccard ≥ 0.55 on word 5-shingles after removing boilerplate shingles present in > 30% of messages), weak: sender domain
(0.45), sender address (0.4), partially similar body. Campaigns = connected components over edges ≥ 0.5. Severity =
0.45·worst member risk + 25·strongest edge + log-size term + 12 if high-impact request (member scores are not summed).
Low-and-slow = ≥ 3 members, most below 65, spanning ≥ 1 day.

## Response actions
Report, mark benign, escalate, assign, resolve/reopen, quarantine (requires confirmation), release, banner — all change local
records only and are audited. Analyst feedback is stored separately from the immutable original prediction and queued for
retraining review; confirmed-phishing indicators enter the IOC store as `pending_review` and do not affect verdicts until approved.
Approving/setting an IOC re-scores every retained message containing it and returns before/after verdicts.

## Deviations from the diagram
* PostgreSQL/SQLite → SQLite only (local prototype; schema is portable).
* "Domain reputation" uses the local IOC store; VirusTotal adapter exists but is not configured or live-tested (no key).
* Optional LLM explanation not used: explanations are deterministic and evidence-templated (spec permits this).
