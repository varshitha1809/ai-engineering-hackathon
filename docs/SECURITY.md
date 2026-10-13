# Security, privacy and limitations

## Controls implemented (and where they are tested)
| Control | Implementation | Test |
|---|---|---|
| Upload/type/size validation | `.eml`/`.txt` only (`.msg` → 415), 5 MB limit (413), empty → 422, batch ≤ 50 | `test_api.py::test_validation_errors_are_explicit` |
| Parser limits | ≤ 200 MIME parts, nesting ≤ 10, attachment text ≤ 200 KB, HTML ≤ 2 MB; 20 s analysis timeout → 504, no verdict | `test_parser.py` |
| No execution | attachments only hashed + magic-byte typed; HTML parsed, never rendered; scripts counted, not run | `test_detectors.py` |
| No SSRF | backend never fetches email URLs; page analysis shown as "unavailable" | `test_campaigns_safety.py::test_analysis_never_opens_network_connections` |
| Untrusted auth headers | Authentication-Results trusted only for configured authserv-ids; pass never lowers risk | `test_detectors.py` |
| Prompt-injection safety | email content is never sent to an LLM or acted upon; hidden instructions shown as inert evidence | `test_detectors.py` |
| Failures never "safe" | missing/tampered model, failed detector, parse failure → INSUFFICIENT/REVIEW + unavailable findings | `test_ml_fusion.py`, `test_campaigns_safety.py` |
| Secrets | `.env` (git-ignored), `.env.example` placeholders, never returned by `/settings` or `/health`; audit redaction | `test_campaigns_safety.py::test_audit_redaction…` |
| Optional auth | `PHISHDNA_API_KEY` → `X-API-Key` required (constant-time compare); in-memory rate limit on analyze/benchmark | `test_api.py::test_api_key_enforced…` |
| Data minimisation | raw input stored separately and only if `PHISHDNA_RETAIN_RAW=true`; evidence excerpts mask account numbers/IBANs; reports exclude full body; delete endpoint removes analysis, evidence, raw input | `test_api.py::test_report_exports`, `test_delete…` |
| External data transfer | VirusTotal lookups only when explicitly enabled + key; hash lookups only, files never uploaded | `test_detectors.py::test_external_provider_timeout…` |
| High-impact actions | local quarantine requires `confirm=true`; all actions say "local record / sandbox" | `test_api.py::test_case_actions…` |

## Known limitations
* Datasets are old (TREC 2005–07, Nazario) and MeAJOR "phishing" labels derive from TREC spam; the model over-scores some
  legitimate notification-style mail and drops to F1 0.88 on an unseen corpus.
* English only. No multilingual fairness claim. Language check is a heuristic that only routes to "insufficient evidence".
* Rules are lexical: word-split and paraphrase variants defeated them in 3 benchmark items. AI-authorship is not detected or used.
* Hidden-content detection is static CSS/attribute analysis; tricks requiring a layout engine (e.g. overlapped elements) are not covered.
* No OCR/QR, no PDF/Office text extraction, no archive unpacking, no `.msg` parsing — disclosed per analysis as unavailable.
* Threat intelligence = local IOC store; VirusTotal adapter untested against the live API (no key). Domain age/CT not implemented.
* Single-user local deployment; no multi-tenant isolation or role enforcement. Rate limiting is per-process memory.
* The benchmark is synthetic and author-written; holdout is not independent of the author. "No strong indicators" is not a safety guarantee.
