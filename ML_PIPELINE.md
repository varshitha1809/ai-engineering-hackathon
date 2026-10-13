# PHISHDNA AI — ML pipeline

All numbers below were produced by the scripts in `scripts/` during this build (13 Oct 2026) and can be
regenerated with the commands at the end. Nothing here is copied from papers or dataset descriptions.

## 1. Datasets, provenance and licence

| Dataset | Source (direct download) | Licence | Role | Status |
|---|---|---|---|---|
| MeAJOR v2.0 (Parquet) | https://zenodo.org/records/18471483/files/meajor_cleaned_preprocessed.parquet.gzip?download=1 | CC-BY-4.0 (Zenodo API metadata) | primary training/val/test | downloaded, 86,278,230 bytes, MD5 verified, 108,685 rows × 20 cols |
| MeAJOR CSV | …/meajor_cleaned_preprocessed.csv?download=1 | CC-BY-4.0 | fallback only | not needed (Parquet parsed) |
| Nazario_5 | https://zenodo.org/records/8339691/files/Nazario_5.csv?download=1 | CC-BY-4.0 (cite Champa et al. 2024) | training candidate (phishing + ham) | downloaded, MD5 verified, 3,065 rows |
| Nazario | …/Nazario.csv | CC-BY-4.0 | overlap check | 1,565 rows — **all 1,565 are contained in Nazario_5** |
| CEAS_08 | …/CEAS_08.csv | CC-BY-4.0 | profile/overlap only (spam ≠ phishing) | 39,154 rows; 2 exact overlaps with MeAJOR |
| Enron | …/Enron.csv | CC-BY-4.0 | profile/overlap only (spam ≠ phishing) | 29,767 rows; 80 exact overlaps with MeAJOR |
| SpamAssassin | …/SpamAssasin.csv | CC-BY-4.0 | **external test only** (never trained on) | 5,809 rows → 5,538 after overlap removal |

The download manifest (URL, bytes, SHA-256, MD5 check, timestamps) is written to `data/reports/download_manifest.json`.
Raw files live in `data/raw/` and are git-ignored.

### Label semantics — an important, documented caveat
The Zenodo record says MeAJOR covers TREC-05/06/07, Nazario and Nigerian Fraud with `label 0 = benign, 1 = phishing`.
**The published file contains only `source ∈ {trec5, trec6, trec7}`** (49,583 / 15,005 / 44,096 rows). TREC's original
labels are ham/spam, so MeAJOR label 1 here is better described as *malicious/unsolicited* than phishing specifically.
Nazario_5 was therefore added as the only supplementary corpus with genuine phishing labels for **both** classes in the same
(non-anonymised) style, which avoids a source↔label confound. CEAS/Enron/SpamAssassin spam was **not** relabelled as phishing.

### Schema (MeAJOR, verified)
`sender, sender_domain, receiver, receiver_domain` (hashed/anonymised), `date, subject, content_types, body, urls,
url_count, url_length_max, url_length_avg, url_subdom_max, url_subdom_avg, attachment_count, has_attachments,
attachment_types, language, source, label`. Bodies are anonymised with placeholders (`[NAME]`, `[ORGANIZATION]`, `<|URL|>` …).
One row has `label = NaN` and one has an empty body; both were dropped (2 rows).

## 2. Preprocessing (`scripts/preprocess_dataset.py`, `backend/app/ml/text_prep.py`)

* Schema validation against the expected MeAJOR column set; abort with a stated blocker if columns are missing.
* Shared train/serve text preparation (`text_prep.py`, version `textprep-1.0`): NFKC, removal of zero-width/bidi characters,
  placeholders we can reproduce at inference (URL, e-mail, phone, IP) → canonical tokens, the same regex substitution applied to
  live mail; NER-only placeholders (`[NAME]` …) are dropped because they cannot be reproduced on live mail. Lower-cased, ≤12k chars.
* De-duplication **before** splitting: exact (normalised-text hash) + near-duplicate (MinHash, 64 permutations, 16 LSH bands,
  word 5-shingles, estimated Jaccard ≥ 0.8) with union-find grouping.
  Result: 5,032 exact-duplicate rows, 7,643 near-duplicate unions, 12 label-conflict groups (20 minority-label rows dropped),
  111,712 → **99,057** rows after collapsing each group to one representative.
* Split: `StratifiedGroupKFold(20, seed 42)` → 70/15/15 train/val/test, stratified by dataset×label, groups never cross splits.

| split | MeAJOR benign | MeAJOR malicious | Nazario_5 benign | Nazario_5 phishing |
|---|---|---|---|---|
| train | 38,284 | 29,101 | 946 | 1,008 |
| val | 8,204 | 6,237 | 203 | 215 |
| test | 8,204 | 6,236 | 203 | 216 |

Profile: `data/reports/dataset_profile.json`; split manifest + corpus hash: `data/processed/split_manifest.json`.

## 3. Training (`scripts/train_model.py`) — Model A

Features: word 1–2-gram TF-IDF (sublinear, min_df 3, ≤300k) + char_wb 3–5-gram TF-IDF on the first 4,000 chars (min_df 5, ≤300k)
= 600,000 features, fitted on **train only**. Candidates (validation F1, fit time):

| pool | classifier | C | MeAJOR val F1 | MeAJOR val FPR | Nazario_5 val F1 | Nazario_5 val FPR | selection score | fit s |
|---|---|---|---|---|---|---|---|---|
| MeAJOR only | LogReg | 1 | 0.9798 | 0.0205 | 0.8211 | 0.0443 | 0.9004 | 19.6 |
| MeAJOR only | LogReg | 4 | 0.9820 | 0.0206 | 0.8208 | 0.0591 | 0.9014 | 23.3 |
| MeAJOR only | LinearSVC | 0.1 | 0.9817 | 0.0177 | 0.8170 | 0.0394 | 0.8993 | 3.4 |
| MeAJOR only | LinearSVC | 0.5 | 0.9845 | 0.0155 | 0.8053 | 0.0591 | 0.8949 | 4.4 |
| MeAJOR+Nazario_5 | LogReg | 1 | 0.9793 | 0.0213 | 0.9720 | 0.0246 | 0.9756 | 21.0 |
| MeAJOR+Nazario_5 | LogReg | 4 | 0.9822 | 0.0156 | 0.9765 | 0.0148 | 0.9793 | 19.0 |
| MeAJOR+Nazario_5 | LinearSVC | 0.1 | 0.9816 | 0.0185 | 0.9741 | 0.0148 | 0.9778 | 3.0 |
| **MeAJOR+Nazario_5** | **LinearSVC** | **0.5** | **0.9847** | **0.0123** | **0.9764** | **0.0099** | **0.9806** | **4.3** |

Selection rule: highest mean validation F1 over MeAJOR and Nazario_5. Training on MeAJOR alone generalises poorly to genuine
phishing (Nazario_5 val F1 ≈ 0.81–0.82); adding Nazario_5 lifts it to ≈ 0.97 with no MeAJOR loss.
The selected SVM was sigmoid-calibrated (Platt) on the validation split; threshold = max-F1 on validation = **0.5211**.
Validation reliability: Brier 0.0108, 10-bin ECE 0.0013.

Artifact: `models/phishdna_text_model.joblib` (complete fitted feature + estimator pipeline, 10.4 MB),
`models/model_metadata.json` (version `textclf-linear_svm-e1a96befb4`, SHA-256 `e1a96bef…`, run `train-20261013T033521Z-9d474c`).
The backend verifies the SHA-256 before loading and refuses a tampered/missing artifact (stage reported as failed).

## 4. Held-out evaluation (`scripts/evaluate_model.py`, run `eval-20261013T034130Z-8b771f`)

Test splits were not used for selection, threshold tuning or calibration.

| set | n | precision | recall | F1 | FPR | PR-AUC | ROC-AUC | Brier | ECE | TP/FP/TN/FN |
|---|---|---|---|---|---|---|---|---|---|---|
| MeAJOR test | 14,440 | 0.9830 | 0.9846 | 0.9838 | 0.0129 | 0.9982 | 0.9986 | 0.0106 | 0.0016 | 6140/106/8098/96 |
| Nazario_5 test | 419 | 0.9596 | 0.9907 | 0.9749 | 0.0443 | 0.9905 | 0.9922 | 0.0238 | 0.0198 | 214/9/194/2 |
| combined test | 14,859 | 0.9822 | 0.9848 | 0.9835 | 0.0137 | 0.9980 | 0.9985 | 0.0109 | 0.0015 | 6354/115/8292/98 |
| SpamAssassin (unseen corpus) | 5,538 | 0.8733 | 0.8868 | 0.8800 | 0.0563 | 0.9451 | 0.9734 | 0.0563 | 0.0176 | 1496/217/3634/191 |

Per source (MeAJOR test): trec5 F1 0.978 (FPR 1.95%), trec6 F1 0.971 (FPR 0.92%), trec7 F1 0.991 (FPR 0.61%).
Single-email latency (full pipeline `predict_proba`): p50 2.29 ms, p95 4.24 ms (n = 300).

**Honest reading.** In-distribution results are very high, partly because TREC spam is easy to separate from Enron/list mail.
The drop on SpamAssassin (F1 0.88, FPR 5.6%) shows real domain shift. On synthetic legitimate *notification-style* mail the model
also over-scores (e.g. GitHub/Zoom notices scored 0.81–0.92), which is why the fusion policy does not let uncorroborated
text-model evidence alone route a message to review (see `docs/ARCHITECTURE.md`).

## 5. What is ML and what is rules

| Capability | Method |
|---|---|
| Text maliciousness score | **Trained** TF-IDF + linear SVM (this pipeline), subject + visible body only |
| Tactics, requested actions, zero-link BEC, callback lures | Deterministic, documented rules (no tactic-labelled data exists) |
| Sender/Reply-To/lookalike/profile/auth/thread checks | Deterministic rules |
| URL lexical checks, attachment static triage | Deterministic rules |
| Hidden content & AI-assistant instruction detection | Deterministic rules, tested on the separate synthetic fixture suite |
| Campaign correlation | Shared-indicator matching + MinHash-style shingle Jaccard |
| Risk fusion | Transparent weighted policy (`backend/app/analysis/fusion.py`) — not a trained fusion model |

No header, attachment, hidden-HTML or prompt-injection feature was used to train the model; the corpora do not contain suitable labels.
No hybrid *trained* structured model was built: MeAJOR's structured columns (url_count etc.) describe URLs that were anonymised away
and are absent from Nazario_5, so a fair hybrid comparison on identical held-out data was not possible. The hybrid comparison is
instead done in the robustness lab (§6) on identical inputs.

## 6. Robustness benchmark (Signature 4)

`scripts/build_benchmark.py` → `data/fixtures/benchmark/benchmark_v1.json`: 58 synthetic, sanitised base cases (reserved
`.test/.example` domains) in 8 categories, split dev/holdout by alternating within category. Validated variants: case/punctuation,
zero-width, homoglyph, word-split, reviewed-table paraphrase, HTML visibility change, hand-written polished rewrite (simulates
AI-polished phrasing). Dev was visible while rules were written; rules were frozen before the first holdout run.

Run `EVAL-261013-041713-7945` (308 items, 300 labelled; model `textclf-linear_svm-e1a96befb4`, rules-1.0.0, fusion-1.0.0):

| subset | baseline P / R / F1 / FPR | hybrid P / R / F1 / FPR | hybrid PR-AUC |
|---|---|---|---|
| dev | 0.909 / 0.579 / 0.707 / 0.212 | 0.968 / 1.000 / 0.984 / 0.121 | 0.997 |
| **holdout** | 0.855 / 0.522 / 0.648 / 0.303 | 0.991 / 0.974 / 0.982 / 0.030 | 0.994 |

Missed (hybrid): `cred-06~word_split`, `thr-02~word_split`, `thr-02~paraphrase`. False alarms: `leg-11` (Zoom recording notice:
text model 0.92 with no other evidence — above the 0.85 strong-text constant, so it goes to review), `leg-05~case_punct`,
`leg-11~case_punct`, `leg-11~html_visibility`, `leg-16~case_punct` (all text-model-driven).
40 malicious items were missed by the baseline and caught by another layer. Latency: hybrid p50 16 ms / p95 31 ms.
Ablation (F1): full 0.983; without AI-injection 0.916; without intent 0.935; without attachment 0.952; without identity 0.961;
without text model 0.967; other layers ≈ no change on this suite.

ML held-out sample run `EVAL-261013-041727-2540` (600 stratified test rows, body text only): baseline F1 0.977 (R 0.977, FPR 1.8%),
hybrid F1 0.969 (R 0.954, FPR 1.2%) — the uncorroborated-text policy trades ~2 points of recall for lower FPR when only body text exists.

## 7. Reproduction

```bash
pip install -r requirements.txt
python scripts/download_datasets.py --supplementary   # streams, MD5-verifies, writes manifest
python scripts/preprocess_dataset.py                  # profile, dedupe, split  (~3 min)
python scripts/train_model.py                         # 8 candidates, select, calibrate, save (~5 min)
python scripts/evaluate_model.py                      # held-out metrics -> models/evaluation_latest.json
python scripts/build_benchmark.py                     # synthetic labelled suite
python scripts/build_demo_fixtures.py                 # local demo sample set
```
`python scripts/train_model.py --quick` gives a small-vocabulary smoke model (do not report its numbers).
