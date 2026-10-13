# Linear SVM — training and evaluation record

An SVM was trained, compared with Logistic Regression and **selected**. All values are from run
`train-20261013T033521Z-9d474c` (`data/reports/train_log.txt`, `models/model_metadata.json`).

## Configuration
* Estimator: `sklearn.svm.LinearSVC(C, max_iter=5000, random_state=42)` (scikit-learn 1.9.1).
* Features: shared FeatureUnion — word 1–2-gram TF-IDF + char_wb 3–5-gram TF-IDF (600,000 features), fitted on train only.
* Grid: C ∈ {0.1, 0.5} on two pools (MeAJOR only; MeAJOR + Nazario_5). LogReg (liblinear, C ∈ {1, 4}) on the same matrices.
* Threshold for each candidate: max-F1 on the concatenated validation set (SVM decision function / LR probability).

## Results (validation)
| pool | C | MeAJOR F1 | MeAJOR FPR | MeAJOR PR-AUC | Nazario_5 F1 | Nazario_5 FPR | mean F1 | fit s |
|---|---|---|---|---|---|---|---|---|
| MeAJOR only | 0.1 | 0.9817 | 0.0177 | 0.9976 | 0.8170 | 0.0394 | 0.8993 | 3.4 |
| MeAJOR only | 0.5 | 0.9845 | 0.0155 | 0.9981 | 0.8053 | 0.0591 | 0.8949 | 4.4 |
| MeAJOR + Nazario_5 | 0.1 | 0.9816 | 0.0185 | 0.9977 | 0.9741 | 0.0148 | 0.9778 | 3.0 |
| **MeAJOR + Nazario_5** | **0.5** | **0.9847** | **0.0123** | **0.9982** | **0.9764** | **0.0099** | **0.9806** | **4.3** |

Best LogReg for comparison: MeAJOR + Nazario_5, C = 4 → mean F1 0.9793 (fit 19.0 s).

## Decision
SVM C = 0.5 on MeAJOR + Nazario_5: highest mean validation F1 (0.9806 vs 0.9793 for LR) and ~4× faster to fit.
Because `LinearSVC` has no probabilities, it was wrapped in `CalibratedClassifierCV(FrozenEstimator(svm), method="sigmoid")`
fitted on the **validation** split (Brier 0.0108, ECE 0.0013 on validation). The operating threshold 0.5211 was then re-tuned
on validation. Explanations use the underlying SVM coefficients × TF-IDF values (exact for a linear model).

## Held-out test (`eval-20261013T034130Z-8b771f`)
MeAJOR test F1 0.9838 (FPR 1.29%), Nazario_5 test F1 0.9749 (FPR 4.43%), SpamAssassin external F1 0.8800 (FPR 5.63%).
Test-set calibration: MeAJOR Brier 0.0106 / ECE 0.0016; Nazario_5 Brier 0.0238 / ECE 0.0198; SpamAssassin Brier 0.0563 / ECE 0.0176.
The backend still reports the *fused* output as a 0–100 policy risk score, not a probability.
