"""Profile, validate, de-duplicate and split the training corpora.

Outputs
  data/reports/dataset_profile.json   schema, counts, labels, sources, missing values, overlaps, manifest
  data/processed/corpus.parquet        prepared text + label + source + dup group + split

Design decisions (see ML_PIPELINE.md):
  * MeAJOR is the primary corpus. Label 0 = benign, 1 = "phishing" per the Zenodo record; the
    rows in the published file come only from TREC-05/06/07 whose original labels are ham/spam,
    so label 1 here is better described as "malicious/unsolicited". This is recorded, not hidden.
  * Nazario_5 (1,565 Nazario phishing + 1,500 ham, both non-anonymised) is the only supplementary
    corpus with genuine phishing labels for both classes, so it is the one candidate added to training.
  * CEAS_08 / Enron / SpamAssassin are spam-vs-ham collections: profiled + overlap-checked only.
    SpamAssassin is kept as an external cross-corpus test set (never trained on).
  * Exact duplicates (normalised text hash) and near-duplicates (MinHash-LSH on word 5-shingles,
    estimated Jaccard >= 0.8) are grouped; every group lands in exactly one split.
  * Splits: stratified, group-aware 70/15/15 (seed 42). The test split is not used until final evaluation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.ml.text_prep import PREP_VERSION, prep_dataset_text  # noqa: E402

RAW = ROOT / "data" / "raw"
PROC = ROOT / "data" / "processed"
REPORTS = ROOT / "data" / "reports"
SEED = 42

MEAJOR_COLUMNS = {"sender", "sender_domain", "receiver", "receiver_domain", "date", "subject", "content_types", "body",
                  "urls", "url_count", "url_length_max", "url_length_avg", "url_subdom_max", "url_subdom_avg",
                  "attachment_count", "has_attachments", "attachment_types", "language", "source", "label"}
SUPP = {
    "nazario_5": ("Nazario_5.csv", "train_candidate", "1 = phishing (Nazario corpus), 0 = legitimate"),
    "nazario": ("Nazario.csv", "overlap_check", "1 = phishing (Nazario corpus), all rows positive"),
    "ceas_08": ("CEAS_08.csv", "profile_only", "1 = spam, 0 = ham (CEAS 2008 spam challenge) - spam is not phishing"),
    "enron": ("Enron.csv", "profile_only", "1 = spam, 0 = ham (Enron-Spam) - spam is not phishing; overlaps TREC-05 sources"),
    "spamassassin": ("SpamAssasin.csv", "external_test", "1 = spam, 0 = ham (SpamAssassin public corpus) - spam is not phishing"),
}


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------- MinHash LSH near-duplicates
_TOK = re.compile(r"[a-z0-9]+")
_P = (1 << 61) - 1


def minhash_signatures(texts: list[str], num_perm: int = 64, shingle: int = 5) -> np.ndarray:
    rng = np.random.default_rng(SEED)
    a = rng.integers(1, _P, num_perm, dtype=np.uint64)
    b = rng.integers(0, _P, num_perm, dtype=np.uint64)
    sigs = np.full((len(texts), num_perm), np.iinfo(np.uint64).max, dtype=np.uint64)
    for i, t in enumerate(texts):
        toks = _TOK.findall(t)
        if len(toks) < shingle:
            sh = {" ".join(toks)}
        else:
            sh = {" ".join(toks[j:j + shingle]) for j in range(0, len(toks) - shingle + 1)}
        hv = np.fromiter((int.from_bytes(hashlib.blake2b(s.encode(), digest_size=8).digest(), "little") % _P
                          for s in sh), dtype=np.uint64, count=len(sh))
        # (a*x + b) mod p computed in float-safe way via python ints would be slow; use uint64 wraparound hashing
        hashed = (hv[:, None] * a[None, :] + b[None, :])
        sigs[i] = hashed.min(axis=0)
    return sigs


class UnionFind:
    def __init__(self, n: int):
        self.p = np.arange(n)

    def find(self, x: int) -> int:
        p = self.p
        while p[x] != x:
            p[x] = p[p[x]]
            x = p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def near_dup_groups(texts: list[str], exact_keys: list[str], threshold: float = 0.8,
                    bands: int = 16, rows: int = 4) -> tuple[np.ndarray, dict]:
    n = len(texts)
    uf = UnionFind(n)
    first: dict[str, int] = {}
    exact_pairs = 0
    for i, k in enumerate(exact_keys):
        if k in first:
            uf.union(first[k], i)
            exact_pairs += 1
        else:
            first[k] = i
    log(f"exact duplicate rows: {exact_pairs}")
    t0 = time.time()
    sigs = minhash_signatures(texts, num_perm=bands * rows)
    log(f"minhash signatures computed in {time.time() - t0:.0f}s")
    near_pairs = 0
    checked = 0
    for bnd in range(bands):
        buckets: dict[bytes, list[int]] = {}
        sl = sigs[:, bnd * rows:(bnd + 1) * rows]
        for i in range(n):
            buckets.setdefault(sl[i].tobytes(), []).append(i)
        for members in buckets.values():
            if len(members) < 2:
                continue
            base = members[0]
            for j in members[1:]:
                if uf.find(base) == uf.find(j):
                    continue
                checked += 1
                est = float(np.mean(sigs[base] == sigs[j]))
                if est >= threshold:
                    uf.union(base, j)
                    near_pairs += 1
    groups = np.array([uf.find(i) for i in range(n)])
    return groups, {"exact_duplicate_rows": exact_pairs, "near_duplicate_unions": near_pairs,
                    "lsh_candidate_pairs_checked": checked, "jaccard_threshold": threshold,
                    "minhash_permutations": bands * rows, "lsh_bands": bands, "shingle_words": 5}


def exact_key(t: str) -> str:
    return hashlib.sha1(re.sub(r"[^a-z0-9]+", "", t).encode()).hexdigest()


# ---------------------------------------------------------------- splitting
def group_stratified_split(labels: np.ndarray, groups: np.ndarray, seed: int = SEED) -> np.ndarray:
    from sklearn.model_selection import StratifiedGroupKFold
    sgkf = StratifiedGroupKFold(n_splits=20, shuffle=True, random_state=seed)
    split = np.empty(len(labels), dtype=object)
    for k, (_, idx) in enumerate(sgkf.split(np.zeros(len(labels)), labels, groups)):
        split[idx] = "test" if k < 3 else ("val" if k < 6 else "train")
    return split


def profile_frame(df: pd.DataFrame, name: str) -> dict:
    return {
        "rows": int(len(df)),
        "columns": {c: str(t) for c, t in df.dtypes.items()},
        "missing_fraction": {c: round(float(df[c].isna().mean()), 4) for c in df.columns},
        "label_counts": {str(k): int(v) for k, v in df["label"].value_counts(dropna=False).items()},
        "body_length": {k: round(float(v), 1) for k, v in df["body"].astype(str).str.len().describe().items()},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-meajor", type=int, default=0, help="optional cap for quick experiments (0 = all)")
    args = ap.parse_args()
    PROC.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    profile: dict = {"prep_version": PREP_VERSION, "seed": SEED, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    manifest = REPORTS / "download_manifest.json"
    if manifest.exists():
        profile["download_manifest"] = json.loads(manifest.read_text())["attempts"]

    # ---------------- MeAJOR
    pq_path = RAW / "meajor_cleaned_preprocessed.parquet.gzip"
    csv_path = RAW / "meajor_cleaned_preprocessed.csv"
    if pq_path.exists():
        mj = pd.read_parquet(pq_path)
        profile["meajor_format"] = "parquet"
    elif csv_path.exists():
        mj = pd.read_csv(csv_path, low_memory=False)
        profile["meajor_format"] = "csv"
    else:
        log("BLOCKER: MeAJOR not found - run scripts/download_datasets.py")
        return 2
    missing_cols = MEAJOR_COLUMNS - set(mj.columns)
    if missing_cols:
        log(f"BLOCKER: MeAJOR schema mismatch, missing {sorted(missing_cols)}")
        return 3
    p = profile_frame(mj, "meajor")
    p["source_counts"] = {str(k): int(v) for k, v in mj["source"].value_counts(dropna=False).items()}
    p["label_by_source"] = {f"{s}|{l}": int(v) for (s, l), v in mj.groupby(["source", "label"], dropna=False).size().items()}
    p["language_top"] = {str(k): int(v) for k, v in mj["language"].value_counts().head(10).items()}
    p["license"] = "CC-BY-4.0 (Zenodo API metadata, record 18471483)"
    p["label_semantics"] = ("0 = benign, 1 = phishing per Zenodo record. Observed: every row has source in "
                            "{trec5, trec6, trec7}; no Nazario / Nigerian Fraud rows are present in this file, "
                            "so label 1 corresponds to the original TREC 'spam' label (malicious/unsolicited).")
    p["anonymisation"] = "entity placeholders such as [NAME], [ORGANIZATION], <|URL|> (see text_prep.py for handling)"
    profile["meajor"] = p

    before = len(mj)
    mj = mj[mj["label"].isin([0, 1])]
    mj = mj[mj["body"].notna() & (mj["body"].astype(str).str.strip() != "")]
    profile["meajor"]["dropped_invalid_label_or_empty_body"] = int(before - len(mj))
    if args.max_meajor:
        mj = mj.sample(n=min(args.max_meajor, len(mj)), random_state=SEED)
    corpus = pd.DataFrame({
        "dataset": "meajor",
        "source": mj["source"].astype(str).values,
        "label": mj["label"].astype(int).values,
        "label_semantics": "meajor_label",
        "text": [prep_dataset_text(s, b) for s, b in zip(mj["subject"].fillna(""), mj["body"].fillna(""))],
        "url_count": mj["url_count"].fillna(0).values,
        "attachment_count": mj["attachment_count"].fillna(0).values,
        "language": mj["language"].astype(str).values,
    })
    log(f"MeAJOR prepared: {len(corpus)} rows")

    # ---------------- supplementary
    profile["supplementary"] = {}
    supp_frames = {}
    for name, (fname, role, sem) in SUPP.items():
        path = RAW / fname
        if not path.exists():
            profile["supplementary"][name] = {"status": "missing", "role": role}
            continue
        df = pd.read_csv(path, low_memory=False)
        sp = profile_frame(df, name)
        sp.update(role=role, label_semantics=sem, license="CC-BY-4.0 (Zenodo record 8339691; cite Champa et al. 2024)")
        profile["supplementary"][name] = sp
        df = df[df["label"].isin([0, 1]) & df["body"].notna()]
        supp_frames[name] = pd.DataFrame({
            "dataset": name, "source": name, "label": df["label"].astype(int).values,
            "label_semantics": "phishing" if name.startswith("nazario") else "spam",
            "text": [prep_dataset_text(s, b) for s, b in zip(df["subject"].fillna("").astype(str), df["body"].astype(str))],
            "url_count": np.nan, "attachment_count": np.nan, "language": "unknown",
        })
        log(f"{name}: {len(df)} rows prepared")

    # ---------------- cross-dataset exact-overlap report (normalised text hash)
    mj_keys = set(corpus["text"].map(exact_key))
    overlaps = {}
    for name, f in supp_frames.items():
        keys = f["text"].map(exact_key)
        overlaps[name] = {"rows": int(len(f)), "exact_overlap_with_meajor": int(keys.isin(mj_keys).sum())}
    if "nazario" in supp_frames and "nazario_5" in supp_frames:
        n5 = set(supp_frames["nazario_5"]["text"].map(exact_key))
        overlaps["nazario"]["exact_overlap_with_nazario_5"] = int(supp_frames["nazario"]["text"].map(exact_key).isin(n5).sum())
    profile["cross_dataset_overlap"] = overlaps
    log(f"overlaps: {overlaps}")

    # ---------------- build training pool (MeAJOR + Nazario_5) and external test (SpamAssassin)
    pool = pd.concat([corpus, supp_frames.get("nazario_5", pd.DataFrame())], ignore_index=True)
    pool = pool[pool["text"].str.len() > 0].reset_index(drop=True)
    keys = pool["text"].map(exact_key).tolist()
    groups, dedup_stats = near_dup_groups(pool["text"].tolist(), keys)
    pool["dup_group"] = groups
    # groups with conflicting labels: keep the majority label, drop the minority rows (label noise)
    g = pool.groupby("dup_group")["label"].agg(["nunique", "count"])
    conflict_groups = g.index[g["nunique"] > 1]
    conflict_rows = pool["dup_group"].isin(conflict_groups)
    maj = pool[conflict_rows].groupby("dup_group")["label"].agg(lambda s: int(s.mode().iloc[0]))
    drop_mask = conflict_rows & (pool["label"] != pool["dup_group"].map(maj))
    dedup_stats["label_conflict_groups"] = int(len(conflict_groups))
    dedup_stats["label_conflict_rows_dropped"] = int(drop_mask.sum())
    pool = pool[~drop_mask].reset_index(drop=True)
    # collapse each duplicate group to one representative (keeps evaluation honest)
    pool["group_size"] = pool.groupby("dup_group")["label"].transform("size")
    before = len(pool)
    pool = pool.drop_duplicates("dup_group", keep="first").reset_index(drop=True)
    dedup_stats["rows_before_collapse"] = int(before)
    dedup_stats["rows_after_collapse"] = int(len(pool))
    profile["deduplication"] = dedup_stats
    log(f"dedup: {dedup_stats}")

    strat = pool["dataset"] + "_" + pool["label"].astype(str)
    pool["split"] = group_stratified_split(strat.values, pool["dup_group"].values)
    profile["splits"] = {f"{d}|{s}|{l}": int(v) for (d, s, l), v in pool.groupby(["dataset", "split", "label"]).size().items()}

    if "spamassassin" in supp_frames:
        ext = supp_frames["spamassassin"].copy()
        pool_keys = set(pool["text"].map(exact_key))
        k = ext["text"].map(exact_key)
        ext = ext[~k.isin(pool_keys)].drop_duplicates("text")
        ext["dup_group"] = -1
        ext["group_size"] = 1
        ext["split"] = "external_test"
        profile["external_test"] = {"dataset": "spamassassin", "rows_after_overlap_removal": int(len(ext)),
                                    "labels": {str(a): int(b) for a, b in ext["label"].value_counts().items()},
                                    "note": "spam/ham labels; used to measure benign false-positive rate and spam "
                                            "detection on an unseen corpus, not phishing recall"}
        pool = pd.concat([pool, ext], ignore_index=True)

    pool.to_parquet(PROC / "corpus.parquet", index=False)
    split_manifest = {"seed": SEED, "prep_version": PREP_VERSION,
                      "counts": profile["splits"], "corpus_sha256": hashlib.sha256((PROC / "corpus.parquet").read_bytes()).hexdigest()}
    (PROC / "split_manifest.json").write_text(json.dumps(split_manifest, indent=2))
    (REPORTS / "dataset_profile.json").write_text(json.dumps(profile, indent=2, default=str))
    log(f"wrote {PROC / 'corpus.parquet'} ({len(pool)} rows) and dataset_profile.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
