"""Reproducible dataset acquisition for PHISHDNA AI.

Streams each dataset from Zenodo, checks HTTP status, byte count against the
server's Content-Length and a minimum plausible size, computes SHA-256 and
writes a manifest (data/reports/download_manifest.json) recording success or
the actual error for every attempt. Large files are written to data/raw/ which
is git-ignored.

Usage:
    python scripts/download_datasets.py                 # MeAJOR (parquet, csv fallback)
    python scripts/download_datasets.py --supplementary # also CEAS/Enron/Nazario_5/SpamAssassin
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
REPORTS = ROOT / "data" / "reports"
MANIFEST = REPORTS / "download_manifest.json"

MEAJOR_PARQUET = {
    "name": "meajor_parquet",
    "url": "https://zenodo.org/records/18471483/files/meajor_cleaned_preprocessed.parquet.gzip?download=1",
    "file": "meajor_cleaned_preprocessed.parquet.gzip",
    "min_bytes": 10_000_000,
    "record": "https://zenodo.org/records/18471483",
    "md5": "78e397ad8447bcdba5a98097921ba8bd",
}
MEAJOR_CSV = {
    "name": "meajor_csv",
    "url": "https://zenodo.org/records/18471483/files/meajor_cleaned_preprocessed.csv?download=1",
    "file": "meajor_cleaned_preprocessed.csv",
    "min_bytes": 10_000_000,
    "record": "https://zenodo.org/records/18471483",
    "md5": "aa8f59e96787cbd696c0b650e5400dc9",
}
SUPPLEMENTARY = [
    {"name": "ceas_08", "url": "https://zenodo.org/records/8339691/files/CEAS_08.csv?download=1",
     "file": "CEAS_08.csv", "min_bytes": 1_000_000, "md5": "1f0d59191eec892a709995d48cd8decb", "record": "https://zenodo.org/records/8339691"},
    {"name": "enron", "url": "https://zenodo.org/records/8339691/files/Enron.csv?download=1",
     "file": "Enron.csv", "min_bytes": 1_000_000, "md5": "10489e0fdcc8af6fe62135c689367d40", "record": "https://zenodo.org/records/8339691"},
    {"name": "nazario", "url": "https://zenodo.org/records/8339691/files/Nazario.csv?download=1",
     "file": "Nazario.csv", "min_bytes": 100_000, "md5": "4022d055bb7cf8602f30f768f652e91e",
     "record": "https://zenodo.org/records/8339691"},
    {"name": "nazario_5", "url": "https://zenodo.org/records/8339691/files/Nazario_5.csv?download=1",
     "file": "Nazario_5.csv", "min_bytes": 100_000, "md5": "45db8330ea4aabbf72f5199949ae03e5", "record": "https://zenodo.org/records/8339691"},
    {"name": "spamassassin", "url": "https://zenodo.org/records/8339691/files/SpamAssasin.csv?download=1",
     "file": "SpamAssasin.csv", "min_bytes": 100_000, "md5": "d921e0b2333bfaa058bd38193e6b3fbd", "record": "https://zenodo.org/records/8339691"},
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def download(spec: dict, force: bool = False, timeout: int = 60) -> dict:
    dest = RAW / spec["file"]
    entry = {"name": spec["name"], "url": spec["url"], "record": spec["record"],
             "path": str(dest.relative_to(ROOT)), "started_at": _now()}
    if dest.exists() and not force and dest.stat().st_size >= spec["min_bytes"]:
        md5 = _digest(dest, "md5")
        if spec.get("md5") and md5 != spec["md5"]:
            entry.update(status="error", error=f"cached file md5 mismatch ({md5}); re-run with --force")
        else:
            entry.update(status="cached", bytes=dest.stat().st_size, sha256=_digest(dest, "sha256"), md5=md5,
                         md5_verified=bool(spec.get("md5")))
        entry["finished_at"] = _now()
        return entry
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with requests.get(spec["url"], stream=True, timeout=timeout) as r:
            entry["http_status"] = r.status_code
            r.raise_for_status()
            expected = int(r.headers.get("content-length") or 0)
            h = hashlib.sha256()
            md5 = hashlib.md5()
            n = 0
            t0 = time.time()
            with open(tmp, "wb") as f:
                for chunk in r.iter_content(chunk_size=1 << 20):
                    f.write(chunk)
                    h.update(chunk)
                    md5.update(chunk)
                    n += len(chunk)
            if expected and n != expected:
                raise IOError(f"truncated download: got {n} bytes, expected {expected}")
            if n < spec["min_bytes"]:
                raise IOError(f"implausibly small file: {n} bytes < {spec['min_bytes']}")
            if spec.get("md5") and md5.hexdigest() != spec["md5"]:
                raise IOError(f"md5 mismatch: got {md5.hexdigest()}, published {spec['md5']}")
            tmp.replace(dest)
            entry.update(status="ok", bytes=n, expected_bytes=expected or None, sha256=h.hexdigest(),
                         md5=md5.hexdigest(), md5_verified=bool(spec.get("md5")), seconds=round(time.time() - t0, 1))
    except Exception as exc:  # record the real failure, never pretend success
        entry.update(status="error", error=f"{type(exc).__name__}: {exc}")
        if tmp.exists():
            tmp.unlink()
    entry["finished_at"] = _now()
    return entry


def _digest(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _parquet_readable(path: Path) -> tuple[bool, str]:
    try:
        import pyarrow.parquet as pq
        meta = pq.ParquetFile(path).metadata
        return True, f"{meta.num_rows} rows, {meta.num_columns} columns"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--supplementary", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {"attempts": []}

    e = download(MEAJOR_PARQUET, args.force)
    if e["status"] in ("ok", "cached"):
        ok, msg = _parquet_readable(ROOT / e["path"])
        e["parse_check"] = msg
        if not ok:
            e["status"] = "parse_error"
    manifest["attempts"].append(e)
    print(json.dumps(e, indent=1))
    if e["status"] not in ("ok", "cached"):
        print("Parquet unavailable, trying CSV fallback", file=sys.stderr)
        e2 = download(MEAJOR_CSV, args.force, timeout=120)
        manifest["attempts"].append(e2)
        print(json.dumps(e2, indent=1))

    if args.supplementary:
        for spec in SUPPLEMENTARY:
            e = download(spec, args.force)
            manifest["attempts"].append(e)
            print(json.dumps(e, indent=1))

    MANIFEST.write_text(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
