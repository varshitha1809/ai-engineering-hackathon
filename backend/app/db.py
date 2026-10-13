"""SQLite persistence (spec §8.2). One short-lived connection per operation; WAL for concurrency.

Raw submitted content lives only in `raw_inputs` (deletable, optional via PHISHDNA_RETAIN_RAW),
separate from normalised evidence (`findings`) and from the audit log, which stores redacted detail only.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY, created_at TEXT NOT NULL, input_source TEXT, channel TEXT DEFAULT 'email', data_label TEXT,
  batch_id TEXT, subject TEXT, from_addr TEXT, from_display TEXT, from_domain TEXT, reply_to_addr TEXT,
  email_date TEXT, raw_sha256 TEXT, preview TEXT, body_text TEXT, parsed_json TEXT,
  verdict TEXT, verdict_label TEXT, risk_score REAL, strengths_json TEXT, fusion_input_json TEXT, decision_json TEXT,
  uncertainty_json TEXT, model_json TEXT, tactics_json TEXT, actions_json TEXT, impact_json TEXT, priority TEXT,
  priority_score REAL, reconstruction_json TEXT, explanation_json TEXT, stage_status_json TEXT,
  model_version TEXT, rules_version TEXT, fusion_version TEXT, latency_ms REAL,
  original_verdict TEXT, original_risk_score REAL, local_state TEXT DEFAULT 'delivered'
);
CREATE INDEX IF NOT EXISTS ix_analyses_created ON analyses(created_at);
CREATE TABLE IF NOT EXISTS raw_inputs (analysis_id TEXT PRIMARY KEY, created_at TEXT, raw BLOB);
CREATE TABLE IF NOT EXISTS analysis_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id TEXT, created_at TEXT, reason TEXT, verdict TEXT, risk_score REAL,
  model_version TEXT, rules_version TEXT, detail_json TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id TEXT NOT NULL, finding_id TEXT, category TEXT, component TEXT,
  severity TEXT, title TEXT, observed_value TEXT, source_location TEXT, method TEXT, version TEXT, confidence REAL,
  status TEXT, explanation TEXT, timestamp TEXT, related_indicator_ids TEXT, related_finding_ids TEXT, span_json TEXT,
  tags_json TEXT);
CREATE INDEX IF NOT EXISTS ix_findings_analysis ON findings(analysis_id);
CREATE TABLE IF NOT EXISTS indicators (
  id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, value TEXT NOT NULL, display_value TEXT,
  first_seen_local TEXT, last_seen_local TEXT, sightings INTEGER DEFAULT 0, reputation TEXT,
  reputation_source TEXT, reputation_checked_at TEXT, provider_detail TEXT, review_status TEXT DEFAULT 'none',
  expires_at TEXT, notes TEXT, UNIQUE(type, value));
CREATE TABLE IF NOT EXISTS analysis_indicators (
  analysis_id TEXT, indicator_id INTEGER, location TEXT, PRIMARY KEY(analysis_id, indicator_id, location));
CREATE TABLE IF NOT EXISTS indicator_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, indicator_id INTEGER, ts TEXT, old_reputation TEXT, new_reputation TEXT,
  source TEXT, actor TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY, created_at TEXT, updated_at TEXT, label TEXT, severity TEXT, severity_score REAL,
  member_count INTEGER, first_seen TEXT, last_seen TEXT, low_and_slow INTEGER, summary_json TEXT);
CREATE TABLE IF NOT EXISTS campaign_members (campaign_id TEXT, analysis_id TEXT, PRIMARY KEY(campaign_id, analysis_id));
CREATE TABLE IF NOT EXISTS campaign_edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id TEXT, src TEXT, dst TEXT, edge_type TEXT, strength REAL,
  strength_label TEXT, evidence_json TEXT, explanation TEXT, created_at TEXT);
CREATE INDEX IF NOT EXISTS ix_edges_src ON campaign_edges(src);
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, analysis_id TEXT UNIQUE, status TEXT, priority TEXT, priority_score REAL, assignee TEXT,
  created_at TEXT, updated_at TEXT, notes_json TEXT, resolution TEXT);
CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id TEXT, case_id TEXT, label TEXT, notes TEXT, reviewer TEXT,
  created_at TEXT, original_verdict TEXT, original_risk_score REAL, model_version TEXT, retraining_status TEXT DEFAULT 'queued');
CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, name TEXT, emails_json TEXT, domains_json TEXT, notes TEXT,
  created_at TEXT, data_label TEXT DEFAULT 'user');
CREATE TABLE IF NOT EXISTS evaluation_runs (
  id TEXT PRIMARY KEY, suite TEXT, status TEXT, progress INTEGER, total INTEGER, started_at TEXT, finished_at TEXT,
  params_json TEXT, metrics_json TEXT, error TEXT, model_version TEXT, rules_version TEXT, fusion_version TEXT);
CREATE TABLE IF NOT EXISTS evaluation_items (
  run_id TEXT, item_id TEXT, base_id TEXT, category TEXT, transform TEXT, label INTEGER, baseline_score REAL,
  baseline_pred INTEGER, hybrid_score REAL, hybrid_verdict TEXT, hybrid_pred INTEGER, strengths_json TEXT,
  latency_ms REAL, detail_json TEXT, PRIMARY KEY(run_id, item_id));
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, action TEXT, actor TEXT, target_type TEXT, target_id TEXT,
  outcome TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_audit_target ON audit_events(target_id);
"""

JSON_COLS = {"parsed_json", "strengths_json", "fusion_input_json", "decision_json", "uncertainty_json", "model_json",
             "tactics_json", "actions_json", "impact_json", "reconstruction_json", "explanation_json", "stage_status_json",
             "related_indicator_ids", "related_finding_ids", "span_json", "tags_json", "summary_json", "evidence_json",
             "notes_json", "emails_json", "domains_json", "params_json", "metrics_json", "detail_json"}


def dumps(v: Any) -> str:
    return json.dumps(v, default=str, ensure_ascii=False)


def decode_row(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    for k in list(d):
        if k in JSON_COLS and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except ValueError:
                pass
    return d


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._init_lock = threading.Lock()
        self.write_lock = threading.RLock()

    def init(self) -> None:
        with self._init_lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.conn() as c:
                c.execute("PRAGMA journal_mode=WAL")
                c.executescript(SCHEMA)

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        try:
            yield c
        finally:
            c.close()

    def one(self, sql: str, params: Iterable = ()) -> dict | None:
        with self.conn() as c:
            return decode_row(c.execute(sql, tuple(params)).fetchone())

    def all(self, sql: str, params: Iterable = ()) -> list[dict]:
        with self.conn() as c:
            return [decode_row(r) for r in c.execute(sql, tuple(params)).fetchall()]  # type: ignore[misc]

    def scalar(self, sql: str, params: Iterable = ()) -> Any:
        with self.conn() as c:
            r = c.execute(sql, tuple(params)).fetchone()
            return r[0] if r else None

    def execute(self, sql: str, params: Iterable = ()) -> int:
        with self.write_lock, self.conn() as c:
            cur = c.execute(sql, tuple(params))
            return cur.lastrowid or cur.rowcount

    def transaction(self):
        return _Tx(self)

    def insert(self, table: str, row: dict, c: sqlite3.Connection | None = None, replace: bool = False) -> int:
        cols = list(row)
        vals = [dumps(row[k]) if (k in JSON_COLS and not isinstance(row[k], str) and row[k] is not None) else row[k] for k in cols]
        sql = f"INSERT {'OR REPLACE ' if replace else ''}INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
        if c is not None:
            return c.execute(sql, vals).lastrowid
        with self.write_lock, self.conn() as cc:
            return cc.execute(sql, vals).lastrowid

    def update(self, table: str, key: str, key_value: Any, fields: dict, c: sqlite3.Connection | None = None) -> None:
        cols = list(fields)
        vals = [dumps(fields[k]) if (k in JSON_COLS and not isinstance(fields[k], str) and fields[k] is not None) else fields[k]
                for k in cols]
        sql = f"UPDATE {table} SET {','.join(f'{k}=?' for k in cols)} WHERE {key}=?"
        if c is not None:
            c.execute(sql, [*vals, key_value])
            return
        with self.write_lock, self.conn() as cc:
            cc.execute(sql, [*vals, key_value])


class _Tx:
    def __init__(self, db: Database):
        self.db = db

    def __enter__(self) -> sqlite3.Connection:
        self.db.write_lock.acquire()
        self.c = sqlite3.connect(self.db.path, timeout=30, isolation_level=None)
        self.c.row_factory = sqlite3.Row
        self.c.execute("BEGIN IMMEDIATE")
        return self.c

    def __exit__(self, et, ev, tb) -> None:
        try:
            self.c.execute("ROLLBACK" if et else "COMMIT")
        finally:
            self.c.close()
            self.db.write_lock.release()
