"""SQLite persistence (WAL mode, one short-lived connection per request)."""
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'user',
  sender TEXT, subject TEXT,
  threat_type TEXT, bucket TEXT, level TEXT,
  risk INTEGER, origin_conf INTEGER,
  status TEXT NOT NULL DEFAULT 'New',
  sha256 TEXT NOT NULL,
  raw BLOB NOT NULL,
  result TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id TEXT REFERENCES analyses(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'Medium',
  status TEXT NOT NULL DEFAULT 'Under Investigation',
  assignee TEXT NOT NULL DEFAULT 'Security Team',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  note TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT,
  status TEXT NOT NULL DEFAULT 'OK',
  ip TEXT
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=8000")
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE_PATH"])
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(path: str):
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    conn = connect(path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def save_analysis(db, result: dict, raw: bytes, source: str = "user", created_at: str | None = None):
    if created_at:
        result["created_at"] = created_at
    db.execute(
        "INSERT INTO analyses (id, created_at, source, sender, subject, threat_type, bucket, level, risk,"
        " origin_conf, status, sha256, raw, result) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (result["id"], result["created_at"], source, result["identity"]["sender"], result["identity"]["subject"],
         result["threat_type"], result["bucket"], result["risk"]["level"], result["risk"]["score"],
         result["origin"]["confidence"], result["status"], result["evidence"]["sha256"], raw, json.dumps(result)),
    )
    db.commit()


def audit(db, action: str, resource: str = "", status: str = "OK", ip: str = "", actor: str = "analyst"):
    db.execute("INSERT INTO audit (ts, actor, action, resource, status, ip) VALUES (?,?,?,?,?,?)",
               (now_iso(), actor, action, resource, status, ip))
    db.commit()


def purge_old(db, days: int) -> int:
    if days <= 0:
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    cur = db.execute("DELETE FROM analyses WHERE created_at < ?", (cutoff,))
    db.commit()
    return cur.rowcount


def case_code(case_id: int) -> str:
    return f"CASE-{1000 + int(case_id)}"
