#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Persistencia SQLite de ROVSKA.

Sin ORM y sin dependencias. Un único fichero ``data/rovska.db`` con modo WAL
para permitir lecturas del panel mientras se ejecuta un escaneo.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from .config import SETTINGS


SCHEMA_VERSION = 1
_LOCK = threading.RLock()


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    target        TEXT NOT NULL,
    profile       TEXT NOT NULL,
    mode          TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'queued',
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    options_json  TEXT NOT NULL DEFAULT '{}',
    stats_json    TEXT NOT NULL DEFAULT '{}',
    error         TEXT,
    created_by    TEXT NOT NULL DEFAULT 'local'
);

CREATE TABLE IF NOT EXISTS hosts (
    scan_id        TEXT NOT NULL,
    ip             TEXT NOT NULL,
    mac            TEXT NOT NULL DEFAULT '',
    vendor         TEXT NOT NULL DEFAULT '',
    hostnames_json TEXT NOT NULL DEFAULT '[]',
    os             TEXT NOT NULL DEFAULT '',
    type           TEXT NOT NULL DEFAULT '',
    risk           INTEGER NOT NULL DEFAULT 0,
    extra_json     TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (scan_id, ip)
);

CREATE TABLE IF NOT EXISTS ports (
    scan_id      TEXT NOT NULL,
    ip           TEXT NOT NULL,
    port         INTEGER NOT NULL,
    proto        TEXT NOT NULL DEFAULT 'tcp',
    state        TEXT NOT NULL DEFAULT 'open',
    service      TEXT NOT NULL DEFAULT '',
    product      TEXT NOT NULL DEFAULT '',
    version      TEXT NOT NULL DEFAULT '',
    extrainfo    TEXT NOT NULL DEFAULT '',
    scripts_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (scan_id, ip, port, proto)
);

CREATE TABLE IF NOT EXISTS findings (
    id               TEXT PRIMARY KEY,
    scan_id          TEXT NOT NULL,
    ip               TEXT NOT NULL DEFAULT '',
    severity         TEXT NOT NULL,
    title            TEXT NOT NULL,
    evidence         TEXT NOT NULL DEFAULT '',
    recommendation   TEXT NOT NULL DEFAULT '',
    cves_json        TEXT NOT NULL DEFAULT '[]',
    cwe_json         TEXT NOT NULL DEFAULT '[]',
    attack_json      TEXT NOT NULL DEFAULT '[]',
    frameworks_json  TEXT NOT NULL DEFAULT '{}',
    source           TEXT NOT NULL DEFAULT 'heuristic',
    confidence       TEXT NOT NULL DEFAULT 'media',
    tags_json        TEXT NOT NULL DEFAULT '[]',
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS good_checks (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    text    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operations (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT,
    kind         TEXT NOT NULL,
    tool         TEXT NOT NULL DEFAULT '',
    target       TEXT NOT NULL DEFAULT '',
    params_json  TEXT NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'queued',
    risk_level   TEXT NOT NULL DEFAULT 'safe',
    dry_run      INTEGER NOT NULL DEFAULT 1,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    exit_code    INTEGER,
    log          TEXT NOT NULL DEFAULT '',
    result_json  TEXT NOT NULL DEFAULT '{}',
    error        TEXT
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL,
    operation_id TEXT,
    tool         TEXT NOT NULL,
    argv_json    TEXT NOT NULL DEFAULT '[]',
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    exit_code    INTEGER,
    output_path  TEXT NOT NULL DEFAULT '',
    parsed       INTEGER NOT NULL DEFAULT 0,
    error        TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT,
    scan_id      TEXT,
    kind         TEXT NOT NULL DEFAULT 'file',
    path         TEXT NOT NULL,
    sha256       TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS annotations (
    ip         TEXT PRIMARY KEY,
    type       TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    level        TEXT NOT NULL DEFAULT 'info',
    operation_id TEXT,
    scan_id      TEXT,
    message      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_dismissals (
    task_id      TEXT PRIMARY KEY,
    dismissed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan   ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_host   ON findings(ip);
CREATE INDEX IF NOT EXISTS idx_ports_scan      ON ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_hosts_scan      ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_operations_scan ON operations(scan_id);
CREATE INDEX IF NOT EXISTS idx_events_op       ON events(operation_id, id);
CREATE INDEX IF NOT EXISTS idx_events_scan     ON events(scan_id, id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_scan  ON tool_runs(scan_id);
"""


def utc_now() -> str:
    """Fecha local legible, coherente con los informes de AUDITORIA_PLUS."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def json_loads(value: Any, default: Any) -> Any:
    if value is None or value == "":
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def connect() -> sqlite3.Connection:
    SETTINGS.ensure_dirs()
    conn = sqlite3.connect(str(SETTINGS.db_path), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


@contextmanager
def tx() -> Iterator[sqlite3.Connection]:
    """Transacción serializada (un solo escritor, lecturas concurrentes)."""
    with _LOCK:
        conn = connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def init_db() -> None:
    with tx() as conn:
        conn.executescript(SCHEMA)
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


def execute(sql: str, params: tuple | list = ()) -> int:
    with tx() as conn:
        cur = conn.execute(sql, params)
        return int(cur.lastrowid or 0)


def executemany(sql: str, rows: list[tuple]) -> None:
    with tx() as conn:
        conn.executemany(sql, rows)


def query(sql: str, params: tuple | list = ()) -> list[dict]:
    with _LOCK:
        conn = connect()
        try:
            cur = conn.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()


def query_one(sql: str, params: tuple | list = ()) -> dict | None:
    rows = query(sql, params)
    return rows[0] if rows else None


def record_event(
    message: str,
    level: str = "info",
    operation_id: str | None = None,
    scan_id: str | None = None,
) -> int:
    """Guarda un evento y lo devuelve para el bus SSE."""
    return execute(
        "INSERT INTO events (ts, level, operation_id, scan_id, message) VALUES (?,?,?,?,?)",
        (utc_now(), level, operation_id, scan_id, message),
    )


def events_since(
    last_id: int = 0,
    operation_id: str | None = None,
    scan_id: str | None = None,
    limit: int = 200,
) -> list[dict]:
    clauses = ["id > ?"]
    params: list[Any] = [last_id]
    if operation_id:
        clauses.append("operation_id = ?")
        params.append(operation_id)
    if scan_id:
        clauses.append("scan_id = ?")
        params.append(scan_id)
    params.append(limit)
    return query(
        f"SELECT * FROM events WHERE {' AND '.join(clauses)} ORDER BY id ASC LIMIT ?",
        params,
    )


# --- anotaciones (compatibles con OVERSEER) --------------------------------


def load_annotations() -> dict[str, dict]:
    rows = query("SELECT ip, type, name FROM annotations")
    return {r["ip"]: {"type": r["type"], "name": r["name"]} for r in rows}


def save_annotation(ip: str, type_value: str = "", name: str = "") -> None:
    with tx() as conn:
        if type_value or name:
            conn.execute(
                """
                INSERT INTO annotations (ip, type, name, updated_at) VALUES (?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    type=excluded.type, name=excluded.name, updated_at=excluded.updated_at
                """,
                (ip, type_value, name, utc_now()),
            )
        else:
            conn.execute("DELETE FROM annotations WHERE ip=?", (ip,))
