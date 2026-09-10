"""SQLite storage for Bootleg. Thin helpers, no ORM."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS toolkits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    slug            TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    token           TEXT NOT NULL,
    archive_secret  TEXT NOT NULL DEFAULT '',
    setup_script    TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    archive_path    TEXT,
    archive_sha256  TEXT,
    archive_size    INTEGER NOT NULL DEFAULT 0,
    archive_built_at TEXT,
    archive_revision INTEGER NOT NULL DEFAULT 0,
    dirty           INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tools (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    toolkit_id    INTEGER NOT NULL REFERENCES toolkits(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    kind          TEXT NOT NULL,            -- 'upload' | 'github'
    enabled       INTEGER NOT NULL DEFAULT 1,
    install_dir   TEXT NOT NULL DEFAULT '',  -- path inside the toolkit
    unpack        INTEGER NOT NULL DEFAULT 0, -- extract archive on the target
    notes         TEXT NOT NULL DEFAULT '',
    filename      TEXT,
    blob_path     TEXT,
    size          INTEGER NOT NULL DEFAULT 0,
    sha256        TEXT,
    version       TEXT NOT NULL DEFAULT '',
    added_at      TEXT NOT NULL,
    updated_at    TEXT,
    -- github tracking
    gh_repo       TEXT,
    gh_pattern    TEXT NOT NULL DEFAULT '',
    gh_prerelease INTEGER NOT NULL DEFAULT 0,
    gh_source     TEXT NOT NULL DEFAULT 'release',  -- 'release' | 'source'
    gh_checked_at TEXT,
    gh_status     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_tools_toolkit ON tools(toolkit_id);

-- One row per deploy script handed out. Only the hash is kept: the server
-- never needs the token back, so a database read yields nothing usable.
-- A key pins itself to the first host that deploys with it, so the script can
-- be re-run there but is useless to anyone who lifts it off that host.
CREATE TABLE IF NOT EXISTS deploy_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    toolkit_id  INTEGER NOT NULL REFERENCES toolkits(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    label       TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    bound_ip     TEXT NOT NULL DEFAULT '',
    used_at      TEXT,
    last_used_at TEXT,
    use_count    INTEGER NOT NULL DEFAULT 0,
    revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_keys_hash ON deploy_keys(token_hash);
CREATE INDEX IF NOT EXISTS idx_keys_toolkit ON deploy_keys(toolkit_id);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    toolkit_id INTEGER,
    level      TEXT NOT NULL DEFAULT 'info',
    message    TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
"""

_write_lock = threading.Lock()


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def get_db() -> sqlite3.Connection:
    """Request-scoped connection."""
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db(path: str | Path) -> None:
    conn = connect(path)
    with conn:
        conn.executescript(SCHEMA)
        _migrate(conn)
    conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after a database was first created."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(toolkits)")}
    if "archive_secret" not in columns:
        conn.execute("ALTER TABLE toolkits ADD COLUMN archive_secret TEXT NOT NULL DEFAULT ''")

    key_columns = {row["name"] for row in conn.execute("PRAGMA table_info(deploy_keys)")}
    for name, ddl in (("bound_ip", "TEXT NOT NULL DEFAULT ''"),
                      ("last_used_at", "TEXT"),
                      ("use_count", "INTEGER NOT NULL DEFAULT 0")):
        if name not in key_columns:
            conn.execute("ALTER TABLE deploy_keys ADD COLUMN {0} {1}".format(name, ddl))
    if "used_by" in key_columns and "bound_ip" not in key_columns:
        conn.execute("UPDATE deploy_keys SET bound_ip = used_by WHERE used_by != ''")
    # Toolkits created before keys were split still derive their archive
    # password from the old token; keep those archives readable.
    conn.execute("UPDATE toolkits SET archive_secret = token WHERE archive_secret = ''")


def get_setting(conn: sqlite3.Connection, key: str, default=None):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    with _write_lock, conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )


def log_event(conn: sqlite3.Connection, message: str, level: str = "info",
              toolkit_id: int | None = None) -> None:
    from .util import now_iso
    with _write_lock, conn:
        conn.execute(
            "INSERT INTO events (toolkit_id, level, message, created_at) VALUES (?,?,?,?)",
            (toolkit_id, level, message, now_iso()),
        )
        conn.execute(
            "DELETE FROM events WHERE id NOT IN "
            "(SELECT id FROM events ORDER BY id DESC LIMIT 500)"
        )
