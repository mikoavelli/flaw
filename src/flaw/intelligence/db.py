"""Single SQLite database for EPSS and KEV cache."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from flaw.core.config import load_settings
from flaw.core.paths import DATA_DIR

DB_PATH: Path = DATA_DIR / "cache.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS epss_scores (
    cve  TEXT PRIMARY KEY,
    score REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS kev_entries (
    cve  TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    """Open a connection and ensure schema exists."""
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    return conn


def get_last_update(conn: sqlite3.Connection, source: str) -> float:
    """Return the unix timestamp of the last update for a given source."""
    cursor = conn.execute(
        "SELECT value FROM metadata WHERE key = ?",
        (f"{source}_updated_at",),
    )
    row = cursor.fetchone()
    return float(row[0]) if row else 0.0


def set_last_update(conn: sqlite3.Connection, source: str) -> None:
    """Record current time as the last update for a given source."""
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        (f"{source}_updated_at", str(time.time())),
    )
    conn.commit()


def is_stale(conn: sqlite3.Connection, source: str) -> bool:
    """Check if a source cache has expired based on configured TTL."""
    settings = load_settings()
    last = get_last_update(conn, source)
    if last == 0.0:
        return True
    age_hours = (time.time() - last) / 3600
    return age_hours >= settings.cache.ttl_hours


def get_entry_count(conn: sqlite3.Connection, table: str) -> int:
    """Return the number of rows in a table."""
    cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
    return cursor.fetchone()[0]


def clear_all(conn: sqlite3.Connection) -> None:
    """Delete all cached data."""
    conn.execute("DELETE FROM epss_scores")
    conn.execute("DELETE FROM kev_entries")
    conn.execute("DELETE FROM metadata")
    conn.commit()
