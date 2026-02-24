"""Tests for the cache database module."""

from __future__ import annotations

import time
from pathlib import Path

from flaw.intelligence.db import (
    clear_all,
    get_connection,
    get_entry_count,
    get_last_update,
    is_stale,
    set_last_update,
)


class TestDatabase:
    """Tests for SQLite cache database."""

    def test_schema_created(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]
        assert "epss_scores" in tables
        assert "kev_entries" in tables
        assert "metadata" in tables
        conn.close()

    def test_set_and_get_last_update(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        set_last_update(conn, "epss")
        ts = get_last_update(conn, "epss")
        assert ts > 0
        assert abs(ts - time.time()) < 2
        conn.close()

    def test_get_last_update_missing(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        assert get_last_update(conn, "epss") == 0.0
        conn.close()

    def test_is_stale_when_never_updated(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        assert is_stale(conn, "epss") is True
        conn.close()

    def test_is_stale_when_fresh(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        set_last_update(conn, "epss")
        assert is_stale(conn, "epss") is False
        conn.close()

    def test_is_stale_when_expired(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("epss_updated_at", str(time.time() - 90000)),
        )
        conn.commit()
        assert is_stale(conn, "epss") is True
        conn.close()

    def test_get_entry_count(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        assert get_entry_count(conn, "epss_scores") == 0
        conn.execute("INSERT INTO epss_scores (cve, score) VALUES ('CVE-2024-0001', 0.5)")
        conn.commit()
        assert get_entry_count(conn, "epss_scores") == 1
        conn.close()

    def test_clear_all(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        conn.execute("INSERT INTO epss_scores (cve, score) VALUES ('CVE-2024-0001', 0.5)")
        conn.execute("INSERT INTO kev_entries (cve) VALUES ('CVE-2024-0001')")
        set_last_update(conn, "epss")
        conn.commit()

        clear_all(conn)

        assert get_entry_count(conn, "epss_scores") == 0
        assert get_entry_count(conn, "kev_entries") == 0
        assert get_last_update(conn, "epss") == 0.0
        conn.close()
