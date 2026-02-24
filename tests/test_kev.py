"""Tests for KEV data module."""

from __future__ import annotations

from pathlib import Path

from flaw.intelligence.db import get_connection
from flaw.intelligence.kev import is_in_kev, lookup


class TestKEVLookup:
    """Tests for KEV lookups (no network)."""

    def test_is_in_kev_found(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        conn.execute("INSERT INTO kev_entries (cve) VALUES (?)", ("CVE-2023-44487",))
        conn.commit()

        assert is_in_kev(conn, "CVE-2023-44487") is True
        conn.close()

    def test_is_in_kev_not_found(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        assert is_in_kev(conn, "CVE-9999-0000") is False
        conn.close()

    def test_lookup_batch(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        conn.executemany(
            "INSERT INTO kev_entries (cve) VALUES (?)",
            [("CVE-2023-0001",), ("CVE-2023-0002",)],
        )
        conn.commit()

        result = lookup(conn, ["CVE-2023-0001", "CVE-2023-0003"])
        assert result == {"CVE-2023-0001"}
        conn.close()

    def test_lookup_empty_input(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        assert lookup(conn, []) == set()
        conn.close()
