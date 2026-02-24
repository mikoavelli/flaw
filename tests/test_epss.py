"""Tests for EPSS data module."""

from __future__ import annotations

from pathlib import Path

from flaw.intelligence.db import get_connection
from flaw.intelligence.epss import get_score, get_scores


class TestEPSSLookup:
    """Tests for EPSS score lookups (no network)."""

    def test_get_score_found(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        conn.execute(
            "INSERT INTO epss_scores (cve, score) VALUES (?, ?)",
            ("CVE-2023-44487", 0.9214),
        )
        conn.commit()

        assert get_score(conn, "CVE-2023-44487") == 0.9214
        conn.close()

    def test_get_score_not_found(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        assert get_score(conn, "CVE-9999-0000") == 0.0
        conn.close()

    def test_get_scores_batch(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        conn.executemany(
            "INSERT INTO epss_scores (cve, score) VALUES (?, ?)",
            [
                ("CVE-2023-0001", 0.5),
                ("CVE-2023-0002", 0.8),
                ("CVE-2023-0003", 0.1),
            ],
        )
        conn.commit()

        result = get_scores(conn, ["CVE-2023-0001", "CVE-2023-0003", "CVE-9999-0000"])
        assert result == {"CVE-2023-0001": 0.5, "CVE-2023-0003": 0.1}
        conn.close()

    def test_get_scores_empty_input(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        assert get_scores(conn, []) == {}
        conn.close()
