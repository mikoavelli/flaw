"""Tests for KEV data module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from flaw.intelligence.db import get_connection
from flaw.intelligence.kev import KEVError, ensure_fresh, is_in_kev, lookup, update


class TestKEVUpdate:
    """Tests for KEV network updates and cache management."""

    @patch("flaw.intelligence.kev.httpx.Client")
    def test_update_success(self, mock_client_class: MagicMock, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": [{"cveID": "CVE-2024-1111"}]}
        mock_client.get.return_value = mock_response

        count = update(conn, tmp_path)
        assert count == 1
        assert is_in_kev(conn, "CVE-2024-1111")
        conn.close()

    @patch("flaw.intelligence.kev.httpx.Client")
    def test_update_http_error(self, mock_client_class: MagicMock, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPError("Network Error")
        mock_client.get.return_value = mock_response

        with pytest.raises(KEVError, match="Failed to download"):
            update(conn, tmp_path)
        conn.close()

    @patch("flaw.intelligence.kev.httpx.Client")
    def test_update_json_error(self, mock_client_class: MagicMock, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("Bad JSON")
        mock_client.get.return_value = mock_response

        with pytest.raises(KEVError, match="Failed to parse"):
            update(conn, tmp_path)
        conn.close()

    @patch("flaw.intelligence.kev.update")
    def test_ensure_fresh_stale(self, mock_update: MagicMock, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        with patch("flaw.intelligence.kev.is_stale", return_value=True):
            ensure_fresh(conn, tmp_path)
            mock_update.assert_called_once()
        conn.close()

    @patch("flaw.intelligence.kev.update", side_effect=KEVError("fail"))
    def test_ensure_fresh_stale_error_handled(self, mock_update: MagicMock, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        with patch("flaw.intelligence.kev.is_stale", return_value=True):
            ensure_fresh(conn, tmp_path)
        conn.close()

    @patch("flaw.intelligence.kev.update")
    def test_ensure_fresh_offline(self, mock_update: MagicMock, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        ensure_fresh(conn, tmp_path, offline=True)
        mock_update.assert_not_called()
        conn.close()


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
