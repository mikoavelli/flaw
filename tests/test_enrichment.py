"""Tests for vulnerability enrichment."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from flaw.intelligence.db import get_connection
from flaw.intelligence.enrichment import enrich
from flaw.intelligence.epss import EPSSError
from flaw.intelligence.kev import KEVError
from flaw.models import Vulnerability


def _make_raw_vuln(cve_id: str = "CVE-2023-44487") -> Vulnerability:
    """Create a raw Trivy vulnerability for testing."""
    return Vulnerability.model_validate(
        {
            "VulnerabilityID": cve_id,
            "PkgName": "nghttp2",
            "InstalledVersion": "1.55.1",
            "Severity": "CRITICAL",
            "CVSS": {"nvd": {"V3Score": 7.5}},
        }
    )


class TestEnrich:
    """Tests for the enrich function."""

    def test_enrich_offline_empty_cache(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        vulns = [_make_raw_vuln()]

        enriched = enrich(conn, vulns, tmp_path, offline=True)

        assert len(enriched) == 1
        assert enriched[0].cve_id == "CVE-2023-44487"
        assert enriched[0].epss == 0.0
        assert enriched[0].in_kev is False
        assert enriched[0].risk_score == 0.0
        conn.close()

    def test_enrich_preserves_fields(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        vulns = [_make_raw_vuln()]

        enriched = enrich(conn, vulns, tmp_path, offline=True)

        assert enriched[0].pkg_name == "nghttp2"
        assert enriched[0].installed_version == "1.55.1"
        assert enriched[0].severity == "CRITICAL"
        assert enriched[0].cvss == 7.5
        conn.close()

    def test_enrich_empty_list(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        assert enrich(conn, [], tmp_path) == []
        conn.close()

    def test_enrich_with_prepopulated_db(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")

        conn.execute(
            "INSERT INTO epss_scores (cve, score) VALUES (?, ?)",
            ("CVE-2023-44487", 0.9214),
        )
        conn.execute("INSERT INTO kev_entries (cve) VALUES (?)", ("CVE-2023-44487",))
        conn.commit()

        vulns = [_make_raw_vuln("CVE-2023-44487")]
        enriched = enrich(conn, vulns, tmp_path, offline=True)

        assert enriched[0].epss == 0.9214
        assert enriched[0].in_kev is True
        assert enriched[0].has_exploit is True
        conn.close()

    @patch("flaw.intelligence.enrichment.epss.update")
    @patch("flaw.intelligence.enrichment.kev.update")
    def test_enrich_force_refresh(
        self, mock_kev: MagicMock, mock_epss: MagicMock, tmp_path: Path
    ) -> None:
        conn = get_connection(tmp_path / "test.db")
        vulns = [_make_raw_vuln()]
        enrich(conn, vulns, tmp_path, force_refresh=True)
        mock_epss.assert_called_once()
        mock_kev.assert_called_once()
        conn.close()

    @patch("flaw.intelligence.enrichment.epss.update", side_effect=EPSSError("fail"))
    @patch("flaw.intelligence.enrichment.kev.update", side_effect=KEVError("fail"))
    def test_enrich_force_refresh_errors(
        self, mock_kev: MagicMock, mock_epss: MagicMock, tmp_path: Path
    ) -> None:
        conn = get_connection(tmp_path / "test.db")
        vulns = [_make_raw_vuln()]
        enrich(conn, vulns, tmp_path, force_refresh=True)
        conn.close()
