"""Tests for the risk scoring engine."""

from __future__ import annotations

from flaw.intelligence.scoring import (
    WEIGHT_CVSS,
    WEIGHT_EPSS,
    WEIGHT_EXPLOIT,
    WEIGHT_KEV,
    _formula_score,
    score_vulnerabilities,
)
from flaw.models import EnrichedVulnerability


def _make_vuln(
    *,
    cvss: float = 0.0,
    epss: float = 0.0,
    in_kev: bool = False,
    has_exploit: bool = False,
) -> EnrichedVulnerability:
    """Helper to create a test vulnerability."""
    return EnrichedVulnerability(
        cve_id="CVE-2024-0001",
        pkg_name="test-pkg",
        installed_version="1.0.0",
        severity="HIGH",
        cvss=cvss,
        epss=epss,
        in_kev=in_kev,
        has_exploit=has_exploit,
    )


class TestFormulaScore:
    """Tests for the weighted formula scoring."""

    def test_all_zeros(self) -> None:
        vuln = _make_vuln()
        assert _formula_score(vuln) == 0.0

    def test_max_score(self) -> None:
        vuln = _make_vuln(cvss=10.0, epss=1.0, in_kev=True, has_exploit=True)
        assert _formula_score(vuln) == 100.0

    def test_cvss_only(self) -> None:
        vuln = _make_vuln(cvss=10.0)
        expected = round(1.0 * WEIGHT_CVSS * 100, 1)
        assert _formula_score(vuln) == expected

    def test_epss_only(self) -> None:
        vuln = _make_vuln(epss=0.5)
        expected = round(0.5 * WEIGHT_EPSS * 100, 1)
        assert _formula_score(vuln) == expected

    def test_kev_flag(self) -> None:
        vuln = _make_vuln(in_kev=True, has_exploit=True)
        expected = round((WEIGHT_KEV + WEIGHT_EXPLOIT) * 100, 1)
        assert _formula_score(vuln) == expected

    def test_realistic_critical(self) -> None:
        vuln = _make_vuln(cvss=7.5, epss=0.9214, in_kev=True, has_exploit=True)
        score = _formula_score(vuln)
        assert score > 80.0
        assert score <= 100.0

    def test_realistic_low(self) -> None:
        vuln = _make_vuln(cvss=4.3, epss=0.001)
        score = _formula_score(vuln)
        assert score < 20.0
        assert score > 0.0


class TestScoreVulnerabilities:
    """Tests for the scoring pipeline."""

    def test_sorted_by_risk_descending(self) -> None:
        vulns = [
            _make_vuln(cvss=3.0, epss=0.01),
            _make_vuln(cvss=9.0, epss=0.9, in_kev=True, has_exploit=True),
            _make_vuln(cvss=5.0, epss=0.1),
        ]
        scored = score_vulnerabilities(vulns)
        assert scored[0].risk_score >= scored[1].risk_score
        assert scored[1].risk_score >= scored[2].risk_score

    def test_empty_list(self) -> None:
        assert score_vulnerabilities([]) == []

    def test_scores_are_assigned(self) -> None:
        vulns = [_make_vuln(cvss=7.5, epss=0.5)]
        scored = score_vulnerabilities(vulns)
        assert scored[0].risk_score > 0.0

    def test_original_not_mutated(self) -> None:
        vulns = [_make_vuln(cvss=7.5, epss=0.5)]
        score_vulnerabilities(vulns)
        assert vulns[0].risk_score == 0.0
