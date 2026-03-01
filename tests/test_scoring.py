"""Tests for the risk scoring engine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from flaw.intelligence.scoring import (
    WEIGHT_CVSS,
    MLScorer,
    _formula_score,
    _parse_cvss_vector,
    _parse_purl,
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
    return EnrichedVulnerability(
        cve_id="CVE-2024-0001",
        pkg_name="test-pkg",
        installed_version="1.0.0",
        severity="HIGH",
        cvss=cvss,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        description="A fake vulnerability for testing.",
        cwe_ids=["CWE-79"],
        purl="pkg:npm/test-pkg@1.0.0",
        epss=epss,
        in_kev=in_kev,
        has_exploit=has_exploit,
    )


class TestParsers:
    def test_parse_purl(self) -> None:
        assert _parse_purl("pkg:deb/debian/util-linux@2.41-5?arch=amd64") == (
            "debian",
            "util-linux",
        )
        assert _parse_purl("pkg:npm/express@4.17.1") == ("npm", "express")

        assert _parse_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.1") == (
            "gin-gonic",
            "gin",
        )

        assert _parse_purl("pkg:maven/org.apache.xmlgraphics/batik-anim@1.14") == (
            "org.apache.xmlgraphics",
            "batik-anim",
        )

        assert _parse_purl("invalid") == ("", "")
        assert _parse_purl("") == ("", "")

        class BadObj:
            def __bool__(self) -> bool:
                return True

            def startswith(self, val: str) -> bool:
                return True

        assert _parse_purl(BadObj()) == ("", "")  # type: ignore

    def test_parse_cvss_vector(self) -> None:
        vec = _parse_cvss_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N")
        assert vec["AV"] == 3
        assert vec["AC"] == 0
        assert vec["PR"] == 2
        assert vec["UI"] == 0
        assert vec["S"] == 1
        assert vec["C"] == 1
        assert vec["I"] == 1
        assert vec["A"] == 0

        assert _parse_cvss_vector("")["AV"] == -1
        assert _parse_cvss_vector("CVSS:3.1/UNKNOWN:X")["AV"] == -1


class TestFormulaScore:
    def test_all_zeros(self) -> None:
        vuln = _make_vuln()
        assert _formula_score(vuln) == 0.0

    def test_max_score(self) -> None:
        vuln = _make_vuln(cvss=10.0, epss=1.0, in_kev=True, has_exploit=True)
        assert round(_formula_score(vuln), 1) == 100.0

    def test_cvss_only(self) -> None:
        vuln = _make_vuln(cvss=10.0)
        expected = 1.0 * WEIGHT_CVSS * 100
        assert round(_formula_score(vuln), 1) == round(expected, 1)


class TestMLScorer:
    def test_ml_scoring_logic(self) -> None:
        model_data = {
            "format": "flaw_xgboost_v1",
            "features": [
                "cvss",
                "av",
                "ac",
                "pr",
                "ui",
                "s",
                "c",
                "i",
                "a",
                "v_npm",
                "p_test-pkg",
            ],
            "vendor_vocab": ["npm"],
            "product_vocab": ["test-pkg"],
            "n_trees": 1,
            "trees": [
                {
                    "split": 0,
                    "split_condition": 5.0,
                    "children": [{"leaf": -1.0}, {"leaf": 1.0}],
                }
            ],
        }
        model = MLScorer(model_data)
        assert model.score(_make_vuln(cvss=3.0)) < 50.0
        assert model.score(_make_vuln(cvss=7.0)) > 50.0


class TestScoreVulnerabilities:
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

    def test_load_corrupted_model(self, tmp_path: Path) -> None:
        import flaw.intelligence.scoring as scoring_module

        scoring_module._cached_model = None
        scoring_module._model_load_attempted = False

        model_file = tmp_path / "corrupted.json"
        model_file.write_text("{invalid json")

        with patch.object(scoring_module, "MODEL_PATH", model_file):
            assert scoring_module._load_model() is None

        scoring_module._cached_model = None
        scoring_module._model_load_attempted = False

    def test_load_wrong_format_model(self, tmp_path: Path) -> None:
        import flaw.intelligence.scoring as scoring_module

        scoring_module._cached_model = None
        scoring_module._model_load_attempted = False

        model_file = tmp_path / "wrong.json"
        model_file.write_text('{"format": "wrong"}')

        with patch.object(scoring_module, "MODEL_PATH", model_file):
            assert scoring_module._load_model() is None

        scoring_module._cached_model = None
        scoring_module._model_load_attempted = False
