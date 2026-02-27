"""Tests for the risk scoring engine."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from flaw.intelligence.scoring import (
    WEIGHT_CVSS,
    MLScorer,
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
    return EnrichedVulnerability(
        cve_id="CVE-2024-0001",
        pkg_name="test-pkg",
        installed_version="1.0.0",
        severity="HIGH",
        cvss=cvss,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        description="A fake vulnerability for testing.",
        cwe_ids=["CWE-79"],
        epss=epss,
        in_kev=in_kev,
        has_exploit=has_exploit,
    )


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
        # Minimal fake model with NLP logic
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
                "p_test-pkg",
                "cwe-79",
                "txt_fake",
            ],
            "vendor_vocab": [],
            "product_vocab": ["test-pkg"],
            "cwe_vocab": ["cwe-79"],
            "desc_vocab": ["fake"],
            "desc_idf": [1.5],
            "n_trees": 1,
            "trees": [
                {
                    "split": 0,  # cvss
                    "split_condition": 5.0,
                    "children": [
                        {"leaf": -1.0},
                        {"leaf": 1.0},
                    ],
                }
            ],
        }
        model = MLScorer(model_data)

        low_vuln = _make_vuln(cvss=3.0)
        high_vuln = _make_vuln(cvss=7.0)

        assert model.score(low_vuln) < 50.0
        assert model.score(high_vuln) > 50.0


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

    def test_ml_model_used_when_available(self, tmp_path: Path) -> None:
        import flaw.intelligence.scoring as scoring_module

        scoring_module._cached_model = None
        scoring_module._model_load_attempted = False

        model_data = {
            "format": "flaw_xgboost_v1",
            "features": ["cvss", "av", "ac", "pr", "ui", "s", "c", "i", "a"],
            "n_trees": 1,
            "trees": [
                {
                    "split": 0,
                    "split_condition": 5.0,
                    "children": [{"leaf": -2.0}, {"leaf": 2.0}],
                }
            ],
        }
        model_file = tmp_path / "model.json"
        model_file.write_text(json.dumps(model_data))

        with patch.object(scoring_module, "MODEL_PATH", model_file):
            scoring_module._cached_model = None
            scoring_module._model_load_attempted = False

            vulns = [_make_vuln(cvss=4.0), _make_vuln(cvss=9.0)]
            scored = score_vulnerabilities(vulns)

            # High CVSS node goes right -> leaf 2.0 -> sigmoid(2) = 0.88 -> 88.0
            assert scored[0].risk_score > 80.0
            # Low CVSS node goes left -> leaf -2.0 -> sigmoid(-2) = 0.11 -> 11.9
            assert scored[1].risk_score < 20.0

        scoring_module._cached_model = None
        scoring_module._model_load_attempted = False
