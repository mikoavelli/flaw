"""Tests for the risk scoring engine."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from flaw.intelligence.scoring import (
    WEIGHT_CVSS,
    WEIGHT_EPSS,
    WEIGHT_EXPLOIT,
    WEIGHT_KEV,
    _formula_score,
    _TreeModel,
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


class TestTreeModel:
    """Tests for the pure-Python tree evaluator."""

    def test_simple_tree(self) -> None:
        tree = {
            "split": 0,
            "split_condition": 5.0,
            "children": [
                {"leaf": -1.0},
                {"leaf": 1.0},
            ],
        }
        model = _TreeModel([tree])

        low = model.predict([3.0, 0.0, 0.0, 0.0])
        high = model.predict([7.0, 0.0, 0.0, 0.0])

        assert low < 0.5
        assert high > 0.5

    def test_multi_tree(self) -> None:
        tree1 = {"leaf": 0.5}
        tree2 = {"leaf": 0.5}
        model = _TreeModel([tree1, tree2])

        result = model.predict([0.0, 0.0, 0.0, 0.0])
        # sigmoid(1.0) ≈ 0.731
        assert 0.7 < result < 0.8

    def test_empty_trees(self) -> None:
        model = _TreeModel([])
        result = model.predict([5.0, 0.5, 0.0, 0.0])
        # sigmoid(0) = 0.5
        assert result == 0.5


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

    def test_ml_model_used_when_available(self, tmp_path: Path) -> None:
        """If a portable model file exists, it should be used."""
        import flaw.intelligence.scoring as scoring_module

        # Reset cached model
        scoring_module._cached_model = None
        scoring_module._model_load_attempted = False

        model_data = {
            "format": "flaw_xgboost_v1",
            "features": ["cvss", "epss", "in_kev", "has_exploit"],
            "n_trees": 1,
            "trees": [
                {
                    "split": 1,  # epss
                    "split_condition": 0.5,
                    "children": [
                        {"leaf": -2.0},
                        {"leaf": 2.0},
                    ],
                }
            ],
        }
        model_file = tmp_path / "model.json"
        model_file.write_text(json.dumps(model_data))

        with patch.object(scoring_module, "MODEL_PATH", model_file):
            scoring_module._cached_model = None
            scoring_module._model_load_attempted = False

            vulns = [
                _make_vuln(cvss=5.0, epss=0.1),
                _make_vuln(cvss=5.0, epss=0.9),
            ]
            scored = score_vulnerabilities(vulns)

            assert scored[0].risk_score > scored[1].risk_score
            assert scored[0].epss == 0.9

        # Cleanup
        scoring_module._cached_model = None
        scoring_module._model_load_attempted = False
