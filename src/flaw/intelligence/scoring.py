"""Risk scoring engine: weighted formula and optional ML inference."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from flaw.core.paths import DATA_DIR
from flaw.models import EnrichedVulnerability

logger = logging.getLogger("flaw")

MODEL_PATH: Path = DATA_DIR / "models" / "xgboost_portable.json"

WEIGHT_CVSS = 0.30
WEIGHT_EPSS = 0.35
WEIGHT_KEV = 0.25
WEIGHT_EXPLOIT = 0.10

_E = 2.718281828459045


def _formula_score(vuln: EnrichedVulnerability) -> float:
    """Compute risk score using the weighted formula."""
    score = (
        (vuln.cvss / 10.0) * WEIGHT_CVSS
        + vuln.epss * WEIGHT_EPSS
        + (1.0 if vuln.in_kev else 0.0) * WEIGHT_KEV
        + (1.0 if vuln.has_exploit else 0.0) * WEIGHT_EXPLOIT
    )
    return round(score * 100, 1)


class _TreeModel:
    """Minimal XGBoost JSON tree evaluator — zero external dependencies."""

    def __init__(self, trees: list[dict]) -> None:
        self._trees = trees

    def predict(self, features: list[float]) -> float:
        """Sum leaf values across all trees, apply sigmoid."""
        raw = sum(self._walk(tree, features) for tree in self._trees)
        return 1.0 / (1.0 + _E ** (-raw))

    def _walk(self, node: dict, features: list[float]) -> float:
        """Recursively traverse a single decision tree."""
        if "leaf" in node:
            return node["leaf"]

        feature_idx = node["split"]
        threshold = node["split_condition"]

        if features[feature_idx] < threshold:
            return self._walk(node["children"][0], features)
        return self._walk(node["children"][1], features)


_cached_model: _TreeModel | None = None
_model_load_attempted: bool = False


def _load_model() -> _TreeModel | None:
    """Load ML model from exported JSON. Returns None if unavailable."""
    global _cached_model, _model_load_attempted  # noqa: PLW0603

    if _model_load_attempted:
        return _cached_model

    _model_load_attempted = True

    if not MODEL_PATH.is_file():
        logger.debug("ML model not found at %s, using formula", MODEL_PATH)
        return None

    try:
        with open(MODEL_PATH) as f:
            data = json.load(f)

        if data.get("format") != "flaw_xgboost_v1":
            logger.warning("Unknown model format, using formula")
            return None

        _cached_model = _TreeModel(data["trees"])
        logger.debug("ML model loaded: %d trees from %s", data["n_trees"], MODEL_PATH)
        return _cached_model
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("Failed to load ML model: %s", e)
        return None


def score_vulnerabilities(
    vulnerabilities: list[EnrichedVulnerability],
) -> list[EnrichedVulnerability]:
    """
    Assign risk scores and sort by risk descending.

    Uses weighted formula: CVSS + EPSS + KEV + exploit signals.
    ML model is NOT used in the main scoring formula — it predicts
    exploitation probability from CVSS components only, which is
    used for analysis and comparison in the diploma.
    """
    logger.debug("Scoring %d vulnerabilities with weighted formula", len(vulnerabilities))

    scored = []
    for vuln in vulnerabilities:
        scored.append(vuln.model_copy(update={"risk_score": _formula_score(vuln)}))

    scored.sort(key=lambda v: v.risk_score, reverse=True)
    return scored
