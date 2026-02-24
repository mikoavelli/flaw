"""Risk scoring engine: weighted formula and optional ML inference."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from flaw.core.paths import DATA_DIR
from flaw.models import EnrichedVulnerability

logger = logging.getLogger("flaw")

MODEL_PATH: Path = DATA_DIR / "models" / "xgboost_v1.json"

# ── Weighted formula (baseline) ──────────────────────────────────

WEIGHT_CVSS = 0.30
WEIGHT_EPSS = 0.35
WEIGHT_KEV = 0.25
WEIGHT_EXPLOIT = 0.10


def _formula_score(vuln: EnrichedVulnerability) -> float:
    """Compute risk score using the weighted formula."""
    score = (
        (vuln.cvss / 10.0) * WEIGHT_CVSS
        + vuln.epss * WEIGHT_EPSS
        + (1.0 if vuln.in_kev else 0.0) * WEIGHT_KEV
        + (1.0 if vuln.has_exploit else 0.0) * WEIGHT_EXPLOIT
    )
    return round(score * 100, 1)


# ── ML inference (pure Python, no dependencies) ──────────────────


class _TreeModel:
    """Minimal XGBoost JSON tree evaluator."""

    def __init__(self, trees: list[dict]) -> None:
        self._trees = trees

    def predict(self, features: list[float]) -> float:
        """Sum leaf values across all trees."""
        raw = sum(self._walk(tree, features) for tree in self._trees)
        # Sigmoid for binary classification
        return 1.0 / (1.0 + 2.718281828 ** (-raw))

    def _walk(self, node: dict, features: list[float]) -> float:
        """Recursively traverse a single tree."""
        if "leaf" in node:
            return node["leaf"]

        feature_idx = node["split"]
        threshold = node["split_condition"]

        if features[feature_idx] < threshold:
            return self._walk(node["children"][0], features)
        return self._walk(node["children"][1], features)


_cached_model: _TreeModel | None = None


def _load_model() -> _TreeModel | None:
    """Load ML model from JSON. Returns None if not available."""
    global _cached_model  # noqa: PLW0603

    if _cached_model is not None:
        return _cached_model

    if not MODEL_PATH.is_file():
        return None

    try:
        with open(MODEL_PATH) as f:
            data = json.load(f)
        _cached_model = _TreeModel(data["trees"])
        logger.debug("ML model loaded from %s", MODEL_PATH)
        return _cached_model
    except (json.JSONDecodeError, KeyError, TypeError):
        logger.warning("Failed to load ML model, falling back to formula.")
        return None


def _ml_score(vuln: EnrichedVulnerability) -> float:
    """Compute risk score using the ML model."""
    model = _load_model()
    if model is None:
        return _formula_score(vuln)

    features = [
        vuln.cvss,
        vuln.epss,
        1.0 if vuln.in_kev else 0.0,
        1.0 if vuln.has_exploit else 0.0,
    ]
    return round(model.predict(features) * 100, 1)


# ── Public API ────────────────────────────────────────────────────


def score_vulnerabilities(
    vulnerabilities: list[EnrichedVulnerability],
) -> list[EnrichedVulnerability]:
    """
    Assign risk scores and sort by risk descending.

    Uses ML model if available, otherwise falls back to weighted formula.
    """
    model = _load_model()
    score_fn = _ml_score if model is not None else _formula_score

    scored = []
    for vuln in vulnerabilities:
        scored.append(vuln.model_copy(update={"risk_score": score_fn(vuln)}))

    scored.sort(key=lambda v: v.risk_score, reverse=True)
    return scored
