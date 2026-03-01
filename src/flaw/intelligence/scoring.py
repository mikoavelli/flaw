"""Risk scoring engine: weighted formula and ML inference."""

from __future__ import annotations

import json
import logging
import math
import re
from pathlib import Path

from flaw.core.paths import DATA_DIR
from flaw.models import EnrichedVulnerability

logger = logging.getLogger("flaw")

MODEL_PATH: Path = DATA_DIR / "models" / "xgboost_portable.json"

WEIGHT_CVSS = 0.30
WEIGHT_EPSS = 0.35
WEIGHT_KEV = 0.25
WEIGHT_EXPLOIT = 0.10

CVSS_MAP = {
    "AV": {"N": 3, "A": 2, "L": 1, "P": 0},
    "AC": {"L": 1, "H": 0},
    "PR": {"N": 2, "L": 1, "H": 0},
    "UI": {"N": 1, "R": 0},
    "S": {"U": 0, "C": 1},
    "C": {"H": 2, "L": 1, "N": 0},
    "I": {"H": 2, "L": 1, "N": 0},
    "A": {"H": 2, "L": 1, "N": 0},
}


def _parse_cvss_vector(vector: str) -> dict[str, int]:
    p = {"AV": -1, "AC": -1, "PR": -1, "UI": -1, "S": -1, "C": -1, "I": -1, "A": -1}
    if not vector:
        return p

    parts = vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/")
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            if k in CVSS_MAP and v in CVSS_MAP[k]:
                p[k] = CVSS_MAP[k][v]
    return p


def _parse_purl(purl: str) -> tuple[str, str]:
    """
    Extracts vendor/namespace and product from a Package URL.

    Examples:
      pkg:deb/debian/util-linux@2.41 -> vendor='debian', product='util-linux'
      pkg:npm/express@4.17 -> vendor='npm', product='express'
      pkg:golang/github.com/gin-gonic/gin -> vendor='gin-gonic', product='gin'
    """
    if not purl or not purl.startswith("pkg:"):
        return "", ""
    try:
        clean_purl = purl[4:].split("@")[0].split("?")[0]
        parts = clean_purl.split("/")

        product = parts[-1]
        vendor = ""

        if len(parts) >= 2:
            vendor = parts[-2]

        return vendor, product
    except Exception:
        return "", ""


def _formula_score(vuln: EnrichedVulnerability) -> float:
    """Compute fallback risk score using the weighted formula."""
    score = (
        (vuln.cvss / 10.0) * WEIGHT_CVSS
        + vuln.epss * WEIGHT_EPSS
        + (1.0 if vuln.in_kev else 0.0) * WEIGHT_KEV
        + (1.0 if vuln.has_exploit else 0.0) * WEIGHT_EXPLOIT
    )
    return score * 100.0


class MLScorer:
    """Pure-Python XGBoost NLP evaluator — zero external dependencies."""

    def __init__(self, data: dict) -> None:
        self.features = data["features"]
        self.trees = data["trees"]

        self.vendor_vocab = data.get("vendor_vocab", [])
        self.product_vocab = data.get("product_vocab", [])
        self.cwe_vocab = data.get("cwe_vocab", [])
        self.desc_vocab = data.get("desc_vocab", [])
        self.desc_idf = data.get("desc_idf", [])

        self._v_map = {v: i for i, v in enumerate(self.vendor_vocab)}
        self._p_map = {p: i for i, p in enumerate(self.product_vocab)}
        self._cwe_map = {c: i for i, c in enumerate(self.cwe_vocab)}
        self._desc_map = {d: i for i, d in enumerate(self.desc_vocab)}

        self._word_pattern = re.compile(r"\b[a-zA-Z]{3,}\b")
        self._token_pattern = re.compile(r"[^\s]+")

    def _tokenize_words(self, text: str) -> list[str]:
        return self._word_pattern.findall(text.lower())

    def _tokenize_tokens(self, text: str) -> list[str]:
        return self._token_pattern.findall(text.lower())

    def score(self, vuln: EnrichedVulnerability) -> float:
        """Compute the ML exploitation probability (0-100)."""
        vec = _parse_cvss_vector(vuln.cvss_vector)

        purl_vendor, purl_product = _parse_purl(vuln.purl)

        vendors_str = purl_vendor if purl_vendor else "unknown"
        products_str = purl_product if purl_product else vuln.pkg_name

        cwe_str = " ".join(vuln.cwe_ids)

        fv = [0.0] * len(self.features)
        fv[0] = float(vuln.cvss)
        fv[1] = float(vec["AV"])
        fv[2] = float(vec["AC"])
        fv[3] = float(vec["PR"])
        fv[4] = float(vec["UI"])
        fv[5] = float(vec["S"])
        fv[6] = float(vec["C"])
        fv[7] = float(vec["I"])
        fv[8] = float(vec["A"])

        idx_offset = 9

        for token in set(self._tokenize_tokens(vendors_str)):
            if token in self._v_map:
                fv[idx_offset + self._v_map[token]] = 1.0
        idx_offset += len(self.vendor_vocab)

        for token in set(self._tokenize_tokens(products_str)):
            if token in self._p_map:
                fv[idx_offset + self._p_map[token]] = 1.0
        idx_offset += len(self.product_vocab)

        for token in set(self._tokenize_tokens(cwe_str)):
            if token in self._cwe_map:
                fv[idx_offset + self._cwe_map[token]] = 1.0
        idx_offset += len(self.cwe_vocab)

        desc_tokens = self._tokenize_words(vuln.description)
        tf_counts: dict[str, int] = {}
        for token in desc_tokens:
            if token in self._desc_map:
                tf_counts[token] = tf_counts.get(token, 0) + 1

        tfidf_values = [0.0] * len(self.desc_vocab)
        sum_sq = 0.0

        for token, tf in tf_counts.items():
            vocab_idx = self._desc_map[token]
            idf = self.desc_idf[vocab_idx]
            val = tf * idf
            tfidf_values[vocab_idx] = val
            sum_sq += val * val

        if sum_sq > 0:
            norm = math.sqrt(sum_sq)
            for i in range(len(tfidf_values)):
                if tfidf_values[i] > 0:
                    fv[idx_offset + i] = tfidf_values[i] / norm

        raw = sum(self._walk(tree, fv) for tree in self.trees)
        prob = 1.0 / (1.0 + math.exp(-raw))
        return prob * 100.0

    def _walk(self, node: dict, features: list[float]) -> float:
        if "leaf" in node:
            return node["leaf"]

        if features[node["split"]] < node["split_condition"]:
            return self._walk(node["children"][0], features)
        return self._walk(node["children"][1], features)


_cached_model: MLScorer | None = None
_model_load_attempted: bool = False


def _load_model() -> MLScorer | None:
    """Load ML model from exported JSON. Returns None if unavailable."""
    global _cached_model, _model_load_attempted  # noqa: PLW0603

    if _model_load_attempted:
        return _cached_model

    _model_load_attempted = True

    if not MODEL_PATH.is_file():
        logger.debug("ML model not found at %s, using formula", MODEL_PATH)
        return None

    try:
        with open(MODEL_PATH, encoding="utf-8") as f:
            data = json.load(f)

        if data.get("format") != "flaw_xgboost_v1":
            logger.warning("Unknown model format, using formula")
            return None

        _cached_model = MLScorer(data)
        logger.debug("ML model loaded: %d trees from %s", data["n_trees"], MODEL_PATH)
        return _cached_model
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("Failed to load ML model: %s", e)
        return None


def score_vulnerabilities(
    vulnerabilities: list[EnrichedVulnerability],
) -> list[EnrichedVulnerability]:
    """Assign risk scores and sort by risk descending."""
    model = _load_model()

    if model:
        logger.debug(
            "Scoring %d vulnerabilities using ML Context-Aware engine", len(vulnerabilities)
        )
    else:
        logger.debug(
            "Scoring %d vulnerabilities with fallback weighted formula", len(vulnerabilities)
        )

    scored = []
    for vuln in vulnerabilities:
        if model:
            score = model.score(vuln)
            if vuln.in_kev:
                score = max(score, 90.0)
        else:
            score = _formula_score(vuln)

        scored.append(vuln.model_copy(update={"risk_score": round(score, 1)}))

    scored.sort(key=lambda v: v.risk_score, reverse=True)
    return scored
