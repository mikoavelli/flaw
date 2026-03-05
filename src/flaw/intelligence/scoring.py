"""Risk scoring engine: weighted formula and ML inference."""

from __future__ import annotations

import json
import logging
import math
import re
from pathlib import Path

from flaw.core.paths import DATA_DIR
from flaw.intelligence.model_manager import ensure_model
from flaw.models import EnrichedVulnerability, VexStatement

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
    if not purl or not purl.startswith("pkg:"):
        return "", ""
    try:
        clean_purl = purl[4:].split("@")[0].split("?")[0]
        parts = clean_purl.split("/")
        product = parts[-1]
        vendor = parts[-2] if len(parts) >= 2 else ""
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
    """Pure-Python XGBoost NLP evaluator — supports dynamic feature injection."""

    def __init__(self, data: dict) -> None:
        self.features = data["features"]
        self.trees = data["trees"]

        self.f_map = {name: i for i, name in enumerate(self.features)}

        self.desc_vocab = data.get("desc_vocab", [])
        self.desc_idf = data.get("desc_idf", [])
        self._desc_map = {d: i for i, d in enumerate(self.desc_vocab)}

        self._word_pattern = re.compile(r"\b[a-zA-Z]{3,}\b")
        self._token_pattern = re.compile(r"[^\s]+")

    def _tokenize_words(self, text: str) -> list[str]:
        return self._word_pattern.findall(text.lower())

    def _tokenize_tokens(self, text: str) -> list[str]:
        return self._token_pattern.findall(text.lower())

    def score(self, vuln: EnrichedVulnerability) -> float:
        fv = [0.0] * len(self.features)

        def set_f(name: str, val: float) -> None:
            if name in self.f_map:
                fv[self.f_map[name]] = float(val)

        vec = _parse_cvss_vector(vuln.cvss_vector)
        set_f("base_score", vuln.cvss)
        set_f("exploitability_score", vuln.exploitability_score)
        set_f("impact_score", vuln.impact_score)
        set_f("attack_vector", vec["AV"])
        set_f("attack_complexity", vec["AC"])
        set_f("privileges_required", vec["PR"])
        set_f("user_interaction", vec["UI"])
        set_f("scope", vec["S"])
        set_f("confidentiality", vec["C"])
        set_f("integrity", vec["I"])
        set_f("availability", vec["A"])

        refs = [r.lower() for r in vuln.references]
        set_f("ref_exploit_db", 1.0 if any("exploit-db.com" in r for r in refs) else 0.0)
        set_f("ref_packetstorm", 1.0 if any("packetstormsecurity.com" in r for r in refs) else 0.0)
        set_f(
            "ref_github_poc",
            1.0
            if any(
                "github.com" in r and ("poc" in r or "exploit" in r or "vuln" in r) for r in refs
            )
            else 0.0,
        )
        set_f(
            "ref_advisory",
            1.0
            if any(
                "security.microsoft.com" in r
                or "ubuntu.com/security" in r
                or "access.redhat.com" in r
                for r in refs
            )
            else 0.0,
        )

        purl_vendor, purl_product = _parse_purl(vuln.purl)
        vendors_str = purl_vendor if purl_vendor else "unknown"
        products_str = purl_product if purl_product else vuln.pkg_name

        joined_cpe = f"{vendors_str} {products_str}".lower()
        set_f("eco_npm", 1.0 if any(x in joined_cpe for x in ("node", "npm", "js")) else 0.0)
        set_f(
            "eco_pypi", 1.0 if any(x in joined_cpe for x in ("python", "django", "flask")) else 0.0
        )
        set_f(
            "eco_maven",
            1.0 if any(x in joined_cpe for x in ("java", "maven", "apache", "spring")) else 0.0,
        )
        set_f("eco_golang", 1.0 if any(x in joined_cpe for x in ("go", "golang")) else 0.0)
        set_f("eco_rust", 1.0 if any(x in joined_cpe for x in ("rust", "cargo")) else 0.0)
        set_f(
            "eco_linux",
            1.0
            if any(
                x in joined_cpe for x in ("linux", "ubuntu", "debian", "alpine", "redhat", "centos")
            )
            else 0.0,
        )
        set_f("eco_windows", 1.0 if any(x in joined_cpe for x in ("microsoft", "windows")) else 0.0)
        set_f(
            "eco_apple",
            1.0 if any(x in joined_cpe for x in ("apple", "mac_os", "iphone_os")) else 0.0,
        )

        cwe_str = " ".join(vuln.cwe_ids)
        for token in set(self._tokenize_tokens(vendors_str)):
            set_f(f"v_{token}", 1.0)
        for token in set(self._tokenize_tokens(products_str)):
            set_f(f"p_{token}", 1.0)
        for token in set(self._tokenize_tokens(cwe_str)):
            set_f(token, 1.0)

        desc_tokens = self._tokenize_words(vuln.description)
        tf_counts: dict[str, int] = {}
        for token in desc_tokens:
            if token in self._desc_map:
                tf_counts[token] = tf_counts.get(token, 0) + 1

        tfidf_values = [0.0] * len(self.desc_vocab)
        sum_sq = 0.0

        for token, tf in tf_counts.items():
            vocab_idx = self._desc_map[token]
            val = tf * self.desc_idf[vocab_idx]
            tfidf_values[vocab_idx] = val
            sum_sq += val * val

        if sum_sq > 0:
            norm = math.sqrt(sum_sq)
            for i in range(len(tfidf_values)):
                if tfidf_values[i] > 0:
                    set_f(f"txt_{self.desc_vocab[i]}", tfidf_values[i] / norm)

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

    model_path = ensure_model()

    if not model_path or not model_path.is_file():
        logger.debug("ML model not available, falling back to formula")
        return None

    try:
        with open(model_path, encoding="utf-8") as f:
            data = json.load(f)

        if data.get("format") not in ("flaw_xgboost_v1", "flaw_xgboost_v2"):
            logger.warning("Unknown model format, using formula")
            return None

        _cached_model = MLScorer(data)
        logger.debug("ML model loaded: %d trees from %s", data["n_trees"], model_path)
        return _cached_model
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("Failed to load ML model: %s", e)
        return None


def score_vulnerabilities(
    vulnerabilities: list[EnrichedVulnerability],
    vex_statements: list[VexStatement] | None = None,
) -> list[EnrichedVulnerability]:
    """Assign risk scores, apply VEX overrides, and sort by risk descending."""
    from flaw.models import VexJustification, VexStatus

    model = _load_model()
    vex_stmts = vex_statements or []

    if model:
        logger.debug(
            "Scoring %d vulnerabilities using ML Context-Aware engine", len(vulnerabilities)
        )
    else:
        logger.debug(
            "Scoring %d vulnerabilities with fallback weighted formula", len(vulnerabilities)
        )

    if vex_stmts:
        logger.debug("Applying %d VEX statements...", len(vex_stmts))

    scored = []
    for vuln in vulnerabilities:
        if model:
            raw_score = model.score(vuln)
            if vuln.in_kev:
                raw_score = max(raw_score, 90.0)
        else:
            raw_score = _formula_score(vuln)

        matched_vex = None
        if vuln.reachable is False:
            from flaw.models import VexStatement

            matched_vex = VexStatement(
                cve_id=vuln.cve_id,
                status=VexStatus.NOT_AFFECTED,
                justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                impact_statement="Scanner detected code as not reachable in the call graph.",
            )

        if not matched_vex:
            for stmt in vex_stmts:
                if stmt.cve_id == vuln.cve_id:
                    if not stmt.purl or (vuln.purl and stmt.purl in vuln.purl):
                        matched_vex = stmt
                        break

        final_score = raw_score
        vex_status = None
        vex_justification = None
        vex_impact = None

        if matched_vex:
            vex_status = matched_vex.status.value
            vex_justification = (
                matched_vex.justification.value if matched_vex.justification else None
            )
            vex_impact = matched_vex.impact_statement

            if matched_vex.status in (VexStatus.NOT_AFFECTED, VexStatus.FIXED):
                final_score = 0.0
            elif matched_vex.status == VexStatus.UNDER_INVESTIGATION:
                final_score = raw_score * 0.5

        scored.append(
            vuln.model_copy(
                update={
                    "risk_score": round(final_score, 1),
                    "vex_status": vex_status,
                    "vex_justification": vex_justification,
                    "vex_statement": vex_impact,
                }
            )
        )

    scored.sort(key=lambda v: v.risk_score, reverse=True)
    return scored
