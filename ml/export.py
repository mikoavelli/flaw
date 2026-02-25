"""Export XGBoost model to JSON format for pure-Python inference."""

from __future__ import annotations

import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).parent.parent / "data" / "models"

FEATURES = [
    "base_score",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality",
    "integrity",
    "availability",
]
FEATURE_TO_IDX = {name: i for i, name in enumerate(FEATURES)}


def _parse_xgboost_dump(dump_lines: list[str]) -> list[dict]:
    trees: list[dict] = []
    current_tree: dict[int, dict] = {}
    current_booster = -1

    for line in dump_lines:
        if line.startswith("booster["):
            if current_tree and current_booster >= 0:
                trees.append(_build_tree(current_tree))
            current_tree = {}
            current_booster += 1
            continue

        line = line.strip()
        if not line:
            continue

        parts = line.split(":")
        if len(parts) < 2:
            continue

        node_id = int(parts[0])
        content = parts[1]

        if content.startswith("leaf="):
            value = float(content.split("=")[1])
            current_tree[node_id] = {"leaf": value}
        else:
            bracket_end = content.index("]")
            condition = content[1:bracket_end]

            lt_pos = condition.index("<")
            feature_name = condition[:lt_pos]
            threshold = float(condition[lt_pos + 1 :])

            if feature_name in FEATURE_TO_IDX:
                feature_idx = FEATURE_TO_IDX[feature_name]
            elif feature_name.startswith("f"):
                feature_idx = int(feature_name[1:])
            else:
                msg = f"Unknown feature in tree dump: {feature_name}"
                raise ValueError(msg)

            rest = content[bracket_end + 2 :]
            params = dict(p.split("=") for p in rest.split(","))

            current_tree[node_id] = {
                "split": feature_idx,
                "split_condition": threshold,
                "yes": int(params["yes"]),
                "no": int(params["no"]),
            }

    if current_tree:
        trees.append(_build_tree(current_tree))

    return trees


def _build_tree(nodes: dict[int, dict]) -> dict:
    def build(node_id: int) -> dict:
        node = nodes[node_id]
        if "leaf" in node:
            return {"leaf": node["leaf"]}
        return {
            "split": node["split"],
            "split_condition": node["split_condition"],
            "children": [
                build(node["yes"]),
                build(node["no"]),
            ],
        }

    return build(0)


def export() -> None:
    from xgboost import XGBClassifier

    model_path = MODEL_DIR / "xgboost_v1.json"
    if not model_path.exists():
        logger.error("Model not found: %s", model_path)
        return

    logger.info("Loading model: %s", model_path)
    model = XGBClassifier()
    model.load_model(str(model_path))

    booster = model.get_booster()
    dump = booster.get_dump()

    full_dump = ""
    for i, tree_str in enumerate(dump):
        full_dump += f"booster[{i}]\n{tree_str}\n"

    trees: list[dict] = _parse_xgboost_dump(full_dump.splitlines())

    export_data = {
        "format": "flaw_xgboost_v1",
        "features": FEATURES,
        "n_trees": len(trees),
        "trees": trees,
    }

    export_path = MODEL_DIR / "xgboost_portable.json"
    export_path.write_text(json.dumps(export_data, indent=2))
    logger.info("Exported %d trees to %s", len(trees), export_path)

    logger.info("Verifying export...")
    from flaw.intelligence.scoring import _TreeModel

    portable_model = _TreeModel(trees)

    test_cases = [
        [9.8, 3, 1, 2, 1, 0, 2, 2, 2],
        [4.0, 1, 0, 0, 0, 0, 1, 0, 0],
        [7.5, 3, 1, 2, 1, 0, 2, 2, 0],
        [3.1, 0, 0, 1, 0, 0, 1, 0, 0],
    ]

    for features in test_cases:
        xgb_prob = model.predict_proba([features])[0][1]
        portable_prob = portable_model.predict(features)
        diff = abs(xgb_prob - portable_prob)
        status = "✓" if diff < 0.01 else "✗"
        logger.info(
            "  %s  xgb=%.4f  portable=%.4f  diff=%.6f",
            status,
            xgb_prob,
            portable_prob,
            diff,
        )


if __name__ == "__main__":
    export()
