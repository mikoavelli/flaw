import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).parent.parent / "data" / "models"


def _parse_xgboost_dump(dump_lines: list[str], feature_to_idx: dict) -> list[dict]:
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

            if feature_name in feature_to_idx:
                feature_idx = feature_to_idx[feature_name]
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
    import sys

    from xgboost import XGBClassifier

    model_path = MODEL_DIR / "xgboost_v1.json"
    meta_path = MODEL_DIR / "model_meta.json"

    if not model_path.exists() or not meta_path.exists():
        logger.error("Model or metadata not found.")
        return

    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)

    features = meta["features"]
    feature_to_idx = {name: i for i, name in enumerate(features)}

    logger.info("Loading model: %s", model_path)
    model = XGBClassifier()
    model.load_model(str(model_path))

    booster = model.get_booster()
    dump = booster.get_dump()

    full_dump = ""
    for i, tree_str in enumerate(dump):
        full_dump += f"booster[{i}]\n{tree_str}\n"

    trees = _parse_xgboost_dump(full_dump.splitlines(), feature_to_idx)

    export_data = {
        "format": "flaw_xgboost_v1",
        "features": features,
        "vendor_vocab": meta.get("vendor_vocab", []),
        "product_vocab": meta.get("product_vocab", []),
        "cwe_vocab": meta.get("cwe_vocab", []),
        "desc_vocab": meta.get("desc_vocab", []),
        "desc_idf": meta.get("desc_idf", []),
        "n_trees": len(trees),
        "trees": trees,
    }

    export_path = MODEL_DIR / "xgboost_portable.json"
    export_path.write_text(json.dumps(export_data, indent=2))
    logger.info("Exported %d trees to %s", len(trees), export_path)

    logger.info("Verifying export...")
    try:
        from flaw.intelligence.scoring import _TreeModel
    except ImportError:
        logger.warning("Could not import flaw.intelligence.scoring to verify export.")
        sys.exit(0)

    portable_model = _TreeModel(export_data["trees"])
    dummy_features = [0.0] * len(features)

    xgb_prob = model.predict_proba([dummy_features])[0][1]
    portable_prob = portable_model.predict(dummy_features)
    diff = abs(xgb_prob - portable_prob)
    status = "OK" if diff < 0.01 else "FAIL"

    logger.info(
        "  %s  xgb=%.4f  portable=%.4f  diff=%.6f",
        status,
        xgb_prob,
        portable_prob,
        diff,
    )


if __name__ == "__main__":
    export()
