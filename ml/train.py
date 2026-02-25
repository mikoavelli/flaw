import json
import logging
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data"
DATASET = DATA_DIR / "dataset.csv"
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
LABEL = "label"


def train():
    if not DATASET.exists():
        logger.error("Data file not found!")
        return

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(DATASET)

    if df.empty:
        logger.error("Dataset is empty!")
        return

    df = df.dropna(subset=FEATURES + [LABEL])

    logger.info(f"Rows loaded: {len(df)}")
    logger.info(
        f"Positive samples (High Risk): {df[LABEL].sum()} ({100 * df[LABEL].sum() / len(df):.2f}%)"
    )

    X = df[FEATURES]
    y = df[LABEL]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pos_count = y_train.sum()
    neg_count = len(y_train) - pos_count
    scale_weight = neg_count / max(pos_count, 1)

    logger.info("Training risk prediction model based on CVSS parameters...")

    model = XGBClassifier(
        n_estimators=30000,
        max_depth=9,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_weight,
        eval_metric="auc",
        early_stopping_rounds=200,
        random_state=42,
        n_jobs=-12,
    )

    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=50)

    model.save_model(str(MODEL_DIR / "xgboost_v1.json"))

    auc_score = float(model.best_score)
    meta = {"features": FEATURES, "score": auc_score, "best_iteration": int(model.best_iteration)}

    with open(MODEL_DIR / "model_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    logger.info("\n--- Final Result ---")
    logger.info(f"AUC on validation data: {auc_score:.4f}")
    logger.info(f"Model trained for {model.best_iteration} iterations")

    import numpy as np

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    logger.info("Top features influencing risk:")
    for i in range(len(FEATURES)):
        logger.info(f"{i + 1}. {FEATURES[indices[i]]}: {importances[indices[i]]:.4f}")


if __name__ == "__main__":
    train()
