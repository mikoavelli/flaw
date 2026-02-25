# train.py
import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data"
DATASET = DATA_DIR / "dataset.csv"
MODEL_DIR = Path(__file__).parent.parent / "data" / "models"

BASE_FEATURES = [
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
        logger.error("Dataset file not found.")
        return

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(DATASET)

    if df.empty:
        logger.error("Dataset is empty.")
        return

    df = df.dropna(subset=BASE_FEATURES + [LABEL])

    logger.info(f"Loaded rows: {len(df)}")
    logger.info(f"Positive samples: {df[LABEL].sum()} ({100 * df[LABEL].sum() / len(df):.2f}%)")

    df["vendors"] = df["vendors"].fillna("")
    df["products"] = df["products"].fillna("")

    vendor_vec = CountVectorizer(max_features=100, binary=True, token_pattern=r"[^\s]+")
    product_vec = CountVectorizer(max_features=100, binary=True, token_pattern=r"[^\s]+")

    X_vendors = vendor_vec.fit_transform(df["vendors"]).toarray()
    X_products = product_vec.fit_transform(df["products"]).toarray()

    vendor_vocab = vendor_vec.get_feature_names_out().tolist()
    product_vocab = product_vec.get_feature_names_out().tolist()

    vendor_cols = [f"v_{c}" for c in vendor_vocab]
    product_cols = [f"p_{c}" for c in product_vocab]

    X_base_df = df[BASE_FEATURES].reset_index(drop=True)
    X_v_df = pd.DataFrame(X_vendors, columns=vendor_cols)
    X_p_df = pd.DataFrame(X_products, columns=product_cols)

    X = pd.concat([X_base_df, X_v_df, X_p_df], axis=1)
    y = df[LABEL].reset_index(drop=True)

    all_features = BASE_FEATURES + vendor_cols + product_cols

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pos_count = y_train.sum()
    neg_count = len(y_train) - pos_count
    scale_weight = neg_count / max(pos_count, 1)

    logger.info("Training XGBoost model...")

    model = XGBClassifier(
        n_estimators=2000,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_weight,
        eval_metric="auc",
        early_stopping_rounds=50,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=50)

    model.save_model(str(MODEL_DIR / "xgboost_v1.json"))

    auc_score = float(model.best_score)
    meta = {
        "features": all_features,
        "vendor_vocab": vendor_vocab,
        "product_vocab": product_vocab,
        "score": auc_score,
        "best_iteration": int(model.best_iteration),
    }

    with open(MODEL_DIR / "model_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    logger.info("\n--- Final Results ---")
    logger.info(f"Test AUC: {auc_score:.4f}")
    logger.info(f"Best iteration: {model.best_iteration}")
    logger.info(f"Total features: {len(all_features)}")

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    logger.info("\nTop 20 feature importance ranking:")
    for i in range(min(20, len(all_features))):
        logger.info(f"{i + 1}. {all_features[indices[i]]}: {importances[indices[i]]:.4f}")


if __name__ == "__main__":
    train()
