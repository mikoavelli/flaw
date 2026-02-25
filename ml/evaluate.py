# evaluate.py
import json
import logging
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data"
DATASET = DATA_DIR / "dataset.csv"
MODEL_DIR = Path(__file__).parent.parent / "data" / "models"
PLOTS_DIR = Path(__file__).parent / "plots"

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


def evaluate() -> None:
    model_path = MODEL_DIR / "xgboost_v1.json"
    meta_path = MODEL_DIR / "model_meta.json"

    if not model_path.exists() or not meta_path.exists():
        logger.error("Model or metadata not found.")
        return

    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)

    all_features = meta["features"]
    vendor_vocab = meta["vendor_vocab"]
    product_vocab = meta["product_vocab"]

    logger.info("Loading dataset and model...")
    df = pd.read_csv(DATASET)
    df = df.dropna(subset=BASE_FEATURES + [LABEL])

    df["vendors"] = df["vendors"].fillna("")
    df["products"] = df["products"].fillna("")

    vendor_vec = CountVectorizer(vocabulary=vendor_vocab, binary=True, token_pattern=r"[^\s]+")
    product_vec = CountVectorizer(vocabulary=product_vocab, binary=True, token_pattern=r"[^\s]+")

    X_vendors = vendor_vec.fit_transform(df["vendors"]).toarray()
    X_products = product_vec.fit_transform(df["products"]).toarray()

    vendor_cols = [f"v_{c}" for c in vendor_vocab]
    product_cols = [f"p_{c}" for c in product_vocab]

    X_base_df = df[BASE_FEATURES].reset_index(drop=True)
    X_v_df = pd.DataFrame(X_vendors, columns=vendor_cols)
    X_p_df = pd.DataFrame(X_products, columns=product_cols)

    X = pd.concat([X_base_df, X_v_df, X_p_df], axis=1)
    y = df[LABEL].reset_index(drop=True)

    _, x_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    model = XGBClassifier()
    model.load_model(str(model_path))

    y_pred = model.predict(x_test)
    y_prob = model.predict_proba(x_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)

    logger.info("\n=== Model Evaluation ===")
    logger.info("Accuracy: %.4f", accuracy)
    logger.info("AUC-ROC:  %.4f", auc)
    logger.info("\nClassification Report:")
    logger.info(classification_report(y_test, y_pred))

    cm = confusion_matrix(y_test, y_pred)
    logger.info("Confusion Matrix:")
    logger.info("%s", cm)

    report = classification_report(y_test, y_pred, output_dict=True)
    metrics = {
        "accuracy": float(accuracy),
        "auc_roc": float(auc),
        "classification_report": report,
        "confusion_matrix": cm.tolist(),
    }
    metrics_path = MODEL_DIR / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2))
    logger.info("\nMetrics saved: %s", metrics_path)

    fpr, tpr, _ = roc_curve(y_test, y_prob)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, label=f"XGBoost (AUC = {auc:.4f})")
    plt.plot([0, 1], [0, 1], "k--", label="Random")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "roc_curve.png", dpi=150)
    logger.info("ROC plot generated: %s", PLOTS_DIR / "roc_curve.png")

    plt.figure(figsize=(10, 8))
    importance = model.feature_importances_
    sorted_idx = importance.argsort()[-30:]
    plt.barh([all_features[i] for i in sorted_idx], importance[sorted_idx])
    plt.xlabel("Importance")
    plt.title("Top 30 Feature Importance")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "feature_importance.png", dpi=150)
    logger.info("Feature importance plot generated: %s", PLOTS_DIR / "feature_importance.png")


if __name__ == "__main__":
    evaluate()
