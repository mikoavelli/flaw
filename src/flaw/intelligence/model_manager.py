"""ML Model auto-downloader and manager."""

from __future__ import annotations

import logging
from pathlib import Path

import httpx

from flaw.core.paths import MODELS_DIR

logger = logging.getLogger("flaw")

MODEL_PATH: Path = MODELS_DIR / "xgboost_portable.json"
MODEL_URL = "https://raw.githubusercontent.com/mikoavelli/flaw/main/data/models/xgboost_portable.json"


def ensure_model(*, force: bool = False, offline: bool = False) -> Path | None:
    """Ensure the ML model exists locally, downloading it if necessary."""
    if MODEL_PATH.exists() and not force:
        return MODEL_PATH

    if offline:
        logger.debug("Offline mode: skipping ML model download.")
        return MODEL_PATH if MODEL_PATH.exists() else None

    logger.debug("Downloading ML model from GitHub...")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        with httpx.Client(timeout=30, follow_redirects=True) as client:
            response = client.get(MODEL_URL)
            response.raise_for_status()
            MODEL_PATH.write_text(response.text, encoding="utf-8")
            logger.debug("ML model downloaded successfully.")
            return MODEL_PATH
    except Exception as e:
        logger.warning("Failed to download ML model: %s", e)
        return MODEL_PATH if MODEL_PATH.exists() else None
