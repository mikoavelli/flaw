"""ML Model auto-downloader and manager."""

from __future__ import annotations

import logging
import time
from pathlib import Path

import httpx

from flaw.core.config import load_settings
from flaw.core.paths import MODELS_DIR

logger = logging.getLogger("flaw")

MODEL_PATH: Path = MODELS_DIR / "xgboost_portable.json"


def _is_model_stale(ttl_days: int) -> bool:
    if not MODEL_PATH.exists():
        return True
    age_days = (time.time() - MODEL_PATH.stat().st_mtime) / 86400
    return age_days >= ttl_days


def ensure_model(*, force: bool = False, offline: bool = False) -> Path | None:
    """Ensure the ML model exists locally, downloading it if necessary."""
    settings = load_settings()

    if MODEL_PATH.exists() and not force:
        if not _is_model_stale(settings.cache.model_ttl_days):
            return MODEL_PATH

    if offline:
        logger.debug("Offline mode: skipping ML model download.")
        return MODEL_PATH if MODEL_PATH.exists() else None

    logger.debug("Downloading ML model from configured URL...")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        with httpx.Client(
            timeout=settings.network.timeout,
            verify=settings.network.verify_ssl,
            follow_redirects=True,
        ) as client:
            response = client.get(settings.urls.model)
            response.raise_for_status()
            MODEL_PATH.write_text(response.text, encoding="utf-8")
            logger.debug("ML model downloaded successfully.")
            return MODEL_PATH
    except Exception as e:
        logger.warning("Failed to download ML model: %s", e)
        return MODEL_PATH if MODEL_PATH.exists() else None
