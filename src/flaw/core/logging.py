"""Logging configuration for the flaw CLI."""

from __future__ import annotations

import logging
import sys


def setup_logging(*, verbose: bool = False, quiet: bool = False) -> None:
    """Configure logging for flaw."""
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING

    # Remove any existing handlers to avoid duplicates
    root = logging.getLogger()
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))

    flaw_logger = logging.getLogger("flaw")
    flaw_logger.handlers.clear()
    flaw_logger.addHandler(handler)
    flaw_logger.setLevel(level)
    flaw_logger.propagate = False

    # Suppress third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
