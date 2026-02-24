"""Logging configuration for the flaw CLI."""

from __future__ import annotations

import logging


def setup_logging(*, verbose: bool = False, quiet: bool = False) -> None:
    """
    Configure root logger for the flaw application.

    Args:
        verbose: Show debug-level output.
        quiet: Suppress everything except errors.
    """
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[logging.StreamHandler()],
    )

    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
