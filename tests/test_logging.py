"""Tests for the logging configuration."""

from __future__ import annotations

import logging

from flaw.core.logging import setup_logging


def test_setup_logging_default() -> None:
    setup_logging()
    logger = logging.getLogger("flaw")
    assert logger.level == logging.WARNING


def test_setup_logging_verbose() -> None:
    setup_logging(verbose=True)
    logger = logging.getLogger("flaw")
    assert logger.level == logging.DEBUG


def test_setup_logging_quiet() -> None:
    setup_logging(quiet=True)
    logger = logging.getLogger("flaw")
    assert logger.level == logging.ERROR


def test_setup_logging_clears_handlers() -> None:
    root = logging.getLogger()
    dummy = logging.NullHandler()
    root.addHandler(dummy)
    setup_logging()

    flaw_logger = logging.getLogger("flaw")
    assert len(flaw_logger.handlers) == 1
    assert isinstance(flaw_logger.handlers[0], logging.StreamHandler)
    assert dummy not in root.handlers
