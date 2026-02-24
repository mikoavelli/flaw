"""Global runtime state shared across CLI commands."""

from __future__ import annotations

from flaw.core.config import RuntimeFlags

_flags = RuntimeFlags()


def set_flags(flags: RuntimeFlags) -> None:
    """Set global runtime flags (called from CLI callback)."""
    global _flags  # noqa: PLW0603
    _flags = flags


def get_flags() -> RuntimeFlags:
    """Get current global runtime flags."""
    return _flags
