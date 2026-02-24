"""Application configuration via flaw.toml and environment variables."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from flaw.core.paths import CONFIG_DIR

CONFIG_FILE = CONFIG_DIR / "flaw.toml"


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Scan-related settings."""

    risk_threshold: float = 70.0
    trivy_timeout: int = 300


@dataclass(frozen=True, slots=True)
class CacheConfig:
    """Cache-related settings."""

    ttl_hours: int = 24


@dataclass(frozen=True, slots=True)
class RuntimeFlags:
    """Flags set via CLI global options (not persisted)."""

    offline: bool = False
    no_cache: bool = False
    verbose: bool = False
    quiet: bool = False


@dataclass(frozen=True, slots=True)
class Settings:
    """Root configuration object."""

    scan: ScanConfig = field(default_factory=ScanConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    flags: RuntimeFlags = field(default_factory=RuntimeFlags)


def _load_toml(path: Path) -> dict:
    """Read and parse a TOML file. Returns empty dict if not found."""
    if not path.is_file():
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def _env(key: str) -> str | None:
    """Read an environment variable with FLAW_ prefix."""
    return os.environ.get(f"FLAW_{key}")


def load_settings(
    config_path: Path | None = None,
    *,
    flags: RuntimeFlags | None = None,
) -> Settings:
    """
    Load settings with priority: env vars > flaw.toml > defaults.

    Args:
        config_path: Override path to config file (useful for testing).
        flags: Runtime flags from CLI global options.
    """
    raw = _load_toml(config_path or CONFIG_FILE)
    scan_raw = raw.get("scan", {})
    cache_raw = raw.get("cache", {})

    scan = ScanConfig(
        risk_threshold=float(_env("RISK_THRESHOLD") or scan_raw.get("risk_threshold", 70.0)),
        trivy_timeout=int(_env("TRIVY_TIMEOUT") or scan_raw.get("trivy_timeout", 300)),
    )

    cache = CacheConfig(
        ttl_hours=int(_env("CACHE_TTL_HOURS") or cache_raw.get("ttl_hours", 24)),
    )

    return Settings(
        scan=scan,
        cache=cache,
        flags=flags or RuntimeFlags(),
    )
