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
    default_format: str = "table"


@dataclass(frozen=True, slots=True)
class CacheConfig:
    """Cache-related settings."""

    ttl_hours: int = 24
    model_ttl_days: int = 30


@dataclass(frozen=True, slots=True)
class NetworkConfig:
    """Network, SSL, and auth settings."""

    timeout: int = 30
    verify_ssl: bool = True
    github_token: str = ""


@dataclass(frozen=True, slots=True)
class UrlsConfig:
    """Mirrors and URLs for data feeds."""

    epss: str = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    kev: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    model: str = (
        "https://raw.githubusercontent.com/mikoavelli/flaw/main/data/models/xgboost_portable.json"
    )
    trivy_api: str = "https://api.github.com/repos/aquasecurity/trivy/releases/latest"


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
    network: NetworkConfig = field(default_factory=NetworkConfig)
    urls: UrlsConfig = field(default_factory=UrlsConfig)
    flags: RuntimeFlags = field(default_factory=RuntimeFlags)


def _load_toml(path: Path) -> dict:
    if not path.is_file():
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def _env(key: str) -> str | None:
    return os.environ.get(f"FLAW_{key}")


def _env_bool(key: str, default: bool) -> bool:
    val = _env(key)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "t", "on")


def load_settings(
    config_path: Path | None = None,
    *,
    flags: RuntimeFlags | None = None,
) -> Settings:
    """Load settings with priority: env vars > flaw.toml > defaults."""
    raw = _load_toml(config_path or CONFIG_FILE)

    scan_raw = raw.get("scan", {})
    cache_raw = raw.get("cache", {})
    network_raw = raw.get("network", {})
    urls_raw = raw.get("urls", {})

    scan = ScanConfig(
        risk_threshold=float(_env("SCAN_RISK_THRESHOLD") or scan_raw.get("risk_threshold", 70.0)),
        trivy_timeout=int(_env("SCAN_TRIVY_TIMEOUT") or scan_raw.get("trivy_timeout", 300)),
        default_format=_env("SCAN_DEFAULT_FORMAT") or scan_raw.get("default_format", "table"),
    )

    cache = CacheConfig(
        ttl_hours=int(_env("CACHE_TTL_HOURS") or cache_raw.get("ttl_hours", 24)),
        model_ttl_days=int(_env("CACHE_MODEL_TTL_DAYS") or cache_raw.get("model_ttl_days", 30)),
    )

    network = NetworkConfig(
        timeout=int(_env("NETWORK_TIMEOUT") or network_raw.get("timeout", 30)),
        verify_ssl=_env_bool("NETWORK_VERIFY_SSL", network_raw.get("verify_ssl", True)),
        github_token=_env("NETWORK_GITHUB_TOKEN") or network_raw.get("github_token", ""),
    )

    default_urls = UrlsConfig()
    urls = UrlsConfig(
        epss=_env("URLS_EPSS") or urls_raw.get("epss", default_urls.epss),
        kev=_env("URLS_KEV") or urls_raw.get("kev", default_urls.kev),
        model=_env("URLS_MODEL") or urls_raw.get("model", default_urls.model),
        trivy_api=_env("URLS_TRIVY_API") or urls_raw.get("trivy_api", default_urls.trivy_api),
    )

    return Settings(
        scan=scan,
        cache=cache,
        network=network,
        urls=urls,
        flags=flags or RuntimeFlags(),
    )
