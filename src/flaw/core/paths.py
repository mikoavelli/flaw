"""XDG-compliant directory management."""

from pathlib import Path

from platformdirs import PlatformDirs

_dirs = PlatformDirs(appname="flaw", appauthor=False)

CONFIG_DIR: Path = _dirs.user_config_path
DATA_DIR: Path = _dirs.user_data_path
CACHE_DIR: Path = _dirs.user_cache_path


def ensure_dirs() -> None:
    """Create all required application directories."""
    for d in (CONFIG_DIR, DATA_DIR, CACHE_DIR):
        d.mkdir(parents=True, exist_ok=True)
