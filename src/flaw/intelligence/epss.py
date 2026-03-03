"""EPSS (Exploit Prediction Scoring System) data fetcher and lookup."""

from __future__ import annotations

import gzip
import logging
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import httpx

from flaw.core.config import load_settings
from flaw.intelligence.db import is_stale, set_last_update

logger = logging.getLogger("flaw")


class EPSSError(Exception):
    """Raised when EPSS data download or parsing fails."""


def _parse_gz(gz_path: Path) -> Iterator[tuple[str, float]]:
    """Yield (cve_id, score) from a gzipped EPSS CSV."""
    with gzip.open(gz_path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or line.startswith("cve"):
                continue
            parts = line.strip().split(",")
            if len(parts) >= 2:
                try:
                    yield (parts[0], float(parts[1]))
                except ValueError:
                    continue


def update(conn: sqlite3.Connection, cache_dir: Path) -> int:
    settings = load_settings()
    gz_path = cache_dir / "epss_temp.csv.gz"

    try:
        with httpx.Client(
            timeout=settings.network.timeout,
            verify=settings.network.verify_ssl,
            follow_redirects=True,
        ) as client:
            with client.stream("GET", settings.urls.epss) as response:
                response.raise_for_status()
                with open(gz_path, "wb") as f:
                    for chunk in response.iter_bytes():
                        f.write(chunk)

        conn.execute("DELETE FROM epss_scores")
        rows = list(_parse_gz(gz_path))
        conn.executemany("INSERT INTO epss_scores (cve, score) VALUES (?, ?)", rows)
        set_last_update(conn, "epss")
        conn.commit()

        return len(rows)

    except httpx.HTTPError as e:
        raise EPSSError(f"Failed to download EPSS data: {e}") from e
    finally:
        if gz_path.exists():
            gz_path.unlink()


def ensure_fresh(
    conn: sqlite3.Connection,
    cache_dir: Path,
    *,
    offline: bool = False,
) -> None:
    """Update EPSS if cache is stale. Warns on failure instead of crashing."""
    if offline:
        logger.debug("Offline mode: skipping EPSS update")
        return
    if not is_stale(conn, "epss"):
        logger.debug("EPSS cache is fresh, skipping update")
        return
    logger.debug("EPSS cache is stale, updating...")
    try:
        count = update(conn, cache_dir)
        logger.debug("EPSS updated: %d entries", count)
    except EPSSError:
        logger.warning("EPSS update failed. Using stale or empty data.")


def get_scores(conn: sqlite3.Connection, cve_ids: list[str]) -> dict[str, float]:
    """Batch lookup of EPSS scores. Returns {cve_id: score}."""
    if not cve_ids:
        return {}

    placeholders = ",".join("?" for _ in cve_ids)
    cursor = conn.execute(
        f"SELECT cve, score FROM epss_scores WHERE cve IN ({placeholders})",  # noqa: S608
        cve_ids,
    )
    return dict(cursor.fetchall())


def get_score(conn: sqlite3.Connection, cve_id: str) -> float:
    """Single CVE EPSS lookup. Returns 0.0 if not found."""
    cursor = conn.execute("SELECT score FROM epss_scores WHERE cve = ?", (cve_id,))
    row = cursor.fetchone()
    return row[0] if row else 0.0
