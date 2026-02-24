"""CISA KEV (Known Exploited Vulnerabilities) catalog fetcher and lookup."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

import httpx

from flaw.intelligence.db import is_stale, set_last_update

logger = logging.getLogger("flaw")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVError(Exception):
    """Raised when KEV data download or parsing fails."""


def update(conn: sqlite3.Connection, cache_dir: Path) -> int:
    """
    Download latest KEV catalog and populate the database.

    Returns:
        Number of entries inserted.
    """
    try:
        with httpx.Client(timeout=30, follow_redirects=True) as client:
            response = client.get(KEV_URL)
            response.raise_for_status()
            data = response.json()

        vulns = data.get("vulnerabilities", [])
        cve_ids = [(v["cveID"],) for v in vulns if "cveID" in v]

        conn.execute("DELETE FROM kev_entries")
        conn.executemany("INSERT INTO kev_entries (cve) VALUES (?)", cve_ids)
        set_last_update(conn, "kev")
        conn.commit()

        logger.debug("KEV updated: %d entries", len(cve_ids))
        return len(cve_ids)

    except httpx.HTTPError as e:
        raise KEVError(f"Failed to download KEV catalog: {e}") from e
    except (KeyError, ValueError) as e:
        raise KEVError(f"Failed to parse KEV data: {e}") from e


def ensure_fresh(
    conn: sqlite3.Connection,
    cache_dir: Path,
    *,
    offline: bool = False,
) -> None:
    """Update KEV if cache is stale. Warns on failure instead of crashing."""
    if offline:
        logger.debug("Offline mode: skipping KEV update")
        return
    if not is_stale(conn, "kev"):
        return
    try:
        update(conn, cache_dir)
    except KEVError:
        logger.warning("KEV update failed. Using stale or empty data.")


def lookup(conn: sqlite3.Connection, cve_ids: list[str]) -> set[str]:
    """Batch lookup. Returns set of CVE IDs that are in the KEV catalog."""
    if not cve_ids:
        return set()

    placeholders = ",".join("?" for _ in cve_ids)
    cursor = conn.execute(
        f"SELECT cve FROM kev_entries WHERE cve IN ({placeholders})",  # noqa: S608
        cve_ids,
    )
    return {row[0] for row in cursor.fetchall()}


def is_in_kev(conn: sqlite3.Connection, cve_id: str) -> bool:
    """Check if a single CVE is in the KEV catalog."""
    cursor = conn.execute("SELECT 1 FROM kev_entries WHERE cve = ?", (cve_id,))
    return cursor.fetchone() is not None
