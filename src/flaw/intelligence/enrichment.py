"""Orchestrate vulnerability enrichment with EPSS and KEV data."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from flaw.intelligence import epss, kev
from flaw.models import EnrichedVulnerability, Vulnerability

logger = logging.getLogger("flaw")


def enrich(
    conn: sqlite3.Connection,
    vulnerabilities: list[Vulnerability],
    cache_dir: Path,
    *,
    offline: bool = False,
    force_refresh: bool = False,
) -> list[EnrichedVulnerability]:
    """
    Enrich raw Trivy vulnerabilities with EPSS scores and KEV flags.

    Args:
        conn: SQLite connection to cache database.
        vulnerabilities: Raw vulnerabilities from Trivy scan.
        cache_dir: Path for temporary download files.
        offline: If True, use cached data only (no downloads).
        force_refresh: If True, re-download regardless of TTL.
    """
    if not vulnerabilities:
        return []

    cve_ids = [v.cve_id for v in vulnerabilities]

    if force_refresh and not offline:
        logger.debug("Force refreshing EPSS and KEV data")
        try:
            epss.update(conn, cache_dir)
        except epss.EPSSError:
            logger.warning("EPSS force refresh failed.")
        try:
            kev.update(conn, cache_dir)
        except kev.KEVError:
            logger.warning("KEV force refresh failed.")
    else:
        epss.ensure_fresh(conn, cache_dir, offline=offline)
        kev.ensure_fresh(conn, cache_dir, offline=offline)

    epss_scores = epss.get_scores(conn, cve_ids)
    kev_set = kev.lookup(conn, cve_ids)

    logger.debug(
        "Enrichment: %d EPSS scores, %d KEV matches",
        len(epss_scores),
        len(kev_set),
    )

    enriched = []
    for v in vulnerabilities:
        enriched.append(
            EnrichedVulnerability(
                cve_id=v.cve_id,
                pkg_name=v.pkg_name,
                installed_version=v.installed_version,
                fixed_version=v.fixed_version,
                severity=v.severity,
                cvss=v.cvss,
                epss=epss_scores.get(v.cve_id, 0.0),
                in_kev=v.cve_id in kev_set,
                has_exploit=v.cve_id in kev_set,
                risk_score=0.0,
            )
        )

    return enriched
