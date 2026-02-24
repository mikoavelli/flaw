"""Orchestration: scan → enrich → score → report."""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from pathlib import Path

from flaw.core.config import Settings, load_settings
from flaw.core.paths import CACHE_DIR, ensure_dirs
from flaw.intelligence.db import get_connection
from flaw.intelligence.enrichment import enrich
from flaw.intelligence.scoring import score_vulnerabilities
from flaw.models import (
    DockerfileIssue,
    EnrichedVulnerability,
    ReportSummary,
    ScanReport,
)
from flaw.scanner.dockerfile import DockerfileLintError, lint
from flaw.scanner.runtime import resolve_image_source
from flaw.scanner.trivy import scan_image

logger = logging.getLogger("flaw")


def _build_summary(vulns: list[EnrichedVulnerability]) -> ReportSummary:
    """Compute summary statistics from scored vulnerabilities."""
    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        key = v.severity.upper()
        if key in severity_counts:
            severity_counts[key] += 1

    return ReportSummary(
        total=len(vulns),
        critical=severity_counts["CRITICAL"],
        high=severity_counts["HIGH"],
        medium=severity_counts["MEDIUM"],
        low=severity_counts["LOW"],
        max_risk_score=max((v.risk_score for v in vulns), default=0.0),
        kev_count=sum(1 for v in vulns if v.in_kev),
        exploit_count=sum(1 for v in vulns if v.has_exploit),
    )


def run_scan(
    image: str,
    *,
    dockerfile: Path | None = None,
    settings: Settings | None = None,
) -> ScanReport:
    """Execute the full scan pipeline."""
    cfg = settings or load_settings()
    ensure_dirs()

    start = time.monotonic()

    # 0. Resolve image source
    source = resolve_image_source(image)

    # 1. Scan
    logger.debug("Starting Trivy scan: %s", image)
    trivy_report = scan_image(
        image,
        timeout=cfg.scan.trivy_timeout,
        image_src=source.runtime if source.is_local else None,
    )
    raw_vulns = trivy_report.all_vulnerabilities
    logger.debug("Trivy found %d vulnerabilities", len(raw_vulns))

    # 2. Enrich
    conn = get_connection()
    try:
        enriched = enrich(
            conn,
            raw_vulns,
            CACHE_DIR,
            offline=cfg.flags.offline,
            force_refresh=cfg.flags.no_cache,
        )
    finally:
        conn.close()

    # 3. Score and sort
    scored = score_vulnerabilities(enriched)
    logger.debug(
        "Scoring complete, max risk: %.1f",
        max((v.risk_score for v in scored), default=0.0),
    )

    # 4. Dockerfile lint (optional)
    dockerfile_issues: list[DockerfileIssue] = []
    if dockerfile is not None:
        try:
            dockerfile_issues = lint(dockerfile)
            logger.debug("Dockerfile lint: %d issues", len(dockerfile_issues))
        except DockerfileLintError as e:
            logger.warning("Dockerfile analysis failed: %s", e)

    # 5. Build report
    duration = round(time.monotonic() - start, 1)
    summary = _build_summary(scored)

    return ScanReport(
        image=image,
        scan_time=datetime.now(UTC).isoformat(),
        duration_seconds=duration,
        runtime=source.runtime,
        summary=summary,
        vulnerabilities=scored,
        dockerfile_issues=dockerfile_issues,
    )
