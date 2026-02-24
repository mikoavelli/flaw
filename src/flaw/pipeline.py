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
from flaw.scanner.runtime import detect_runtime
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
    skip_enrich: bool = False,
    dockerfile: Path | None = None,
    settings: Settings | None = None,
) -> ScanReport:
    """
    Execute the full scan pipeline.

    Args:
        image: Container image reference.
        skip_enrich: Skip EPSS/KEV enrichment.
        dockerfile: Optional Dockerfile path for additional analysis.
        settings: Override settings (useful for testing).

    Returns:
        Complete scan report with scored vulnerabilities.
    """
    cfg = settings or load_settings()
    ensure_dirs()

    start = time.monotonic()

    # 0. Detect runtime
    runtime = detect_runtime()
    logger.debug("Container runtime: %s", runtime)

    # 1. Scan
    logger.debug("Scanning image: %s", image)
    trivy_report = scan_image(image, timeout=cfg.scan.trivy_timeout)
    raw_vulns = trivy_report.all_vulnerabilities
    logger.debug("Found %d raw vulnerabilities", len(raw_vulns))

    # 2. Enrich
    conn = get_connection()
    try:
        enriched = enrich(conn, raw_vulns, CACHE_DIR, skip_enrich=skip_enrich)
    finally:
        conn.close()

    # 3. Score and sort
    scored = score_vulnerabilities(enriched)

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
        runtime=runtime,
        summary=summary,
        vulnerabilities=scored,
        dockerfile_issues=dockerfile_issues,
    )
