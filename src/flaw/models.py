"""Pydantic models for vulnerability data throughout the pipeline."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

# ── Trivy raw models ──────────────────────────────────────────────


class Vulnerability(BaseModel):
    """Single vulnerability from Trivy scan output."""

    cve_id: str = Field(alias="VulnerabilityID")
    pkg_name: str = Field(alias="PkgName")
    installed_version: str = Field(alias="InstalledVersion")
    fixed_version: str = Field(default="", alias="FixedVersion")
    severity: str = Field(alias="Severity")
    cvss: float = 0.0

    model_config = {"populate_by_name": True}

    @model_validator(mode="before")
    @classmethod
    def extract_cvss(cls, data: Any) -> Any:
        """Extract best available CVSS v3 score from Trivy's nested CVSS object."""
        if not isinstance(data, dict):
            return data

        cvss_map = data.get("CVSS") or {}
        score = 0.0

        # Priority: NVD first, then any other source
        if "nvd" in cvss_map:
            score = cvss_map["nvd"].get("V3Score", 0.0) or 0.0
        else:
            for source in cvss_map.values():
                if isinstance(source, dict) and source.get("V3Score"):
                    score = source["V3Score"]
                    break

        data["cvss"] = score
        return data


class ScanResult(BaseModel):
    """Single scan target (e.g., OS packages, Python packages)."""

    target: str = Field(alias="Target")
    vulnerabilities: list[Vulnerability] = Field(default_factory=list, alias="Vulnerabilities")

    model_config = {"populate_by_name": True}

    @field_validator("vulnerabilities", mode="before")
    @classmethod
    def null_to_empty(cls, v: Any) -> list:
        """Trivy returns null instead of [] when no vulnerabilities found."""
        return v or []


class TrivyReport(BaseModel):
    """Root model for Trivy JSON output."""

    results: list[ScanResult] = Field(default_factory=list, alias="Results")

    model_config = {"populate_by_name": True}

    @field_validator("results", mode="before")
    @classmethod
    def null_to_empty(cls, v: Any) -> list:
        """Handle null Results."""
        return v or []

    @property
    def total_vulnerabilities(self) -> int:
        """Total count of vulnerabilities across all targets."""
        return sum(len(r.vulnerabilities) for r in self.results)

    @property
    def all_vulnerabilities(self) -> list[Vulnerability]:
        """Flat list of all vulnerabilities."""
        return [v for r in self.results for v in r.vulnerabilities]


# ── Enriched models (used after intelligence layer) ───────────────


class EnrichedVulnerability(BaseModel):
    """Vulnerability enriched with EPSS, KEV, and risk score."""

    cve_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str = ""
    severity: str
    cvss: float = 0.0
    epss: float = 0.0
    in_kev: bool = False
    has_exploit: bool = False
    risk_score: float = 0.0


# ── Dockerfile models ─────────────────────────────────────────────


class DockerfileIssue(BaseModel):
    """Single issue found during Dockerfile analysis."""

    id: str
    severity: str
    description: str
    line: int | None = None


# ── Report models ─────────────────────────────────────────────────


class ReportSummary(BaseModel):
    """Aggregated statistics for the scan report."""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    max_risk_score: float = 0.0
    kev_count: int = 0
    exploit_count: int = 0


class ScanReport(BaseModel):
    """Complete scan report — final output model."""

    image: str
    scan_time: str
    duration_seconds: float
    runtime: str = "unknown"
    summary: ReportSummary = Field(default_factory=ReportSummary)
    vulnerabilities: list[EnrichedVulnerability] = Field(default_factory=list)
    dockerfile_issues: list[DockerfileIssue] = Field(default_factory=list)
