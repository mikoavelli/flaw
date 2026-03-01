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

    description: str = Field(default="", alias="Description")
    cwe_ids: list[str] = Field(default_factory=list, alias="CweIDs")

    purl: str = Field(default="", alias="PURL")
    cvss: float = 0.0
    cvss_vector: str = ""

    model_config = {"populate_by_name": True}

    @field_validator("cwe_ids", mode="before")
    @classmethod
    def null_to_empty_list(cls, v: Any) -> list:
        return v or []

    @model_validator(mode="before")
    @classmethod
    def extract_nested_data(cls, data: Any) -> Any:
        """Extract CVSS scores and PURL from nested Trivy objects."""
        if not isinstance(data, dict):
            return data

        cvss_map = data.get("CVSS") or {}
        score = 0.0
        vector = ""

        if "nvd" in cvss_map:
            score = cvss_map["nvd"].get("V3Score", 0.0) or 0.0
            vector = cvss_map["nvd"].get("V3Vector", "") or ""
        else:
            for source in cvss_map.values():
                if isinstance(source, dict) and source.get("V3Score"):
                    score = source["V3Score"]
                    vector = source.get("V3Vector", "")
                    break

        data["cvss"] = score
        data["cvss_vector"] = vector

        pkg_id = data.get("PkgIdentifier")
        if isinstance(pkg_id, dict) and "PURL" in pkg_id:
            data["purl"] = pkg_id["PURL"]
        elif "PURL" in data:
            data["purl"] = data["PURL"]

        return data


class ScanResult(BaseModel):
    """Single scan target (e.g., OS packages, Python packages)."""

    target: str = Field(alias="Target")
    vulnerabilities: list[Vulnerability] = Field(default_factory=list, alias="Vulnerabilities")

    model_config = {"populate_by_name": True}

    @field_validator("vulnerabilities", mode="before")
    @classmethod
    def null_to_empty(cls, v: Any) -> list:
        return v or []


class TrivyReport(BaseModel):
    """Root model for Trivy JSON output."""

    results: list[ScanResult] = Field(default_factory=list, alias="Results")

    model_config = {"populate_by_name": True}

    @field_validator("results", mode="before")
    @classmethod
    def null_to_empty(cls, v: Any) -> list:
        return v or []

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(r.vulnerabilities) for r in self.results)

    @property
    def all_vulnerabilities(self) -> list[Vulnerability]:
        return [v for r in self.results for v in r.vulnerabilities]


# ── Enriched models (used after intelligence layer) ───────────────


class EnrichedVulnerability(BaseModel):
    """Vulnerability enriched with EPSS, KEV, ML context, and risk score."""

    cve_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str = ""
    severity: str

    cvss: float = 0.0
    cvss_vector: str = ""
    description: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    purl: str = ""

    epss: float = 0.0
    in_kev: bool = False
    has_exploit: bool = False
    risk_score: float = 0.0


# ── Dockerfile models ─────────────────────────────────────────────


class DockerfileIssue(BaseModel):
    id: str
    severity: str
    description: str
    line: int | None = None


# ── Report models ─────────────────────────────────────────────────


class ReportSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    max_risk_score: float = 0.0
    kev_count: int = 0
    exploit_count: int = 0


class ScanReport(BaseModel):
    image: str
    scan_time: str
    duration_seconds: float
    runtime: str = "unknown"
    summary: ReportSummary = Field(default_factory=ReportSummary)
    vulnerabilities: list[EnrichedVulnerability] = Field(default_factory=list)
    dockerfile_issues: list[DockerfileIssue] | None = None
