"""Pydantic models for vulnerability data throughout the pipeline."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class Vulnerability(BaseModel):
    """Single vulnerability from Trivy scan output."""

    cve_id: str = Field(alias="VulnerabilityID")
    pkg_name: str = Field(alias="PkgName")
    installed_version: str = Field(alias="InstalledVersion")
    fixed_version: str = Field(default="", alias="FixedVersion")
    severity: str = Field(alias="Severity")

    description: str = Field(default="", alias="Description")
    cwe_ids: list[str] = Field(default_factory=list, alias="CweIDs")
    references: list[str] = Field(default_factory=list, alias="References")

    purl: str = Field(default="", alias="PURL")
    cvss: float = 0.0
    cvss_vector: str = ""
    exploitability_score: float = 0.0
    impact_score: float = 0.0

    model_config = {"populate_by_name": True}

    @field_validator("cwe_ids", "references", mode="before")
    @classmethod
    def null_to_empty_list(cls, v: Any) -> list:
        return v or []

    @model_validator(mode="before")
    @classmethod
    def extract_nested_data(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        cvss_map = data.get("CVSS") or {}
        score = 0.0
        vector = ""
        exploitability = 0.0
        impact = 0.0

        if "nvd" in cvss_map:
            nvd_data = cvss_map["nvd"]
            score = nvd_data.get("V3Score", 0.0) or 0.0
            vector = nvd_data.get("V3Vector", "") or ""
            exploitability = nvd_data.get("ExploitabilityScore", 0.0) or 0.0
            impact = nvd_data.get("ImpactScore", 0.0) or 0.0
        else:
            for source in cvss_map.values():
                if isinstance(source, dict) and source.get("V3Score"):
                    score = source["V3Score"]
                    vector = source.get("V3Vector", "")
                    exploitability = source.get("ExploitabilityScore", 0.0) or 0.0
                    impact = source.get("ImpactScore", 0.0) or 0.0
                    break

        data["cvss"] = score
        data["cvss_vector"] = vector
        data["exploitability_score"] = exploitability
        data["impact_score"] = impact

        pkg_id = data.get("PkgIdentifier")
        purl = ""
        if isinstance(pkg_id, dict) and "PURL" in pkg_id:
            purl = pkg_id["PURL"]
        elif isinstance(pkg_id, str):
            purl = pkg_id
        elif "PURL" in data:
            purl = data["PURL"]
        data["purl"] = purl

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


class EnrichedVulnerability(BaseModel):
    """Vulnerability enriched with EPSS, KEV, ML context, and risk score."""

    cve_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str = ""
    severity: str

    cvss: float = 0.0
    cvss_vector: str = ""
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    description: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    purl: str = ""

    epss: float = 0.0
    in_kev: bool = False
    has_exploit: bool = False
    risk_score: float = 0.0


class DockerfileIssue(BaseModel):
    id: str
    severity: str
    description: str
    line: int | None = None


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
