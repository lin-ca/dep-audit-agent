"""Pydantic models for input/response validation"""

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

type OPERATOR = Literal[">=", "<=", ">", "<", "==", "!=", "~="]


class DependencyVersion(BaseModel):
    version_str: str
    operator: OPERATOR = Field(description="Operator for specifying version number")


class Dependency(BaseModel):
    name: str
    versions: list[DependencyVersion]
    ecosystem: str = "PyPI"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class VulnerabilityFinding(BaseModel):
    dep_ref: Dependency
    cve_id: str
    severity: Severity
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    affected_range: str
    fix_version: str | None
    description: str = Field(
        ..., description="Raw text from OSV API — sanitize before passing to LLM"
    )


class Metadata(BaseModel):
    timestamp: datetime
    file_parsed: str


class AuditReport(BaseModel):
    findings: list[VulnerabilityFinding]
    unpinned_deps_flagged: list[str]
    metadata: Metadata


class OSVVulnerability(BaseModel):
    """
    Minimal vuln reference from OSV's batch query response. Only id and modified
    are returned by querybatch; full details are fetched later in enrich_cve_details.
    """

    id: str
    modified: datetime


class OSVQueryResult(BaseModel):
    """Vulnerabilities found for a single queried dependency version."""

    vulns: list[OSVVulnerability] = []


class OSVBatchResponse(BaseModel):
    """Validated shape of OSV.dev's /querybatch response, one result per query."""

    results: list[OSVQueryResult]


class DependencyVulnMatch(BaseModel):
    """An OSV query result paired back with the (dependency, version) it was queried for."""

    dependency: Dependency
    version: DependencyVersion
    vulns: list[OSVVulnerability]


class OSVVulnRangeEvent(BaseModel):
    """One boundary of an affected version range, e.g. {"introduced": "0"} or {"fixed": "2.29.0"}."""

    introduced: str | None = None
    fixed: str | None = None


class OSVVulnRange(BaseModel):
    type: str
    events: list[OSVVulnRangeEvent] = []


class OSVAffectedPackage(BaseModel):
    name: str
    ecosystem: str


class OSVAffected(BaseModel):
    """The affected package and version ranges for one entry in a vuln's `affected` list."""

    package: OSVAffectedPackage
    ranges: list[OSVVulnRange] = []


class OSVVulnDatabaseSpecific(BaseModel):
    severity: str | None = None


class OSVSeverity(BaseModel):
    """One CVSS scoring entry, e.g. {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}."""

    type: str
    score: str


class OSVVulnDetail(BaseModel):
    """
    Validated shape of OSV.dev's GET /v1/vulns/{id} response (fields we use).
    `summary`/`details` are untrusted external text — sanitize before passing to an LLM.
    """

    id: str
    summary: str | None = None
    details: str | None = None
    affected: list[OSVAffected] = []
    severity: list[OSVSeverity] = []
    database_specific: OSVVulnDatabaseSpecific | None = None
