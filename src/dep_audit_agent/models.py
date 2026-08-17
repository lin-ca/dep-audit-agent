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


class AgentPlan(BaseModel):
    """Ordered list of tool calls with parameters."""

    # TODO Fill in when implementing agent
    pass
