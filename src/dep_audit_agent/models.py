"""Pydantic models for input/response validation"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Dependency(BaseModel):
    name: str
    version: str | None
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


class AgentPlan(BaseModel):
    """Ordered list of tool calls with parameters."""

    # TODO Fill in when implementing agent
    pass
