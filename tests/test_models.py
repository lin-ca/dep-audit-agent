from datetime import datetime

import pytest
from pydantic import ValidationError

from dep_audit_agent.models import (
    AuditReport,
    Dependency,
    Metadata,
    Severity,
    VulnerabilityFinding,
)

# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def test_dependency_defaults_ecosystem() -> None:
    flask = Dependency(name="flask", version="3.0.0")
    assert flask.ecosystem == "PyPI"


def test_dependency_version_none() -> None:
    flask = Dependency(name="flask", version=None)
    assert flask.version is None


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        ("critical", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("unknown", Severity.UNKNOWN),
    ],
)
def test_severity_coercion(finding: dict, value: str, expected: Severity) -> None:
    assert VulnerabilityFinding(**{**finding, "severity": value}).severity == expected


def test_severity_invalid(finding: dict) -> None:
    with pytest.raises(ValidationError):
        VulnerabilityFinding(**{**finding, "severity": "bogus"})


# ---------------------------------------------------------------------------
# VulnerabilityFinding — cvss_score
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("score", [0.0, 5.0, 10.0])
def test_cvss_score_valid(finding: dict, score: float) -> None:
    assert VulnerabilityFinding(**{**finding, "cvss_score": score}).cvss_score == score


def test_cvss_score_default_none(finding: dict) -> None:
    assert VulnerabilityFinding(**finding).cvss_score is None


@pytest.mark.parametrize("score", [-0.1, 10.1, 100.0])
def test_cvss_score_out_of_range(finding: dict, score: float) -> None:
    with pytest.raises(ValidationError):
        VulnerabilityFinding(**{**finding, "cvss_score": score})


# ---------------------------------------------------------------------------
# VulnerabilityFinding — dep_ref is a Dependency object
# ---------------------------------------------------------------------------


def test_finding_dep_ref_is_dependency(finding: dict, dep: Dependency) -> None:
    result = VulnerabilityFinding(**finding)
    assert isinstance(result.dep_ref, Dependency)
    assert result.dep_ref.name == dep.name


def test_finding_dep_ref_coerced_from_dict(finding: dict) -> None:
    result = VulnerabilityFinding(
        **{**finding, "dep_ref": {"name": "flask", "version": "3.0.0"}}
    )
    assert isinstance(result.dep_ref, Dependency)


# ---------------------------------------------------------------------------
# AuditReport
# ---------------------------------------------------------------------------


def test_audit_report_empty_findings() -> None:
    report = AuditReport(
        findings=[],
        unpinned_deps_flagged=[],
        metadata=Metadata(timestamp=datetime.now(), file_parsed="requirements.txt"),
    )
    assert report.findings == []
    assert report.unpinned_deps_flagged == []


def test_audit_report_with_finding(finding: dict) -> None:
    result = VulnerabilityFinding(**finding)
    report = AuditReport(
        findings=[result],
        unpinned_deps_flagged=["flask"],
        metadata=Metadata(timestamp=datetime.now(), file_parsed="requirements.txt"),
    )
    assert len(report.findings) == 1
    assert report.unpinned_deps_flagged == ["flask"]
