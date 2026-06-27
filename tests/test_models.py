import pytest
from pydantic import ValidationError

from dep_audit_agent.models import (
    Dependency,
    DependencyVersion,
    Severity,
    VulnerabilityFinding,
)


def test_dependency_defaults_ecosystem() -> None:
    flask = Dependency(
        name="flask",
        versions=[DependencyVersion(version_str="3.0.0", operator="==")],
    )
    assert flask.ecosystem == "PyPI"


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


@pytest.mark.parametrize("score", [0.0, 5.0, 10.0])
def test_cvss_score_valid(finding: dict, score: float) -> None:
    assert VulnerabilityFinding(**{**finding, "cvss_score": score}).cvss_score == score


def test_cvss_score_default_none(finding: dict) -> None:
    assert VulnerabilityFinding(**finding).cvss_score is None


@pytest.mark.parametrize("score", [-0.1, 10.1, 100.0])
def test_cvss_score_out_of_range(finding: dict, score: float) -> None:
    with pytest.raises(ValidationError):
        VulnerabilityFinding(**{**finding, "cvss_score": score})
