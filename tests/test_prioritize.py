"""Tests for tools/prioritize.py"""

import pytest

from dep_audit_agent.models import Dependency, Severity, VulnerabilityFinding
from dep_audit_agent.tools.prioritize import prioritize_findings


def _finding(
    cve_id: str, severity: Severity, cvss_score: float | None, dep: Dependency
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        dep_ref=dep,
        cve_id=cve_id,
        severity=severity,
        cvss_score=cvss_score,
        affected_range="<2.29.0",
        fix_version="2.29.0",
        description="A vulnerability.",
    )


def test_prioritize_findings_sorts_by_severity_tier(dep: Dependency) -> None:
    low = _finding("CVE-LOW", Severity.LOW, None, dep)
    critical = _finding("CVE-CRITICAL", Severity.CRITICAL, None, dep)
    unknown = _finding("CVE-UNKNOWN", Severity.UNKNOWN, None, dep)
    medium = _finding("CVE-MEDIUM", Severity.MEDIUM, None, dep)
    high = _finding("CVE-HIGH", Severity.HIGH, None, dep)

    prioritized, _ = prioritize_findings([low, critical, unknown, medium, high], [])

    assert [f.cve_id for f in prioritized] == [
        "CVE-CRITICAL",
        "CVE-HIGH",
        "CVE-MEDIUM",
        "CVE-LOW",
        "CVE-UNKNOWN",
    ]


def test_prioritize_findings_sorts_by_cvss_descending_within_tier(
    dep: Dependency,
) -> None:
    low_score = _finding("CVE-LOW-SCORE", Severity.HIGH, 4.0, dep)
    high_score = _finding("CVE-HIGH-SCORE", Severity.HIGH, 8.5, dep)
    mid_score = _finding("CVE-MID-SCORE", Severity.HIGH, 6.0, dep)

    prioritized, _ = prioritize_findings([low_score, high_score, mid_score], [])

    assert [f.cve_id for f in prioritized] == [
        "CVE-HIGH-SCORE",
        "CVE-MID-SCORE",
        "CVE-LOW-SCORE",
    ]


def test_prioritize_findings_missing_cvss_score_sorts_last_within_tier(
    dep: Dependency,
) -> None:
    scored = _finding("CVE-SCORED", Severity.HIGH, 0.0, dep)
    unscored = _finding("CVE-UNSCORED", Severity.HIGH, None, dep)

    prioritized, _ = prioritize_findings([unscored, scored], [])

    assert [f.cve_id for f in prioritized] == ["CVE-SCORED", "CVE-UNSCORED"]


def test_prioritize_findings_severity_dominates_cvss_score(dep: Dependency) -> None:
    # a HIGH-severity finding with a low score must still outrank a
    # MEDIUM-severity finding with a high score
    high_low_score = _finding("CVE-HIGH-LOW-SCORE", Severity.HIGH, 1.0, dep)
    medium_high_score = _finding("CVE-MEDIUM-HIGH-SCORE", Severity.MEDIUM, 9.9, dep)

    prioritized, _ = prioritize_findings([medium_high_score, high_low_score], [])

    assert [f.cve_id for f in prioritized] == [
        "CVE-HIGH-LOW-SCORE",
        "CVE-MEDIUM-HIGH-SCORE",
    ]


def test_prioritize_findings_passes_through_unpinned_unchanged() -> None:
    _, flagged_unpinned = prioritize_findings([], ["flask", "django"])

    assert flagged_unpinned == ["flask", "django"]


def test_prioritize_findings_empty_findings_returns_empty_list() -> None:
    prioritized, flagged_unpinned = prioritize_findings([], [])

    assert prioritized == []
    assert flagged_unpinned == []


def test_prioritize_findings_does_not_mutate_input_list(dep: Dependency) -> None:
    low = _finding("CVE-LOW", Severity.LOW, None, dep)
    critical = _finding("CVE-CRITICAL", Severity.CRITICAL, None, dep)
    original = [low, critical]

    prioritize_findings(original, [])

    assert original == [low, critical]


@pytest.mark.parametrize("severity", list(Severity))
def test_prioritize_findings_handles_every_severity_alone(
    dep: Dependency, severity: Severity
) -> None:
    finding = _finding("CVE-SOLO", severity, None, dep)

    prioritized, _ = prioritize_findings([finding], [])

    assert prioritized == [finding]
