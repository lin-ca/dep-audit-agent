from dep_audit_agent.models import Severity, VulnerabilityFinding

_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.UNKNOWN,
)
_SEVERITY_RANK: dict[Severity, int] = {s: i for i, s in enumerate(_SEVERITY_ORDER)}


def _sort_key(finding: VulnerabilityFinding) -> tuple[int, float]:
    # Severity is a StrEnum, so it compares alphabetically, not by urgency
    # (e.g. "low" < "medium") — an explicit rank is required to sort by tier.
    # A missing CVSS score sorts last within its tier: no score data shouldn't
    # outrank a finding we know is genuinely low-severity.
    cvss = finding.cvss_score if finding.cvss_score is not None else float("-inf")
    return (_SEVERITY_RANK[finding.severity], -cvss)


def prioritize_findings(
    findings: list[VulnerabilityFinding], unpinned: list[str]
) -> tuple[list[VulnerabilityFinding], list[str]]:
    """
    Sorts findings by severity tier (CRITICAL -> UNKNOWN), then by CVSS score
    descending within each tier.

    `unpinned` is passed through unchanged as the separate flagged-unpinned list.
    """
    return sorted(findings, key=_sort_key), unpinned
