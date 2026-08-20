import asyncio

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

from dep_audit_agent.connectors.osv_client import OSVClient
from dep_audit_agent.models import (
    Dependency,
    DependencyVulnMatch,
    OSVAffected,
    OSVVulnDetail,
    Severity,
    VulnerabilityFinding,
)

_SEVERITY_BY_OSV_LABEL: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_DESCRIPTION_MAX_LEN = 500

# Newest-first: prefer the highest CVSS version an advisory publishes.
_CVSS_PARSERS_BY_OSV_LABEL: dict[str, type[CVSS2 | CVSS3 | CVSS4]] = {
    "CVSS_V4": CVSS4,
    "CVSS_V3": CVSS3,
    "CVSS_V2": CVSS2,
}


async def batch_query_osv(
    deps: list[Dependency], client: OSVClient
) -> tuple[list[DependencyVulnMatch], list[str]]:
    """
    Queries OSV.dev for known vulnerabilities in pinned dependencies.

    Dependencies without an exact ("==") version constraint cannot be queried
    against OSV and are returned separately as unpinned.

    Returns a tuple of (dependency-paired OSV query matches, names of unpinned deps).
    """
    # OSV version queries require an exact version; range-constrained deps are skipped here
    pinned = [d for d in deps if any(v.operator == "==" for v in d.versions)]
    unpinned = [d.name for d in deps if not any(v.operator == "==" for v in d.versions)]

    # Only call OSV API on pinned dependencies:
    matches = await client.query_and_match(pinned)
    return matches, unpinned


def _map_severity(raw: str | None) -> Severity:
    if raw is None:
        return Severity.UNKNOWN
    return _SEVERITY_BY_OSV_LABEL.get(raw.upper(), Severity.UNKNOWN)


def _extract_cvss_score(detail: OSVVulnDetail) -> float | None:
    """
    Parses a numeric CVSS base score out of OSV's `severity` vector strings.

    The vector strings are untrusted external text supplied by the advisory source,
    so a malformed or unrecognized vector yields None instead of raising — one bad
    vector must not take down enrichment for every other finding.
    """
    scores_by_type = {entry.type: entry.score for entry in detail.severity}
    for label, parser in _CVSS_PARSERS_BY_OSV_LABEL.items():
        vector = scores_by_type.get(label)
        if vector is None:
            continue
        try:
            return float(parser(vector).base_score)
        except CVSSError:
            continue
    return None


def _find_affected(detail: OSVVulnDetail, dep: Dependency) -> OSVAffected | None:
    """
    Finds the `affected` entry in `detail` matching `dep`. An advisory's `affected`
    list can cover multiple packages/ecosystems, so the entry for our dependency
    isn't necessarily the first one.
    """
    for affected in detail.affected:
        if (
            affected.package.name == dep.name
            and affected.package.ecosystem == dep.ecosystem
        ):
            return affected
    return None


def _affected_range_and_fix_version(
    affected: OSVAffected | None,
) -> tuple[str, str | None]:
    """
    Renders the first range of `affected` as a version-constraint string (e.g. "<2.29.0"
    or ">=1.0.0,<2.29.0"), OSV's convention for an unbounded lower bound being introduced="0".
    """
    if affected is None or not affected.ranges:
        return "unknown", None

    # Prefer a version-based range (ECOSYSTEM/SEMVER) over a GIT range: OSV lists both
    # for the same entry when available, and GIT events are commit hashes, not versions.
    range_ = next((r for r in affected.ranges if r.type != "GIT"), affected.ranges[0])
    events = range_.events
    introduced = next((e.introduced for e in events if e.introduced is not None), "0")
    fixed = next((e.fixed for e in events if e.fixed is not None), None)

    if fixed is None:
        return f">={introduced}", None
    if introduced == "0":
        return f"<{fixed}", fixed
    return f">={introduced},<{fixed}", fixed


def _build_finding(
    detail: OSVVulnDetail, dep: Dependency
) -> VulnerabilityFinding | None:
    """
    Builds one VulnerabilityFinding from one OSV advisory. Never raises: a single
    malformed advisory (e.g. an unparseable CVSS vector or a missing affected entry)
    must not prevent every other advisory in the batch from producing a finding.
    """
    try:
        affected = _find_affected(detail, dep)
        affected_range, fix_version = _affected_range_and_fix_version(affected)
        description = (detail.summary or detail.details or "")[:_DESCRIPTION_MAX_LEN]
        return VulnerabilityFinding(
            dep_ref=dep,
            cve_id=detail.id,
            severity=_map_severity(
                detail.database_specific.severity if detail.database_specific else None
            ),
            cvss_score=_extract_cvss_score(detail),
            affected_range=affected_range,
            fix_version=fix_version,
            description=description,
        )
    except (ValueError, TypeError):
        return None


async def enrich_cve_details(
    matches: list[DependencyVulnMatch], client: OSVClient
) -> list[VulnerabilityFinding]:
    """
    Fetches full details for every distinct vulnerability id referenced in `matches`
    (one request each, deduplicated) and expands each (dependency, vulnerability)
    pair into a VulnerabilityFinding.

    LLM Map-Reduce pattern: each OSV advisory is an untrusted external document
    (description text, CVSS vectors, version ranges — all attacker-influenceable via
    a malicious package maintainer) processed independently of every other advisory.
    A failure or injection attempt in one advisory is contained to that advisory's
    finding and never reaches — or corrupts the output for — any other. The
    coordinator only ever receives these structured VulnerabilityFinding models,
    never raw advisory text.
    """
    unique_ids = {vuln.id for match in matches for vuln in match.vulns}
    results = await asyncio.gather(
        *(client.get_vuln_detail(vuln_id) for vuln_id in unique_ids),
        return_exceptions=True,
    )
    # A single failed lookup (e.g. a withdrawn advisory) shouldn't drop findings for
    # every other vulnerability, so failed ids are skipped rather than raised.
    details_by_id = {
        detail.id: detail for detail in results if isinstance(detail, OSVVulnDetail)
    }

    findings = []
    for match in matches:
        for vuln in match.vulns:
            detail = details_by_id.get(vuln.id)
            if detail is None:
                continue
            finding = _build_finding(detail, match.dependency)
            if finding is not None:
                findings.append(finding)
    return findings
