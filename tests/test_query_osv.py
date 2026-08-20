"""Tests for tools/query_osv.py"""

from collections.abc import Callable

import pytest

from dep_audit_agent.connectors.exceptions import OSVRequestError
from dep_audit_agent.models import (
    Dependency,
    DependencyVersion,
    DependencyVulnMatch,
    OSVAffected,
    OSVAffectedPackage,
    OSVSeverity,
    OSVVulnDatabaseSpecific,
    OSVVulnDetail,
    OSVVulnerability,
    OSVVulnRange,
    OSVVulnRangeEvent,
    Severity,
)
from dep_audit_agent.tools.query_osv import batch_query_osv, enrich_cve_details

# ---------------------------------------------------------------------------
# batch_query_osv
# ---------------------------------------------------------------------------


class _FakeQueryClient:
    """Test double standing in for OSVClient — batch_query_osv only relies
    on the async query_and_match method, so a duck-typed fake is sufficient."""

    def __init__(self, matches: list[DependencyVulnMatch]) -> None:
        self._matches = matches
        self.received_deps: list[Dependency] | None = None

    async def query_and_match(
        self, deps: list[Dependency]
    ) -> list[DependencyVulnMatch]:
        self.received_deps = deps
        return self._matches


@pytest.mark.parametrize(
    "pinned_names, unpinned_names",
    [
        pytest.param(["requests"], ["flask"], id="mixed-pinned-and-unpinned"),
        pytest.param([], ["flask"], id="all-unpinned"),
        pytest.param([], [], id="empty-input"),
    ],
)
async def test_batch_query_osv_splits_pinned_and_unpinned(
    pinned_dep_factory: Callable[[str], Dependency],
    unpinned_dep_factory: Callable[[str], Dependency],
    pinned_names: list[str],
    unpinned_names: list[str],
) -> None:
    pinned_deps = [pinned_dep_factory(name) for name in pinned_names]
    unpinned_deps = [unpinned_dep_factory(name) for name in unpinned_names]
    client = _FakeQueryClient([])

    _, actual_unpinned = await batch_query_osv(pinned_deps + unpinned_deps, client)

    assert actual_unpinned == unpinned_names
    assert client.received_deps == pinned_deps


async def test_batch_query_osv_dep_with_mixed_operators_counts_as_pinned() -> None:
    dep = Dependency(
        name="celery",
        versions=[
            DependencyVersion(version_str="5.0", operator=">="),
            DependencyVersion(version_str="5.3.4", operator="=="),
        ],
    )
    client = _FakeQueryClient([])

    _, unpinned_names = await batch_query_osv([dep], client)

    assert unpinned_names == []
    assert client.received_deps == [dep]


async def test_batch_query_osv_returns_client_matches(
    pinned_dep_factory: Callable[[str], Dependency],
) -> None:
    pinned = pinned_dep_factory("requests")
    matches = [
        DependencyVulnMatch(dependency=pinned, version=pinned.versions[0], vulns=[])
    ]
    client = _FakeQueryClient(matches)

    actual_matches, _ = await batch_query_osv([pinned], client)

    assert actual_matches == matches


# ---------------------------------------------------------------------------
# enrich_cve_details
# ---------------------------------------------------------------------------


class _FakeDetailClient:
    """Test double standing in for OSVClient — enrich_cve_details only relies
    on the async get_vuln_detail method, so a duck-typed fake is sufficient."""

    def __init__(
        self,
        details_by_id: dict[str, OSVVulnDetail],
        failing_ids: frozenset[str] = frozenset(),
    ) -> None:
        self._details_by_id = details_by_id
        self._failing_ids = failing_ids
        self.requested_ids: list[str] = []

    async def get_vuln_detail(self, vuln_id: str) -> OSVVulnDetail:
        self.requested_ids.append(vuln_id)
        if vuln_id in self._failing_ids:
            raise OSVRequestError(f"OSV request failed for {vuln_id}")
        return self._details_by_id[vuln_id]


def _detail(
    vuln_id: str,
    dep: Dependency,
    *,
    severity: str | None = None,
    introduced: str | None = "0",
    fixed: str | None = "2.29.0",
    summary: str | None = "A vulnerability.",
    cvss_vectors: list[OSVSeverity] | None = None,
) -> OSVVulnDetail:
    return OSVVulnDetail(
        id=vuln_id,
        summary=summary,
        affected=[
            OSVAffected(
                package=OSVAffectedPackage(name=dep.name, ecosystem=dep.ecosystem),
                ranges=[
                    OSVVulnRange(
                        type="ECOSYSTEM",
                        events=[OSVVulnRangeEvent(introduced=introduced, fixed=fixed)],
                    )
                ],
            )
        ],
        severity=cvss_vectors or [],
        database_specific=(
            OSVVulnDatabaseSpecific(severity=severity) if severity else None
        ),
    )


async def test_enrich_cve_details_maps_detail_onto_finding(
    dep: Dependency,
) -> None:
    detail = _detail("CVE-2023-1234", dep, severity="HIGH")
    match = DependencyVulnMatch(
        dependency=dep,
        version=dep.versions[0],
        vulns=[OSVVulnerability(id="CVE-2023-1234", modified="2023-01-01T00:00:00Z")],
    )
    client = _FakeDetailClient({"CVE-2023-1234": detail})

    findings = await enrich_cve_details([match], client)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.dep_ref == dep
    assert finding.cve_id == "CVE-2023-1234"
    assert finding.severity == Severity.HIGH
    assert finding.affected_range == "<2.29.0"
    assert finding.fix_version == "2.29.0"
    assert finding.description == "A vulnerability."


async def test_enrich_cve_details_fetches_each_unique_vuln_once(
    dep: Dependency, pinned_dep_factory: Callable[[str], Dependency]
) -> None:
    other_dep = pinned_dep_factory("flask")
    shared_vuln = OSVVulnerability(id="CVE-2023-1234", modified="2023-01-01T00:00:00Z")
    matches = [
        DependencyVulnMatch(
            dependency=dep, version=dep.versions[0], vulns=[shared_vuln]
        ),
        DependencyVulnMatch(
            dependency=other_dep, version=other_dep.versions[0], vulns=[shared_vuln]
        ),
    ]
    client = _FakeDetailClient({"CVE-2023-1234": _detail("CVE-2023-1234", dep)})

    findings = await enrich_cve_details(matches, client)

    assert client.requested_ids == ["CVE-2023-1234"]
    assert len(findings) == 2


async def test_enrich_cve_details_empty_matches_returns_empty_list() -> None:
    client = _FakeDetailClient({})

    findings = await enrich_cve_details([], client)

    assert findings == []


@pytest.mark.parametrize(
    "raw_severity, expected",
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("MODERATE", Severity.MEDIUM),
        ("MEDIUM", Severity.MEDIUM),
        ("LOW", Severity.LOW),
        ("low", Severity.LOW),
        ("bogus", Severity.UNKNOWN),
        (None, Severity.UNKNOWN),
    ],
)
async def test_enrich_cve_details_maps_severity_labels(
    dep: Dependency, raw_severity: str | None, expected: Severity
) -> None:
    detail = _detail("CVE-2023-1234", dep, severity=raw_severity)
    match = DependencyVulnMatch(
        dependency=dep,
        version=dep.versions[0],
        vulns=[OSVVulnerability(id="CVE-2023-1234", modified="2023-01-01T00:00:00Z")],
    )
    client = _FakeDetailClient({"CVE-2023-1234": detail})

    findings = await enrich_cve_details([match], client)

    assert findings[0].severity == expected


@pytest.mark.parametrize(
    "introduced, fixed, expected_range, expected_fix_version",
    [
        pytest.param("0", "2.29.0", "<2.29.0", "2.29.0", id="unbounded-lower"),
        pytest.param(
            "1.0.0", "2.29.0", ">=1.0.0,<2.29.0", "2.29.0", id="bounded-lower"
        ),
        pytest.param("1.0.0", None, ">=1.0.0", None, id="no-fix-available"),
    ],
)
async def test_enrich_cve_details_renders_affected_range(
    dep: Dependency,
    introduced: str,
    fixed: str | None,
    expected_range: str,
    expected_fix_version: str | None,
) -> None:
    detail = _detail("CVE-2023-1234", dep, introduced=introduced, fixed=fixed)
    match = DependencyVulnMatch(
        dependency=dep,
        version=dep.versions[0],
        vulns=[OSVVulnerability(id="CVE-2023-1234", modified="2023-01-01T00:00:00Z")],
    )
    client = _FakeDetailClient({"CVE-2023-1234": detail})

    findings = await enrich_cve_details([match], client)

    assert findings[0].affected_range == expected_range
    assert findings[0].fix_version == expected_fix_version


async def test_enrich_cve_details_prefers_ecosystem_range_over_git_range(
    dep: Dependency,
) -> None:
    # OSV lists a GIT range (commit hashes) ahead of the ECOSYSTEM range (versions)
    # for the same affected entry — the version-based range must win.
    detail = OSVVulnDetail(
        id="CVE-2023-1234",
        summary="A vulnerability.",
        affected=[
            OSVAffected(
                package=OSVAffectedPackage(name=dep.name, ecosystem=dep.ecosystem),
                ranges=[
                    OSVVulnRange(
                        type="GIT",
                        events=[
                            OSVVulnRangeEvent(introduced="0"),
                            OSVVulnRangeEvent(fixed="a1b2c3d"),
                        ],
                    ),
                    OSVVulnRange(
                        type="ECOSYSTEM",
                        events=[
                            OSVVulnRangeEvent(introduced="0"),
                            OSVVulnRangeEvent(fixed="2.29.0"),
                        ],
                    ),
                ],
            )
        ],
    )
    match = DependencyVulnMatch(
        dependency=dep,
        version=dep.versions[0],
        vulns=[OSVVulnerability(id="CVE-2023-1234", modified="2023-01-01T00:00:00Z")],
    )
    client = _FakeDetailClient({"CVE-2023-1234": detail})

    findings = await enrich_cve_details([match], client)

    assert findings[0].affected_range == "<2.29.0"
    assert findings[0].fix_version == "2.29.0"


async def test_enrich_cve_details_skips_findings_for_failed_detail_lookups(
    dep: Dependency, pinned_dep_factory: Callable[[str], Dependency]
) -> None:
    other_dep = pinned_dep_factory("flask")
    ok_vuln = OSVVulnerability(id="CVE-OK", modified="2023-01-01T00:00:00Z")
    failing_vuln = OSVVulnerability(id="CVE-FAILS", modified="2023-01-01T00:00:00Z")
    matches = [
        DependencyVulnMatch(dependency=dep, version=dep.versions[0], vulns=[ok_vuln]),
        DependencyVulnMatch(
            dependency=other_dep, version=other_dep.versions[0], vulns=[failing_vuln]
        ),
    ]
    client = _FakeDetailClient(
        {"CVE-OK": _detail("CVE-OK", dep)}, failing_ids=frozenset({"CVE-FAILS"})
    )

    findings = await enrich_cve_details(matches, client)

    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-OK"


async def test_enrich_cve_details_no_matching_affected_entry_is_unknown_range(
    dep: Dependency, pinned_dep_factory: Callable[[str], Dependency]
) -> None:
    # detail's `affected` list refers to a different package than the queried dependency
    other_dep = pinned_dep_factory("flask")
    detail = _detail("CVE-2023-1234", other_dep)
    match = DependencyVulnMatch(
        dependency=dep,
        version=dep.versions[0],
        vulns=[OSVVulnerability(id="CVE-2023-1234", modified="2023-01-01T00:00:00Z")],
    )
    client = _FakeDetailClient({"CVE-2023-1234": detail})

    findings = await enrich_cve_details([match], client)

    assert findings[0].affected_range == "unknown"
    assert findings[0].fix_version is None


# ---------------------------------------------------------------------------
# enrich_cve_details — CVSS score extraction
# ---------------------------------------------------------------------------


async def test_enrich_cve_details_extracts_cvss_score_from_v3_vector(
    dep: Dependency,
) -> None:
    detail = _detail(
        "CVE-2023-1234",
        dep,
        cvss_vectors=[
            OSVSeverity(
                type="CVSS_V3", score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            )
        ],
    )
    match = DependencyVulnMatch(
        dependency=dep,
        version=dep.versions[0],
        vulns=[OSVVulnerability(id="CVE-2023-1234", modified="2023-01-01T00:00:00Z")],
    )
    client = _FakeDetailClient({"CVE-2023-1234": detail})

    findings = await enrich_cve_details([match], client)

    assert findings[0].cvss_score == 9.8


async def test_enrich_cve_details_prefers_newer_cvss_version(dep: Dependency) -> None:
    # advisory publishes both v3 and v4 vectors for the same finding — v4 should win
    detail = _detail(
        "CVE-2023-1234",
        dep,
        cvss_vectors=[
            OSVSeverity(
                type="CVSS_V3", score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            ),
            OSVSeverity(
                type="CVSS_V4",
                score="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            ),
        ],
    )
    match = DependencyVulnMatch(
        dependency=dep,
        version=dep.versions[0],
        vulns=[OSVVulnerability(id="CVE-2023-1234", modified="2023-01-01T00:00:00Z")],
    )
    client = _FakeDetailClient({"CVE-2023-1234": detail})

    findings = await enrich_cve_details([match], client)

    assert findings[0].cvss_score == 9.3


async def test_enrich_cve_details_no_severity_vectors_yields_none_score(
    dep: Dependency,
) -> None:
    detail = _detail("CVE-2023-1234", dep)
    match = DependencyVulnMatch(
        dependency=dep,
        version=dep.versions[0],
        vulns=[OSVVulnerability(id="CVE-2023-1234", modified="2023-01-01T00:00:00Z")],
    )
    client = _FakeDetailClient({"CVE-2023-1234": detail})

    findings = await enrich_cve_details([match], client)

    assert findings[0].cvss_score is None


async def test_enrich_cve_details_malformed_cvss_vector_does_not_break_batch(
    dep: Dependency, pinned_dep_factory: Callable[[str], Dependency]
) -> None:
    # a malformed vector on one advisory must not crash enrichment for the batch,
    # and must not affect the finding produced for any other advisory
    other_dep = pinned_dep_factory("flask")
    bad_detail = _detail(
        "CVE-BAD",
        dep,
        cvss_vectors=[OSVSeverity(type="CVSS_V3", score="not-a-real-vector")],
    )
    good_detail = _detail(
        "CVE-GOOD",
        other_dep,
        cvss_vectors=[
            OSVSeverity(
                type="CVSS_V3", score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            )
        ],
    )
    matches = [
        DependencyVulnMatch(
            dependency=dep,
            version=dep.versions[0],
            vulns=[OSVVulnerability(id="CVE-BAD", modified="2023-01-01T00:00:00Z")],
        ),
        DependencyVulnMatch(
            dependency=other_dep,
            version=other_dep.versions[0],
            vulns=[OSVVulnerability(id="CVE-GOOD", modified="2023-01-01T00:00:00Z")],
        ),
    ]
    client = _FakeDetailClient({"CVE-BAD": bad_detail, "CVE-GOOD": good_detail})

    findings = await enrich_cve_details(matches, client)

    findings_by_id = {f.cve_id: f for f in findings}
    assert len(findings) == 2
    assert findings_by_id["CVE-BAD"].cvss_score is None
    assert findings_by_id["CVE-GOOD"].cvss_score == 9.8


# ---------------------------------------------------------------------------
# enrich_cve_details — description truncation
# ---------------------------------------------------------------------------


async def test_enrich_cve_details_truncates_description_to_500_chars(
    dep: Dependency,
) -> None:
    detail = _detail("CVE-2023-1234", dep, summary="x" * 600)
    match = DependencyVulnMatch(
        dependency=dep,
        version=dep.versions[0],
        vulns=[OSVVulnerability(id="CVE-2023-1234", modified="2023-01-01T00:00:00Z")],
    )
    client = _FakeDetailClient({"CVE-2023-1234": detail})

    findings = await enrich_cve_details([match], client)

    assert len(findings[0].description) == 500
    assert findings[0].description == "x" * 500


async def test_enrich_cve_details_leaves_short_description_untouched(
    dep: Dependency,
) -> None:
    detail = _detail("CVE-2023-1234", dep, summary="short.")
    match = DependencyVulnMatch(
        dependency=dep,
        version=dep.versions[0],
        vulns=[OSVVulnerability(id="CVE-2023-1234", modified="2023-01-01T00:00:00Z")],
    )
    client = _FakeDetailClient({"CVE-2023-1234": detail})

    findings = await enrich_cve_details([match], client)

    assert findings[0].description == "short."
