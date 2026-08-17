"""Tests for tools/query_osv.py"""

from collections.abc import Callable

import pytest

from dep_audit_agent.models import (
    Dependency,
    DependencyVersion,
    OSVBatchResponse,
    OSVQueryResult,
)
from dep_audit_agent.tools.query_osv import batch_query_osv


class _FakeOSVClient:
    """Test double standing in for OSVClient — batch_query_osv only relies
    on the async batch_query method, so a duck-typed fake is sufficient."""

    def __init__(self, response: OSVBatchResponse) -> None:
        self._response = response
        self.received_deps: list[Dependency] | None = None

    async def batch_query(self, deps: list[Dependency]) -> OSVBatchResponse:
        self.received_deps = deps
        return self._response


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
    client = _FakeOSVClient(OSVBatchResponse(results=[]))

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
    client = _FakeOSVClient(OSVBatchResponse(results=[]))

    _, unpinned_names = await batch_query_osv([dep], client)

    assert unpinned_names == []
    assert client.received_deps == [dep]


async def test_batch_query_osv_returns_client_results(
    pinned_dep_factory: Callable[[str], Dependency],
) -> None:
    pinned = pinned_dep_factory("requests")
    results = [OSVQueryResult(vulns=[])]
    client = _FakeOSVClient(OSVBatchResponse(results=results))

    osv_results, _ = await batch_query_osv([pinned], client)

    assert osv_results == results
