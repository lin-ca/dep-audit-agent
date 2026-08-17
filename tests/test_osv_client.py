"""Tests for connectors/osv_client.py"""

import json
from collections.abc import Callable

import httpx
import pytest

from dep_audit_agent.connectors.exceptions import (
    OSVRequestError,
    OSVResponseValidationError,
)
from dep_audit_agent.connectors.osv_client import OSVClient
from dep_audit_agent.models import Dependency, DependencyVersion

MockAsyncClient = Callable[
    [Callable[[httpx.Request], httpx.Response]], httpx.AsyncClient
]

# ---------------------------------------------------------------------------
# batch_query — happy path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "response_json, expected_vuln_ids",
    [
        (
            {
                "results": [
                    {
                        "vulns": [
                            {"id": "CVE-2023-1234", "modified": "2023-01-01T00:00:00Z"}
                        ]
                    }
                ]
            },
            ["CVE-2023-1234"],
        ),
        ({"results": [{"vulns": []}]}, []),
    ],
    ids=["with-vulns", "no-vulns"],
)
async def test_batch_query_returns_validated_response(
    dep: Dependency,
    mock_async_client: MockAsyncClient,
    response_json: dict,
    expected_vuln_ids: list[str],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response_json)

    async with mock_async_client(handler) as http_client:
        result = await OSVClient(http_client).batch_query([dep])

    assert [v.id for v in result.results[0].vulns] == expected_vuln_ids


# ---------------------------------------------------------------------------
# batch_query — payload construction
# ---------------------------------------------------------------------------


async def test_batch_query_sends_one_query_per_dependency_version(
    mock_async_client: MockAsyncClient,
) -> None:
    dep = Dependency(
        name="flask",
        versions=[
            DependencyVersion(version_str="2.0", operator=">="),
            DependencyVersion(version_str="3.0", operator="<"),
        ],
    )
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"results": [{"vulns": []}, {"vulns": []}]})

    async with mock_async_client(handler) as http_client:
        await OSVClient(http_client).batch_query([dep])

    assert captured["body"] == {
        "queries": [
            {"version": "2.0", "package": {"name": "flask", "ecosystem": "PyPI"}},
            {"version": "3.0", "package": {"name": "flask", "ecosystem": "PyPI"}},
        ]
    }


@pytest.mark.parametrize(
    "deps",
    [[], [Dependency(name="setuptools", versions=[])]],
    ids=["empty-deps-list", "dependency-with-no-versions"],
)
async def test_batch_query_sends_no_queries_when_nothing_pinned(
    mock_async_client: MockAsyncClient, deps: list[Dependency]
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"results": []})

    async with mock_async_client(handler) as http_client:
        await OSVClient(http_client).batch_query(deps)

    assert captured["body"] == {"queries": []}


# ---------------------------------------------------------------------------
# batch_query — error handling
# ---------------------------------------------------------------------------


def _http_error_handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(500)


def _timeout_handler(_request: httpx.Request) -> httpx.Response:
    raise httpx.TimeoutException("timed out")


@pytest.mark.parametrize(
    "handler", [_http_error_handler, _timeout_handler], ids=["http-error", "timeout"]
)
async def test_batch_query_transport_failure_raises_osv_request_error(
    dep: Dependency,
    mock_async_client: MockAsyncClient,
    handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    async with mock_async_client(handler) as http_client:
        with pytest.raises(OSVRequestError):
            await OSVClient(http_client).batch_query([dep])


def _missing_required_field_handler(_request: httpx.Request) -> httpx.Response:
    # "modified" is required by OSVVulnerability but missing here
    return httpx.Response(200, json={"results": [{"vulns": [{"id": "CVE-2023-1234"}]}]})


def _non_json_handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="not json")


@pytest.mark.parametrize(
    "handler",
    [_missing_required_field_handler, _non_json_handler],
    ids=["schema-mismatch", "non-json-body"],
)
async def test_batch_query_invalid_response_raises_validation_error(
    dep: Dependency,
    mock_async_client: MockAsyncClient,
    handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    async with mock_async_client(handler) as http_client:
        with pytest.raises(OSVResponseValidationError):
            await OSVClient(http_client).batch_query([dep])
