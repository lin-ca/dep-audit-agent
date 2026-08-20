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
# query_and_match — happy path
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
async def test_query_and_match_returns_validated_response(
    dep: Dependency,
    mock_async_client: MockAsyncClient,
    response_json: dict,
    expected_vuln_ids: list[str],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response_json)

    async with mock_async_client(handler) as http_client:
        matches = await OSVClient(http_client).query_and_match([dep])

    assert [v.id for v in matches[0].vulns] == expected_vuln_ids


async def test_query_and_match_pairs_results_with_their_dependency(
    pinned_dep_factory: Callable[[str], Dependency],
    mock_async_client: MockAsyncClient,
) -> None:
    requests_dep = pinned_dep_factory("requests")
    flask_dep = pinned_dep_factory("flask")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {"id": "CVE-REQUESTS", "modified": "2023-01-01T00:00:00Z"}
                        ]
                    },
                    {"vulns": []},
                ]
            },
        )

    async with mock_async_client(handler) as http_client:
        matches = await OSVClient(http_client).query_and_match(
            [requests_dep, flask_dep]
        )

    assert matches[0].dependency == requests_dep
    assert [v.id for v in matches[0].vulns] == ["CVE-REQUESTS"]
    assert matches[1].dependency == flask_dep
    assert matches[1].vulns == []


async def test_query_and_match_result_count_mismatch_raises_validation_error(
    pinned_dep_factory: Callable[[str], Dependency],
    mock_async_client: MockAsyncClient,
) -> None:
    deps = [pinned_dep_factory("requests"), pinned_dep_factory("flask")]

    def handler(_request: httpx.Request) -> httpx.Response:
        # Only one result for two queried dependencies.
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    async with mock_async_client(handler) as http_client:
        with pytest.raises(OSVResponseValidationError):
            await OSVClient(http_client).query_and_match(deps)


# ---------------------------------------------------------------------------
# query_and_match — payload construction
# ---------------------------------------------------------------------------


async def test_query_and_match_sends_one_query_per_dependency_version(
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
        await OSVClient(http_client).query_and_match([dep])

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
async def test_query_and_match_sends_no_queries_when_nothing_pinned(
    mock_async_client: MockAsyncClient, deps: list[Dependency]
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"results": []})

    async with mock_async_client(handler) as http_client:
        await OSVClient(http_client).query_and_match(deps)

    assert captured["body"] == {"queries": []}


# ---------------------------------------------------------------------------
# query_and_match / get_vuln_detail — error handling
# ---------------------------------------------------------------------------


def _http_error_handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(500)


def _timeout_handler(_request: httpx.Request) -> httpx.Response:
    raise httpx.TimeoutException("timed out")


def _connect_error_handler(_request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused")


@pytest.mark.parametrize(
    "handler",
    [_http_error_handler, _timeout_handler, _connect_error_handler],
    ids=["http-error", "timeout", "connect-error"],
)
async def test_query_and_match_transport_failure_raises_osv_request_error(
    dep: Dependency,
    mock_async_client: MockAsyncClient,
    handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    async with mock_async_client(handler) as http_client:
        with pytest.raises(OSVRequestError):
            await OSVClient(http_client).query_and_match([dep])


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
async def test_query_and_match_invalid_response_raises_validation_error(
    dep: Dependency,
    mock_async_client: MockAsyncClient,
    handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    async with mock_async_client(handler) as http_client:
        with pytest.raises(OSVResponseValidationError):
            await OSVClient(http_client).query_and_match([dep])


# ---------------------------------------------------------------------------
# get_vuln_detail
# ---------------------------------------------------------------------------


async def test_get_vuln_detail_returns_validated_response(
    mock_async_client: MockAsyncClient,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/vulns/CVE-2023-1234"
        return httpx.Response(
            200, json={"id": "CVE-2023-1234", "summary": "A vulnerability."}
        )

    async with mock_async_client(handler) as http_client:
        detail = await OSVClient(http_client).get_vuln_detail("CVE-2023-1234")

    assert detail.id == "CVE-2023-1234"
    assert detail.summary == "A vulnerability."


@pytest.mark.parametrize(
    "handler",
    [_http_error_handler, _timeout_handler, _connect_error_handler],
    ids=["http-error", "timeout", "connect-error"],
)
async def test_get_vuln_detail_transport_failure_raises_osv_request_error(
    mock_async_client: MockAsyncClient,
    handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    async with mock_async_client(handler) as http_client:
        with pytest.raises(OSVRequestError):
            await OSVClient(http_client).get_vuln_detail("CVE-2023-1234")


@pytest.mark.parametrize(
    "handler",
    [_missing_required_field_handler, _non_json_handler],
    ids=["schema-mismatch", "non-json-body"],
)
async def test_get_vuln_detail_invalid_response_raises_validation_error(
    mock_async_client: MockAsyncClient,
    handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    async with mock_async_client(handler) as http_client:
        with pytest.raises(OSVResponseValidationError):
            await OSVClient(http_client).get_vuln_detail("CVE-2023-1234")
