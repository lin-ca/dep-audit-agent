"""Shared test fixtures for dep_audit_agent tests."""

from collections.abc import Callable

import httpx
import pytest

from dep_audit_agent.models import Dependency, DependencyVersion, Severity

# Captured at import time, before any test monkeypatches httpx.AsyncClient.
_REAL_ASYNC_CLIENT = httpx.AsyncClient


@pytest.fixture
def dep() -> Dependency:
    return Dependency(
        name="requests",
        versions=[DependencyVersion(version_str="2.28.0", operator="==")],
    )


@pytest.fixture
def finding(dep: Dependency) -> dict:
    return {
        "dep_ref": dep,
        "cve_id": "CVE-2023-1234",
        "severity": Severity.HIGH,
        "affected_range": "<2.29.0",
        "fix_version": "2.29.0",
        "description": "A vulnerability in requests.",
    }


@pytest.fixture
def pinned_dep_factory() -> Callable[[str], Dependency]:
    def _make(name: str, version_str: str = "1.0.0") -> Dependency:
        return Dependency(
            name=name,
            versions=[DependencyVersion(version_str=version_str, operator="==")],
        )

    return _make


@pytest.fixture
def unpinned_dep_factory() -> Callable[[str], Dependency]:
    def _make(name: str, version_str: str = "1.0.0") -> Dependency:
        return Dependency(
            name=name,
            versions=[DependencyVersion(version_str=version_str, operator=">=")],
        )

    return _make


@pytest.fixture
def mock_async_client() -> Callable[
    [Callable[[httpx.Request], httpx.Response]], httpx.AsyncClient
]:
    """Builds an AsyncClient backed by a MockTransport, so tests never hit the network."""

    def _make(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
        return _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler))

    return _make


@pytest.fixture
def patch_async_client(
    monkeypatch: pytest.MonkeyPatch,
    mock_async_client: Callable[
        [Callable[[httpx.Request], httpx.Response]], httpx.AsyncClient
    ],
) -> Callable[[Callable[[httpx.Request], httpx.Response]], None]:
    """Patches main's httpx.AsyncClient constructor to return a mock-backed client."""

    def _patch(handler: Callable[[httpx.Request], httpx.Response]) -> None:
        monkeypatch.setattr(
            "dep_audit_agent.main.httpx.AsyncClient",
            lambda *_args, **_kwargs: mock_async_client(handler),
        )

    return _patch
