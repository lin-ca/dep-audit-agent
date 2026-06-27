"""Shared test fixtures for dep_audit_agent tests."""

import pytest

from dep_audit_agent.models import Dependency, DependencyVersion, Severity


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
