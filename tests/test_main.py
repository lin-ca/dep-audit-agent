"""Tests for main.py"""

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from dep_audit_agent.main import _parse_file, _run_pipeline
from dep_audit_agent.models import Dependency

PatchAsyncClient = Callable[[Callable[[httpx.Request], httpx.Response]], None]

# ---------------------------------------------------------------------------
# _parse_file dispatch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename, expected_parser",
    [
        ("pyproject.toml", "toml"),
        ("requirements.txt", "text"),
        ("requirements", "text"),
        ("requirements.in", "text"),
    ],
)
def test_parse_file_dispatches_by_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    expected_parser: str,
) -> None:
    calls: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        "dep_audit_agent.main.parse_toml_file",
        lambda f: calls.append(("toml", f)) or [],
    )
    monkeypatch.setattr(
        "dep_audit_agent.main.parse_text_file",
        lambda f: calls.append(("text", f)) or [],
    )
    file = tmp_path / filename
    file.touch()

    _parse_file(file)

    assert calls == [(expected_parser, file)]


# ---------------------------------------------------------------------------
# _run_pipeline
# ---------------------------------------------------------------------------


async def test_run_pipeline_queries_osv_and_prints_results(
    tmp_path: Path,
    patch_async_client: PatchAsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.28.0\nflask>=2.0\n")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    patch_async_client(handler)

    await _run_pipeline(req_file, "./reports/")

    captured = capsys.readouterr()
    assert "Unpinned deps skipped: ['flask']" in captured.out
    assert "OSV results:" in captured.out


async def test_run_pipeline_parses_file_before_querying(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    patch_async_client: PatchAsyncClient,
) -> None:
    req_file = tmp_path / "pyproject.toml"
    req_file.write_text('[project]\ndependencies = ["requests==2.28.0"]\n')

    parsed: list[Dependency] = []

    def fake_parse_file(f: Path) -> list[Dependency]:
        parsed.append(f)
        return []

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": []})

    monkeypatch.setattr("dep_audit_agent.main._parse_file", fake_parse_file)
    patch_async_client(handler)

    await _run_pipeline(req_file, "./reports/")

    assert parsed == [req_file]
