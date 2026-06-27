from pathlib import Path

import pytest

from dep_audit_agent.tools.parse_dependencies import (
    parse_dependencies,
    parse_text_file,
    parse_toml_file,
)

# ---------------------------------------------------------------------------
# parse_dependencies (unit)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "dep_str, expected_name, expected_versions",
    [
        ("requests==2.28.0", "requests", [("==", "2.28.0")]),
        ("flask>=2.0,<3.0", "flask", [(">=", "2.0"), ("<", "3.0")]),
        ("setuptools", "setuptools", []),
        ("celery~=5.3.4", "celery", [("~=", "5.3.4")]),
        ("numpy!=1.24.0", "numpy", [("!=", "1.24.0")]),
        ("requests[security]>=2.28.0", "requests", [(">=", "2.28.0")]),
    ],
)
def test_parse_dependencies(
    dep_str: str,
    expected_name: str,
    expected_versions: list[tuple[str, str]],
) -> None:
    result = parse_dependencies([dep_str])
    assert len(result) == 1
    dep = result[0]
    assert dep.name == expected_name
    assert dep.ecosystem == "PyPI"
    actual = {(v.operator, v.version_str) for v in dep.versions}
    assert actual == set(expected_versions)


def test_parse_dependencies_unpinned_yields_empty_versions() -> None:
    result = parse_dependencies(["setuptools"])
    assert result[0].versions == []


# ---------------------------------------------------------------------------
# parse_toml_file
# ---------------------------------------------------------------------------


def test_parse_toml_file(tmp_path: Path) -> None:
    toml = tmp_path / "pyproject.toml"
    toml.write_text(
        '[project]\ndependencies = ["requests>=2.28.0", "flask==3.0.0", "setuptools"]\n'
    )
    result = parse_toml_file(toml)
    names = {d.name for d in result}
    assert names == {"requests", "flask", "setuptools"}


def test_parse_toml_file_no_dependencies_section(tmp_path: Path) -> None:
    toml = tmp_path / "pyproject.toml"
    toml.write_text("[project]\nname = 'foo'\n")
    assert parse_toml_file(toml) == []


# ---------------------------------------------------------------------------
# parse_text_file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line, expected_name",
    [
        ("requests>=2.28.0\n", "requests"),
        ("black==26.3.1\n", "black"),
        ("setuptools\n", "setuptools"),
        ("requests>=2.28.0  # inline comment\n", "requests"),
        ('pywin32>=300; sys_platform == "win32"\n', "pywin32"),
    ],
)
def test_parse_text_file_single_lines(
    tmp_path: Path, line: str, expected_name: str
) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text(line)
    result = parse_text_file(req)
    assert len(result) == 1
    assert result[0].name == expected_name


@pytest.mark.parametrize(
    "line",
    [
        "# full-line comment\n",
        "\n",
        "-r other.txt\n",
        "--index-url https://pypi.org/simple/\n",
    ],
)
def test_parse_text_file_skipped_lines(tmp_path: Path, line: str) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text(line)
    assert parse_text_file(req) == []


def test_parse_text_file_example_file() -> None:
    example = Path(__file__).parent.parent / "example_files/example_requirements.txt"
    result = parse_text_file(example)
    names = {d.name for d in result}
    assert "requests" in names
    assert "black" in names
    assert "setuptools" in names
