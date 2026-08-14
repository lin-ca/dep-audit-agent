import tomllib
from pathlib import Path

from packaging.requirements import Requirement

from dep_audit_agent.models import Dependency, DependencyVersion


def parse_dependencies(deps: list[str]) -> list[Dependency]:
    # Context-Minimization: raw dependency strings are parsed into structured
    # Dependency models here and are not retained or passed to any subsequent step.
    parsed_deps = []
    for dep in deps:
        r = Requirement(dep)
        versions = [
            DependencyVersion(version_str=s.version, operator=s.operator)
            for s in r.specifier
        ]
        parsed_deps.append(Dependency(name=r.name, versions=versions, ecosystem="PyPI"))
    return parsed_deps


def parse_toml_file(toml_file: Path) -> list[Dependency]:
    with open(toml_file, "rb") as f:
        data = tomllib.load(f)
    # Only [project.dependencies] is audited; optional-dependencies and dev groups are out of scope
    deps = data.get("project", {}).get("dependencies", [])
    return parse_dependencies(deps)


def parse_text_file(txt_file: Path) -> list[Dependency]:
    deps = []
    with open(txt_file) as f:
        for line in f:
            # Strip inline comments before whitespace so "pkg>=1.0  # note" parses correctly
            stripped_line = line.split("#")[0].strip()
            if not stripped_line or stripped_line.startswith("-"):
                continue
            deps.append(stripped_line)
    return parse_dependencies(deps)
