from pathlib import Path

import typer

from dep_audit_agent.models import Dependency
from dep_audit_agent.tools.parse_dependencies import parse_text_file, parse_toml_file

app = typer.Typer()


def _parse_file(file: Path) -> list[Dependency]:
    if file.suffix == ".toml":
        return parse_toml_file(file)
    return parse_text_file(file)


@app.command()
def audit(file: Path, output: str = "./reports/") -> None:
    deps = _parse_file(file)
    for dep in deps:
        print(dep)


def main() -> None:
    app()


if __name__ == "__main__":
    app()
