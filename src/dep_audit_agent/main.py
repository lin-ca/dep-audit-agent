import asyncio
from pathlib import Path

import httpx
import typer

from dep_audit_agent.connectors.osv_client import OSVClient
from dep_audit_agent.models import Dependency
from dep_audit_agent.tools.parse_dependencies import parse_text_file, parse_toml_file
from dep_audit_agent.tools.prioritize import prioritize_findings
from dep_audit_agent.tools.query_osv import batch_query_osv, enrich_cve_details

app = typer.Typer()


def _parse_file(file: Path) -> list[Dependency]:
    if file.suffix == ".toml":
        return parse_toml_file(file)
    return parse_text_file(file)


async def _run_pipeline(file: Path, _output: str) -> None:
    """
    Runs the dependency audit pipeline: parse -> query OSV -> enrich cve -> prioritize.

    Report generation is not yet implemented.
    """
    deps = _parse_file(file)

    async with httpx.AsyncClient() as http_client:
        osv_client = OSVClient(http_client)
        matches, unpinned = await batch_query_osv(deps, osv_client)
        findings = await enrich_cve_details(matches, osv_client)

    prioritized, flagged_unpinned = prioritize_findings(findings, unpinned)

    print(f"Unpinned deps skipped: {flagged_unpinned}")
    print(f"Findings: {prioritized}")

    # TODO: generate_report(prioritized, flagged_unpinned, output)


@app.command()
def audit(file: Path, output: str = "./reports/") -> None:
    """Audit a project's dependencies (pyproject.toml or requirements.txt) for known vulnerabilities."""
    asyncio.run(_run_pipeline(file, output))


def main() -> None:
    app()


if __name__ == "__main__":
    app()
