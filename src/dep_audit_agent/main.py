import asyncio
from pathlib import Path

import anthropic
import httpx
import typer

from dep_audit_agent.config import get_settings
from dep_audit_agent.connectors.claude import ClaudeConnector
from dep_audit_agent.connectors.osv_client import OSVClient
from dep_audit_agent.models import Dependency
from dep_audit_agent.tools.generate_report import generate_report
from dep_audit_agent.tools.parse_dependencies import parse_text_file, parse_toml_file
from dep_audit_agent.tools.prioritize import prioritize_findings
from dep_audit_agent.tools.query_osv import batch_query_osv, enrich_cve_details

app = typer.Typer()


def _parse_file(file: Path) -> list[Dependency]:
    if file.suffix == ".toml":
        return parse_toml_file(file)
    return parse_text_file(file)


async def _run_pipeline(file: Path, output: str) -> None:
    """Runs the full dependency audit pipeline: parse -> query OSV -> enrich CVE
    -> prioritize -> generate report."""
    deps = _parse_file(file)

    async with httpx.AsyncClient() as http_client:
        osv_client = OSVClient(http_client)
        matches, unpinned = await batch_query_osv(deps, osv_client)
        findings = await enrich_cve_details(matches, osv_client)

    prioritized, flagged_unpinned = prioritize_findings(findings, unpinned)

    settings = get_settings()
    async with anthropic.AsyncAnthropic(
        api_key=settings.anthropic_api_key.get_secret_value()
    ) as anthropic_client:
        claude_connector = ClaudeConnector(anthropic_client, settings.anthropic_model)
        report_path = await generate_report(
            prioritized, flagged_unpinned, claude_connector, Path(output)
        )

    print(f"Report written to {report_path}")


@app.command()
def audit(file: Path, output: str = "./reports/") -> None:
    """Audit a project's dependencies (pyproject.toml or requirements.txt) for known vulnerabilities."""
    asyncio.run(_run_pipeline(file, output))


def main() -> None:
    app()


if __name__ == "__main__":
    app()
