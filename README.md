# Dependency Vulnerability Auditor Agent

The agent receives a pyproject.toml or requirements.txt, queries [OSV.dev](https://osv.dev) for known vulnerabilities, and produces a prioritized, actionable Markdown security report.

Pipeline: `parse_dependencies → batch_query_osv → enrich_cve_details → prioritize_findings → generate_report`. The first four steps are deterministic Python; `generate_report` makes a single Anthropic API call to triage findings, flag condition-dependent CVEs with explicit uncertainty, and write the report. See [`docs/adr/0001-agentic-vs-deterministic-boundaries.md`](docs/adr/0001-agentic-vs-deterministic-boundaries.md) for why the pipeline is split this way.

## Setup

```
cp .env.example .env   # set ANTHROPIC_API_KEY
make install
```

## Usage

```uv run dep-audit-agent example_files/example_pyproject.toml```

```uv run dep-audit-agent example_files/example_requirements.txt```

Reports are written to `./reports/report.md` by default (`--output` to change the directory).