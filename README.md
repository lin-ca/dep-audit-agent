# Dependency Vulnerability Auditor Agent

The agent receives a pyproject.toml or requirements.txt, and its job is to produce a prioritized, actionable security report.


```uv run dep-audit-agent example_files/example_pyproject.toml```

```uv run dep-audit-agent example_files/example_requirements.txt```