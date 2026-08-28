# Dependency Vulnerability Auditor Agent

This CLI parses a `pyproject.toml` or `requirements.txt`, queries [OSV.dev](https://osv.dev) for known vulnerabilities, and produces a prioritized, actionable Markdown security report.

Pipeline: `parse_dependencies → batch_query_osv → enrich_cve_details → prioritize_findings → generate_report`. The first four steps are deterministic Python; `generate_report` makes a single Anthropic API call to triage findings, flag condition-dependent CVEs with explicit uncertainty, and write the report.

## Setup

```
cp .env.example .env   # set ANTHROPIC_API_KEY
make install
```

## Usage

```uv run dep-audit-agent example_files/example_pyproject.toml```

```uv run dep-audit-agent example_files/example_requirements.txt```

Reports are written to `./reports/report.md` by default (`--output` to change the directory).

## Design origin

I set out to build this project as a demonstration of restrained, security-conscious agent design, prompted by [Beurer-Kellner et al., "Design Patterns for Securing LLM Agents against Prompt Injections"](https://arxiv.org/abs/2506.08837) (arXiv:2506.08837). Three of the paper's patterns looked directly applicable to a dependency auditor:

- **Plan-Then-Execute** — commit to the full tool-call sequence upfront, before any untrusted content (an OSV advisory) is in context, so that content can influence the report but never which tools run or in what order.
- **LLM Map-Reduce** — process each untrusted document (one CVE advisory per package) in isolation, so a malicious or malformed one can't corrupt any other, and pass only a structured verdict back to the coordinator, never raw text.
- **Context-Minimization** — parse untrusted input into a typed model immediately and drop the original text, so it can't resurface in a later prompt.

The original plan also expected three points where the agent would need to exercise judgment: unpinned dependencies (query anyway or flag?), ambiguous/condition-dependent CVEs (how to communicate uncertainty?), and prioritizing a long finding list.

## What I implemented and what I cut

Two of the three patterns were integrated exactly as planned. One didn't fit into the actual data flow, and that turned out to be the more interesting result. Full reasoning in [`docs/adr/0001-agentic-vs-deterministic-boundaries.md`](docs/adr/0001-agentic-vs-deterministic-boundaries.md); summary here.

**Implemented as designed:**

- **Context-Minimization** — [`parse_dependencies`](src/dep_audit_agent/tools/parse_dependencies.py) turns raw file text into structured `Dependency` models and never retains or re-passes the original text.
- **LLM Map-Reduce** — [`enrich_cve_details`](src/dep_audit_agent/tools/query_osv.py) fetches and processes each OSV advisory independently (`asyncio.gather(..., return_exceptions=True)`); a failed or hostile advisory is contained to its own finding, and only structured `VulnerabilityFinding` models cross back to the coordinator.

**Cut: Plan-Then-Execute.** The original design wrapped the "ambiguous CVE" judgment call in an upfront `AgentPlan`, built right after parsing, that would decide which downstream steps to run. Once I tried to build it, there was nothing real for it to decide: at that point in the pipeline there's no OSV data yet — no CVEs, no severities, no advisory text — so any plan it produced ("run enrichment if there are pinned deps") was already implied by the fixed pipeline order. Worse, of the three anticipated "agentic decisions," two turned out to be plain deterministic rules once actually coded:

- Unpinned-dependency handling is an exact `==` operator check ([`batch_query_osv`](src/dep_audit_agent/tools/query_osv.py)).
- Prioritization is a sort by severity tier then CVSS score ([`prioritize_findings`](src/dep_audit_agent/tools/prioritize.py)).

Neither needed an LLM to get right, and routing either through one would only have added cost, latency, and a new failure mode (bad JSON, a hallucinated tool argument) for something a five-line `if` already handles correctly every time. That left exactly one genuine judgment call — condition-dependent CVE exploitability — and it only makes sense to make *after* real findings exist, i.e. after the point a Plan-Then-Execute planner would have to commit to a plan. Building the planner anyway would have been agentic machinery with nothing real to decide, so [`generate_report`](src/dep_audit_agent/tools/generate_report.py) makes that call directly, once, against real data — the pipeline itself stays a fixed, unbranching sequence, so there was never a decision-point for untrusted content to hijack in the first place.

One consequence worth being explicit about: what shipped is not an agent in the autonomous sense. There's no loop, no runtime tool selection, no branching on model output — the five steps always run in the same fixed order, and exactly one of them calls an LLM, once, non-recursively, over data that's already fully computed. That's an LLM-augmented deterministic pipeline, not an agent. "Agent" survives in the repo name as a holdover from the original brief; the write-up below describes the pipeline that's actually there, not the name on the tin.

## Security engineering

- **Schema enforcement on all external data** — every OSV response is validated through a Pydantic model before it reaches the LLM (`OSVBatchResponse`, `OSVVulnDetail`, etc. in [`models.py`](src/dep_audit_agent/models.py)); malformed responses raise `OSVResponseValidationError` in [`osv_client.py`](src/dep_audit_agent/connectors/osv_client.py) instead of propagating as bad data.
- **Prompt injection defense** — OSV advisory text is untrusted third-party content. It's wrapped in `<advisory_description>` tags with an explicit system-prompt instruction to treat everything inside as data, never as instructions, and control characters are stripped before insertion (`_sanitize_for_prompt` in [`generate_report.py`](src/dep_audit_agent/tools/generate_report.py)) so advisory text can't break out of the delimiter framing.
- **Confidence flagging over hallucinated verdicts** — unpinned dependencies are flagged and explicitly skipped rather than guessed at ([`query_osv.py`](src/dep_audit_agent/tools/query_osv.py)); the report system prompt requires explicit uncertainty language for condition-dependent CVEs instead of an assumed verdict.
- **Fault isolation** — a single failed OSV lookup or malformed advisory is skipped, not raised: one bad vulnerability record can't take down the batch (`return_exceptions=True` and the per-finding `try/except` in [`query_osv.py`](src/dep_audit_agent/tools/query_osv.py)).
- **Input validation** — dependency strings are parsed via `packaging.requirements.Requirement`, which rejects malformed PEP 508 syntax before it can reach a tool call.
- **Sandboxed scope** — the pipeline has no write access beyond the generated report file, no network access beyond OSV.dev and the Anthropic API, and no ability to modify the audited project.

## Possible next steps

Some additions that would still be worth including:

- **Eval set + CI gating** — a small, fixed set of representative audit runs (a known-vulnerable package, a clean package) with expected findings committed as golden output, so the one LLM call in the pipeline has a regression signal to check against, not just the unit tests that already cover the deterministic steps.
- **Structured logging** — context-rich logs across each pipeline step (tool name, OSV query outcome, finding counts), with CVE description text explicitly excluded from the log stream.