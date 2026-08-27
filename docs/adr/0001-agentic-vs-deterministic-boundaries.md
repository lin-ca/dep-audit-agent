# ADR 0001: Where this agent uses an LLM, and where it deliberately doesn't

## Status

Accepted

## Context

The pipeline is `parse_dependencies → batch_query_osv → enrich_cve_details →
prioritize_findings → generate_report`. Early design notes for the agent
listed three "decisions" it was supposed to make:

1. Unpinned dependencies (no exact version): flag rather than query blindly.
2. Ambiguous CVEs (condition-dependent exploitability): mark uncertainty
   instead of hallucinating a verdict.
3. Many findings: prioritize by CVSS score instead of listing them raw.

Turns out (1) and (3) are already handled by plain code, no LLM involved:

- `batch_query_osv` splits dependencies into pinned/unpinned by checking for
  an exact `==` version operator. That's a fixed rule, nothing ambiguous
  about it.
- `prioritize_findings` sorts by severity tier and then CVSS score. Also a
  fixed rule over numeric/enum data.

Sending either of those through an LLM call would just add cost, latency,
and a new way to fail (bad JSON, a hallucinated tool argument) for something
a five-line `if` statement already gets right every time. This is basically
the point Anthropic makes in "Building Effective Agents": use the simplest
approach that works, and only add agentic complexity where it actually earns
its keep, not because a step could technically be phrased as an agent
decision.

That left (2) as the one real judgment call, so the original design (see
`agent/CLAUDE.md`) wrapped it in a Plan-Then-Execute pattern: an upfront
`AgentPlan`, built from the parsed dependency list, that would decide things
like which downstream steps to run before any OSV call happened.

That planner didn't survive contact with the actual data flow. At the point
`AgentPlan` gets built, right after parsing, there's no OSV data yet: no
CVEs, no severities, no advisory text. There's nothing real for a plan to
decide. Anything it could plausibly output ("run enrichment if there are
pinned deps") is already implied by the deterministic pipeline itself. A
planning step with no genuine decision to make is the same mistake as (1)
and (3): agentic machinery around something plain code already handles, just
one step removed.

## Decision

No separate upfront planning phase, and no `AgentPlan` model. There are two
genuine LLM decision points, and both only make sense once real findings
exist, i.e. after `enrich_cve_details` has run, inside `generate_report`:

- **Triage.** Given the actual findings (severity, CVSS score, advisory
  text), decide which ones are worth the expensive per-CVE
  ambiguous-exploitability pass versus a cheap templated line. This needs
  real data to operate on, which is exactly what wasn't available at
  upfront-planning time, so it has to live here instead.
- **Ambiguous CVE assessment and report synthesis.** For the triaged subset,
  judge condition-dependent exploitability and mark uncertainty explicitly
  rather than hallucinating a verdict. Then turn the full set of findings,
  triaged and templated alike, into a readable, prioritized write-up.

Everything else (parsing, OSV querying, severity/CVSS mapping, sorting)
stays deterministic Python: faster, free, fully testable with plain
`pytest`, and correct by construction instead of by prompting. The pipeline
always runs its five steps in the same fixed order; no branch is decided by
an LLM before the data that branch would depend on exists.

## Consequences

- No planner infrastructure to build or maintain: no `AgentPlan` model, no
  tool-name enum, no forced-tool-use call at the start of a run.
- Simpler control flow overall. The only two Anthropic API calls per run are
  the triage/assessment pass and the report synthesis, both inside
  `generate_report`, both operating on real data.
- The deterministic majority of the codebase stays testable without mocking
  an LLM at all, already true today for `batch_query_osv`,
  `enrich_cve_details`, and `prioritize_findings`.
- This mirrors the same judgment call as the rest of this ADR: the original
  plan asked for a Plan-Then-Execute agent, but building it to spec here
  would have meant shipping a component with no genuine work to do. Cutting
  it is the more defensible engineering call, not a shortcut.
