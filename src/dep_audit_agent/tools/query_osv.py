from dep_audit_agent.connectors.osv_client import OSVClient
from dep_audit_agent.models import Dependency, OSVQueryResult


async def batch_query_osv(
    deps: list[Dependency], client: OSVClient
) -> tuple[list[OSVQueryResult], list[str]]:
    # OSV version queries require an exact version; range-constrained deps are skipped here
    pinned = [d for d in deps if any(v.operator == "==" for v in d.versions)]
    unpinned = [d.name for d in deps if not any(v.operator == "==" for v in d.versions)]

    # Only call OSV API on pinned dependencies:
    osv_response = await client.batch_query(pinned)
    return osv_response.results, unpinned
