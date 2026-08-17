from dep_audit_agent.connectors.osv_client import OSVClient
from dep_audit_agent.models import Dependency, OSVQueryResult


async def batch_query_osv(
    deps: list[Dependency], client: OSVClient
) -> tuple[list[OSVQueryResult], list[str]]:
    """
    Queries OSV.dev for known vulnerabilities in pinned dependencies.

    Dependencies without an exact ("==") version constraint cannot be queried
    against OSV and are returned separately as unpinned.

    Returns a tuple of (per-dependency OSV query results, names of unpinned deps).
    """
    # OSV version queries require an exact version; range-constrained deps are skipped here
    pinned = [d for d in deps if any(v.operator == "==" for v in d.versions)]
    unpinned = [d.name for d in deps if not any(v.operator == "==" for v in d.versions)]

    # Only call OSV API on pinned dependencies:
    osv_response = await client.batch_query(pinned)
    return osv_response.results, unpinned
