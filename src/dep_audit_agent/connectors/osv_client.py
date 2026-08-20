from typing import Any

from httpx import AsyncClient, HTTPStatusError, Response, TransportError
from pydantic import BaseModel

from dep_audit_agent.connectors.exceptions import (
    OSVRequestError,
    OSVResponseValidationError,
)
from dep_audit_agent.models import (
    Dependency,
    DependencyVersion,
    DependencyVulnMatch,
    OSVBatchResponse,
    OSVVulnDetail,
)


class OSVClient:
    """
    Client for connecting to the open-source OSV.dev API
    to identify known third-party open source dependency vulnerabilities.
    """

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, http_client: AsyncClient):
        self._client = http_client

    def _flatten_queries(
        self, deps: list[Dependency]
    ) -> list[tuple[Dependency, DependencyVersion]]:
        """
        Expands each dependency into one (dependency, version) pair per pinned version,
        in the same order used to build the querybatch payload — so results returned by
        OSV (which are positional, not labeled) can be zipped back to their origin.
        """
        return [(dep, v) for dep in deps for v in dep.versions]

    # use dict[str, Any] instead of a precise TypedDict (to avoid mypy's generic type error in strict mode).
    def _build_payload(
        self, flat_queries: list[tuple[Dependency, DependencyVersion]]
    ) -> dict[str, Any]:
        """
        Builds the required payload structure required for the OSV.dev API querybatch endpoint.
        """
        return {
            "queries": [
                {
                    "version": version.version_str,
                    "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                }
                for dep, version in flat_queries
            ]
        }

    async def _request_and_validate[T: BaseModel](
        self, method: str, url: str, model: type[T], **kwargs: Any
    ) -> T:
        """
        Sends a request to the OSV API and validates the JSON response against `model`.
        Shared by every OSV endpoint call so request/error handling stays in one place.
        """
        try:
            response: Response = await self._client.request(method, url, **kwargs)
            response.raise_for_status()
        except (HTTPStatusError, TransportError) as exc:
            raise OSVRequestError(f"OSV request failed: {exc}") from exc

        try:
            return model.model_validate(response.json())
        # use ValueError (superclass of pydantic's ValidationError) to also catch
        # json.JSONDecodeError if OSV api returns non-JSON response
        except ValueError as exc:
            raise OSVResponseValidationError("OSV response failed validation") from exc

    async def query_and_match(
        self, deps: list[Dependency]
    ) -> list[DependencyVulnMatch]:
        """
        Queries OSV.dev and pairs each result with the (dependency, version) it was
        queried for. Done here, right where OSV's positional correspondence between
        queries and results is guaranteed, so nothing downstream has to re-derive it.
        """
        flat_queries = self._flatten_queries(deps)
        response = await self._request_and_validate(
            "POST",
            f"{self.BASE_URL}/querybatch",
            OSVBatchResponse,
            json=self._build_payload(flat_queries),
        )
        try:
            return [
                DependencyVulnMatch(dependency=dep, version=version, vulns=result.vulns)
                for (dep, version), result in zip(
                    flat_queries, response.results, strict=True
                )
            ]
        except ValueError as exc:
            raise OSVResponseValidationError(
                f"OSV returned {len(response.results)} results "
                f"for {len(flat_queries)} queries"
            ) from exc

    async def get_vuln_detail(self, vuln_id: str) -> OSVVulnDetail:
        """
        Calls OSV.dev API's GET /v1/vulns/{id} for full details on a single vulnerability.
        """
        return await self._request_and_validate(
            "GET", f"{self.BASE_URL}/vulns/{vuln_id}", OSVVulnDetail
        )
