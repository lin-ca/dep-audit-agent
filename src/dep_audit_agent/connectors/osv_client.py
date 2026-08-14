from httpx import AsyncClient

from dep_audit_agent.models import Dependency, OSVBatchResponse


class OSVClient:
    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, http_client: AsyncClient):
        self._client = http_client

    def _build_payload(self, deps: list[Dependency]) -> dict:

        queries = []

        for dep in deps:
            for v in dep.versions:
                queries.append(
                    {
                        "version": v.version_str,
                        "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                    }
                )
        return {"queries": queries}

    async def batch_query(self, deps: list[Dependency]) -> OSVBatchResponse:

        response = await self._client.post(
            f"{self.BASE_URL}/querybatch",
            json=self._build_payload(deps),
        )

        response.raise_for_status()

        return OSVBatchResponse.model_validate(response.json())
