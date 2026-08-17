from httpx import AsyncClient, HTTPStatusError, TimeoutException
from pydantic import ValidationError

from dep_audit_agent.connectors.exceptions import (
    OSVRequestError,
    OSVResponseValidationError,
)
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

        try:
            response = await self._client.post(
                f"{self.BASE_URL}/querybatch",
                json=self._build_payload(deps),
            )
            response.raise_for_status()
        except (HTTPStatusError, TimeoutException) as exc:
            raise OSVRequestError(f"OSV request failed: {exc}") from exc

        try:
            return OSVBatchResponse.model_validate(response.json())
        except ValidationError as exc:
            raise OSVResponseValidationError("OSV response failed validation") from exc
