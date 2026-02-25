"""MASS API HTTP client for the MCP server.

Singleton httpx.AsyncClient that authenticates via X-API-Key header.
All MCP tools use get_client() to access the MASS API.
"""

import json
import logging

import httpx

from mass.mcp_server.config import config

logger = logging.getLogger(__name__)

_client: "MassClient | None" = None


class MassClient:
    """Async HTTP client for the MASS REST API."""

    def __init__(self) -> None:
        self.base_url = config.api_url.rstrip("/")
        self.api_key = config.api_key
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"X-API-Key": self.api_key} if self.api_key else {},
            timeout=httpx.Timeout(config.timeout, connect=10.0),
        )

    async def get(self, path: str, **params) -> dict:
        """GET /api/v1{path} with query params."""
        # Filter out None values from params
        filtered = {k: v for k, v in params.items() if v is not None}
        resp = await self._http.get(f"/api/v1{path}", params=filtered)
        resp.raise_for_status()
        return resp.json()

    async def post(self, path: str, data: dict | None = None) -> dict:
        """POST /api/v1{path} with JSON body."""
        resp = await self._http.post(f"/api/v1{path}", json=data or {})
        resp.raise_for_status()
        return resp.json()

    async def patch(self, path: str, data: dict | None = None) -> dict:
        """PATCH /api/v1{path} with JSON body."""
        resp = await self._http.patch(f"/api/v1{path}", json=data or {})
        resp.raise_for_status()
        return resp.json()

    async def delete(self, path: str) -> dict:
        """DELETE /api/v1{path}."""
        resp = await self._http.delete(f"/api/v1{path}")
        resp.raise_for_status()
        return resp.json()

    async def close(self) -> None:
        await self._http.aclose()


def get_client() -> MassClient:
    """Return singleton MassClient instance."""
    global _client
    if _client is None:
        _client = MassClient()
    return _client


def format_json(data: dict | list, indent: int = 2) -> str:
    """Format API response data as readable JSON string."""
    return json.dumps(data, indent=indent, default=str)


def summarize_findings(findings: list[dict]) -> str:
    """Summarize a list of findings into a readable string."""
    if not findings:
        return "No findings."

    by_severity: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    lines = [f"**{len(findings)} findings total**"]
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = by_severity.get(sev, 0)
        if count:
            lines.append(f"- {sev.upper()}: {count}")

    return "\n".join(lines)
