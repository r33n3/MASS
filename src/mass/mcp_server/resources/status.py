"""MCP resources — read-only data accessible to Claude Desktop."""

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.client import format_json, get_client


def register(mcp: FastMCP) -> None:

    @mcp.resource("mass://status")
    async def system_status() -> str:
        """MASS system health and status overview."""
        try:
            client = get_client()
            health = await client.get("/health/detailed")
            return format_json(health)
        except Exception as e:
            return f"Error fetching status: {e}"

    @mcp.resource("mass://findings/recent")
    async def recent_findings() -> str:
        """Most recent security findings across all scans."""
        try:
            client = get_client()
            result = await client.get("/findings", limit=10)
            items = result.get("items", result) if isinstance(result, dict) else result
            if not isinstance(items, list):
                return "No findings available."
            return format_json(items)
        except Exception as e:
            return f"Error fetching findings: {e}"

    @mcp.resource("mass://stats")
    async def dashboard_stats() -> str:
        """Dashboard statistics — scan counts, finding summaries, system activity."""
        try:
            client = get_client()
            stats = await client.get("/dashboard/stats")
            return format_json(stats)
        except Exception as e:
            return f"Error fetching stats: {e}"
