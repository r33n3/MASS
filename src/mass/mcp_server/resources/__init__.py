"""MCP resource registration."""

from mcp.server.fastmcp import FastMCP


def register_all_resources(mcp: FastMCP) -> None:
    """Register all MASS MCP resources."""
    from mass.mcp_server.resources.status import register as reg_status
    reg_status(mcp)
