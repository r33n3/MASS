"""MASS MCP Server — entry point.

Exposes the MASS security platform as an MCP server for Claude Desktop.
Supports stdio (local) and SSE (remote) transports.

Usage:
    # stdio (Claude Desktop default)
    python -m mass.mcp_server.server

    # SSE (remote/shared)
    MASS_MCP_TRANSPORT=sse python -m mass.mcp_server.server

Environment Variables:
    MASS_API_KEY        Your MASS API key (required)
    MASS_API_URL        MASS API base URL (default: http://localhost:8000)
    MASS_MCP_TRANSPORT  Transport: stdio or sse (default: stdio)
    MASS_MCP_HOST       SSE host (default: 0.0.0.0)
    MASS_MCP_PORT       SSE port (default: 8100)
"""

import logging
import os
import sys

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.config import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Create MCP server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "MASS Security Platform",
    instructions=(
        "AI security scanning, MCP server interrogation, vulnerability assessment, "
        "cross-model comparison, supply chain verification, privacy analysis, "
        "threat intelligence, and cloud-native security — all from Claude Desktop."
    ),
    host=config.sse_host,
    port=config.sse_port,
)

# ---------------------------------------------------------------------------
# Register tools and resources
# ---------------------------------------------------------------------------

from mass.mcp_server.tools import register_all_tools
from mass.mcp_server.resources import register_all_resources

register_all_tools(mcp)
register_all_resources(mcp)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Run the MASS MCP server."""
    if not config.api_key:
        print(
            "WARNING: MASS_API_KEY not set. API calls will fail unless "
            "MASS is running in development mode.",
            file=sys.stderr,
        )

    transport = config.transport.lower()
    if transport == "sse":
        logger.info(
            "Starting MASS MCP server (SSE) on %s:%s",
            config.sse_host, config.sse_port,
        )
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
