"""MCP tool registration.

Registers all 20 workflow-oriented tools with the FastMCP server instance.
"""

from mcp.server.fastmcp import FastMCP


def register_all_tools(mcp: FastMCP) -> None:
    """Register all MASS MCP tools."""
    from mass.mcp_server.tools.scanning import register as reg_scanning
    from mass.mcp_server.tools.targets import register as reg_targets
    from mass.mcp_server.tools.explain import register as reg_explain
    from mass.mcp_server.tools.mcp_testing import register as reg_mcp_testing
    from mass.mcp_server.tools.cross_model import register as reg_cross_model
    from mass.mcp_server.tools.cloud import register as reg_cloud
    from mass.mcp_server.tools.supply_chain import register as reg_supply_chain
    from mass.mcp_server.tools.privacy import register as reg_privacy
    from mass.mcp_server.tools.threat_intel import register as reg_threat_intel
    from mass.mcp_server.tools.cicd import register as reg_cicd
    from mass.mcp_server.tools.platform import register as reg_platform

    reg_scanning(mcp)
    reg_targets(mcp)
    reg_explain(mcp)
    reg_mcp_testing(mcp)
    reg_cross_model(mcp)
    reg_cloud(mcp)
    reg_supply_chain(mcp)
    reg_privacy(mcp)
    reg_threat_intel(mcp)
    reg_cicd(mcp)
    reg_platform(mcp)
