"""MCP server configuration."""

import os


class MCPConfig:
    """Configuration for the MASS MCP server."""

    # MASS API connection
    api_url: str = os.environ.get("MASS_API_URL", "http://localhost:8000")
    api_key: str = os.environ.get("MASS_API_KEY", "")

    # MCP transport
    transport: str = os.environ.get("MASS_MCP_TRANSPORT", "stdio")
    sse_host: str = os.environ.get("MASS_MCP_HOST", "0.0.0.0")
    sse_port: int = int(os.environ.get("MASS_MCP_PORT", "8100"))

    # Request defaults
    timeout: float = float(os.environ.get("MASS_MCP_TIMEOUT", "60.0"))
    default_limit: int = int(os.environ.get("MASS_MCP_DEFAULT_LIMIT", "20"))


config = MCPConfig()
