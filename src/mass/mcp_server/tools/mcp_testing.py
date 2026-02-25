"""MCP testing tools — interrogate_mcp, audit_package, run_sandbox."""

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.client import get_client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def interrogate_mcp(
        server_url: str | None = None,
        command: str | None = None,
        args: str | None = None,
        transport: str = "sse",
        categories: str | None = None,
        max_test_cases: int = 50,
    ) -> str:
        """Test an MCP server's security by running adversarial probes against its tools.

        Provide either server_url (for SSE/HTTP servers) or command (for stdio servers).

        Args:
            server_url: MCP server URL (for SSE or HTTP transport).
            command: Command to launch stdio MCP server (e.g., 'npx @example/server').
            args: Space-separated arguments for the stdio command.
            transport: Transport type — sse, http, or stdio.
            categories: Comma-separated attack categories (e.g., 'tool_injection,data_exfiltration').
            max_test_cases: Maximum test cases per tool (default: 50).
        """
        client = get_client()

        data: dict = {
            "transport": transport,
            "max_test_cases": max_test_cases,
        }

        if server_url:
            data["server_url"] = server_url
        elif command:
            data["command"] = command
            if args:
                data["args"] = args.split()
        else:
            return "Error: Provide either server_url or command."

        if categories:
            data["categories"] = categories.split(",")

        result = await client.post("/mcp-interrogation", data)
        job_id = result.get("id", result.get("job_id", "?"))

        return (
            f"MCP interrogation started.\n\n"
            f"- **Job ID**: `{job_id}`\n"
            f"- **Server**: {server_url or command}\n"
            f"- **Transport**: {transport}\n"
            f"- **Status**: {result.get('status', 'pending')}\n\n"
            f"Use `get_scan_results(scan_id=\"{job_id}\")` or check the MASS dashboard for results."
        )

    @mcp.tool()
    async def audit_package(
        package_name: str,
        registry: str = "npm",
        version: str | None = None,
        transport: str = "stdio",
    ) -> str:
        """Audit an npm or pip package for MCP server security in an isolated Docker container.

        Installs the package in a container, discovers MCP tools, and runs security tests.

        Args:
            package_name: Package name (e.g., '@anthropic/mcp-server-filesystem').
            registry: Package registry — npm or pip (default: npm).
            version: Specific version to audit (default: latest).
            transport: MCP transport — stdio, sse, or http (default: stdio).
        """
        client = get_client()

        data: dict = {
            "package_name": package_name,
            "registry": registry,
            "transport": transport,
        }
        if version:
            data["version"] = version

        result = await client.post("/mcp-audit", data)
        job_id = result.get("id", result.get("job_id", "?"))

        return (
            f"Package audit started in isolated container.\n\n"
            f"- **Job ID**: `{job_id}`\n"
            f"- **Package**: {package_name}{'@' + version if version else ''}\n"
            f"- **Registry**: {registry}\n"
            f"- **Status**: {result.get('status', 'pending')}\n\n"
            f"The package will be installed in a Docker container, "
            f"MCP tools discovered, and security tests run automatically."
        )

    @mcp.tool()
    async def run_sandbox(
        scenario: str,
        target_url: str | None = None,
        target_command: str | None = None,
    ) -> str:
        """Run a security scenario against an MCP server in the sandbox environment.

        Tests scenarios like command injection, data exfiltration, privilege escalation,
        indirect prompt injection, and DoS boundary testing.

        Args:
            scenario: Scenario name or YAML path (e.g., 'mcp_command_injection',
                      'mcp_data_access_attacks', 'mcp_exfiltration_privesc').
            target_url: MCP server URL (for SSE/HTTP targets).
            target_command: Command to start MCP server (for stdio targets).
        """
        client = get_client()

        data: dict = {"scenario": scenario}
        if target_url:
            data["target_url"] = target_url
        if target_command:
            data["target_command"] = target_command

        result = await client.post("/sandbox/run", data)
        job_id = result.get("id", result.get("job_id", "?"))

        return (
            f"Sandbox scenario started.\n\n"
            f"- **Job ID**: `{job_id}`\n"
            f"- **Scenario**: {scenario}\n"
            f"- **Status**: {result.get('status', 'pending')}\n\n"
            f"Results will be available in the MASS dashboard."
        )
