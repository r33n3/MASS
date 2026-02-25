"""Scanning tools — scan_target, get_scan_results, search_findings."""

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.client import format_json, get_client, summarize_findings


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def scan_target(
        target_path: str,
        target_type: str = "deployment",
        system_prompt: str | None = None,
        model_provider: str | None = None,
        model_name: str | None = None,
    ) -> str:
        """Start a security scan on an AI deployment, MCP server, model file, or agent.

        Args:
            target_path: Path or URL of the target to scan.
            target_type: Type of target. One of: deployment, mcp_server, model_file,
                         skill_file, instruction_file, model_endpoint, agent_endpoint.
            system_prompt: System prompt to test (for model/agent endpoints).
            model_provider: LLM provider (ollama, openai, anthropic, gemini, grok, bedrock, azure_openai).
            model_name: Model name (e.g., gpt-4o-mini, claude-sonnet-4-20250514, llama3.2).
        """
        client = get_client()

        # Create or find deployment
        deploy_data: dict = {
            "name": target_path.split("/")[-1] if "/" in target_path else target_path,
            "source_path": target_path,
            "target_type": target_type,
        }
        if system_prompt:
            deploy_data["system_prompt"] = system_prompt
        if model_provider:
            deploy_data["model_provider"] = model_provider
        if model_name:
            deploy_data["model_name"] = model_name

        target = await client.post("/targets", deploy_data)
        target_id = target.get("id", "")

        # Start scan
        scan_data: dict = {"deployment_id": target_id}
        scan = await client.post("/scans", scan_data)
        scan_id = scan.get("id", "")

        return (
            f"Scan started successfully.\n\n"
            f"- **Scan ID**: `{scan_id}`\n"
            f"- **Target**: {target_path}\n"
            f"- **Type**: {target_type}\n"
            f"- **Status**: {scan.get('status', 'pending')}\n\n"
            f"Use `get_scan_results(scan_id=\"{scan_id}\")` to check progress and view findings."
        )

    @mcp.tool()
    async def get_scan_results(
        scan_id: str,
        include_findings: bool = True,
        max_findings: int = 20,
    ) -> str:
        """Get scan status and findings.

        Args:
            scan_id: The scan ID returned by scan_target.
            include_findings: Whether to include detailed findings (default: True).
            max_findings: Maximum number of findings to return (default: 20).
        """
        client = get_client()
        scan = await client.get(f"/scans/{scan_id}")

        lines = [
            f"## Scan: {scan_id}",
            f"- **Status**: {scan.get('status', 'unknown')}",
            f"- **Target**: {scan.get('deployment_name', scan.get('deployment_id', 'N/A'))}",
            f"- **Created**: {scan.get('created_at', 'N/A')}",
        ]

        if scan.get("completed_at"):
            lines.append(f"- **Completed**: {scan['completed_at']}")
        if scan.get("duration_seconds"):
            lines.append(f"- **Duration**: {scan['duration_seconds']}s")

        # Summary counts
        summary = scan.get("summary", {})
        if summary:
            lines.append(f"\n### Summary")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = summary.get(sev, 0)
                if count:
                    lines.append(f"- {sev.upper()}: {count}")

        if include_findings and scan.get("status") in ("completed", "running"):
            findings = await client.get(
                "/findings",
                scan_id=scan_id,
                limit=max_findings,
            )
            items = findings.get("items", findings) if isinstance(findings, dict) else findings
            if isinstance(items, list) and items:
                lines.append(f"\n### Findings ({len(items)} shown)")
                for f in items:
                    sev = f.get("severity", "?").upper()
                    title = f.get("title", "Untitled")
                    cat = f.get("category", "")
                    lines.append(f"- **[{sev}]** {title} ({cat})")
                    if f.get("description"):
                        desc = f["description"][:200]
                        lines.append(f"  {desc}")

        return "\n".join(lines)

    @mcp.tool()
    async def search_findings(
        scan_id: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        search: str | None = None,
        limit: int = 20,
    ) -> str:
        """Search and filter security findings across scans.

        Args:
            scan_id: Filter by scan ID.
            severity: Filter by severity (critical, high, medium, low, info).
            category: Filter by category (e.g., prompt_injection, jailbreak, data_leakage).
            search: Free-text search in finding titles and descriptions.
            limit: Maximum results to return (default: 20).
        """
        client = get_client()
        params: dict = {"limit": limit}
        if scan_id:
            params["scan_id"] = scan_id
        if severity:
            params["severity"] = severity
        if category:
            params["category"] = category
        if search:
            params["search"] = search

        result = await client.get("/findings", **params)
        items = result.get("items", result) if isinstance(result, dict) else result
        if not isinstance(items, list):
            items = []

        if not items:
            return "No findings match the specified filters."

        lines = [f"## Findings ({len(items)} results)\n"]
        for f in items:
            fid = f.get("id", "?")
            sev = f.get("severity", "?").upper()
            title = f.get("title", "Untitled")
            cat = f.get("category", "")
            lines.append(f"### [{sev}] {title}")
            lines.append(f"- **ID**: `{fid}`")
            lines.append(f"- **Category**: {cat}")
            if f.get("description"):
                lines.append(f"- **Description**: {f['description'][:300]}")
            if f.get("remediation"):
                lines.append(f"- **Remediation**: {f['remediation'][:200]}")
            lines.append("")

        total = result.get("pagination", {}).get("total", len(items))
        if total > len(items):
            lines.append(f"_Showing {len(items)} of {total} total findings._")

        return "\n".join(lines)
