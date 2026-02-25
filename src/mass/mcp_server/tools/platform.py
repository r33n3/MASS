"""Platform tools — get_dashboard, get_status, chat."""

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.client import format_json, get_client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def get_dashboard() -> str:
        """Get MASS dashboard overview — recent scans, finding stats, and system activity."""
        client = get_client()

        try:
            stats = await client.get("/dashboard/stats")
        except Exception:
            stats = {}

        lines = ["## MASS Dashboard\n"]

        # System stats
        if stats:
            lines.append("### Overview")
            lines.append(f"- **Total Scans**: {stats.get('total_scans', 0)}")
            lines.append(f"- **Total Findings**: {stats.get('total_findings', 0)}")
            lines.append(f"- **Total Targets**: {stats.get('total_deployments', stats.get('total_targets', 0))}")

            by_sev = stats.get("findings_by_severity", {})
            if by_sev:
                lines.append("\n### Findings by Severity")
                for sev in ["critical", "high", "medium", "low", "info"]:
                    count = by_sev.get(sev, 0)
                    if count:
                        lines.append(f"- {sev.upper()}: {count}")

            recent = stats.get("recent_scans", [])
            if recent:
                lines.append("\n### Recent Scans")
                for s in recent[:5]:
                    sid = s.get("id", "?")
                    status = s.get("status", "?")
                    name = s.get("deployment_name", s.get("name", "Unnamed"))
                    lines.append(f"- `{sid}` — {name} [{status}]")

        if not stats:
            lines.append("_Dashboard data unavailable. Is the MASS API running?_")

        return "\n".join(lines)

    @mcp.tool()
    async def get_status(
        module: str | None = None,
    ) -> str:
        """Check MASS system health and module status.

        Args:
            module: Specific module to check — cloud, cross_model, supply_chain,
                    privacy, explain, threat_intel, cicd, integrations.
                    If omitted, returns overall system health.
        """
        client = get_client()

        if module:
            module_paths = {
                "cloud": "/cloud/status",
                "cross_model": "/cross-model/status",
                "supply_chain": "/supply-chain/status",
                "privacy": "/privacy/status",
                "explain": "/explain/status",
                "threat_intel": "/threat-intel/status",
                "cicd": "/cicd/status",
                "integrations": "/integrations/status",
            }
            path = module_paths.get(module, f"/{module}/status")
            result = await client.get(path)
            lines = [f"## Module Status: {module}\n"]
            for k, v in result.items():
                if k == "status":
                    lines.append(f"- **Status**: {v}")
                elif isinstance(v, (str, int, float, bool)):
                    lines.append(f"- **{k}**: {v}")
                elif isinstance(v, list):
                    lines.append(f"- **{k}**: {', '.join(str(i) for i in v[:10])}")
            return "\n".join(lines)

        # Overall system health
        try:
            health = await client.get("/health/detailed")
        except Exception:
            try:
                health = await client.get("/health")
            except Exception:
                return "Error: Could not connect to MASS API. Is it running?"

        lines = ["## MASS System Health\n"]
        lines.append(f"- **Status**: {health.get('status', '?')}")

        checks = health.get("checks", {})
        if checks:
            lines.append("\n### Subsystems")
            for name, info in checks.items():
                if isinstance(info, dict):
                    s = info.get("status", "?")
                    latency = info.get("latency_ms", "")
                    lat_str = f" ({latency}ms)" if latency else ""
                    lines.append(f"- **{name}**: {s}{lat_str}")
                else:
                    lines.append(f"- **{name}**: {info}")

        return "\n".join(lines)

    @mcp.tool()
    async def chat(
        message: str,
        scan_id: str | None = None,
    ) -> str:
        """Chat with the MASS security assistant. Supports context-aware conversations
        about scans, findings, and security topics.

        Args:
            message: Your message or question about security findings, scan results, etc.
            scan_id: Optional scan ID for context-aware responses about a specific scan.
        """
        client = get_client()
        data: dict = {"message": message}
        if scan_id:
            data["scan_id"] = scan_id

        result = await client.post("/chat", data)
        response = result.get("response", result.get("message", ""))

        if result.get("tool_calls"):
            tool_info = f"\n\n_Used {len(result['tool_calls'])} tool calls to answer._"
            return f"{response}{tool_info}"

        return response
