"""CI/CD and GitHub integration tools — manage_cicd, export_issues."""

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.client import get_client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def manage_cicd(
        action: str = "list",
        integration_id: str | None = None,
        provider: str | None = None,
        name: str | None = None,
        webhook_url: str | None = None,
        scan_id: str | None = None,
    ) -> str:
        """Manage CI/CD integrations, webhooks, and quality gates.

        Args:
            action: Action — list, create, delete, gate, or status.
            integration_id: Integration ID (for delete).
            provider: CI/CD provider — github, gitlab, or generic (for create).
            name: Integration name (for create).
            webhook_url: Webhook endpoint URL (for create).
            scan_id: Scan ID (for gate check — returns pass/fail).
        """
        client = get_client()

        if action == "list":
            result = await client.get("/cicd/integrations")
            items = result.get("items", [])
            if not items:
                return "No CI/CD integrations configured."
            lines = ["## CI/CD Integrations\n"]
            for i in items:
                lines.append(
                    f"- **{i.get('name', '?')}** (`{i.get('id', '?')}`)\n"
                    f"  Provider: {i.get('provider', '?')} | Active: {i.get('is_active', '?')}"
                )
            return "\n".join(lines)

        elif action == "create":
            if not provider or not name:
                return "Error: 'provider' and 'name' are required."
            data: dict = {"provider": provider, "name": name}
            if webhook_url:
                data["webhook_url"] = webhook_url
            result = await client.post("/cicd/integrations", data)
            return (
                f"CI/CD integration created.\n\n"
                f"- **ID**: `{result.get('id', '?')}`\n"
                f"- **Name**: {result.get('name', '?')}\n"
                f"- **Provider**: {result.get('provider', '?')}\n"
                f"- **Webhook Secret**: `{result.get('webhook_secret', 'N/A')}`"
            )

        elif action == "delete":
            if not integration_id:
                return "Error: integration_id is required."
            await client.delete(f"/cicd/integrations/{integration_id}")
            return f"Integration `{integration_id}` deleted."

        elif action == "gate":
            if not scan_id:
                return "Error: scan_id is required for quality gate check."
            result = await client.get(f"/cicd/gate/{scan_id}")
            gate_status = result.get("status", result.get("gate", "?"))
            lines = [
                f"## Quality Gate: {gate_status}",
                f"- **Scan**: {scan_id}",
            ]
            if result.get("findings_by_severity"):
                for sev, count in result["findings_by_severity"].items():
                    lines.append(f"- {sev.upper()}: {count}")
            if result.get("threshold"):
                lines.append(f"- **Threshold**: {result['threshold']}")
            return "\n".join(lines)

        elif action == "status":
            result = await client.get("/cicd/status")
            return (
                f"## CI/CD Module Status\n"
                f"- **Status**: {result.get('status', '?')}\n"
                f"- **Integrations**: {result.get('total_integrations', 0)}\n"
                f"- **Builds**: {result.get('total_builds', 0)}"
            )

        else:
            return f"Unknown action: {action}. Use: list, create, delete, gate, or status."

    @mcp.tool()
    async def export_issues(
        config_id: str,
        scan_id: str,
        min_severity: str = "medium",
        dry_run: bool = False,
    ) -> str:
        """Export security findings as GitHub Issues.

        Args:
            config_id: GitHub integration config ID.
            scan_id: Scan ID to export findings from.
            min_severity: Minimum severity to export — critical, high, medium, or low.
            dry_run: If True, preview issues without creating them.
        """
        client = get_client()
        result = await client.post(f"/integrations/github/{config_id}/export", {
            "scan_id": scan_id,
            "min_severity": min_severity,
            "dry_run": dry_run,
        })

        created = result.get("issues_created", result.get("created_count", 0))
        skipped = result.get("issues_skipped", result.get("skipped_count", 0))

        prefix = "**DRY RUN** — " if dry_run else ""
        return (
            f"{prefix}GitHub issues export complete.\n\n"
            f"- **Issues Created**: {created}\n"
            f"- **Skipped (duplicates)**: {skipped}\n"
            f"- **Min Severity**: {min_severity}"
        )
