"""Target management tool — manage_targets."""

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.client import format_json, get_client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def manage_targets(
        action: str = "list",
        target_id: str | None = None,
        name: str | None = None,
        target_type: str | None = None,
        source_path: str | None = None,
        search: str | None = None,
        limit: int = 20,
    ) -> str:
        """Manage security scan targets (AI deployments, MCP servers, models, agents).

        Args:
            action: Action to perform — list, get, create, or delete.
            target_id: Target ID (required for get/delete).
            name: Target name (for create).
            target_type: Type: deployment, mcp_server, model_file, skill_file,
                         instruction_file, model_endpoint, agent_endpoint.
            source_path: Path or URL of the target (for create).
            search: Search term for filtering (for list).
            limit: Max results for list (default: 20).
        """
        client = get_client()

        if action == "list":
            params: dict = {"limit": limit}
            if search:
                params["search"] = search
            if target_type:
                params["type"] = target_type
            result = await client.get("/targets", **params)
            items = result.get("items", result) if isinstance(result, dict) else result
            if not isinstance(items, list):
                items = []

            if not items:
                return "No targets found."

            lines = [f"## Targets ({len(items)} found)\n"]
            for t in items:
                tid = t.get("id", "?")
                tname = t.get("name", "Unnamed")
                ttype = t.get("target_type", t.get("type", "?"))
                status = t.get("status", "?")
                lines.append(f"- **{tname}** (`{tid}`)")
                lines.append(f"  Type: {ttype} | Status: {status}")
            return "\n".join(lines)

        elif action == "get":
            if not target_id:
                return "Error: target_id is required for the 'get' action."
            result = await client.get(f"/targets/{target_id}")
            name = result.get("name", "Unnamed")
            lines = [
                f"## Target: {name}",
                f"- **ID**: `{result.get('id', '?')}`",
                f"- **Type**: {result.get('target_type', result.get('type', '?'))}",
                f"- **Path**: {result.get('source_path', 'N/A')}",
                f"- **Status**: {result.get('status', '?')}",
                f"- **Created**: {result.get('created_at', 'N/A')}",
            ]
            if result.get("scan_count"):
                lines.append(f"- **Scans**: {result['scan_count']}")
            if result.get("last_scanned_at"):
                lines.append(f"- **Last Scanned**: {result['last_scanned_at']}")
            return "\n".join(lines)

        elif action == "create":
            if not source_path:
                return "Error: source_path is required for the 'create' action."
            data: dict = {
                "name": name or source_path.split("/")[-1],
                "source_path": source_path,
                "target_type": target_type or "deployment",
            }
            result = await client.post("/targets", data)
            return (
                f"Target created successfully.\n\n"
                f"- **ID**: `{result.get('id', '?')}`\n"
                f"- **Name**: {result.get('name', '?')}\n"
                f"- **Type**: {result.get('target_type', '?')}"
            )

        elif action == "delete":
            if not target_id:
                return "Error: target_id is required for the 'delete' action."
            await client.delete(f"/targets/{target_id}")
            return f"Target `{target_id}` deleted successfully."

        else:
            return f"Unknown action: {action}. Use: list, get, create, or delete."
