"""Threat intelligence tool — get_threat_intel."""

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.client import get_client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def get_threat_intel(
        action: str = "items",
        item_id: str | None = None,
        severity: str | None = None,
        search: str | None = None,
        limit: int = 20,
    ) -> str:
        """Query AI/ML threat intelligence — threat items, MITRE ATLAS techniques, and coverage.

        Args:
            action: Action — items, techniques, coverage, analyze, or generate_payloads.
            item_id: Threat item ID (for analyze/generate_payloads).
            severity: Filter by severity (for items).
            search: Search term (for items).
            limit: Max results (default: 20).
        """
        client = get_client()

        if action == "items":
            params: dict = {"limit": limit}
            if severity:
                params["severity"] = severity
            if search:
                params["search"] = search
            result = await client.get("/threat-intel/items", **params)
            items = result.get("items", [])
            if not items:
                return "No threat intelligence items found."
            lines = ["## Threat Intelligence Items\n"]
            for t in items:
                sev = t.get("severity", "?").upper()
                title = t.get("title", "Untitled")
                status = t.get("status", "?")
                lines.append(f"- **[{sev}]** {title} ({status})")
                lines.append(f"  ID: `{t.get('id', '?')}`")
            return "\n".join(lines)

        elif action == "techniques":
            result = await client.get("/threat-intel/techniques")
            items = result.get("items", result) if isinstance(result, dict) else result
            if not isinstance(items, list):
                items = []
            lines = ["## MITRE ATLAS Techniques\n"]
            for t in items[:30]:
                tid = t.get("technique_id", t.get("id", "?"))
                name = t.get("name", "?")
                covered = t.get("covered", False)
                marker = "[covered]" if covered else "[gap]"
                lines.append(f"- **{tid}** — {name} {marker}")
            return "\n".join(lines)

        elif action == "coverage":
            result = await client.get("/threat-intel/coverage")
            lines = ["## MITRE ATLAS Coverage\n"]
            total = result.get("total_techniques", 0)
            covered = result.get("covered_techniques", 0)
            pct = round(covered / total * 100, 1) if total else 0
            lines.append(f"- **Total Techniques**: {total}")
            lines.append(f"- **Covered**: {covered} ({pct}%)")
            lines.append(f"- **Gaps**: {total - covered}")
            gaps = result.get("gaps", [])
            if gaps:
                lines.append("\n### Top Gaps")
                for g in gaps[:10]:
                    lines.append(f"- {g.get('technique_id', '?')} — {g.get('name', '?')}")
            return "\n".join(lines)

        elif action == "analyze":
            if not item_id:
                return "Error: item_id is required for 'analyze' action."
            result = await client.post(f"/threat-intel/items/{item_id}/analyze")
            return (
                f"## Threat Analysis\n\n"
                f"{result.get('analysis', result.get('summary', 'Analysis complete.'))}"
            )

        elif action == "generate_payloads":
            if not item_id:
                return "Error: item_id is required."
            result = await client.post(f"/threat-intel/items/{item_id}/generate-payloads")
            payloads = result.get("payloads", [])
            lines = [f"## Generated Payloads ({len(payloads)})\n"]
            for p in payloads[:10]:
                lines.append(f"- **{p.get('category', '?')}**: `{p.get('payload', '?')[:100]}`")
            return "\n".join(lines)

        else:
            return f"Unknown action: {action}. Use: items, techniques, coverage, analyze, or generate_payloads."
