"""Explainability tools — explain_finding, get_remediation."""

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.client import get_client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def explain_finding(
        finding_id: str,
        audience: str = "developer",
        depth: str = "standard",
        include_attack_chain: bool = True,
        include_remediation: bool = True,
    ) -> str:
        """Explain a security finding in human-readable language.

        Generates a detailed explanation including risk description, attack chain,
        remediation steps, and compliance context.

        Args:
            finding_id: The finding ID to explain.
            audience: Target audience — developer, security_engineer, executive, or compliance_officer.
            depth: Explanation depth — brief, standard, or detailed.
            include_attack_chain: Include step-by-step attack chain (default: True).
            include_remediation: Include remediation guidance (default: True).
        """
        client = get_client()
        result = await client.post("/explain/finding", {
            "finding_id": finding_id,
            "audience": audience,
            "depth": depth,
            "include_attack_chain": include_attack_chain,
            "include_remediation": include_remediation,
        })

        lines = [f"## Finding Explanation\n"]

        if result.get("explanation"):
            lines.append(result["explanation"])

        if result.get("risk_description"):
            lines.append(f"\n### Risk\n{result['risk_description']}")

        if result.get("attack_chain") and include_attack_chain:
            lines.append("\n### Attack Chain")
            chain = result["attack_chain"]
            if isinstance(chain, list):
                for i, step in enumerate(chain, 1):
                    lines.append(f"{i}. {step}")
            elif isinstance(chain, str):
                lines.append(chain)

        if result.get("remediation") and include_remediation:
            lines.append(f"\n### Remediation\n{result['remediation']}")

        if result.get("compliance_context"):
            lines.append(f"\n### Compliance\n{result['compliance_context']}")

        return "\n".join(lines)

    @mcp.tool()
    async def get_remediation(
        scan_id: str,
        max_items: int = 10,
        group_by: str = "severity",
    ) -> str:
        """Generate a prioritized remediation plan from scan findings.

        Args:
            scan_id: The scan to generate a remediation plan for.
            max_items: Maximum remediation items (default: 10).
            group_by: Group by severity or category (default: severity).
        """
        client = get_client()
        result = await client.post("/explain/remediation-plan", {
            "scan_id": scan_id,
            "max_items": max_items,
            "group_by": group_by,
        })

        lines = [f"## Remediation Plan\n"]

        if result.get("summary"):
            lines.append(result["summary"])

        if result.get("quick_wins"):
            lines.append("\n### Quick Wins")
            for qw in result["quick_wins"]:
                lines.append(f"- {qw}")

        items = result.get("items", [])
        if items:
            lines.append(f"\n### Prioritized Items ({len(items)})")
            for i, item in enumerate(items, 1):
                priority = item.get("priority", "?")
                title = item.get("title", "Untitled")
                effort = item.get("effort", "?")
                lines.append(f"\n**{i}. [{priority}] {title}** (Effort: {effort})")
                if item.get("description"):
                    lines.append(f"   {item['description'][:300]}")
                if item.get("steps"):
                    for step in item["steps"]:
                        lines.append(f"   - {step}")

        return "\n".join(lines)
