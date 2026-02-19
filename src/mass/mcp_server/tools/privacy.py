"""Privacy risk analysis tool — assess_privacy."""

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.client import get_client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def assess_privacy(
        action: str = "assess",
        scan_id: str | None = None,
        job_id: str | None = None,
        frameworks: str = "gdpr,owasp_llm",
    ) -> str:
        """Run privacy impact assessments, PII detection, and compliance checks.

        Args:
            action: Action — assess, compliance, pii_exposure, flows, or status.
            scan_id: Scan ID to assess (for assess/compliance).
            job_id: Assessment job ID (for status).
            frameworks: Comma-separated compliance frameworks — gdpr, owasp_llm, eu_ai_act,
                        hipaa, ccpa, nist_ai, mitre_atlas (default: gdpr,owasp_llm).
        """
        client = get_client()

        if action == "assess":
            if not scan_id:
                return "Error: scan_id is required for 'assess' action."
            result = await client.post("/privacy/assess", {
                "scan_id": scan_id,
                "frameworks": frameworks.split(","),
            })
            jid = result.get("id", "?")
            return (
                f"Privacy impact assessment started.\n\n"
                f"- **Job ID**: `{jid}`\n"
                f"- **Scan**: {scan_id}\n"
                f"- **Frameworks**: {frameworks}\n"
                f"- **Status**: {result.get('status', 'pending')}\n\n"
                f"Use `assess_privacy(action=\"status\", job_id=\"{jid}\")` to check progress."
            )

        elif action == "compliance":
            if not scan_id:
                return "Error: scan_id is required."
            result = await client.post("/privacy/compliance", {
                "scan_id": scan_id,
                "frameworks": frameworks.split(","),
            })
            lines = [f"## Compliance Check\n"]
            checks = result.get("checks", result.get("items", []))
            if isinstance(checks, list):
                for c in checks:
                    fw = c.get("framework", "?")
                    status = c.get("status", "?")
                    lines.append(f"- **{fw}**: {status}")
                    controls = c.get("controls", [])
                    for ctrl in controls[:5]:
                        lines.append(f"  - {ctrl.get('name', '?')}: {ctrl.get('status', '?')}")
            return "\n".join(lines) if len(lines) > 1 else f"Compliance check completed.\n\n{result}"

        elif action == "pii_exposure":
            result = await client.get("/privacy/pii-exposure")
            lines = ["## PII Exposure Summary\n"]
            categories = result.get("categories", result)
            if isinstance(categories, dict):
                for cat, count in categories.items():
                    lines.append(f"- **{cat}**: {count} exposures")
            elif isinstance(categories, list):
                for item in categories:
                    lines.append(f"- **{item.get('category', '?')}**: {item.get('count', 0)} exposures")
            return "\n".join(lines) if len(lines) > 1 else f"PII exposure data:\n{result}"

        elif action == "flows":
            result = await client.get("/privacy/data-flows")
            items = result.get("items", [])
            if not items:
                return "No data flows tracked."
            lines = ["## Data Flows\n"]
            for f in items:
                lines.append(
                    f"- **{f.get('name', '?')}** — {f.get('direction', '?')}\n"
                    f"  Risk: {f.get('risk_level', '?')} | PII: {f.get('pii_categories', [])}"
                )
            return "\n".join(lines)

        elif action == "status":
            if not job_id:
                return "Error: job_id is required."
            result = await client.get(f"/privacy/assess/{job_id}")
            return (
                f"## Privacy Assessment: `{job_id}`\n"
                f"- **Status**: {result.get('status', '?')}\n"
                f"- **Risk Level**: {result.get('overall_risk', 'N/A')}\n"
                f"- **PII Categories Found**: {result.get('pii_categories_count', 0)}\n"
                f"- **Compliance Gaps**: {result.get('compliance_gaps_count', 0)}"
            )

        else:
            return f"Unknown action: {action}. Use: assess, compliance, pii_exposure, flows, or status."
