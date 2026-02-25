"""Supply chain verification tool — check_supply_chain."""

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.client import get_client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def check_supply_chain(
        action: str = "scan",
        target: str | None = None,
        job_id: str | None = None,
        ecosystem: str | None = None,
        sbom_format: str = "cyclonedx",
    ) -> str:
        """Verify AI supply chain security — packages, models, SBOMs, and vulnerabilities.

        Args:
            action: Action — scan, verify_model, sbom, vulnerabilities, or status.
            target: Target path/name (for scan/verify_model/sbom).
            job_id: Job ID (for checking scan/verify status).
            ecosystem: Package ecosystem — pypi, npm, huggingface, docker (for scan).
            sbom_format: SBOM format — cyclonedx or spdx (for sbom action).
        """
        client = get_client()

        if action == "scan":
            data: dict = {}
            if target:
                data["target_path"] = target
            if ecosystem:
                data["ecosystem"] = ecosystem
            result = await client.post("/supply-chain/scan", data)
            jid = result.get("id", "?")
            return (
                f"Supply chain scan started.\n\n"
                f"- **Job ID**: `{jid}`\n"
                f"- **Status**: {result.get('status', 'pending')}\n\n"
                f"Use `check_supply_chain(action=\"status\", job_id=\"{jid}\")` to check progress."
            )

        elif action == "verify_model":
            if not target:
                return "Error: 'target' (model file path) is required."
            result = await client.post("/supply-chain/verify-model", {"model_path": target})
            jid = result.get("id", "?")
            return (
                f"Model verification started.\n\n"
                f"- **Job ID**: `{jid}`\n"
                f"- **Model**: {target}\n"
                f"- **Status**: {result.get('status', 'pending')}"
            )

        elif action == "sbom":
            if not target:
                return "Error: 'target' is required for SBOM generation."
            result = await client.post("/supply-chain/sbom", {
                "target_path": target,
                "format": sbom_format,
            })
            return (
                f"SBOM generated.\n\n"
                f"- **Format**: {sbom_format.upper()}\n"
                f"- **Packages**: {result.get('components_count', result.get('packages_count', '?'))}\n"
                f"- **ID**: `{result.get('id', '?')}`"
            )

        elif action == "vulnerabilities":
            result = await client.get("/supply-chain/vulnerabilities")
            items = result.get("items", [])
            if not items:
                return "No known vulnerabilities found."
            lines = ["## Supply Chain Vulnerabilities\n"]
            for v in items[:20]:
                sev = v.get("severity", "?").upper()
                name = v.get("package_name", "?")
                cve = v.get("cve_id", "")
                lines.append(f"- **[{sev}]** {name} — {cve}")
                if v.get("description"):
                    lines.append(f"  {v['description'][:200]}")
            return "\n".join(lines)

        elif action == "status":
            if not job_id:
                return "Error: job_id is required for 'status' action."
            try:
                result = await client.get(f"/supply-chain/scan/{job_id}")
            except Exception:
                result = await client.get(f"/supply-chain/verify-model/{job_id}")
            return (
                f"## Supply Chain Job: `{job_id}`\n"
                f"- **Status**: {result.get('status', '?')}\n"
                f"- **Findings**: {result.get('findings_count', result.get('issues_count', 0))}"
            )

        else:
            return f"Unknown action: {action}. Use: scan, verify_model, sbom, vulnerabilities, or status."
