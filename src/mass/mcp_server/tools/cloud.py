"""Cloud-native tools — assess_cloud, manage_cloud_accounts."""

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.client import get_client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def assess_cloud(
        action: str = "discover",
        account_id: str | None = None,
        job_id: str | None = None,
        resource_types: str | None = None,
        include_iac_scan: bool = True,
    ) -> str:
        """Discover and assess cloud-hosted AI resources.

        Args:
            action: Action — discover, assess, resources, or status.
            account_id: Cloud account ID (required for discover/assess).
            job_id: Job ID (for checking discovery/assessment status).
            resource_types: Comma-separated resource types to discover
                            (e.g., 'model_endpoint,inference_service,container_service').
            include_iac_scan: Include Terraform/K8s manifest scanning (default: True).
        """
        client = get_client()

        if action == "discover":
            if not account_id:
                return "Error: account_id is required for 'discover' action."
            data: dict = {"account_id": account_id}
            if resource_types:
                data["resource_types"] = resource_types.split(",")
            result = await client.post("/cloud/discover", data)
            jid = result.get("id", "?")
            return (
                f"Cloud resource discovery started.\n\n"
                f"- **Job ID**: `{jid}`\n"
                f"- **Account**: {account_id}\n"
                f"- **Status**: {result.get('status', 'pending')}\n\n"
                f"Use `assess_cloud(action=\"status\", job_id=\"{jid}\")` to check progress."
            )

        elif action == "assess":
            if not account_id:
                return "Error: account_id is required for 'assess' action."
            data = {
                "account_id": account_id,
                "include_iac_scan": include_iac_scan,
            }
            result = await client.post("/cloud/assess", data)
            jid = result.get("id", "?")
            return (
                f"Cloud security assessment started.\n\n"
                f"- **Job ID**: `{jid}`\n"
                f"- **Account**: {account_id}\n"
                f"- **Status**: {result.get('status', 'pending')}\n\n"
                f"Use `assess_cloud(action=\"status\", job_id=\"{jid}\")` to check progress."
            )

        elif action == "status":
            if not job_id:
                return "Error: job_id is required for 'status' action."
            # Try discovery first, then assessment
            try:
                result = await client.get(f"/cloud/discover/{job_id}")
                lines = [
                    f"## Discovery: `{job_id}`",
                    f"- **Status**: {result.get('status', '?')}",
                    f"- **Resources Found**: {result.get('resources_found', 0)}",
                ]
                by_type = result.get("resources_by_type", {})
                if by_type:
                    lines.append("\n### Resources by Type")
                    for rtype, count in by_type.items():
                        lines.append(f"- {rtype}: {count}")
                return "\n".join(lines)
            except Exception:
                pass

            result = await client.get(f"/cloud/assess/{job_id}")
            lines = [
                f"## Assessment: `{job_id}`",
                f"- **Status**: {result.get('status', '?')}",
                f"- **Resources Assessed**: {result.get('resources_assessed', 0)}",
                f"- **Checks Run**: {result.get('checks_run', 0)}",
                f"- **Findings**: {result.get('findings_count', 0)}",
                f"- **Security Grade**: {result.get('security_grade', 'N/A')}",
            ]
            by_sev = result.get("findings_by_severity", {})
            if by_sev:
                lines.append("\n### Findings by Severity")
                for sev in ["critical", "high", "medium", "low"]:
                    count = by_sev.get(sev, 0)
                    if count:
                        lines.append(f"- {sev.upper()}: {count}")
            return "\n".join(lines)

        elif action == "resources":
            params: dict = {"limit": 50}
            if account_id:
                params["account_id"] = account_id
            result = await client.get("/cloud/resources", **params)
            items = result.get("items", [])
            if not items:
                return "No cloud resources found."
            lines = ["## Cloud Resources\n"]
            for r in items:
                name = r.get("name", "Unnamed")
                rtype = r.get("resource_type", "?")
                grade = r.get("security_grade", "-")
                lines.append(f"- **{name}** ({rtype}) — Grade: {grade}")
            return "\n".join(lines)

        else:
            return f"Unknown action: {action}. Use: discover, assess, resources, or status."

    @mcp.tool()
    async def manage_cloud_accounts(
        action: str = "list",
        account_id: str | None = None,
        provider: str | None = None,
        name: str | None = None,
        cloud_account_id: str | None = None,
        region: str | None = None,
    ) -> str:
        """Manage cloud account registrations for resource discovery.

        Args:
            action: Action — list, create, get, or delete.
            account_id: MASS account ID (for get/delete).
            provider: Cloud provider — aws, azure, gcp, or kubernetes (for create).
            name: Display name (for create).
            cloud_account_id: AWS Account ID, Azure Subscription ID, or GCP Project ID.
            region: Primary region (e.g., us-east-1, eastus).
        """
        client = get_client()

        if action == "list":
            result = await client.get("/cloud/accounts")
            items = result.get("items", [])
            if not items:
                return "No cloud accounts registered."
            lines = ["## Cloud Accounts\n"]
            for a in items:
                lines.append(
                    f"- **{a.get('name', '?')}** (`{a.get('id', '?')}`)\n"
                    f"  Provider: {a.get('provider', '?')} | "
                    f"Resources: {a.get('resources_count', 0)}"
                )
            return "\n".join(lines)

        elif action == "create":
            if not provider or not name:
                return "Error: 'provider' and 'name' are required for 'create' action."
            data: dict = {"provider": provider, "name": name}
            if cloud_account_id:
                data["account_id"] = cloud_account_id
            if region:
                data["region"] = region
            result = await client.post("/cloud/accounts", data)
            return (
                f"Cloud account registered.\n\n"
                f"- **ID**: `{result.get('id', '?')}`\n"
                f"- **Name**: {result.get('name', '?')}\n"
                f"- **Provider**: {result.get('provider', '?')}"
            )

        elif action == "get":
            if not account_id:
                return "Error: account_id is required."
            result = await client.get(f"/cloud/accounts/{account_id}")
            return (
                f"## Cloud Account: {result.get('name', '?')}\n"
                f"- **ID**: `{result.get('id', '?')}`\n"
                f"- **Provider**: {result.get('provider', '?')}\n"
                f"- **Region**: {result.get('region', 'N/A')}\n"
                f"- **Resources**: {result.get('resources_count', 0)}\n"
                f"- **Last Discovery**: {result.get('last_discovery_at', 'Never')}"
            )

        elif action == "delete":
            if not account_id:
                return "Error: account_id is required."
            await client.delete(f"/cloud/accounts/{account_id}")
            return f"Cloud account `{account_id}` deleted."

        else:
            return f"Unknown action: {action}. Use: list, create, get, or delete."
