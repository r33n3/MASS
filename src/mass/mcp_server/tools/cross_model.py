"""Cross-model comparison tool — compare_models."""

from mcp.server.fastmcp import FastMCP

from mass.mcp_server.client import format_json, get_client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def compare_models(
        action: str = "start",
        job_id: str | None = None,
        models: str | None = None,
        categories: str | None = None,
        max_probes: int = 0,
        system_prompt: str | None = None,
    ) -> str:
        """Compare security posture across multiple LLM models.

        Runs the same security probes against multiple models in parallel and
        ranks them by vulnerability rate and severity.

        Args:
            action: Action — start, status, list, or cancel.
            job_id: Comparison job ID (for status/cancel).
            models: JSON array of models to compare. Each model needs provider and model fields.
                    Example: '[{"provider":"ollama","model":"llama3.2"},{"provider":"openai","model":"gpt-4o-mini"}]'
            categories: Comma-separated attack categories to test
                        (e.g., 'prompt_injection,jailbreak,data_leakage').
            max_probes: Maximum probes per model (0 = all, default: 0).
            system_prompt: System prompt to inject into all models.
        """
        client = get_client()

        if action == "start":
            if not models:
                return (
                    "Error: 'models' is required. Provide a JSON array, e.g.:\n"
                    '`[{"provider":"ollama","model":"llama3.2"},{"provider":"openai","model":"gpt-4o-mini"}]`'
                )
            import json
            try:
                model_list = json.loads(models)
            except json.JSONDecodeError:
                return "Error: 'models' must be valid JSON."

            data: dict = {"models": model_list}
            if categories:
                data["categories"] = categories.split(",")
            if max_probes > 0:
                data["max_probes"] = max_probes
            if system_prompt:
                data["system_prompt"] = system_prompt

            result = await client.post("/cross-model/compare", data)
            jid = result.get("id", "?")
            return (
                f"Cross-model comparison started.\n\n"
                f"- **Job ID**: `{jid}`\n"
                f"- **Models**: {len(model_list)} models\n"
                f"- **Status**: {result.get('status', 'pending')}\n\n"
                f"Use `compare_models(action=\"status\", job_id=\"{jid}\")` to check progress."
            )

        elif action == "status":
            if not job_id:
                return "Error: job_id is required for 'status' action."
            result = await client.get(f"/cross-model/compare/{job_id}")

            lines = [
                f"## Cross-Model Comparison: `{job_id}`",
                f"- **Status**: {result.get('status', '?')}",
                f"- **Models**: {result.get('models_count', 0)}",
                f"- **Total Probes**: {result.get('total_probes', 0)}",
                f"- **Total Findings**: {result.get('total_findings', 0)}",
            ]

            ranking = result.get("overall_ranking", [])
            if ranking:
                lines.append("\n### Security Ranking (best first)")
                for r in ranking:
                    rank = r.get("rank", "?")
                    label = r.get("label", "?")
                    score = r.get("security_score", 0)
                    vulns = r.get("total_vulnerabilities", 0)
                    lines.append(f"{rank}. **{label}** — Score: {score}/100, Vulnerabilities: {vulns}")

            return "\n".join(lines)

        elif action == "list":
            result = await client.get("/cross-model/comparisons")
            items = result.get("items", [])
            if not items:
                return "No cross-model comparisons found."
            lines = ["## Cross-Model Comparisons\n"]
            for c in items:
                lines.append(f"- `{c.get('id', '?')}` — {c.get('name', 'Unnamed')} [{c.get('status', '?')}]")
            return "\n".join(lines)

        elif action == "cancel":
            if not job_id:
                return "Error: job_id is required for 'cancel' action."
            await client.post(f"/cross-model/compare/{job_id}/cancel")
            return f"Comparison `{job_id}` cancelled."

        else:
            return f"Unknown action: {action}. Use: start, status, list, or cancel."
