"""Tool executor for chat tool calling.

Defines available tools and executes them against MASS repositories.
Tools run in-process using the same DB session and tenant context
as the chat endpoint.
"""

import json
import logging
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from mass.storage.models.deployment import Deployment, Scan
from mass.storage.models.finding import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonical tool definitions (provider-agnostic)
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "search",
        "description": (
            "Search across MASS targets, scans, and findings. "
            "Matches target names, scan IDs, finding titles, "
            "categories, and severity levels. "
            "Returns matching items grouped by type."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query (e.g. target name, 'critical', category)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results per category (default 10)",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "list_targets",
        "description": (
            "List registered deployment targets with their type, "
            "path, and scan count."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max targets to return (default 10)",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_scan_status",
        "description": (
            "Get detailed status of a specific scan including "
            "progress, finding counts by severity, and verdict."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "string",
                    "description": "The scan ID (full or prefix)",
                },
            },
            "required": ["scan_id"],
        },
    },
    {
        "name": "list_findings",
        "description": (
            "List security findings, optionally filtered by scan "
            "and/or severity. Omit scan_id to list across all scans."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "string",
                    "description": "Optional scan ID to filter by (omit for all scans)",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Filter by severity level",
                },
                "status": {
                    "type": "string",
                    "enum": ["open", "confirmed", "false_positive", "fixed", "accepted"],
                    "description": "Filter by finding status (default: all)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max findings to return (default 20)",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_finding_detail",
        "description": (
            "Get full details of a specific finding including "
            "description, evidence, remediation, code snippet, "
            "and compliance mappings."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "The finding ID",
                },
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "start_scan",
        "description": (
            "Start a security scan on a registered target. "
            "Returns the new scan ID."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_id": {
                    "type": "string",
                    "description": "The deployment/target ID to scan",
                },
                "profile": {
                    "type": "string",
                    "enum": ["quick", "standard", "comprehensive"],
                    "description": "Scan profile (default standard)",
                },
            },
            "required": ["target_id"],
        },
    },
    {
        "name": "get_stats",
        "description": (
            "Get dashboard statistics: total targets, scans, "
            "findings, severity breakdown, and status breakdown."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "lookup_model",
        "description": (
            "Look up an AI/ML model on HuggingFace to get details: "
            "architecture, parameter count, capabilities, author, popularity, "
            "and whether it appears in any scanned project. "
            "Use when users ask about a model name or GGUF filename."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "model_name": {
                    "type": "string",
                    "description": (
                        "Model name or identifier. Accepts HuggingFace IDs "
                        "(e.g. 'Qwen/Qwen2.5-VL-7B-Instruct'), Ollama tags "
                        "(e.g. 'qwen3:8b'), or GGUF filenames "
                        "(e.g. 'Qwen3VL-8B-Instruct-Q4_K_M.gguf')"
                    ),
                },
            },
            "required": ["model_name"],
        },
    },
    {
        "name": "read_file",
        "description": (
            "Find and read a file from a scanned project/target directory. "
            "Use when users ask about a specific file, want to see its contents, "
            "or ask what a file does. Searches across all scanned target directories."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": (
                        "Filename or partial path to search for "
                        "(e.g. 'config.py', 'aDiOS_config.py', 'src/main.py')"
                    ),
                },
                "target_name": {
                    "type": "string",
                    "description": (
                        "Optional: target/project name to search within. "
                        "If omitted, searches all targets."
                    ),
                },
            },
            "required": ["filename"],
        },
    },
    {
        "name": "list_sandbox_jobs",
        "description": (
            "List sandbox security test runs with their status, score, "
            "scenario name, and findings count. Use when users ask about "
            "sandbox runs, sandbox results, or security tests."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max jobs to return (default 20)",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_sandbox_results",
        "description": (
            "Get full results of a sandbox security test including "
            "step-by-step timeline, findings, score, compliance mapping, "
            "and guardrail recommendations. Use when users ask about "
            "a specific sandbox run's details or results."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "job_id": {
                    "type": "string",
                    "description": "The sandbox job ID",
                },
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "list_sandbox_scenarios",
        "description": (
            "List available sandbox security test scenarios (built-in "
            "and custom). Each scenario defines turns, assertions, and "
            "tool mocks for testing AI application security."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "start_sandbox_run",
        "description": (
            "Start a sandbox security test using a named scenario against "
            "a model. Returns the job ID to track progress. Use when users "
            "ask to run a sandbox test or security test on a project."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "scenario_name": {
                    "type": "string",
                    "description": "Name of the scenario to run",
                },
                "model_provider": {
                    "type": "string",
                    "description": (
                        "Provider: openai, anthropic, ollama, gemini, grok "
                        "(default: openai)"
                    ),
                },
                "model_name": {
                    "type": "string",
                    "description": "Model name (default: gpt-4o)",
                },
                "deployment_id": {
                    "type": "string",
                    "description": "Optional: link to a scanned project/target",
                },
            },
            "required": ["scenario_name"],
        },
    },
]


class ToolExecutor:
    """Executes chat tools against MASS repositories."""

    def __init__(self, session: AsyncSession, tenant_id: str) -> None:
        self.session = session
        self.tenant_id = tenant_id

    async def execute(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool by name and return results."""
        handler = getattr(self, f"_tool_{name}", None)
        if handler is None:
            return {"error": f"Unknown tool: {name}"}
        try:
            return await handler(**arguments)
        except Exception as exc:
            logger.warning("Tool %s failed: %s", name, exc, exc_info=True)
            return {"error": f"Tool execution failed: {str(exc)}"}

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    async def _tool_search(
        self, query: str, limit: int = 10
    ) -> dict[str, Any]:
        """Search across targets, scans, and findings."""
        q = query.lower()
        targets = []
        scans = []
        findings = []

        # Search deployments by name
        dep_stmt = (
            select(Deployment)
            .where(Deployment.tenant_id == self.tenant_id)
            .where(func.lower(Deployment.name).contains(q))
            .order_by(Deployment.created_at.desc())
            .limit(limit)
        )
        dep_result = await self.session.execute(dep_stmt)
        for dep in dep_result.scalars():
            meta = {}
            if dep.meta:
                try:
                    meta = json.loads(dep.meta)
                except (json.JSONDecodeError, TypeError):
                    pass
            targets.append({
                "id": dep.id,
                "name": dep.name,
                "type": meta.get("target_type", dep.deployment_type),
                "path": dep.source_path or dep.source_url or "",
            })

        # Search scans by ID prefix or deployment name
        scan_stmt = (
            select(Scan, Deployment.name.label("dep_name"))
            .outerjoin(Deployment, Scan.deployment_id == Deployment.id)
            .where(Scan.tenant_id == self.tenant_id)
            .where(
                func.lower(Scan.id).contains(q)
                | func.lower(Deployment.name).contains(q)
            )
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )
        scan_result = await self.session.execute(scan_stmt)
        for row in scan_result:
            scan = row[0]
            dep_name = row[1] or scan.deployment_id
            scans.append({
                "id": scan.id,
                "target": dep_name,
                "status": scan.status,
                "profile": scan.profile,
                "findings": scan.total_findings,
            })

        # Search findings by title, category, or severity
        finding_stmt = (
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.tenant_id == self.tenant_id)
            .where(
                func.lower(Finding.title).contains(q)
                | func.lower(Finding.category).contains(q)
                | func.lower(Finding.severity).contains(q)
            )
            .order_by(
                case(
                    (Finding.severity == "critical", 0),
                    (Finding.severity == "high", 1),
                    (Finding.severity == "medium", 2),
                    (Finding.severity == "low", 3),
                    else_=4,
                ),
                Finding.created_at.desc(),
            )
            .limit(limit)
        )
        finding_result = await self.session.execute(finding_stmt)
        for f in finding_result.scalars():
            findings.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "status": f.status,
            })

        return {
            "query": query,
            "targets": targets,
            "scans": scans,
            "findings": findings,
        }

    async def _tool_list_targets(self, limit: int = 10) -> dict[str, Any]:
        """List registered deployment targets."""
        stmt = (
            select(Deployment)
            .where(Deployment.tenant_id == self.tenant_id)
            .order_by(Deployment.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        deployments = result.scalars().all()

        items = []
        for d in deployments:
            meta = {}
            if d.meta:
                try:
                    meta = json.loads(d.meta)
                except (json.JSONDecodeError, TypeError):
                    pass
            items.append({
                "id": d.id,
                "name": d.name,
                "type": meta.get("target_type", d.deployment_type),
                "path": d.source_path or d.source_url or "",
            })

        return {"targets": items, "total": len(items)}

    async def _tool_get_scan_status(self, scan_id: str) -> dict[str, Any]:
        """Get detailed scan status."""
        # Support prefix matching
        stmt = (
            select(Scan, Deployment.name.label("dep_name"))
            .outerjoin(Deployment, Scan.deployment_id == Deployment.id)
            .where(Scan.tenant_id == self.tenant_id)
            .where(Scan.id.startswith(scan_id))
            .limit(1)
        )
        result = await self.session.execute(stmt)
        row = result.first()
        if not row:
            return {"error": f"Scan not found: {scan_id}"}

        scan = row[0]
        dep_name = row[1] or scan.deployment_id

        data: dict[str, Any] = {
            "id": scan.id,
            "target": dep_name,
            "status": scan.status,
            "profile": scan.profile,
            "progress": scan.progress_percent,
            "current_phase": scan.current_phase,
            "total_findings": scan.total_findings,
            "critical": scan.critical_findings,
            "high": scan.high_findings,
            "medium": scan.medium_findings,
            "low": scan.low_findings,
            "duration_seconds": scan.duration_seconds,
        }
        if scan.verdict:
            try:
                verdict_data = json.loads(scan.verdict)
                data["verdict_risk_level"] = verdict_data.get("risk_level", "")
                data["verdict_summary"] = verdict_data.get("overall_assessment", "")[:300]
            except (json.JSONDecodeError, TypeError):
                pass

        return data

    async def _tool_list_findings(
        self,
        scan_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """List findings, optionally filtered by scan and/or severity."""
        full_scan_id = None

        # If scan_id provided, resolve by prefix
        if scan_id:
            scan_stmt = (
                select(Scan.id)
                .where(Scan.tenant_id == self.tenant_id)
                .where(Scan.id.startswith(scan_id))
                .limit(1)
            )
            scan_result = await self.session.execute(scan_stmt)
            full_scan_id = scan_result.scalar_one_or_none()
            if not full_scan_id:
                return {"error": f"Scan not found: {scan_id}"}

        # Build query — join with Scan for tenant filtering
        stmt = (
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.tenant_id == self.tenant_id)
            .order_by(
                case(
                    (Finding.severity == "critical", 0),
                    (Finding.severity == "high", 1),
                    (Finding.severity == "medium", 2),
                    (Finding.severity == "low", 3),
                    else_=4,
                ),
                Finding.created_at.desc(),
            )
            .limit(limit)
        )
        if full_scan_id:
            stmt = stmt.where(Finding.scan_id == full_scan_id)
        if severity:
            stmt = stmt.where(Finding.severity == severity.lower())
        if status:
            stmt = stmt.where(Finding.status == status.lower())

        result = await self.session.execute(stmt)
        items = []
        for f in result.scalars():
            location = f.file_path or ""
            if f.line_number and location:
                location += f":{f.line_number}"
            items.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "status": f.status,
                "scan_id": f.scan_id,
                "location": location,
            })

        resp: dict[str, Any] = {"findings": items, "total": len(items)}
        if full_scan_id:
            resp["scan_id"] = full_scan_id
        return resp

    async def _tool_get_finding_detail(
        self, finding_id: str
    ) -> dict[str, Any]:
        """Get full finding details."""
        stmt = (
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.tenant_id == self.tenant_id)
            .where(Finding.id == finding_id)
        )
        result = await self.session.execute(stmt)
        f = result.scalar_one_or_none()
        if not f:
            return {"error": f"Finding not found: {finding_id}"}

        location = f.file_path or ""
        if f.line_number and location:
            location += f":{f.line_number}"

        return {
            "id": f.id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "status": f.status,
            "category": f.category,
            "location": location,
            "code_snippet": f.code_snippet or "",
            "evidence": f.evidence or "",
            "remediation": f.remediation or "",
            "cwe_id": f.cwe_id or "",
            "owasp_category": f.owasp_category or "",
            "mitre_technique": f.mitre_technique or "",
        }

    async def _tool_start_scan(
        self,
        target_id: str,
        profile: str = "standard",
    ) -> dict[str, Any]:
        """Start a scan on a target."""
        # Verify target exists
        dep_stmt = (
            select(Deployment)
            .where(Deployment.tenant_id == self.tenant_id)
            .where(Deployment.id == target_id)
        )
        dep_result = await self.session.execute(dep_stmt)
        deployment = dep_result.scalar_one_or_none()
        if not deployment:
            return {"error": f"Target not found: {target_id}"}

        # Create scan
        from mass.core.types import ScanStatus as ScanStatusEnum

        scan = Scan(
            tenant_id=self.tenant_id,
            deployment_id=deployment.id,
            profile=profile,
            status=ScanStatusEnum.PENDING.value,
            total_findings=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
        )
        self.session.add(scan)
        await self.session.flush()

        scan_id = scan.id
        await self.session.commit()

        # Dispatch to background execution
        import asyncio

        try:
            from mass.api.services.scan_execution import ScanExecutionService

            svc = ScanExecutionService()
            asyncio.get_event_loop().create_task(svc.execute_scan(scan_id))
        except Exception as exc:
            logger.warning("Failed to dispatch scan %s: %s", scan_id, exc)

        return {
            "scan_id": scan_id,
            "target": deployment.name,
            "profile": profile,
            "status": "pending",
            "message": f"Scan started on {deployment.name} ({profile} profile)",
        }

    async def _tool_get_stats(self) -> dict[str, Any]:
        """Get dashboard statistics."""
        dep_count = (
            await self.session.execute(
                select(func.count()).select_from(Deployment)
                .where(Deployment.tenant_id == self.tenant_id)
            )
        ).scalar() or 0

        scan_count = (
            await self.session.execute(
                select(func.count()).select_from(Scan)
                .where(Scan.tenant_id == self.tenant_id)
            )
        ).scalar() or 0

        active_scans = (
            await self.session.execute(
                select(func.count()).select_from(Scan)
                .where(Scan.tenant_id == self.tenant_id)
                .where(Scan.status.in_(["running", "pending"]))
            )
        ).scalar() or 0

        total_findings = (
            await self.session.execute(
                select(func.count()).select_from(Finding)
                .join(Scan, Finding.scan_id == Scan.id)
                .where(Scan.tenant_id == self.tenant_id)
            )
        ).scalar() or 0

        # Severity breakdown
        sev_rows = (
            await self.session.execute(
                select(Finding.severity, func.count())
                .join(Scan, Finding.scan_id == Scan.id)
                .where(Scan.tenant_id == self.tenant_id)
                .group_by(Finding.severity)
            )
        ).all()
        severity = {row[0]: row[1] for row in sev_rows}

        # Status breakdown
        status_rows = (
            await self.session.execute(
                select(Finding.status, func.count())
                .join(Scan, Finding.scan_id == Scan.id)
                .where(Scan.tenant_id == self.tenant_id)
                .group_by(Finding.status)
            )
        ).all()
        finding_status = {row[0]: row[1] for row in status_rows}

        return {
            "targets": dep_count,
            "scans": scan_count,
            "active_scans": active_scans,
            "total_findings": total_findings,
            "severity": severity,
            "finding_status": finding_status,
        }

    # ------------------------------------------------------------------
    # lookup_model — HuggingFace model search + project cross-reference
    # ------------------------------------------------------------------

    async def _tool_lookup_model(self, model_name: str) -> dict[str, Any]:
        """Look up an AI/ML model on HuggingFace and cross-reference with project architecture."""
        import httpx
        from mass.api.services.ollama_manager import _normalize_for_matching

        raw_input = model_name.strip()
        normalized = _normalize_for_matching(raw_input)
        search_query = normalized.replace("-", " ")

        hf_model_data = None
        search_results: list[dict] = []

        async with httpx.AsyncClient(timeout=15.0) as client:
            # Direct fetch if input looks like a HuggingFace ID (owner/model)
            if "/" in raw_input:
                try:
                    resp = await client.get(
                        f"https://huggingface.co/api/models/{raw_input}"
                    )
                    if resp.status_code == 200:
                        hf_model_data = resp.json()
                except Exception:
                    pass

            if not hf_model_data:
                # Search HuggingFace
                try:
                    resp = await client.get(
                        "https://huggingface.co/api/models",
                        params={"search": search_query, "limit": 5},
                    )
                    if resp.status_code == 200:
                        search_results = resp.json()
                except Exception:
                    pass

                if search_results:
                    # Pick best match via normalized name comparison
                    best = None
                    best_score = -1.0
                    for sr in search_results:
                        sr_norm = _normalize_for_matching(sr.get("id", ""))
                        if sr_norm == normalized:
                            best = sr
                            break
                        if normalized in sr_norm or sr_norm in normalized:
                            score = len(normalized) / max(len(sr_norm), 1)
                            if score > best_score:
                                best = sr
                                best_score = score
                    if not best:
                        best = search_results[0]

                    # Fetch full details for best match
                    try:
                        resp = await client.get(
                            f"https://huggingface.co/api/models/{best['id']}"
                        )
                        if resp.status_code == 200:
                            hf_model_data = resp.json()
                    except Exception:
                        hf_model_data = best  # Use lighter search data as fallback

        if not hf_model_data:
            return {
                "model_name": raw_input,
                "found": False,
                "message": f"No model matching '{raw_input}' found on HuggingFace.",
                "suggestions": [sr.get("id") for sr in search_results[:3]],
            }

        # Extract concise summary
        model_id = hf_model_data.get("id", "")
        author = hf_model_data.get("author") or (
            model_id.split("/")[0] if "/" in model_id else ""
        )

        # Parameter count from safetensors metadata
        param_count = None
        safetensors = hf_model_data.get("safetensors") or {}
        if safetensors:
            params = safetensors.get("parameters") or {}
            total = safetensors.get("total") or (
                max(params.values(), default=0) if params else 0
            )
            if total:
                if total >= 1_000_000_000:
                    param_count = f"{total / 1_000_000_000:.1f}B"
                elif total >= 1_000_000:
                    param_count = f"{total / 1_000_000:.0f}M"
                else:
                    param_count = str(total)

        # Architecture info
        config = hf_model_data.get("config") or {}
        architectures = config.get("architectures") or []

        # Filter tags to interesting ones
        tags = hf_model_data.get("tags") or []
        noise_tags = {
            "transformers", "safetensors", "pytorch", "onnx", "gguf",
            "text-generation-inference", "endpoints_compatible",
        }
        interesting_tags = [
            t for t in tags
            if t not in noise_tags
            and not t.startswith("arxiv:")
            and not t.startswith("base_model:")
            and not t.startswith("license:")
        ][:10]

        summary: dict[str, Any] = {
            "model_id": model_id,
            "found": True,
            "author": author,
            "pipeline_tag": hf_model_data.get("pipeline_tag", ""),
            "architectures": architectures,
            "parameter_count": param_count,
            "library": hf_model_data.get("library_name", ""),
            "tags": interesting_tags,
            "downloads": hf_model_data.get("downloads", 0),
            "likes": hf_model_data.get("likes", 0),
            "last_modified": hf_model_data.get("lastModified", ""),
            "url": f"https://huggingface.co/{model_id}",
        }

        # Cross-reference with project architecture maps
        project_usage: list[dict] = []
        try:
            dep_result = await self.session.execute(
                select(Deployment).where(
                    Deployment.tenant_id == self.tenant_id
                )
            )
            model_norm = _normalize_for_matching(
                model_id.split("/")[-1] if "/" in model_id else model_id
            )
            for dep in dep_result.scalars():
                if not dep.meta:
                    continue
                try:
                    meta = json.loads(dep.meta)
                except (json.JSONDecodeError, TypeError):
                    continue
                arch_map = meta.get("architecture_map") or {}
                for mc in arch_map.get("model_connections") or []:
                    mc_name = mc.get("model_name") or ""
                    mc_norm = _normalize_for_matching(mc_name)
                    if (
                        mc_norm == model_norm
                        or mc_norm in model_norm
                        or model_norm in mc_norm
                    ):
                        project_usage.append({
                            "deployment": dep.name,
                            "provider": mc.get("provider", ""),
                            "model_name_in_code": mc_name,
                            "call_location": mc.get("call_location", ""),
                            "has_tools": mc.get("has_tools", False),
                        })
        except Exception as exc:
            logger.warning("Model cross-reference failed: %s", exc)

        if project_usage:
            summary["project_usage"] = project_usage

        # Include alternative matches from search
        if search_results and len(search_results) > 1:
            alternatives = [
                sr.get("id") for sr in search_results
                if sr.get("id") != model_id
            ][:3]
            if alternatives:
                summary["similar_models"] = alternatives

        return summary

    async def _tool_read_file(
        self, filename: str, target_name: str | None = None
    ) -> dict[str, Any]:
        """Find and read a file from scanned project directories."""
        import os
        from mass.core.filesystem import walk_with_exclusions

        ALLOWED_ROOTS = [
            "/app/targets",
            "/app/github_clones",
            "/app/data",
        ]
        MAX_LINES = 200
        MAX_BYTES = 15_000

        # Collect source directories from deployments
        dep_stmt = (
            select(Deployment)
            .where(Deployment.tenant_id == self.tenant_id)
        )
        if target_name:
            dep_stmt = dep_stmt.where(
                func.lower(Deployment.name).contains(target_name.lower())
            )
        dep_result = await self.session.execute(dep_stmt)

        search_dirs: list[tuple[str, str]] = []  # (dir_path, deployment_name)
        for dep in dep_result.scalars():
            path = dep.source_path or ""
            if not path:
                continue
            abs_path = os.path.abspath(path)
            if any(abs_path.startswith(root) for root in ALLOWED_ROOTS):
                search_dirs.append((abs_path, dep.name))

        if not search_dirs:
            return {
                "found": False,
                "error": "No scanned target directories found"
                + (f" matching '{target_name}'" if target_name else ""),
            }

        # Search for matching files
        filename_lower = filename.lower().replace("\\", "/")
        matches: list[dict[str, str]] = []

        for dir_path, dep_name in search_dirs:
            if not os.path.isdir(dir_path):
                continue
            try:
                all_files = walk_with_exclusions(dir_path, max_files=5000)
            except Exception:
                continue

            for rel_path in all_files:
                rel_lower = rel_path.lower()
                # Match by exact filename or path suffix
                if (
                    rel_lower == filename_lower
                    or rel_lower.endswith("/" + filename_lower)
                    or os.path.basename(rel_lower) == os.path.basename(filename_lower)
                ):
                    full_path = os.path.join(dir_path, rel_path)
                    matches.append({
                        "path": rel_path,
                        "full_path": full_path,
                        "target": dep_name,
                    })

        if not matches:
            return {
                "found": False,
                "error": f"File '{filename}' not found in scanned targets",
                "searched_targets": [name for _, name in search_dirs],
            }

        # Read the best match (first match; prefer exact name matches)
        exact = [
            m for m in matches
            if os.path.basename(m["path"]).lower() == os.path.basename(filename_lower)
        ]
        best = exact[0] if exact else matches[0]

        # Check file size
        try:
            file_size = os.path.getsize(best["full_path"])
        except OSError:
            return {"found": False, "error": f"Cannot access file: {best['path']}"}

        if file_size > 5 * 1024 * 1024:
            return {
                "found": True,
                "path": best["path"],
                "target": best["target"],
                "size": file_size,
                "error": "File too large to read (>5MB)",
            }

        # Read file content
        try:
            with open(best["full_path"], "r", errors="replace") as f:
                lines = []
                total_bytes = 0
                for i, line in enumerate(f):
                    if i >= MAX_LINES:
                        lines.append(f"\n... truncated at {MAX_LINES} lines ...")
                        break
                    total_bytes += len(line)
                    if total_bytes > MAX_BYTES:
                        lines.append(f"\n... truncated at ~{MAX_BYTES // 1000}KB ...")
                        break
                    lines.append(line.rstrip("\n\r"))
                content = "\n".join(lines)
        except Exception as exc:
            return {
                "found": True,
                "path": best["path"],
                "target": best["target"],
                "error": f"Error reading file: {exc}",
            }

        result: dict[str, Any] = {
            "found": True,
            "path": best["path"],
            "target": best["target"],
            "size": file_size,
            "content": content,
        }

        # Note other matches if there are multiple
        if len(matches) > 1:
            result["other_matches"] = [
                {"path": m["path"], "target": m["target"]}
                for m in matches[1:5]
            ]

        return result

    # ------------------------------------------------------------------
    # Sandbox tools
    # ------------------------------------------------------------------

    async def _tool_list_sandbox_jobs(self, limit: int = 20) -> dict[str, Any]:
        """List sandbox security test runs."""
        try:
            from mass.api.routes.sandbox import _list_from_redis

            jobs = await _list_from_redis()
            items = []
            for j in jobs[:limit]:
                items.append({
                    "job_id": j.get("job_id", ""),
                    "scenario_name": j.get("scenario_name", ""),
                    "status": j.get("status", ""),
                    "score": j.get("score"),
                    "model_used": j.get("model_used", ""),
                    "findings_count": j.get("findings_count", 0),
                    "passed_assertions": j.get("passed_assertions", 0),
                    "failed_assertions": j.get("failed_assertions", 0),
                    "duration_seconds": j.get("duration_seconds", 0),
                    "turns": f"{j.get('turns_completed', 0)}/{j.get('turns_total', 0)}",
                    "created_at": j.get("created_at", ""),
                })
            return {"jobs": items, "total": len(items)}
        except Exception as exc:
            logger.warning("list_sandbox_jobs failed: %s", exc)
            return {"error": str(exc), "jobs": []}

    async def _tool_get_sandbox_results(self, job_id: str) -> dict[str, Any]:
        """Get full results of a sandbox security test."""
        try:
            from mass.api.routes.sandbox import _load_from_redis

            data = await _load_from_redis(job_id)
            if not data:
                return {"error": f"Sandbox job '{job_id}' not found"}

            # Build concise summary
            result: dict[str, Any] = {
                "job_id": data.get("job_id", ""),
                "scenario_name": data.get("scenario_name", ""),
                "status": data.get("status", ""),
                "score": data.get("score"),
                "model_used": data.get("model_used", ""),
                "duration_seconds": data.get("duration_seconds", 0),
                "passed_assertions": data.get("passed_assertions", 0),
                "failed_assertions": data.get("failed_assertions", 0),
            }

            # Steps summary (concise)
            steps = data.get("steps", [])
            result["steps"] = [
                {
                    "turn": s.get("turn_number", i),
                    "user_input": (s.get("user_input", ""))[:100],
                    "response_preview": (s.get("model_response", ""))[:150],
                    "tool_calls": [tc.get("name", "") for tc in s.get("tool_calls", [])],
                    "pass": len(s.get("assertions_failed", [])) == 0,
                    "assertions_failed": s.get("assertions_failed", []),
                }
                for i, s in enumerate(steps)
            ]

            # Findings
            findings = data.get("findings", [])
            result["findings"] = [
                {
                    "title": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "category": f.get("category", ""),
                    "description": (f.get("description", ""))[:200],
                }
                for f in findings
            ]
            result["findings_count"] = len(findings)

            # Guardrail recommendations (concise)
            guardrails = data.get("guardrail_recommendations", [])
            result["guardrail_recommendations"] = [
                {
                    "type": g.get("guardrail_type", ""),
                    "recommendation": g.get("recommendation", ""),
                    "triggered_by": g.get("triggered_by", ""),
                }
                for g in guardrails[:6]
            ]

            return result
        except Exception as exc:
            logger.warning("get_sandbox_results failed: %s", exc)
            return {"error": str(exc)}

    async def _tool_list_sandbox_scenarios(self) -> dict[str, Any]:
        """List available sandbox security test scenarios."""
        try:
            from mass.sandbox.scenario import list_builtin_scenarios

            scenarios = list_builtin_scenarios()
            items = [
                {
                    "name": s["name"],
                    "category": s.get("category", "general"),
                    "description": s.get("description", ""),
                    "tags": s.get("tags", []),
                    "turns_count": s.get("turns_count", 0),
                    "source": "builtin",
                }
                for s in scenarios
            ]

            # Also check custom scenarios
            from mass.api.routes.sandbox import _custom_scenarios_dir
            import yaml

            custom_dir = _custom_scenarios_dir()
            for yaml_file in sorted(custom_dir.glob("*.yaml")):
                try:
                    with open(yaml_file, encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    items.append({
                        "name": data.get("name", yaml_file.stem),
                        "category": data.get("category", "general"),
                        "description": data.get("description", ""),
                        "tags": data.get("tags", []),
                        "turns_count": len(data.get("turns", [])),
                        "source": "custom",
                    })
                except Exception:
                    continue

            return {"scenarios": items, "total": len(items)}
        except Exception as exc:
            logger.warning("list_sandbox_scenarios failed: %s", exc)
            return {"error": str(exc), "scenarios": []}

    async def _tool_start_sandbox_run(
        self,
        scenario_name: str,
        model_provider: str = "openai",
        model_name: str = "gpt-4o",
        deployment_id: str | None = None,
    ) -> dict[str, Any]:
        """Start a sandbox security test."""
        try:
            import asyncio
            from uuid import uuid4
            from datetime import datetime

            from mass.sandbox.scenario import Scenario, load_builtin_scenario
            from mass.api.routes.sandbox import (
                _save_to_redis,
                _execute_sandbox,
                _custom_scenarios_dir,
            )

            # Resolve scenario
            scenario = load_builtin_scenario(scenario_name)
            if not scenario:
                custom_file = _custom_scenarios_dir() / f"{scenario_name}.yaml"
                if custom_file.exists():
                    scenario = Scenario.from_yaml(custom_file)

            if not scenario:
                return {"error": f"Scenario '{scenario_name}' not found"}

            # Apply overrides
            scenario.model_provider = model_provider
            scenario.model_name = model_name

            job_id = str(uuid4())
            now = datetime.utcnow().isoformat()
            model_label = f"{model_provider}/{model_name}"

            await _save_to_redis(job_id, {
                "job_id": job_id,
                "status": "pending",
                "scenario_name": scenario.name,
                "scenario_dict": scenario.to_dict(),
                "model_used": model_label,
                "provider_used": model_provider,
                "deployment_id": deployment_id,
                "tenant_id": self.tenant_id,
                "use_judge": False,
                "turns_total": len(scenario.turns),
                "created_at": now,
            })

            # Dispatch background execution
            asyncio.get_event_loop().create_task(_execute_sandbox(job_id, scenario))

            return {
                "job_id": job_id,
                "scenario_name": scenario.name,
                "model": model_label,
                "turns_total": len(scenario.turns),
                "status": "pending",
                "message": f"Sandbox run started: {scenario.name} with {model_label}",
            }
        except Exception as exc:
            logger.warning("start_sandbox_run failed: %s", exc)
            return {"error": str(exc)}
