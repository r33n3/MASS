"""Tool executor for chat tool calling.

Defines available tools and executes them against MASS repositories.
Tools run in-process using the same DB session and tenant context
as the chat endpoint.
"""

import json
import logging
from typing import Any

from sqlalchemy import func, select
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
            "Returns matching items grouped by type."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query string",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results per category (default 5)",
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
            "List security findings for a scan, optionally "
            "filtered by severity."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "string",
                    "description": "The scan ID to list findings for",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Filter by severity level",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max findings to return (default 20)",
                },
            },
            "required": ["scan_id"],
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
        self, query: str, limit: int = 5
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

        # Search findings by title or category
        finding_stmt = (
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.tenant_id == self.tenant_id)
            .where(
                func.lower(Finding.title).contains(q)
                | func.lower(Finding.category).contains(q)
            )
            .order_by(Finding.created_at.desc())
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
        scan_id: str,
        severity: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """List findings for a scan."""
        # Find scan by prefix
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

        stmt = (
            select(Finding)
            .where(Finding.scan_id == full_scan_id)
            .order_by(
                func.case(
                    (Finding.severity == "critical", 0),
                    (Finding.severity == "high", 1),
                    (Finding.severity == "medium", 2),
                    (Finding.severity == "low", 3),
                    else_=4,
                )
            )
            .limit(limit)
        )
        if severity:
            stmt = stmt.where(Finding.severity == severity.lower())

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
                "location": location,
            })

        return {"scan_id": full_scan_id, "findings": items, "total": len(items)}

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
