"""API routes for containerized MCP server package auditing.

Spin up MCP server packages (npm/pip) in sandboxed Docker containers,
run the full MCPInterrogator pipeline against them, then tear down.
This is the CI/CD security scanner mode for MCP servers.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from pydantic import BaseModel, Field

from mass.api.dependencies import CurrentTenantDep
from mass.api.utils.job_store import JobStore

logger = logging.getLogger(__name__)

router = APIRouter()

# Redis-backed job storage (per ARCHITECTURE.md Rule 1)
_store = JobStore("audit")


# ── Schemas ────────────────────────────────────────────────────────────


class MCPAuditRequest(BaseModel):
    """Request to start a containerized MCP package audit."""
    name: str = Field(description="Display name for this audit")
    package: str = Field(description="Package spec (e.g. '@coingecko/mcp-server', 'mcp-server-fetch')")
    runtime: str = Field(
        default="npx",
        description="Runtime: npx, npm, pip, uvx, or command",
    )
    command: str | None = Field(
        default=None,
        description="Custom command override (for runtime='command')",
    )
    args: list[str] = Field(
        default_factory=list,
        description="Additional arguments for the server",
    )
    env: dict[str, str] = Field(
        default_factory=dict,
        description="Environment variables for the MCP server",
    )
    timeout: int = Field(
        default=600,
        ge=60,
        le=3600,
        description="Max seconds before auto-kill (default 600)",
    )
    # Test configuration
    attack_categories: list[str] = Field(
        default_factory=list,
        description="Attack categories to test (empty = all)",
    )
    max_payloads_per_category: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Max payloads per attack category",
    )
    run_baseline: bool = Field(
        default=True,
        description="Run benign baseline calls first",
    )
    run_sandbox_scenarios: bool = Field(
        default=False,
        description="Also run proposal-based sandbox scenario testing",
    )
    use_ollama: bool = Field(
        default=False,
        description="Use Ollama to craft realistic attack prompts",
    )
    allow_network: bool = Field(
        default=True,
        description="Allow the container internet access (needed for some packages to download deps)",
    )


class MCPAuditToolInfo(BaseModel):
    """Discovered tool info."""
    name: str
    description: str
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    inferred_risks: list[str] = Field(default_factory=list)


class MCPAuditFinding(BaseModel):
    """Security finding from audit."""
    id: str
    tool_name: str
    parameter_name: str
    attack_category: str
    severity: str
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str = ""


class MCPAuditTestResult(BaseModel):
    """Single test result for transcript."""
    tool_name: str
    parameter_name: str
    attack_category: str
    severity: str
    payload_description: str
    arguments_sent: dict[str, Any] = Field(default_factory=dict)
    success: bool = True
    passed: bool = True
    response: Any = None
    error: str | None = None
    duration_ms: float = 0.0
    findings: list[str] = Field(default_factory=list)


class MCPAuditResponse(BaseModel):
    """Audit job status and results."""
    audit_id: str
    name: str
    package: str
    runtime: str
    status: str  # pending | starting | interrogating | scenarios | completed | failed
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None

    # Progress
    phase: str = ""
    phase_detail: str = ""
    tools_discovered: int = 0
    total_tests: int = 0
    tests_completed: int = 0
    tests_passed: int = 0
    tests_failed: int = 0

    # Results
    tools: list[MCPAuditToolInfo] = Field(default_factory=list)
    findings: list[MCPAuditFinding] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    test_results: list[MCPAuditTestResult] = Field(default_factory=list)

    # Sandbox results (if run_sandbox_scenarios was True)
    sandbox_job_ids: list[str] = Field(default_factory=list)
    proposals_count: int = 0

    # Debug
    container_logs: str | None = None
    error: str | None = None


# ── Endpoints ──────────────────────────────────────────────────────────


@router.post(
    "",
    response_model=MCPAuditResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start containerized MCP package audit",
    description=(
        "Spins up an MCP server package in a sandboxed Docker container, "
        "runs the full security interrogation pipeline, then tears down. "
        "Supports npm (npx) and pip packages."
    ),
)
async def start_mcp_audit(
    request: MCPAuditRequest,
    background_tasks: BackgroundTasks,
    tenant: CurrentTenantDep,
) -> MCPAuditResponse:
    """Start an MCP package audit."""
    from mass.mcp.container import docker_available

    # Validate Docker is available
    if not docker_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Docker is not available. Containerized MCP auditing requires "
                "the Docker socket to be mounted at /var/run/docker.sock."
            ),
        )

    # Validate runtime
    valid_runtimes = {"npx", "npm", "pip", "uvx", "command"}
    if request.runtime not in valid_runtimes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid runtime: {request.runtime}. Must be one of: {', '.join(valid_runtimes)}",
        )

    if request.runtime == "command" and not request.command:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Custom 'command' is required when runtime='command'",
        )

    # Create job
    audit_id = str(uuid4())
    now = datetime.utcnow().isoformat()

    job: dict[str, Any] = {
        "id": audit_id,
        "name": request.name,
        "package": request.package,
        "runtime": request.runtime,
        "tenant_id": tenant.tenant_id,
        "status": "pending",
        "phase": "",
        "phase_detail": "",
        "created_at": now,
        "started_at": None,
        "completed_at": None,
        "config": request.model_dump(),
        "result": None,
        "container_logs": None,
        "error": None,
        # Tracking
        "tools_discovered": 0,
        "total_tests": 0,
        "tests_completed": 0,
        "tests_passed": 0,
        "tests_failed": 0,
        "tools": [],
        "findings": [],
        "severity_counts": {},
        "test_results": [],
        "sandbox_job_ids": [],
        "proposals_count": 0,
    }
    await _store.save(audit_id, job)

    # Start background task
    background_tasks.add_task(_run_audit, audit_id)

    return _format_audit_response(job)


@router.get(
    "/jobs",
    response_model=list[MCPAuditResponse],
    summary="List MCP audit jobs",
)
async def list_audit_jobs(
    tenant: CurrentTenantDep,
    limit: int = 50,
) -> list[MCPAuditResponse]:
    """List all audit jobs for the tenant."""
    jobs = await _store.list_jobs(tenant_id=tenant.tenant_id, limit=limit)
    return [_format_audit_response(j) for j in jobs]


@router.get(
    "/jobs/{audit_id}",
    response_model=MCPAuditResponse,
    summary="Get MCP audit job details",
)
async def get_audit_job(
    audit_id: str,
    tenant: CurrentTenantDep,
) -> MCPAuditResponse:
    """Get details and results of an MCP audit job."""
    job = await _store.load(audit_id)
    if not job or job.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit job not found: {audit_id}",
        )
    return _format_audit_response(job)


@router.delete(
    "/jobs/{audit_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancel and cleanup MCP audit",
)
async def cancel_audit_job(
    audit_id: str,
    tenant: CurrentTenantDep,
) -> None:
    """Cancel a running audit and clean up its container."""
    job = await _store.load(audit_id)
    if not job or job.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit job not found: {audit_id}",
        )

    if job["status"] in ("completed", "failed"):
        return  # Already done

    job["status"] = "failed"
    job["error"] = "Cancelled by user"
    job["completed_at"] = datetime.utcnow().isoformat()
    await _store.save(audit_id, job)


@router.get(
    "/docker-status",
    summary="Check Docker availability for auditing",
)
async def check_docker_status(tenant: CurrentTenantDep) -> dict:
    """Check if Docker is available for containerized auditing."""
    from mass.mcp.container import docker_available
    available = docker_available()
    return {
        "docker_available": available,
        "message": (
            "Docker is ready for containerized MCP auditing."
            if available
            else "Docker socket not available. Mount /var/run/docker.sock to enable auditing."
        ),
    }


# ── Background task ───────────────────────────────────────────────────


_AUDIT_TIMEOUT = 600  # default, overridden by request


async def _run_audit(audit_id: str) -> None:
    """Run the full audit pipeline in the background."""
    from mass.mcp.container import MCPAuditContainer
    from mass.mcp.interrogator import (
        InterrogationConfig,
        MCPInterrogator,
    )
    from mass.mcp.client import MCPTransport
    from mass.mcp.tool_tester import AttackCategory

    job = await _store.load(audit_id)
    if not job:
        return

    config = job["config"]
    container: MCPAuditContainer | None = None

    try:
        job["status"] = "starting"
        job["phase"] = "container_setup"
        job["phase_detail"] = "Creating container..."
        job["started_at"] = datetime.utcnow().isoformat()
        await _store.save(audit_id, job)
        await _broadcast_audit_update(audit_id, job)

        # ── Phase 1: Start container ───────────────────────────────
        container = MCPAuditContainer(
            package=config["package"],
            runtime=config["runtime"],
            env=config.get("env", {}),
            timeout=config.get("timeout", 600),
            command=config.get("command"),
            args=config.get("args", []),
            allow_network=config.get("allow_network", True),
        )
        job["phase_detail"] = "Installing package and starting MCP server..."
        await _broadcast_audit_update(audit_id, job)

        base_url = await asyncio.wait_for(
            container.start(),
            timeout=min(config.get("timeout", 600), 300),  # max 5 min for startup
        )

        job["phase"] = "interrogation"
        job["phase_detail"] = "Connecting to MCP server..."
        job["status"] = "interrogating"
        await _broadcast_audit_update(audit_id, job)

        # ── Phase 2: Run interrogation ─────────────────────────────
        # Parse attack categories
        categories: list[AttackCategory] = []
        for cat_str in config.get("attack_categories", []):
            try:
                categories.append(AttackCategory(cat_str))
            except ValueError:
                pass
        if not categories:
            categories = list(AttackCategory)

        interrogation_config = InterrogationConfig(
            transport=MCPTransport.HTTP,
            url=base_url,
            timeout=30.0,
            attack_categories=categories,
            max_payloads_per_category=config.get("max_payloads_per_category", 5),
            run_benign_baseline=config.get("run_baseline", True),
            use_ollama=config.get("use_ollama", False),
        )

        interrogator = MCPInterrogator(interrogation_config)

        job["phase_detail"] = "Enumerating tools and running security tests..."
        await _broadcast_audit_update(audit_id, job)

        result = await asyncio.wait_for(
            interrogator.run(),
            timeout=config.get("timeout", 600),
        )

        # Serialize results into job dict for Redis storage
        _populate_job_from_result(job, result)

        job["phase_detail"] = f"Interrogation complete: {len(result.findings)} findings"
        await _broadcast_audit_update(audit_id, job)

        # ── Phase 3 (optional): Sandbox scenarios ──────────────────
        if config.get("run_sandbox_scenarios") and result.tools_discovered:
            job["phase"] = "scenarios"
            job["status"] = "scenarios"
            job["phase_detail"] = "Generating and running sandbox scenarios..."
            await _broadcast_audit_update(audit_id, job)

            try:
                sandbox_ids, proposal_count = await _run_sandbox_phase(
                    base_url, result, job, audit_id,
                )
                job["sandbox_job_ids"] = sandbox_ids
                job["proposals_count"] = proposal_count
            except Exception as e:
                logger.warning("Sandbox phase failed for audit %s: %s", audit_id, e)
                job["phase_detail"] = f"Sandbox phase failed: {e}"

        # ── Phase 4: Cleanup ───────────────────────────────────────
        job["phase"] = "cleanup"
        job["phase_detail"] = "Tearing down container..."
        await _broadcast_audit_update(audit_id, job)

        # Get logs before stopping
        job["container_logs"] = await container.get_logs(tail=100)
        await container.stop()
        job["_container"] = None

        job["status"] = "completed"
        job["phase"] = "done"
        job["phase_detail"] = "Audit complete"
        job["completed_at"] = datetime.utcnow().isoformat()

    except asyncio.TimeoutError:
        logger.warning("Audit %s timed out", audit_id)
        job["status"] = "failed"
        job["error"] = f"Audit timed out after {config.get('timeout', 600)}s"
        job["completed_at"] = datetime.utcnow().isoformat()
        if container:
            job["container_logs"] = await container.get_logs(tail=100)

    except Exception as e:
        logger.exception("Audit %s failed: %s", audit_id, e)
        job["status"] = "failed"
        job["error"] = str(e)
        job["completed_at"] = datetime.utcnow().isoformat()
        if container:
            try:
                job["container_logs"] = await container.get_logs(tail=100)
            except Exception:
                pass

    finally:
        # Always clean up the container
        if container:
            try:
                await container.stop()
            except Exception as e:
                logger.warning("Cleanup failed for audit %s: %s", audit_id, e)
            pass  # container cleaned up

        await _broadcast_audit_update(audit_id, job)


async def _run_sandbox_phase(
    base_url: str,
    interrogation_result: Any,
    job: dict[str, Any],
    audit_id: str,
) -> tuple[list[str], int]:
    """Run sandbox scenario testing against the live container.

    Returns (list of sandbox job IDs, number of proposals).
    """
    from mass.sandbox.surface import discover_surface
    from mass.sandbox.profiles import PROFILES
    from mass.sandbox.proposer import ScenarioProposer

    # Discover surface from the live MCP server
    surface = await discover_surface(
        "mcp_server",
        mcp_url=base_url,
        mcp_transport="http",
    )

    if not surface.tools and not surface.models:
        return [], 0

    # Generate proposals
    proposer = ScenarioProposer(PROFILES.get("standard"))
    report = proposer.propose(surface, target_type="mcp_server")

    if not report.proposals:
        return [], 0

    # Auto-approve critical and high priority proposals
    for proposal in report.proposals:
        if proposal.priority in ("critical", "high"):
            proposal.approved = True

    approved_count = sum(1 for p in report.proposals if p.approved)
    if approved_count == 0:
        # Approve all if none are critical/high
        for proposal in report.proposals:
            proposal.approved = True

    # Generate scenarios from approved proposals
    scenarios = proposer.execute_approved(report)
    if not scenarios:
        return [], len(report.proposals)

    # Apply MCP config to each scenario for live execution
    for scenario in scenarios:
        scenario.tool_mode = "live"
        scenario.mcp_transport = "http"
        scenario.mcp_url = base_url

    # Create sandbox jobs (reuse sandbox route pattern)
    from mass.api.routes.sandbox import _execute_sandbox, _sandbox_store

    sandbox_ids: list[str] = []
    for scenario in scenarios[:10]:  # Cap at 10 scenarios
        job_id = str(uuid4())
        now = datetime.utcnow().isoformat()

        await _sandbox_store.save(job_id, {
            "job_id": job_id,
            "status": "pending",
            "scenario_name": scenario.name,
            "scenario_dict": scenario.to_dict() if hasattr(scenario, "to_dict") else {},
            "model_used": f"{scenario.model_provider}/{scenario.model_name}",
            "provider_used": scenario.model_provider,
            "turns_total": len(scenario.turns),
            "tenant_id": job.get("tenant_id"),
            "use_judge": False,
            "created_at": now,
            "audit_id": audit_id,
        })

        asyncio.create_task(_execute_sandbox(job_id))
        sandbox_ids.append(job_id)

    return sandbox_ids, len(report.proposals)


def _populate_job_from_result(job: dict[str, Any], result: Any) -> None:
    """Extract formatted data from InterrogationResult into job dict."""
    # Tools
    tools: list[dict] = []
    for tool in getattr(result, "tools_discovered", []):
        inferred_risks = []
        for param in tool.parameters:
            if param.is_command:
                inferred_risks.append("Command Injection")
            if param.is_path:
                inferred_risks.append("Path Traversal")
            if param.is_url:
                inferred_risks.append("SSRF")
            if param.is_query:
                inferred_risks.append("SQL Injection")
        tools.append({
            "name": tool.name,
            "description": tool.description,
            "parameters": [
                {"name": p.name, "type": p.type, "description": p.description, "required": p.required}
                for p in tool.parameters
            ],
            "inferred_risks": list(set(inferred_risks)),
        })
    job["tools"] = tools
    job["tools_discovered"] = len(tools)

    # Findings
    findings: list[dict] = []
    for finding in getattr(result, "findings", []):
        findings.append({
            "id": finding.id,
            "tool_name": finding.tool_name,
            "parameter_name": finding.parameter_name,
            "attack_category": finding.attack_category,
            "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            "title": finding.title,
            "description": finding.description,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
        })
    job["findings"] = findings

    # Severity counts
    job["severity_counts"] = getattr(result, "severity_counts", {})

    # Test counts
    job["total_tests"] = getattr(result, "total_tests", 0)
    job["tests_passed"] = getattr(result, "tests_passed", 0)
    job["tests_failed"] = getattr(result, "tests_failed", 0)
    job["tests_completed"] = job["tests_passed"] + job["tests_failed"]

    # Test results (transcript)
    test_results: list[dict] = []
    for tr in getattr(result, "test_results", []):
        tc = tr.test_case
        tcr = tr.tool_result
        cat_val = tc.attack_category.value if hasattr(tc.attack_category, "value") else str(tc.attack_category)
        sev_val = tc.severity.value if hasattr(tc.severity, "value") else str(tc.severity)
        resp = tcr.result
        if isinstance(resp, str) and len(resp) > 500:
            resp = resp[:500] + "..."
        test_results.append({
            "tool_name": tc.tool_name,
            "parameter_name": tc.parameter_name,
            "attack_category": cat_val,
            "severity": sev_val,
            "payload_description": tc.description,
            "arguments_sent": tcr.arguments,
            "success": tcr.success,
            "passed": tr.passed,
            "response": resp,
            "error": tcr.error,
            "duration_ms": tcr.duration_ms,
            "findings": tr.findings,
        })
    job["test_results"] = test_results


def _format_audit_response(job: dict[str, Any]) -> MCPAuditResponse:
    """Format job dict as MCPAuditResponse."""
    return MCPAuditResponse(
        audit_id=job["id"],
        name=job["name"],
        package=job["package"],
        runtime=job["runtime"],
        status=job["status"],
        created_at=job["created_at"],
        started_at=job.get("started_at"),
        completed_at=job.get("completed_at"),
        phase=job.get("phase", ""),
        phase_detail=job.get("phase_detail", ""),
        tools_discovered=job.get("tools_discovered", 0),
        total_tests=job.get("total_tests", 0),
        tests_completed=job.get("tests_completed", 0),
        tests_passed=job.get("tests_passed", 0),
        tests_failed=job.get("tests_failed", 0),
        tools=[MCPAuditToolInfo(**t) for t in job.get("tools", [])],
        findings=[MCPAuditFinding(**f) for f in job.get("findings", [])],
        severity_counts=job.get("severity_counts", {}),
        test_results=[MCPAuditTestResult(**t) for t in job.get("test_results", [])],
        sandbox_job_ids=job.get("sandbox_job_ids", []),
        proposals_count=job.get("proposals_count", 0),
        container_logs=job.get("container_logs"),
        error=job.get("error"),
    )


# ── WebSocket broadcast ───────────────────────────────────────────────


async def _broadcast_audit_update(audit_id: str, job: dict[str, Any] | None = None) -> None:
    """Save job to Redis and broadcast status via WebSocket."""
    if job is None:
        job = await _store.load(audit_id)
    if not job:
        return
    # Always persist to Redis on broadcast
    await _store.save(audit_id, job)
    try:
        from mass.dashboard.websocket import manager

        await manager.broadcast({
            "type": "mcp_audit_update",
            "audit_id": audit_id,
            "status": job["status"],
            "phase": job.get("phase", ""),
            "phase_detail": job.get("phase_detail", ""),
            "tools_discovered": job.get("tools_discovered", 0),
            "total_tests": job.get("total_tests", 0),
            "tests_completed": job.get("tests_completed", 0),
            "findings_count": len(job.get("findings", [])),
            "error": job.get("error"),
        })
    except Exception:
        logger.debug("Failed to broadcast audit update", exc_info=True)
