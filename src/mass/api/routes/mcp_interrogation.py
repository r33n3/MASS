"""MCP interrogation API endpoints.

Provides endpoints for security testing of remote MCP servers:
- Start interrogation jobs
- Monitor job progress
- Retrieve findings
"""

import asyncio
import logging
from datetime import datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from pydantic import BaseModel, Field

from mass.api.dependencies import CurrentTenantDep
from mass.mcp import (
    MCPTransport,
    InterrogationConfig,
    InterrogationStatus,
    AttackCategory,
    interrogate_mcp_server,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# In-memory job storage (would use database in production)
_jobs: dict[str, dict[str, Any]] = {}


class MCPConnectionConfig(BaseModel):
    """MCP server connection configuration."""
    transport: str = Field(
        default="stdio",
        description="Transport type: stdio, http, or sse"
    )

    # For stdio transport
    command: str | None = Field(
        default=None,
        description="Command to start MCP server (for stdio transport)"
    )
    args: list[str] = Field(
        default_factory=list,
        description="Command arguments"
    )
    env: dict[str, str] = Field(
        default_factory=dict,
        description="Environment variables"
    )
    cwd: str | None = Field(
        default=None,
        description="Working directory"
    )

    # For HTTP/SSE transport
    url: str | None = Field(
        default=None,
        description="Server URL (for http/sse transport)"
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="HTTP headers"
    )

    timeout: float = Field(
        default=30.0,
        description="Connection timeout in seconds"
    )


class MCPInterrogationRequest(BaseModel):
    """Request to start MCP interrogation."""
    name: str = Field(
        description="Name for this interrogation job"
    )
    connection: MCPConnectionConfig = Field(
        description="MCP server connection configuration"
    )

    # Attack categories to test
    attack_categories: list[str] = Field(
        default_factory=lambda: [c.value for c in AttackCategory],
        description="Attack categories to test (command_injection, path_traversal, ssrf, sql_injection, prompt_injection, template_injection)"
    )
    max_payloads_per_category: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum payloads per attack category"
    )

    # Baseline settings
    run_baseline: bool = Field(
        default=True,
        description="Run benign calls to establish baseline"
    )
    baseline_samples: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Number of baseline samples per tool"
    )

    # Ollama settings
    use_ollama: bool = Field(
        default=False,
        description="Use Ollama to craft realistic prompts"
    )
    ollama_url: str = Field(
        default="http://localhost:11434",
        description="Ollama server URL"
    )
    ollama_model: str = Field(
        default="llama3.2",
        description="Ollama model to use"
    )

    # Execution settings
    delay_between_tests_ms: int = Field(
        default=100,
        ge=0,
        le=5000,
        description="Delay between tests in milliseconds"
    )
    stop_on_critical: bool = Field(
        default=False,
        description="Stop testing if critical vulnerability found"
    )


class MCPToolInfo(BaseModel):
    """Information about a discovered MCP tool."""
    name: str
    description: str
    parameters: list[dict[str, Any]]
    inferred_risks: list[str] = Field(
        default_factory=list,
        description="Inferred security risks based on parameter types"
    )


class MCPFinding(BaseModel):
    """Security finding from MCP interrogation."""
    id: str
    tool_name: str
    parameter_name: str
    attack_category: str
    severity: str
    title: str
    description: str
    evidence: dict[str, Any]
    recommendation: str


class MCPInterrogationResponse(BaseModel):
    """Response with interrogation job info."""
    job_id: str
    name: str
    status: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None

    # Progress
    tools_discovered: int = 0
    total_tests: int = 0
    tests_completed: int = 0
    tests_passed: int = 0
    tests_failed: int = 0

    # Results (only when completed)
    tools: list[MCPToolInfo] = Field(default_factory=list)
    findings: list[MCPFinding] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)

    error: str | None = None


@router.post(
    "",
    response_model=MCPInterrogationResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start MCP interrogation",
    description=(
        "Starts a security interrogation job against an MCP server. "
        "The job runs in the background and can be monitored via GET /jobs/{job_id}."
    ),
)
async def start_mcp_interrogation(
    request: MCPInterrogationRequest,
    background_tasks: BackgroundTasks,
    tenant: CurrentTenantDep,
) -> MCPInterrogationResponse:
    """Start an MCP server security interrogation."""
    # Validate transport
    try:
        transport = MCPTransport(request.connection.transport)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid transport: {request.connection.transport}. Must be stdio, http, or sse."
        )

    # Validate connection config
    if transport == MCPTransport.STDIO and not request.connection.command:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Command is required for stdio transport"
        )
    if transport in (MCPTransport.HTTP, MCPTransport.SSE) and not request.connection.url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is required for http/sse transport"
        )

    # Parse attack categories
    categories = []
    for cat_str in request.attack_categories:
        try:
            categories.append(AttackCategory(cat_str))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid attack category: {cat_str}"
            )

    # Create job
    job_id = str(uuid4())
    job = {
        "id": job_id,
        "name": request.name,
        "tenant_id": tenant.id,
        "status": InterrogationStatus.PENDING.value,
        "created_at": datetime.utcnow().isoformat(),
        "started_at": None,
        "completed_at": None,
        "config": request.model_dump(),
        "result": None,
        "error": None,
    }
    _jobs[job_id] = job

    # Build interrogation config
    config = InterrogationConfig(
        transport=transport,
        command=request.connection.command or "",
        args=request.connection.args,
        env=request.connection.env,
        url=request.connection.url or "",
        headers=request.connection.headers,
        timeout=request.connection.timeout,
        attack_categories=categories,
        max_payloads_per_category=request.max_payloads_per_category,
        run_benign_baseline=request.run_baseline,
        baseline_samples=request.baseline_samples,
        use_ollama=request.use_ollama,
        ollama_url=request.ollama_url,
        ollama_model=request.ollama_model,
        delay_between_tests_ms=request.delay_between_tests_ms,
        stop_on_critical=request.stop_on_critical,
    )

    # Start background task
    background_tasks.add_task(_run_interrogation, job_id, config)

    return MCPInterrogationResponse(
        job_id=job_id,
        name=request.name,
        status=InterrogationStatus.PENDING.value,
        created_at=job["created_at"],
    )


async def _run_interrogation(job_id: str, config: InterrogationConfig) -> None:
    """Run interrogation in background."""
    job = _jobs.get(job_id)
    if not job:
        return

    job["status"] = InterrogationStatus.CONNECTING.value
    job["started_at"] = datetime.utcnow().isoformat()

    try:
        result = await interrogate_mcp_server(config)

        job["status"] = result.status.value
        job["completed_at"] = datetime.utcnow().isoformat()
        job["result"] = result
        job["error"] = result.error

    except Exception as e:
        logger.exception(f"Interrogation {job_id} failed")
        job["status"] = InterrogationStatus.FAILED.value
        job["completed_at"] = datetime.utcnow().isoformat()
        job["error"] = str(e)


@router.get(
    "/jobs",
    response_model=list[MCPInterrogationResponse],
    summary="List interrogation jobs",
)
async def list_interrogation_jobs(
    tenant: CurrentTenantDep,
    status: str | None = None,
    limit: int = 50,
) -> list[MCPInterrogationResponse]:
    """List MCP interrogation jobs for the tenant."""
    jobs = [
        j for j in _jobs.values()
        if j.get("tenant_id") == tenant.id
    ]

    if status:
        jobs = [j for j in jobs if j.get("status") == status]

    # Sort by created_at descending
    jobs.sort(key=lambda j: j.get("created_at", ""), reverse=True)
    jobs = jobs[:limit]

    return [_format_job_response(j) for j in jobs]


@router.get(
    "/jobs/{job_id}",
    response_model=MCPInterrogationResponse,
    summary="Get interrogation job",
)
async def get_interrogation_job(
    job_id: str,
    tenant: CurrentTenantDep,
) -> MCPInterrogationResponse:
    """Get details of an MCP interrogation job."""
    job = _jobs.get(job_id)

    if not job or job.get("tenant_id") != tenant.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job not found: {job_id}"
        )

    return _format_job_response(job)


@router.delete(
    "/jobs/{job_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancel interrogation job",
)
async def cancel_interrogation_job(
    job_id: str,
    tenant: CurrentTenantDep,
) -> None:
    """Cancel a running interrogation job."""
    job = _jobs.get(job_id)

    if not job or job.get("tenant_id") != tenant.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job not found: {job_id}"
        )

    if job["status"] in (
        InterrogationStatus.COMPLETED.value,
        InterrogationStatus.FAILED.value,
        InterrogationStatus.CANCELLED.value,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Job is already {job['status']}"
        )

    job["status"] = InterrogationStatus.CANCELLED.value
    job["completed_at"] = datetime.utcnow().isoformat()


def _format_job_response(job: dict[str, Any]) -> MCPInterrogationResponse:
    """Format job dict as response model."""
    result = job.get("result")

    tools: list[MCPToolInfo] = []
    findings: list[MCPFinding] = []
    severity_counts: dict[str, int] = {}

    if result:
        # Format tools
        for tool in getattr(result, "tools_discovered", []):
            inferred_risks = []
            for param in tool.parameters:
                if param.is_command:
                    inferred_risks.append("command_injection")
                if param.is_path:
                    inferred_risks.append("path_traversal")
                if param.is_url:
                    inferred_risks.append("ssrf")
                if param.is_query:
                    inferred_risks.append("sql_injection")

            tools.append(MCPToolInfo(
                name=tool.name,
                description=tool.description,
                parameters=[
                    {
                        "name": p.name,
                        "type": p.type,
                        "description": p.description,
                        "required": p.required,
                    }
                    for p in tool.parameters
                ],
                inferred_risks=list(set(inferred_risks)),
            ))

        # Format findings
        for finding in getattr(result, "findings", []):
            findings.append(MCPFinding(
                id=finding.id,
                tool_name=finding.tool_name,
                parameter_name=finding.parameter_name,
                attack_category=finding.attack_category,
                severity=finding.severity.value,
                title=finding.title,
                description=finding.description,
                evidence=finding.evidence,
                recommendation=finding.recommendation,
            ))

        severity_counts = getattr(result, "severity_counts", {})

    return MCPInterrogationResponse(
        job_id=job["id"],
        name=job["name"],
        status=job["status"],
        created_at=job["created_at"],
        started_at=job.get("started_at"),
        completed_at=job.get("completed_at"),
        tools_discovered=len(tools),
        total_tests=getattr(result, "total_tests", 0) if result else 0,
        tests_completed=getattr(result, "tests_passed", 0) + getattr(result, "tests_failed", 0) if result else 0,
        tests_passed=getattr(result, "tests_passed", 0) if result else 0,
        tests_failed=getattr(result, "tests_failed", 0) if result else 0,
        tools=tools,
        findings=findings,
        severity_counts=severity_counts,
        error=job.get("error"),
    )


@router.get(
    "/categories",
    response_model=list[dict[str, str]],
    summary="List attack categories",
)
async def list_attack_categories(
    tenant: CurrentTenantDep,
) -> list[dict[str, str]]:
    """List available attack categories for MCP interrogation."""
    return [
        {
            "id": cat.value,
            "name": cat.value.replace("_", " ").title(),
            "description": _get_category_description(cat),
        }
        for cat in AttackCategory
    ]


def _get_category_description(category: AttackCategory) -> str:
    """Get description for attack category."""
    descriptions = {
        AttackCategory.COMMAND_INJECTION: "Test for OS command injection via tool parameters",
        AttackCategory.PATH_TRAVERSAL: "Test for path traversal to access unauthorized files",
        AttackCategory.SSRF: "Test for Server-Side Request Forgery to access internal resources",
        AttackCategory.SQL_INJECTION: "Test for SQL injection in database-related tools",
        AttackCategory.XSS: "Test for Cross-Site Scripting in output handling",
        AttackCategory.TEMPLATE_INJECTION: "Test for template injection in rendering tools",
        AttackCategory.LDAP_INJECTION: "Test for LDAP injection in directory tools",
        AttackCategory.PROMPT_INJECTION: "Test for prompt injection in AI-powered tools",
        AttackCategory.DENIAL_OF_SERVICE: "Test for resource exhaustion vulnerabilities",
    }
    return descriptions.get(category, "Security testing for this attack vector")
