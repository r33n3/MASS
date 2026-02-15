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
from mass.api.utils.job_store import JobStore
from mass.mcp import (
    MCPTransport,
    InterrogationConfig,
    InterrogationStatus,
    AttackCategory,
    interrogate_mcp_server,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Redis-backed job storage (per ARCHITECTURE.md Rule 1)
_store = JobStore("interrogation")


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

    # Location context - where the vulnerability exists
    attack_surface: str = Field(
        default="",
        description="Description of where the vulnerability exists in the MCP tool interface"
    )
    vulnerable_input: str = Field(
        default="",
        description="The specific input/payload that triggered the finding"
    )
    vulnerable_output: str = Field(
        default="",
        description="The tool response that indicates the vulnerability"
    )
    workflow_context: str = Field(
        default="",
        description="Context about where this tool fits in AI workflows (e.g., 'User input → Tool → LLM response')"
    )


class MCPTestResultEntry(BaseModel):
    """Single test result for transcript display."""
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


class MCPInterrogationResponse(BaseModel):
    """Response with interrogation job info."""
    job_id: str
    name: str
    status: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None

    # Connection config (for re-running)
    connection: dict[str, Any] | None = None

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
    test_results: list[MCPTestResultEntry] = Field(default_factory=list)

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
        "tenant_id": tenant.tenant_id,
        "status": InterrogationStatus.PENDING.value,
        "created_at": datetime.utcnow().isoformat(),
        "started_at": None,
        "completed_at": None,
        "config": request.model_dump(),
        "error": None,
        # Pre-initialize result fields
        "tools": [],
        "findings": [],
        "severity_counts": {},
        "test_results": [],
        "total_tests": 0,
        "tests_passed": 0,
        "tests_failed": 0,
    }
    await _store.save(job_id, job)

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


# Maximum time (seconds) an MCP interrogation job may run before being killed
_INTERROGATION_TIMEOUT = 600  # 10 minutes


async def _run_interrogation(job_id: str, config: InterrogationConfig) -> None:
    """Run interrogation in background with timeout protection."""
    job = await _store.load(job_id)
    if not job:
        return

    job["status"] = InterrogationStatus.CONNECTING.value
    job["started_at"] = datetime.utcnow().isoformat()
    await _store.save(job_id, job)

    # Broadcast job started
    await _broadcast_job_status(job_id, job)

    try:
        result = await asyncio.wait_for(
            interrogate_mcp_server(config),
            timeout=_INTERROGATION_TIMEOUT,
        )

        job["status"] = result.status.value
        job["completed_at"] = datetime.utcnow().isoformat()
        job["error"] = result.error

        # Serialize result into job dict for Redis storage
        _populate_job_from_result(job, result)

    except asyncio.TimeoutError:
        logger.warning("Interrogation %s timed out after %ds", job_id, _INTERROGATION_TIMEOUT)
        job["status"] = InterrogationStatus.FAILED.value
        job["completed_at"] = datetime.utcnow().isoformat()
        job["error"] = f"Timed out after {_INTERROGATION_TIMEOUT}s"

    except Exception as e:
        logger.exception(f"Interrogation {job_id} failed")
        job["status"] = InterrogationStatus.FAILED.value
        job["completed_at"] = datetime.utcnow().isoformat()
        job["error"] = str(e)

    # Final save and broadcast
    await _store.save(job_id, job)
    await _broadcast_job_status(job_id, job)


async def _broadcast_job_status(job_id: str, job: dict[str, Any] | None = None) -> None:
    """Broadcast current interrogation job status via WebSocket."""
    if job is None:
        job = await _store.load(job_id)
    if not job:
        return
    try:
        from mass.dashboard.websocket import broadcast_interrogation_update

        cfg = job.get("config", {})
        name = cfg.get("name", job.get("name", ""))

        # Derive duration from timestamps
        duration = 0.0
        if job.get("started_at"):
            start = datetime.fromisoformat(job["started_at"])
            end = datetime.fromisoformat(job["completed_at"]) if job.get("completed_at") else datetime.utcnow()
            duration = (end - start).total_seconds()

        await broadcast_interrogation_update(
            job_id=job_id,
            status=job["status"],
            message=name,
            strategies_run=job.get("total_tests", 0),
            successful_attacks=len(job.get("findings", [])),
            duration_seconds=duration,
        )
    except Exception:
        logger.debug("Failed to broadcast interrogation update", exc_info=True)


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
    jobs = await _store.list_jobs(tenant_id=tenant.tenant_id, limit=limit)

    if status:
        jobs = [j for j in jobs if j.get("status") == status]

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
    job = await _store.load(job_id)

    if not job or job.get("tenant_id") != tenant.tenant_id:
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
    job = await _store.load(job_id)

    if not job or job.get("tenant_id") != tenant.tenant_id:
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
    await _store.save(job_id, job)


def _populate_job_from_result(job: dict[str, Any], result: Any) -> None:
    """Extract and serialize InterrogationResult into job dict for Redis storage."""
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
                inferred_risks.append("SSRF (Server-Side Request Forgery)")
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

    # Findings with location context
    findings: list[dict] = []
    for finding in getattr(result, "findings", []):
        attack_surface = _build_attack_surface(finding)
        evidence = finding.evidence or {}
        vulnerable_input = ""
        vulnerable_output = ""

        if "arguments" in evidence:
            args = evidence["arguments"]
            if finding.parameter_name and finding.parameter_name in args:
                vulnerable_input = str(args[finding.parameter_name])
            else:
                vulnerable_input = str(args)
        if "result_sample" in evidence:
            vulnerable_output = str(evidence["result_sample"])[:200]
        elif "indicator" in evidence:
            vulnerable_output = f"Response contained: {evidence['indicator']}"

        workflow_context = _build_workflow_context(finding)
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
            "attack_surface": attack_surface,
            "vulnerable_input": vulnerable_input,
            "vulnerable_output": vulnerable_output,
            "workflow_context": workflow_context,
        })
    job["findings"] = findings
    job["severity_counts"] = getattr(result, "severity_counts", {})

    # Test results transcript
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

    # Counts
    job["total_tests"] = getattr(result, "total_tests", 0)
    job["tests_passed"] = getattr(result, "tests_passed", 0)
    job["tests_failed"] = getattr(result, "tests_failed", 0)


def _format_job_response(job: dict[str, Any]) -> MCPInterrogationResponse:
    """Format job dict as response model (all data already serialized in job)."""
    config_data = job.get("config", {})
    connection_data = config_data.get("connection") if config_data else None

    tools = [MCPToolInfo(**t) for t in job.get("tools", [])]
    findings = [MCPFinding(**f) for f in job.get("findings", [])]
    test_entries = [MCPTestResultEntry(**t) for t in job.get("test_results", [])]

    return MCPInterrogationResponse(
        job_id=job["id"],
        name=job["name"],
        status=job["status"],
        created_at=job["created_at"],
        started_at=job.get("started_at"),
        completed_at=job.get("completed_at"),
        connection=connection_data,
        tools_discovered=len(tools),
        total_tests=job.get("total_tests", 0),
        tests_completed=job.get("tests_passed", 0) + job.get("tests_failed", 0),
        tests_passed=job.get("tests_passed", 0),
        tests_failed=job.get("tests_failed", 0),
        tools=tools,
        findings=findings,
        severity_counts=job.get("severity_counts", {}),
        test_results=test_entries,
        error=job.get("error"),
    )


class MCPTestConnectionRequest(BaseModel):
    """Request to test MCP server connection and list tools."""
    connection: MCPConnectionConfig


class MCPTestConnectionResponse(BaseModel):
    """Response from MCP connection test."""
    connected: bool = False
    server_info: dict[str, Any] = Field(default_factory=dict)
    tools: list[MCPToolInfo] = Field(default_factory=list)
    transport_used: str | None = None
    error: str | None = None
    duration_ms: float = 0.0


@router.post(
    "/test-connection",
    response_model=MCPTestConnectionResponse,
    summary="Test MCP server connection",
    description="Connect to an MCP server and list its tools without running any attacks.",
)
async def test_mcp_connection(
    request: MCPTestConnectionRequest,
    tenant: CurrentTenantDep,
) -> MCPTestConnectionResponse:
    """Test connection to an MCP server and discover tools."""
    import time

    from mass.mcp.client import MCPClient, MCPTransport as ClientTransport

    start = time.time()
    conn = request.connection

    # Validate
    try:
        transport = MCPTransport(conn.transport)
    except ValueError:
        return MCPTestConnectionResponse(
            error=f"Invalid transport: {conn.transport}",
            duration_ms=(time.time() - start) * 1000,
        )

    if transport in (MCPTransport.HTTP, MCPTransport.SSE) and not conn.url:
        return MCPTestConnectionResponse(
            error="Server URL is required for HTTP/SSE transport",
            duration_ms=(time.time() - start) * 1000,
        )

    if transport == MCPTransport.STDIO and not conn.command:
        return MCPTestConnectionResponse(
            error="Command is required for stdio transport",
            duration_ms=(time.time() - start) * 1000,
        )

    client = None
    used_transport = transport.value
    try:
        if transport == MCPTransport.STDIO:
            client = MCPClient.stdio(
                command=conn.command or "",
                args=conn.args,
                env=conn.env,
            )
            await asyncio.wait_for(client.connect(), timeout=conn.timeout)
        elif transport in (MCPTransport.HTTP, MCPTransport.SSE):
            # Try primary, auto-fallback to alternate transport
            url = conn.url or ""
            primary = transport
            fallback = MCPTransport.HTTP if transport == MCPTransport.SSE else MCPTransport.SSE

            try:
                client = (
                    MCPClient.sse(sse_url=url, headers=conn.headers, timeout=conn.timeout)
                    if primary == MCPTransport.SSE
                    else MCPClient.http(base_url=url, headers=conn.headers, timeout=conn.timeout)
                )
                await asyncio.wait_for(client.connect(), timeout=conn.timeout)
                used_transport = primary.value
            except Exception as primary_err:
                # Cleanup
                if client:
                    try:
                        await client.disconnect()
                    except Exception:
                        pass

                # Adjust URL for fallback: /sse ↔ /mcp
                fallback_url = url
                if fallback == MCPTransport.SSE:
                    if url.endswith("/mcp"):
                        fallback_url = url[:-4] + "/sse"
                    elif not url.endswith("/sse"):
                        fallback_url = url.rstrip("/") + "/sse"
                else:
                    if url.endswith("/sse"):
                        fallback_url = url[:-4] + "/mcp"
                    elif not url.endswith("/mcp"):
                        fallback_url = url.rstrip("/") + "/mcp"

                try:
                    client = (
                        MCPClient.sse(sse_url=fallback_url, headers=conn.headers, timeout=conn.timeout)
                        if fallback == MCPTransport.SSE
                        else MCPClient.http(base_url=fallback_url, headers=conn.headers, timeout=conn.timeout)
                    )
                    await asyncio.wait_for(client.connect(), timeout=conn.timeout)
                    used_transport = f"{fallback.value} (fallback)"
                except Exception:
                    raise RuntimeError(
                        f"Both transports failed for {url}.\n"
                        f"  {primary.value}: {primary_err}\n"
                        f"  {fallback.value} ({fallback_url}): server unreachable.\n"
                        f"The MCP server may be down."
                    )

        server_info = await client.get_server_info()
        raw_tools = await client.list_tools()

        tools = []
        for t in raw_tools:
            params = [
                {
                    "name": p.name,
                    "type": p.type,
                    "description": p.description,
                    "required": p.required,
                }
                for p in t.parameters
            ]
            tools.append(MCPToolInfo(
                name=t.name,
                description=t.description,
                parameters=params,
            ))

        return MCPTestConnectionResponse(
            connected=True,
            server_info=server_info,
            tools=tools,
            transport_used=used_transport,
            duration_ms=(time.time() - start) * 1000,
        )

    except asyncio.TimeoutError:
        return MCPTestConnectionResponse(
            error=f"Connection timed out after {conn.timeout}s",
            duration_ms=(time.time() - start) * 1000,
        )
    except Exception as e:
        detail = str(e)
        if "401" in detail or "Unauthorized" in detail:
            error_msg = "Authentication failed (401 Unauthorized). Check your API key."
        elif "403" in detail or "Forbidden" in detail:
            error_msg = "Access denied (403 Forbidden). Check your API key permissions."
        elif "Connection" in detail.lower() or "connect" in detail.lower():
            error_msg = f"Connection failed: {detail}"
        else:
            error_msg = f"Error: {detail}"
        return MCPTestConnectionResponse(
            error=error_msg,
            duration_ms=(time.time() - start) * 1000,
        )
    finally:
        if client:
            try:
                await client.disconnect()
            except Exception:
                pass


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
        AttackCategory.COMMAND_INJECTION: (
            "Test for OS Command Injection - a vulnerability where an attacker can execute "
            "arbitrary operating system commands on the server by injecting malicious input "
            "into parameters that are passed to shell commands."
        ),
        AttackCategory.PATH_TRAVERSAL: (
            "Test for Path Traversal (Directory Traversal) - a vulnerability where an attacker "
            "can access files and directories outside the intended directory by manipulating "
            "file path parameters using sequences like '../' to navigate the filesystem."
        ),
        AttackCategory.SSRF: (
            "Test for SSRF (Server-Side Request Forgery) - a vulnerability where an attacker "
            "can make the server send HTTP requests to arbitrary destinations, potentially "
            "accessing internal services, cloud metadata endpoints, or other protected resources."
        ),
        AttackCategory.SQL_INJECTION: (
            "Test for SQL Injection (SQLi) - a vulnerability where an attacker can inject "
            "malicious SQL code into database queries, potentially reading, modifying, or "
            "deleting data, or executing administrative operations on the database."
        ),
        AttackCategory.XSS: (
            "Test for XSS (Cross-Site Scripting) - a vulnerability where an attacker can "
            "inject malicious scripts that execute in the context of other users' browsers, "
            "potentially stealing session tokens, credentials, or performing actions on their behalf."
        ),
        AttackCategory.TEMPLATE_INJECTION: (
            "Test for SSTI (Server-Side Template Injection) - a vulnerability where an attacker "
            "can inject template directives that are executed by the server's template engine, "
            "potentially leading to remote code execution or information disclosure."
        ),
        AttackCategory.LDAP_INJECTION: (
            "Test for LDAP Injection - a vulnerability where an attacker can manipulate LDAP "
            "(Lightweight Directory Access Protocol) queries to bypass authentication, access "
            "unauthorized data, or modify directory entries."
        ),
        AttackCategory.PROMPT_INJECTION: (
            "Test for Prompt Injection - a vulnerability in AI/LLM-powered tools where an "
            "attacker can override system instructions or manipulate the model's behavior "
            "by crafting malicious input that is interpreted as instructions."
        ),
        AttackCategory.DENIAL_OF_SERVICE: (
            "Test for DoS (Denial of Service) - a vulnerability where an attacker can exhaust "
            "system resources (CPU, memory, disk, network) causing the service to become "
            "unavailable or unresponsive to legitimate users."
        ),
    }
    return descriptions.get(category, "Security testing for this attack vector")


def _build_attack_surface(finding) -> str:
    """Build a human-readable description of where the vulnerability exists."""
    category = finding.attack_category
    tool = finding.tool_name
    param = finding.parameter_name

    # Map attack categories to attack surface descriptions
    surface_templates = {
        "command_injection": (
            f"MCP Tool '{tool}' → Parameter '{param}' accepts user input that is passed to "
            f"OS command execution. Malicious input can escape the intended command context."
        ),
        "path_traversal": (
            f"MCP Tool '{tool}' → Parameter '{param}' accepts file paths. Attackers can use "
            f"directory traversal sequences (../) to access files outside the intended directory."
        ),
        "ssrf": (
            f"MCP Tool '{tool}' → Parameter '{param}' accepts URLs. The server fetches these URLs, "
            f"allowing attackers to reach internal services or cloud metadata endpoints."
        ),
        "sql_injection": (
            f"MCP Tool '{tool}' → Parameter '{param}' is used in database queries. User input "
            f"can modify query logic to extract, modify, or delete data."
        ),
        "prompt_injection": (
            f"MCP Tool '{tool}' → Parameter '{param}' feeds into an LLM prompt. Attackers can "
            f"inject instructions that override the system prompt or manipulate model behavior."
        ),
        "template_injection": (
            f"MCP Tool '{tool}' → Parameter '{param}' is rendered by a template engine. "
            f"Malicious template syntax can execute arbitrary code on the server."
        ),
        "restriction_bypass": (
            f"MCP Tool '{tool}' → Security restrictions were bypassed. The tool executed an "
            f"operation that should have been blocked by access controls."
        ),
        "extra_action": (
            f"MCP Tool '{tool}' → The tool performed actions beyond its documented scope. "
            f"This indicates potential Confused Deputy or privilege escalation issues."
        ),
        "information_leakage": (
            f"MCP Tool '{tool}' → Sensitive data was exposed in the tool's response. "
            f"Output sanitization is missing or insufficient."
        ),
    }

    return surface_templates.get(
        category,
        f"MCP Tool '{tool}' → Parameter '{param}' is vulnerable to {category.replace('_', ' ')}."
    )


def _build_workflow_context(finding) -> str:
    """Build a description of how this vulnerability fits in AI workflows."""
    category = finding.attack_category
    tool = finding.tool_name

    # Common AI workflow patterns where MCP tools are used
    workflow_contexts = {
        "command_injection": (
            f"Workflow Impact: User message → LLM decides to call '{tool}' → "
            f"Malicious input executes OS commands → Attacker gains server access. "
            f"This is critical because LLMs may call tools based on user requests without "
            f"understanding the security implications of the input."
        ),
        "path_traversal": (
            f"Workflow Impact: User asks for file content → LLM calls '{tool}' with user-provided path → "
            f"Attacker reads /etc/passwd, .env files, or source code. "
            f"AI agents often need file access, making this a high-value attack vector."
        ),
        "ssrf": (
            f"Workflow Impact: User provides URL → LLM calls '{tool}' to fetch content → "
            f"Attacker accesses internal services (databases, admin panels) or cloud metadata. "
            f"SSRF is particularly dangerous in cloud environments where metadata contains credentials."
        ),
        "sql_injection": (
            f"Workflow Impact: User query → LLM generates database lookup via '{tool}' → "
            f"Attacker extracts all database records or modifies data. "
            f"AI-to-database workflows must use parameterized queries exclusively."
        ),
        "prompt_injection": (
            f"Workflow Impact: User input → Tool '{tool}' processes input → Result fed to LLM → "
            f"Attacker's hidden instructions override system behavior. "
            f"This can cause the AI to ignore safety guidelines or leak system prompts."
        ),
        "restriction_bypass": (
            f"Workflow Impact: LLM calls '{tool}' with validated input → Tool ignores restrictions → "
            f"Attacker accesses resources that should be blocked. "
            f"Defense-in-depth is required; don't rely solely on LLM-side validation."
        ),
        "information_leakage": (
            f"Workflow Impact: Tool '{tool}' returns data to LLM → LLM includes sensitive data in response → "
            f"User sees credentials, PII, or internal information. "
            f"All tool outputs should be sanitized before reaching the user."
        ),
    }

    return workflow_contexts.get(
        category,
        f"Workflow Impact: When '{tool}' is called in an AI workflow with malicious input, "
        f"the {category.replace('_', ' ')} vulnerability can be exploited to compromise the system."
    )
