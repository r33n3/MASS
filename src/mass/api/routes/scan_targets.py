"""Scan target endpoints.

One-call endpoints that register a target and trigger a scan in a single
request. Designed for developer workflows where creating a deployment
and then a separate scan is too many steps.

Supports all target types:
- Full deployment directory
- MCP server config (file or inline JSON)
- Model file (GGUF, safetensors, etc.)
- Skill file (Python/JS with AI logic)
- Instruction / prompt file (system prompt text)
- Remote model endpoint (dynamic probing only)
"""

import json
import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from mass.api.dependencies import (
    CurrentTenantDep,
    DBSession,
    ScanRepo,
    DeploymentRepo,
    get_scan_queue,
)
from mass.api.schemas.deployment import MCPServerConfig, TargetType
from mass.core.config import get_settings
from mass.core.target_helpers import infer_deployment_type, validate_target_type_requirements
from mass.core.types import ScanStatus
from mass.storage.models.deployment import Deployment, Scan

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class ScanTargetRequest(BaseModel):
    """Unified request to register a target and trigger a scan."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255, description="Target name")
    target_type: TargetType = Field(
        ...,
        description=(
            "What kind of target: deployment, mcp_server, model_file, "
            "skill_file, instruction_file, model_endpoint"
        ),
    )
    profile: str = Field(
        default="standard",
        description="Scan profile: quick, standard, comprehensive",
    )
    auto_scan: bool = Field(
        default=True,
        description="Automatically start scan after registration",
    )

    # Source location (at least one required for file-based targets)
    source_path: str | None = Field(
        default=None,
        description="Path to directory or file on the server filesystem",
    )
    target_files: list[str] | None = Field(
        default=None,
        description="Specific file paths within source_path to scan",
    )
    exclude_paths: list[str] | None = Field(
        default=None,
        description="Glob patterns or file paths to exclude (e.g. 'docs/**', 'tests/', '*.md')",
    )

    # Inline content (for targets that can be supplied directly)
    content: str | None = Field(
        default=None,
        description=(
            "Inline content: system prompt text for instruction_file, "
            "MCP config JSON for mcp_server, code for skill_file"
        ),
    )

    # Model configuration (for model_endpoint target type)
    model_endpoint: str | None = Field(default=None, description="Model API endpoint URL")
    model_provider: str | None = Field(default=None, description="Model provider")
    model_name: str | None = Field(default=None, description="Model identifier")
    model_api_key: str | None = Field(default=None, description="API key for model provider")
    system_prompt: str | None = Field(default=None, description="System prompt to test")

    # MCP server configurations (for mcp_server target type)
    mcp_servers: list[MCPServerConfig] | None = Field(
        default=None,
        description="MCP server definitions to scan",
    )

    # Agent endpoint configuration (for agent_endpoint target type)
    agent_url: str | None = Field(
        default=None,
        description="Agent API endpoint URL for agent-to-agent analysis",
    )
    agent_protocol: str | None = Field(
        default=None,
        description="Agent communication protocol: rest, grpc, mcp, a2a, custom",
    )
    agent_auth_type: str | None = Field(
        default=None,
        description="Agent auth mechanism: bearer, api_key, oauth2, mtls, none",
    )
    agent_auth_token: str | None = Field(
        default=None,
        description="Auth token or API key for agent endpoint",
    )
    upstream_agents: list[str] | None = Field(
        default=None,
        description="URLs of upstream agents that call this agent",
    )
    downstream_agents: list[str] | None = Field(
        default=None,
        description="URLs of downstream agents this agent delegates to",
    )

    tags: list[str] | None = Field(default=None, description="Tags for categorization")


class ScanTargetResponse(BaseModel):
    """Response from scan-target creation."""

    model_config = ConfigDict(extra="forbid")

    deployment_id: str = Field(..., description="Created deployment ID")
    scan_id: str | None = Field(default=None, description="Scan ID (if auto_scan=true)")
    target_type: str = Field(..., description="Target type")
    status: str = Field(..., description="Current status")
    message: str = Field(..., description="Status message")


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "",
    response_model=ScanTargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register and scan a target",
    description=(
        "Register any target type (deployment, MCP server, model file, "
        "skill file, instruction file, model endpoint) and optionally "
        "trigger an immediate scan. Combines deployment creation and "
        "scan dispatch into a single call."
    ),
)
async def create_scan_target(
    request: ScanTargetRequest,
    background_tasks: BackgroundTasks,
    tenant: CurrentTenantDep,
    db: DBSession,
    scan_repo: ScanRepo,
    deployment_repo: DeploymentRepo,
) -> ScanTargetResponse:
    """Register a scan target and optionally trigger a scan."""
    # Translate host paths to Docker-accessible paths
    if request.source_path:
        from mass.api.routes.discovery import _translate_path
        translated_path, translate_error = _translate_path(request.source_path)
        if translate_error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=translate_error,
            )
        request.source_path = str(translated_path)

    # Validate request based on target_type
    validate_target_type_requirements(
        request.target_type,
        source_path=request.source_path,
        target_files=request.target_files,
        content=request.content,
        mcp_servers=request.mcp_servers,
        system_prompt=request.system_prompt,
        model_endpoint=request.model_endpoint,
        model_provider=request.model_provider,
        agent_url=request.agent_url,
    )

    # Build deployment metadata
    meta_data: dict[str, Any] = {
        "target_type": request.target_type.value,
        "source_type": "local",
    }
    if request.target_files:
        meta_data["target_files"] = request.target_files
    if request.content:
        meta_data["inline_content"] = request.content
    if request.tags:
        meta_data["tags"] = request.tags
    if request.model_endpoint:
        meta_data["model_endpoint"] = request.model_endpoint
    if request.model_provider:
        meta_data["model_provider"] = request.model_provider
    if request.model_name:
        meta_data["model_name"] = request.model_name
    if request.model_api_key:
        meta_data["model_api_key"] = request.model_api_key
    if request.system_prompt:
        meta_data["system_prompt"] = request.system_prompt
    if request.mcp_servers:
        meta_data["mcp_servers"] = [
            s.model_dump(exclude_none=True) for s in request.mcp_servers
        ]
    if request.agent_url:
        meta_data["agent_url"] = request.agent_url
    if request.agent_protocol:
        meta_data["agent_protocol"] = request.agent_protocol
    if request.agent_auth_type:
        meta_data["agent_auth_type"] = request.agent_auth_type
    if request.agent_auth_token:
        meta_data["agent_auth_token"] = request.agent_auth_token
    if request.upstream_agents:
        meta_data["upstream_agents"] = request.upstream_agents
    if request.downstream_agents:
        meta_data["downstream_agents"] = request.downstream_agents

    # Reuse existing deployment if same source_path or name already exists
    existing = None
    if request.source_path:
        existing = await deployment_repo.find_by_source_path(
            tenant.tenant_id, request.source_path
        )
    if not existing:
        existing = await deployment_repo.find_by_name(
            tenant.tenant_id, request.name
        )

    if existing:
        created_deployment = existing
        created_deployment.meta = json.dumps(meta_data)
        if request.source_path:
            created_deployment.source_path = request.source_path
        await db.flush()
        logger.info("Reusing deployment %s for target '%s'", existing.id, request.name)
    else:
        deployment = Deployment(
            tenant_id=tenant.tenant_id,
            name=request.name,
            deployment_type=infer_deployment_type(request.target_type),
            source_path=request.source_path,
            meta=json.dumps(meta_data),
        )
        created_deployment = await deployment_repo.create(deployment)
        await db.flush()

    # If auto_scan is disabled, just return the deployment
    if not request.auto_scan:
        await db.commit()
        return ScanTargetResponse(
            deployment_id=created_deployment.id,
            scan_id=None,
            target_type=request.target_type.value,
            status="registered",
            message=f"Target registered. Use POST /scans to start a scan.",
        )

    # Enforce concurrent scan limit
    settings = get_settings()
    active_count = await scan_repo.count(
        tenant_id=tenant.tenant_id, status="running",
    )
    pending_count = await scan_repo.count(
        tenant_id=tenant.tenant_id, status="pending",
    )
    if active_count + pending_count >= settings.scan_max_concurrent:
        # Queue the scan instead of rejecting — it will be picked up
        # when capacity frees up (by the worker poll loop or next request)
        scan_config = {}
        if request.exclude_paths:
            scan_config["exclude_paths"] = request.exclude_paths
        queued_scan = Scan(
            tenant_id=tenant.tenant_id,
            deployment_id=created_deployment.id,
            profile=request.profile,
            status="queued",
            config=json.dumps(scan_config) if scan_config else None,
            total_findings=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
        )
        created_queued = await scan_repo.create(queued_scan)
        await db.commit()
        return ScanTargetResponse(
            deployment_id=created_deployment.id,
            scan_id=created_queued.id,
            target_type=request.target_type.value,
            status="queued",
            message=(
                f"Target registered and scan queued (position: "
                f"{pending_count + 1}). Will start automatically when "
                f"capacity is available."
            ),
        )

    # Create scan record
    scan_config = {}
    if request.exclude_paths:
        scan_config["exclude_paths"] = request.exclude_paths
    scan = Scan(
        tenant_id=tenant.tenant_id,
        deployment_id=created_deployment.id,
        profile=request.profile,
        status=ScanStatus.PENDING.value,
        config=json.dumps(scan_config) if scan_config else None,
        total_findings=0,
        critical_findings=0,
        high_findings=0,
        medium_findings=0,
        low_findings=0,
    )
    created_scan = await scan_repo.create(scan)
    await db.commit()

    # Dispatch to worker queue or fallback to in-process
    dispatched = False
    queue = await get_scan_queue()
    if queue is not None:
        try:
            from mass.workers.base import Job, JobPriority

            job = Job(
                job_type="full_scan",
                payload={"scan_id": created_scan.id},
                scan_id=created_scan.id,
                tenant_id=tenant.tenant_id,
                queue_name="scans",
                timeout_seconds=1800,
                priority=JobPriority.NORMAL,
            )
            await queue.enqueue(job)
            dispatched = True
            logger.info("Scan %s dispatched to worker queue", created_scan.id)
        except Exception as e:
            logger.warning(
                "Failed to enqueue scan %s, falling back to in-process: %s",
                created_scan.id, e,
            )

    if not dispatched:
        logger.info("Scan %s running in-process (no worker queue)", created_scan.id)
        from mass.api.services.scan_execution import ScanExecutionService
        scan_service = ScanExecutionService()
        background_tasks.add_task(scan_service.execute_scan, created_scan.id)

    return ScanTargetResponse(
        deployment_id=created_deployment.id,
        scan_id=created_scan.id,
        target_type=request.target_type.value,
        status="scanning",
        message=f"Target registered and scan started ({request.profile} profile).",
    )


# Validation and deployment type inference are handled by
# mass.core.target_helpers (validate_target_type_requirements, infer_deployment_type).
