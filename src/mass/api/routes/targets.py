"""Unified target inventory endpoints.

Provides a single view that merges filesystem-discovered targets with
database-registered deployments, enriched with scan status.  Also supports
manual target addition without triggering a scan.
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status

from mass.api.dependencies import (
    CurrentTenantDep,
    DBSession,
    DeploymentRepo,
    PaginationDep,
    ScanRepo,
)
from mass.api.schemas.common import PaginationMeta, SuccessResponse
from mass.api.schemas.deployment import MCPServerConfig, TargetType
from mass.api.schemas.target import (
    TargetCreate,
    TargetDetailResponse,
    TargetDiscoveryInfo,
    TargetListResponse,
    TargetResponse,
    TargetScanSummary,
    TargetSource,
    TargetStatus,
)
from mass.core.filesystem import (
    EXCLUDED_DIRS,
    MODEL_EXTENSIONS,
    scan_directory_quick,
    detect_ai_frameworks,
)
from mass.api.schemas.questionnaire import RiskQuestionnaire
from mass.core.target_helpers import infer_deployment_type, validate_target_type_requirements
from mass.storage.models.deployment import Deployment, Scan

# Path constants shared with discovery module
from mass.api.routes.discovery import TARGETS_BASE, GITHUB_CLONES_DIR

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_meta(deployment: Deployment) -> dict:
    """Parse the meta JSON column into a dict."""
    if deployment.meta:
        try:
            return json.loads(deployment.meta)
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def _scan_filesystem_targets() -> list[dict[str, Any]]:
    """Enumerate directories available for scanning under /app/targets/.

    Uses the shared scan_directory_quick() from mass.core.filesystem.

    Returns a list of dicts with keys: name, path, file_count, has_models,
    has_code, source.
    """
    targets: list[dict[str, Any]] = []

    if not TARGETS_BASE.is_dir():
        return targets

    # Mounted targets (skip internal dirs prefixed with _)
    for entry in sorted(TARGETS_BASE.iterdir()):
        if entry.name.startswith("_"):
            continue
        info = scan_directory_quick(entry)
        if info:
            targets.append({**info, "source": "local"})

    # GitHub clones
    if GITHUB_CLONES_DIR.is_dir():
        for entry in sorted(GITHUB_CLONES_DIR.iterdir()):
            info = scan_directory_quick(entry)
            if info:
                targets.append({**info, "source": "github"})

    return targets


def _normalize_path(p: str) -> str:
    """Normalize a path for comparison (lowercase, forward slashes)."""
    return p.replace("\\", "/").rstrip("/").lower()


def _synthetic_id(path: str) -> str:
    """Generate a deterministic synthetic ID for filesystem-only targets."""
    return f"fs-{hashlib.md5(path.encode()).hexdigest()[:12]}"


STAGE_ORDER = {
    TargetStatus.DISCOVERED: 0,
    TargetStatus.PROFILED: 1,
    TargetStatus.SCANNED: 2,
    TargetStatus.INTERROGATED: 3,
}


def _compute_status_from_scan(scan: Scan) -> TargetStatus:
    """Compute pipeline status from a completed scan."""
    if scan.profile == "comprehensive" or (scan.jobs_total or 0) >= 8:
        return TargetStatus.INTERROGATED
    return TargetStatus.SCANNED


def _determine_status(
    latest_scan: Scan | None,
    meta: dict | None = None,
) -> TargetStatus:
    """Determine target pipeline stage from scan history and metadata.

    Priority: stored pipeline_status > computed from scan > discovery info.
    """
    stored = None
    if meta and meta.get("pipeline_status"):
        try:
            stored = TargetStatus(meta["pipeline_status"])
        except ValueError:
            pass

    computed = None
    if latest_scan is not None and latest_scan.status == "completed":
        computed = _compute_status_from_scan(latest_scan)

    # Return whichever is further along in the pipeline
    if stored and computed:
        return stored if STAGE_ORDER.get(stored, 0) >= STAGE_ORDER.get(computed, 0) else computed
    if computed:
        return computed
    if stored:
        return stored

    # Fallback: check discovery info
    if meta and meta.get("discovery"):
        return TargetStatus.PROFILED
    return TargetStatus.DISCOVERED


def _next_action(target_status: TargetStatus, meta: dict | None = None) -> str | None:
    """Determine the next pipeline step for a target."""
    if target_status == TargetStatus.DISCOVERED:
        return "profile"
    if target_status == TargetStatus.PROFILED:
        return "scan"
    if target_status == TargetStatus.SCANNED:
        # Only suggest interrogation if target has something to probe
        if meta:
            has_probes = (
                meta.get("model_endpoint")
                or meta.get("agent_url")
                or meta.get("mcp_servers")
                or (meta.get("discovery", {}).get("has_models"))
            )
            if has_probes:
                return "interrogate"
        return "interrogate"  # Default: suggest it, user can skip
    # INTERROGATED — pipeline complete
    return None


def _build_scan_summary(scans: list[Scan]) -> TargetScanSummary:
    """Build scan summary from a list of scans."""
    if not scans:
        return TargetScanSummary()

    total_findings = sum(s.total_findings for s in scans)
    critical = sum(s.critical_findings for s in scans)
    high = sum(s.high_findings for s in scans)

    latest = scans[0]  # Already sorted desc by created_at
    return TargetScanSummary(
        total_scans=len(scans),
        last_scan_at=latest.completed_at or latest.started_at or latest.created_at,
        last_scan_status=latest.status,
        total_findings=total_findings,
        critical_findings=critical,
        high_findings=high,
    )


def _determine_source(meta: dict) -> TargetSource:
    """Determine target source from deployment metadata."""
    if meta.get("agent_url") or meta.get("model_endpoint"):
        return TargetSource.REMOTE
    if meta.get("source_type") == "github":
        return TargetSource.GITHUB
    return TargetSource.LOCAL


def _deployment_to_target_response(
    deployment: Deployment,
    latest_scan: Scan | None,
    scan_count: int = 0,
    fs_info: dict[str, Any] | None = None,
) -> TargetResponse:
    """Convert a Deployment to a unified TargetResponse."""
    meta = _parse_meta(deployment)
    target_type = meta.get("target_type", "deployment")
    tags = meta.get("tags")
    source = _determine_source(meta)
    target_status = _determine_status(latest_scan, meta)

    # Persist pipeline_status back to meta if it changed
    if meta.get("pipeline_status") != target_status.value:
        meta["pipeline_status"] = target_status.value
        deployment.meta = json.dumps(meta)

    # Build scan summary if we have scan data
    scan_summary = None
    if latest_scan is not None:
        scan_summary = TargetScanSummary(
            total_scans=scan_count,
            last_scan_at=latest_scan.completed_at or latest_scan.started_at or latest_scan.created_at,
            last_scan_status=latest_scan.status,
            total_findings=latest_scan.total_findings,
            critical_findings=latest_scan.critical_findings,
            high_findings=latest_scan.high_findings,
        )

    return TargetResponse(
        id=deployment.id,
        name=deployment.name,
        target_type=target_type,
        status=target_status,
        source=source,
        source_path=deployment.source_path,
        description=deployment.description,
        tags=tags,
        file_count=fs_info["file_count"] if fs_info else None,
        has_models=fs_info["has_models"] if fs_info else None,
        has_code=fs_info["has_code"] if fs_info else None,
        scan_summary=scan_summary,
        next_action=_next_action(target_status, meta),
        pipeline_status=meta.get("auto_pipeline_status"),
        created_at=deployment.created_at,
        updated_at=deployment.updated_at,
    )


def _fs_to_target_response(fs: dict[str, Any]) -> TargetResponse:
    """Convert a filesystem entry to a discovered TargetResponse."""
    source = TargetSource.GITHUB if fs["source"] == "github" else TargetSource.LOCAL
    return TargetResponse(
        id=_synthetic_id(fs["path"]),
        name=fs["name"],
        target_type="deployment",
        status=TargetStatus.DISCOVERED,
        source=source,
        source_path=fs["path"],
        description=None,
        tags=None,
        file_count=fs["file_count"],
        has_models=fs["has_models"],
        has_code=fs["has_code"],
        scan_summary=None,
        next_action="profile",
        created_at=None,
        updated_at=None,
    )


def _run_filesystem_discovery(path: Path) -> TargetDiscoveryInfo:
    """Run lightweight filesystem profiling on a target path.

    Uses shared helpers from mass.core.filesystem for consistency.
    """
    if not path.is_dir():
        return TargetDiscoveryInfo()

    info = scan_directory_quick(path)
    if not info:
        return TargetDiscoveryInfo()

    ai_frameworks = detect_ai_frameworks(path)

    # Recommend scan profile
    if ai_frameworks and info["has_models"]:
        recommended = "comprehensive"
    elif ai_frameworks or info["has_models"]:
        recommended = "standard"
    else:
        recommended = "quick"

    return TargetDiscoveryInfo(
        file_count=info["file_count"],
        has_models=info["has_models"],
        has_code=info["has_code"],
        ai_frameworks=ai_frameworks,
        recommended_profile=recommended,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "",
    response_model=TargetListResponse,
    summary="List all targets",
    description=(
        "Unified target inventory merging filesystem-discovered targets with "
        "database-registered deployments. Each target includes a pipeline stage: "
        "discovered → profiled → scanned → interrogated, plus next_action "
        "indicating the recommended next step."
    ),
)
async def list_targets(
    tenant: CurrentTenantDep,
    db: DBSession,
    deployment_repo: DeploymentRepo,
    scan_repo: ScanRepo,
    pagination: PaginationDep,
    target_status: TargetStatus | None = Query(None, alias="status", description="Filter by status"),
    target_type: str | None = Query(None, description="Filter by target type"),
    search: str | None = Query(None, description="Search by name"),
) -> TargetListResponse:
    """List all targets with unified status."""
    # 1. Scan filesystem for available targets
    fs_targets = _scan_filesystem_targets()

    # 2. Query all deployments for this tenant
    deployments = await deployment_repo.list(
        offset=0,
        limit=1000,
        tenant_id=tenant.tenant_id,
    )

    # 3. Build path-to-deployment index for merging (keeps most recent per path)
    path_to_deployment: dict[str, Deployment] = {}
    for dep in deployments:
        if dep.source_path:
            norm = _normalize_path(dep.source_path)
            if norm not in path_to_deployment:
                path_to_deployment[norm] = dep

    # 4. Batch-fetch latest scans and counts (2 queries instead of 2*N)
    dep_ids = [dep.id for dep in deployments]
    latest_scans = await scan_repo.get_latest_by_deployments(dep_ids)
    scan_counts = await scan_repo.count_by_deployments(dep_ids)

    # 5. Merge filesystem and DB targets (deduplicated by path)
    merged: list[TargetResponse] = []
    matched_deployment_ids: set[str] = set()
    seen_paths: set[str] = set()
    seen_names: set[str] = set()

    # Filesystem targets — check if they have a matching deployment
    for fs in fs_targets:
        normalized = _normalize_path(fs["path"])
        deployment = path_to_deployment.get(normalized)

        if deployment:
            matched_deployment_ids.add(deployment.id)
            seen_paths.add(normalized)
            seen_names.add(deployment.name.lower())
            merged.append(_deployment_to_target_response(
                deployment,
                latest_scans.get(deployment.id),
                scan_counts.get(deployment.id, 0),
                fs_info=fs,
            ))
        else:
            seen_paths.add(normalized)
            merged.append(_fs_to_target_response(fs))

    # DB-only targets (no filesystem match — remote endpoints, deleted paths, etc.)
    # Deduplicate: skip if another deployment with same path was already added
    for dep in deployments:
        if dep.id in matched_deployment_ids:
            continue
        # Skip duplicates by path
        if dep.source_path:
            norm = _normalize_path(dep.source_path)
            if norm in seen_paths:
                continue
            seen_paths.add(norm)
        # Skip duplicates by name (for remote targets without paths)
        name_key = dep.name.lower()
        if name_key in seen_names:
            continue
        seen_names.add(name_key)
        merged.append(_deployment_to_target_response(
            dep,
            latest_scans.get(dep.id),
            scan_counts.get(dep.id, 0),
        ))

    # 5b. Persist any pipeline_status updates (dirty deployments auto-flushed)
    await db.commit()

    # 6. Apply filters
    if target_status is not None:
        merged = [t for t in merged if t.status == target_status]
    if target_type is not None:
        merged = [t for t in merged if t.target_type == target_type]
    if search:
        search_lower = search.lower()
        merged = [t for t in merged if search_lower in t.name.lower()]

    # 7. Paginate
    total = len(merged)
    page = merged[pagination.offset : pagination.offset + pagination.limit]

    return TargetListResponse(
        items=page,
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=pagination.offset + len(page) < total,
        ),
    )


@router.post(
    "",
    response_model=TargetDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new target",
    description=(
        "Manually add a target to the inventory. Supports all target types. "
        "Does not trigger a scan — use /scan-targets or /scans for that. "
        "Set auto_discover=true to run filesystem profiling."
    ),
)
async def create_target(
    request: TargetCreate,
    tenant: CurrentTenantDep,
    db: DBSession,
    deployment_repo: DeploymentRepo,
    background_tasks: BackgroundTasks,
) -> TargetDetailResponse:
    """Register a new target manually."""
    # Validate request based on target type (shared helper)
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

    # Translate path if provided
    translated_path = request.source_path
    if request.source_path:
        from mass.api.routes.discovery import _translate_path

        resolved, error = _translate_path(request.source_path)
        if error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error,
            )
        translated_path = str(resolved)

    # Build metadata JSON
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
        meta_data["source_type"] = "remote"
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
        meta_data["source_type"] = "remote"
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

    # Run auto-discovery if requested and path exists
    discovery_info = None
    if request.auto_discover and translated_path:
        target_path = Path(translated_path)
        if target_path.is_dir():
            discovery_info = _run_filesystem_discovery(target_path)
            meta_data["discovery"] = discovery_info.model_dump()

    # Determine initial pipeline status and persist it
    create_status = TargetStatus.PROFILED if discovery_info else TargetStatus.DISCOVERED
    meta_data["pipeline_status"] = create_status.value

    # Reuse existing deployment if same source_path or name exists
    existing = None
    if translated_path:
        existing = await deployment_repo.find_by_source_path(
            tenant.tenant_id, translated_path
        )
    if not existing:
        existing = await deployment_repo.find_by_name(
            tenant.tenant_id, request.name
        )

    if existing:
        created = existing
        created.meta = json.dumps(meta_data)
        if request.description:
            created.description = request.description
        if translated_path:
            created.source_path = translated_path
        await db.commit()
        logger.info("Reusing deployment %s for target '%s'", existing.id, request.name)
    else:
        deployment = Deployment(
            tenant_id=tenant.tenant_id,
            name=request.name,
            description=request.description,
            deployment_type=infer_deployment_type(request.target_type),
            source_path=translated_path,
            source_branch=request.source_ref,
            meta=json.dumps(meta_data),
        )
        created = await deployment_repo.create(deployment)
        await db.commit()

    # Determine source
    source = _determine_source(meta_data)
    if source == TargetSource.LOCAL and request.source_path and (
        request.source_path.startswith("https://github.com/")
        or request.source_path.startswith("git@github.com:")
    ):
        source = TargetSource.GITHUB

    # Reconstruct MCP server configs for response
    mcp_servers = None
    if meta_data.get("mcp_servers"):
        mcp_servers = [MCPServerConfig(**s) for s in meta_data["mcp_servers"]]

    # Kick off auto-pipeline if requested
    auto_pipeline_status = None
    if request.auto_pipeline and translated_path:
        from mass.api.services.auto_pipeline import run_auto_pipeline

        background_tasks.add_task(
            run_auto_pipeline,
            deployment_id=created.id,
            tenant_id=tenant.tenant_id,
            provider=request.auto_pipeline_provider or "ollama",
            model=request.auto_pipeline_model,
            api_key=request.auto_pipeline_key,
            profile="standard",
        )
        auto_pipeline_status = "profiling"
        logger.info("Auto-pipeline started for target '%s'", request.name)

    return TargetDetailResponse(
        id=created.id,
        name=created.name,
        target_type=request.target_type.value,
        status=create_status,
        source=source,
        source_path=created.source_path,
        description=created.description,
        tags=request.tags,
        file_count=discovery_info.file_count if discovery_info else None,
        has_models=discovery_info.has_models if discovery_info else None,
        has_code=discovery_info.has_code if discovery_info else None,
        scan_summary=None,
        next_action=_next_action(create_status, meta_data),
        pipeline_status=auto_pipeline_status,
        created_at=created.created_at,
        updated_at=created.updated_at,
        discovery_info=discovery_info,
        recent_scans=None,
        model_endpoint=meta_data.get("model_endpoint"),
        model_provider=meta_data.get("model_provider"),
        model_name=meta_data.get("model_name"),
        system_prompt=meta_data.get("system_prompt"),
        mcp_servers=mcp_servers,
        agent_url=meta_data.get("agent_url"),
        agent_protocol=meta_data.get("agent_protocol"),
    )


@router.get(
    "/{target_id}",
    response_model=TargetDetailResponse,
    summary="Get target detail",
    description="Get full detail for a registered target including scan history.",
)
async def get_target(
    target_id: str,
    tenant: CurrentTenantDep,
    db: DBSession,
    deployment_repo: DeploymentRepo,
    scan_repo: ScanRepo,
) -> TargetDetailResponse:
    """Get target detail with scan history."""
    # Handle filesystem-only targets (synthetic IDs)
    if target_id.startswith("fs-"):
        # Find the matching filesystem target by checking all candidates
        fs_targets = _scan_filesystem_targets()
        for fs in fs_targets:
            if _synthetic_id(fs["path"]) == target_id:
                source = TargetSource.GITHUB if fs["source"] == "github" else TargetSource.LOCAL
                discovery_info = _run_filesystem_discovery(Path(fs["path"]))
                return TargetDetailResponse(
                    id=target_id,
                    name=fs["name"],
                    target_type="deployment",
                    status=TargetStatus.DISCOVERED,
                    source=source,
                    source_path=fs["path"],
                    description=None,
                    tags=None,
                    file_count=fs["file_count"],
                    has_models=fs["has_models"],
                    has_code=fs["has_code"],
                    scan_summary=None,
                    next_action="profile",
                    created_at=None,
                    updated_at=None,
                    discovery_info=discovery_info,
                    recent_scans=None,
                )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Filesystem target not found",
        )

    deployment = await deployment_repo.get(target_id)
    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    meta = _parse_meta(deployment)

    # Get recent scans
    scans = await scan_repo.list_by_deployment(target_id, limit=10)
    latest_scan = scans[0] if scans else None

    # Build scan summary
    scan_summary = _build_scan_summary(list(scans)) if scans else None

    # Build recent scans list
    recent_scans = [
        {
            "scan_id": s.id,
            "status": s.status,
            "profile": s.profile,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "total_findings": s.total_findings,
            "critical_findings": s.critical_findings,
            "high_findings": s.high_findings,
        }
        for s in scans
    ]

    # Reconstruct discovery info from meta
    discovery_info = None
    if meta.get("discovery"):
        discovery_info = TargetDiscoveryInfo(**meta["discovery"])

    # Reconstruct MCP server configs
    mcp_servers = None
    if meta.get("mcp_servers"):
        mcp_servers = [MCPServerConfig(**s) for s in meta["mcp_servers"]]

    source = _determine_source(meta)
    target_status = _determine_status(latest_scan, meta)

    # Persist pipeline_status if it changed
    if meta.get("pipeline_status") != target_status.value:
        meta["pipeline_status"] = target_status.value
        deployment.meta = json.dumps(meta)
        await db.commit()

    return TargetDetailResponse(
        id=deployment.id,
        name=deployment.name,
        target_type=meta.get("target_type", "deployment"),
        status=target_status,
        source=source,
        source_path=deployment.source_path,
        description=deployment.description,
        tags=meta.get("tags"),
        file_count=discovery_info.file_count if discovery_info else None,
        has_models=discovery_info.has_models if discovery_info else None,
        has_code=discovery_info.has_code if discovery_info else None,
        scan_summary=scan_summary,
        next_action=_next_action(target_status, meta),
        pipeline_status=meta.get("auto_pipeline_status"),
        created_at=deployment.created_at,
        updated_at=deployment.updated_at,
        discovery_info=discovery_info,
        recent_scans=recent_scans if recent_scans else None,
        model_endpoint=meta.get("model_endpoint"),
        model_provider=meta.get("model_provider"),
        model_name=meta.get("model_name"),
        system_prompt=meta.get("system_prompt"),
        mcp_servers=mcp_servers,
        agent_url=meta.get("agent_url"),
        agent_protocol=meta.get("agent_protocol"),
        topology=meta.get("topology"),
        architecture_map=meta.get("architecture_map"),
        risk_questionnaire=meta.get("risk_questionnaire"),
        risk_posture=meta.get("risk_posture"),
        inline_content=meta.get("inline_content"),
        instruction_review=meta.get("instruction_review"),
    )


@router.delete(
    "/{target_id}",
    response_model=SuccessResponse,
    summary="Delete target",
    description=(
        "Remove a target and its scans/findings from the database. "
        "Filesystem-discovered targets will reappear on next refresh "
        "unless the directory is removed from the targets mount."
    ),
)
async def delete_target(
    target_id: str,
    tenant: CurrentTenantDep,
    db: DBSession,
    deployment_repo: DeploymentRepo,
) -> SuccessResponse:
    """Delete a target (hard delete with cascade)."""
    # Filesystem-only targets have synthetic IDs — no DB record to delete
    if target_id.startswith("fs-"):
        return SuccessResponse(
            message=(
                "This is a filesystem-discovered target with no database record. "
                "Remove the directory from the targets mount to hide it."
            )
        )

    deployment = await deployment_repo.get(target_id)
    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    name = deployment.name
    await deployment_repo.delete(deployment)
    await db.commit()

    return SuccessResponse(
        message=f"Target '{name}' and associated scans/findings deleted"
    )


@router.patch(
    "/{target_id}/status",
    response_model=SuccessResponse,
    summary="Update target pipeline status",
    description="Advance a target's pipeline stage (e.g. after profiling or interrogation).",
)
async def update_target_status(
    target_id: str,
    new_status: TargetStatus = Query(..., alias="status", description="New pipeline status"),
    tenant: CurrentTenantDep = ...,
    db: DBSession = ...,
    deployment_repo: DeploymentRepo = ...,
) -> SuccessResponse:
    """Update a target's pipeline status."""
    deployment = await deployment_repo.get(target_id)
    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    meta = _parse_meta(deployment)
    old_status = meta.get("pipeline_status", "discovered")

    # Only allow forward progression (or explicit reset)
    old_order = STAGE_ORDER.get(TargetStatus(old_status), 0) if old_status else 0
    new_order = STAGE_ORDER.get(new_status, 0)
    if new_order < old_order:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot regress from {old_status} to {new_status.value}",
        )

    meta["pipeline_status"] = new_status.value
    deployment.meta = json.dumps(meta)
    await db.commit()

    return SuccessResponse(message=f"Target status updated to {new_status.value}")


@router.post(
    "/{target_id}/profile",
    response_model=TargetDetailResponse,
    summary="Run AI architecture profiling",
    description=(
        "Use an LLM to analyze the target's code and build an architecture map: "
        "entry points, model connections, tools, data flows, and safety measures. "
        "Supports Ollama (local), OpenAI, and Anthropic providers."
    ),
)
async def profile_target(
    target_id: str,
    tenant: CurrentTenantDep,
    db: DBSession,
    deployment_repo: DeploymentRepo,
    scan_repo: ScanRepo,
    provider: str = Query(default="ollama", description="LLM provider: ollama, openai, anthropic"),
    model: str | None = Query(default=None, description="Model name (auto-resolved if omitted)"),
    api_key: str | None = Query(default=None, alias="key", description="API key for cloud providers"),
) -> TargetDetailResponse:
    """Run AI-powered architecture profiling on a target."""
    from mass.api.services.code_analysis import analyze_target_architecture

    # Handle filesystem-only targets: promote to DB deployment first
    if target_id.startswith("fs-"):
        fs_targets = _scan_filesystem_targets()
        matched = None
        for fs in fs_targets:
            if _synthetic_id(fs["path"]) == target_id:
                matched = fs
                break
        if not matched:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Filesystem target not found",
            )
        # Register as a DB deployment
        from mass.core.target_helpers import infer_deployment_type
        deployment = Deployment(
            tenant_id=tenant.tenant_id,
            name=matched["name"],
            deployment_type=infer_deployment_type("deployment"),
            source_path=matched["path"],
            meta=json.dumps({"target_type": "deployment", "source_type": "local"}),
        )
        deployment = await deployment_repo.create(deployment)
        await db.flush()
        target_id = deployment.id
    else:
        deployment = await deployment_repo.get(target_id)
        if not deployment or deployment.tenant_id != tenant.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target not found",
            )

    # Resolve API key from environment if not provided
    if not api_key and provider != "ollama":
        import os
        key_envs = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
        api_key = os.getenv(key_envs.get(provider, ""), "")

    # Run architecture analysis
    arch_map = await analyze_target_architecture(
        deployment=deployment,
        provider=provider,
        model=model,
        api_key=api_key,
        db=db,
    )

    # Return updated target detail
    return await get_target(target_id, tenant, db, deployment_repo, scan_repo)


@router.post(
    "/{target_id}/review-instructions",
    response_model=TargetDetailResponse,
    summary="Run LLM instruction security review",
    description=(
        "Use an LLM to analyze instruction file content (system prompts, rules "
        "files, CLAUDE.md, etc.) for security risks, missing controls, and "
        "hardening recommendations. Supports Ollama (local), OpenAI, and Anthropic."
    ),
)
async def review_instructions(
    target_id: str,
    tenant: CurrentTenantDep,
    db: DBSession,
    deployment_repo: DeploymentRepo,
    scan_repo: ScanRepo,
    provider: str = Query(default="ollama", description="LLM provider: ollama, openai, anthropic"),
    model: str | None = Query(default=None, description="Model name (auto-resolved if omitted)"),
    api_key: str | None = Query(default=None, alias="key", description="API key for cloud providers"),
) -> TargetDetailResponse:
    """Run LLM-powered security review on instruction content."""
    from mass.api.services.instruction_review import (
        get_instruction_content,
        review_instruction_content,
    )

    deployment = await deployment_repo.get(target_id)
    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    meta = _parse_meta(deployment)

    # Retrieve instruction content
    content = get_instruction_content(deployment, meta)
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No instruction content found. Provide inline content, system prompt, or a source file path.",
        )

    # Resolve API key from environment if not provided
    if not api_key and provider != "ollama":
        import os
        key_envs = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
        api_key = os.getenv(key_envs.get(provider, ""), "")

    # Run LLM review
    await review_instruction_content(
        content=content,
        deployment=deployment,
        provider=provider,
        model=model,
        api_key=api_key,
        db=db,
    )

    # Return updated target detail
    return await get_target(target_id, tenant, db, deployment_repo, scan_repo)


@router.put(
    "/{target_id}/questionnaire",
    summary="Save risk questionnaire",
    description=(
        "Save user-provided risk context for a target. Computes a risk multiplier "
        "based on deployment environment, data sensitivity, and compliance requirements."
    ),
)
async def save_questionnaire(
    target_id: str,
    body: RiskQuestionnaire,
    tenant: CurrentTenantDep,
    db: DBSession,
    deployment_repo: DeploymentRepo,
) -> dict:
    """Save risk questionnaire and compute risk factors."""
    from mass.api.schemas.questionnaire import compute_risk_factors

    # Handle filesystem-only targets: promote to DB deployment first
    if target_id.startswith("fs-"):
        fs_targets = _scan_filesystem_targets()
        matched = None
        for fs in fs_targets:
            if _synthetic_id(fs["path"]) == target_id:
                matched = fs
                break
        if not matched:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Filesystem target not found",
            )
        from mass.core.target_helpers import infer_deployment_type
        deployment = Deployment(
            tenant_id=tenant.tenant_id,
            name=matched["name"],
            deployment_type=infer_deployment_type("deployment"),
            source_path=matched["path"],
            meta=json.dumps({"target_type": "deployment", "source_type": "local"}),
        )
        deployment = await deployment_repo.create(deployment)
        await db.flush()
    else:
        deployment = await deployment_repo.get(target_id)
        if not deployment or deployment.tenant_id != tenant.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target not found",
            )

    meta = _parse_meta(deployment)

    questionnaire_data = body.model_dump(exclude_none=True)
    meta["risk_questionnaire"] = questionnaire_data

    # Compute risk posture
    multiplier, factors = compute_risk_factors(body)
    level = "low"
    if multiplier >= 3.0:
        level = "critical"
    elif multiplier >= 2.0:
        level = "high"
    elif multiplier >= 1.5:
        level = "medium"

    meta["risk_posture"] = {
        "multiplier": multiplier,
        "level": level,
        "factors": factors,
    }

    deployment.meta = json.dumps(meta)
    await db.commit()

    return {
        "questionnaire": questionnaire_data,
        "risk_multiplier": multiplier,
        "risk_factors": factors,
        "risk_level": level,
    }


@router.post(
    "/{target_id}/verify",
    summary="Verify fixes via rescan",
    description=(
        "Trigger a verification rescan of the target and compare findings "
        "with the most recent completed scan. Returns scan IDs for polling."
    ),
)
async def verify_fixes(
    target_id: str,
    tenant: CurrentTenantDep,
    db: DBSession,
    deployment_repo: DeploymentRepo,
    scan_repo: ScanRepo,
    background_tasks: BackgroundTasks,
) -> dict:
    """Dispatch a verification rescan and return IDs for comparison."""
    from mass.core.types import ScanStatus

    deployment = await deployment_repo.get(target_id)
    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    # Find most recent completed scan
    scans = await scan_repo.list_by_deployment(target_id, limit=10)
    baseline_scan = None
    for s in scans:
        if s.status == "completed":
            baseline_scan = s
            break

    if not baseline_scan:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No completed scan found for this target. Run a scan first.",
        )

    # Create verification scan with same profile
    from mass.storage.models.deployment import Scan

    verification_scan = Scan(
        tenant_id=tenant.tenant_id,
        deployment_id=target_id,
        profile=baseline_scan.profile,
        status=ScanStatus.PENDING.value,
        total_findings=0,
        critical_findings=0,
        high_findings=0,
        medium_findings=0,
        low_findings=0,
    )
    created_scan = await scan_repo.create(verification_scan)
    await db.commit()

    # Dispatch scan
    dispatched = False
    try:
        from mass.api.dependencies import get_scan_queue

        queue = await get_scan_queue()
        if queue is not None:
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
    except Exception as e:
        logger.warning("Verify: queue dispatch failed: %s", e)

    if not dispatched:
        from mass.api.services.scan_execution import ScanExecutionService

        scan_service = ScanExecutionService()
        background_tasks.add_task(scan_service.execute_scan, created_scan.id)

    return {
        "verification_scan_id": created_scan.id,
        "baseline_scan_id": baseline_scan.id,
        "status": "dispatched",
        "message": "Verification scan started. Poll scan status and then compare results.",
    }
