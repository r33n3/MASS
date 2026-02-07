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

from fastapi import APIRouter, HTTPException, Query, status

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

    # 3. Build path-to-deployment index for merging
    path_to_deployment: dict[str, Deployment] = {}
    for dep in deployments:
        if dep.source_path:
            path_to_deployment[_normalize_path(dep.source_path)] = dep

    # 4. Batch-fetch latest scans and counts (2 queries instead of 2*N)
    dep_ids = [dep.id for dep in deployments]
    latest_scans = await scan_repo.get_latest_by_deployments(dep_ids)
    scan_counts = await scan_repo.count_by_deployments(dep_ids)

    # 5. Merge filesystem and DB targets
    merged: list[TargetResponse] = []
    matched_deployment_ids: set[str] = set()

    # Filesystem targets — check if they have a matching deployment
    for fs in fs_targets:
        normalized = _normalize_path(fs["path"])
        deployment = path_to_deployment.get(normalized)

        if deployment:
            matched_deployment_ids.add(deployment.id)
            merged.append(_deployment_to_target_response(
                deployment,
                latest_scans.get(deployment.id),
                scan_counts.get(deployment.id, 0),
                fs_info=fs,
            ))
        else:
            merged.append(_fs_to_target_response(fs))

    # DB-only targets (no filesystem match — remote endpoints, deleted paths, etc.)
    for dep in deployments:
        if dep.id not in matched_deployment_ids:
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

    # Create deployment record (shared helper for type inference)
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
    )


@router.delete(
    "/{target_id}",
    response_model=SuccessResponse,
    summary="Delete target",
    description="Remove a target from the inventory (soft delete).",
)
async def delete_target(
    target_id: str,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> SuccessResponse:
    """Delete a target (soft delete)."""
    deployment = await deployment_repo.get(target_id)
    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    await deployment_repo.soft_delete(deployment)

    return SuccessResponse(message="Target deleted successfully")


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
