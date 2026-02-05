"""Scan endpoints.

CRUD operations for security scans and scan management.
"""

import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException, status

from mass.api.dependencies import (
    CurrentTenantDep,
    DBSession,
    ScanRepo,
    DeploymentRepo,
    FindingRepo,
    PaginationDep,
    get_scan_queue,
)
from mass.api.services.scan_execution import ScanExecutionService

logger = logging.getLogger(__name__)
from mass.api.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanListResponse,
    ScanStatusResponse,
    ScanCancelResponse,
    ScanSeverityCounts,
    ScanJobResponse,
)
from mass.api.schemas.deployment import DeploymentSummary
from mass.api.schemas.finding import FindingResponse, FindingListResponse, FindingSummary
from mass.api.schemas.common import PaginationMeta
from mass.core.types import ScanStatus
from mass.storage.models.deployment import Scan

router = APIRouter()


def _scan_to_response(scan: Scan, include_jobs: bool = False) -> ScanResponse:
    """Convert a scan model to response schema.

    Maps actual model fields to API schema fields.
    """
    import json

    # Extract deployment info if available (don't trigger lazy loading)
    deployment_id = scan.deployment_id
    deployment_name = "Unknown"
    deployment_version = None

    # Only access deployment if it's already loaded
    if hasattr(scan, '__dict__') and 'deployment' in scan.__dict__:
        if scan.deployment:
            deployment_id = scan.deployment.id
            deployment_name = scan.deployment.name
            # Extract version from deployment meta
            if scan.deployment.meta:
                try:
                    meta_data = json.loads(scan.deployment.meta)
                    deployment_version = meta_data.get("version")
                except (json.JSONDecodeError, TypeError):
                    pass

    deployment_summary = DeploymentSummary(
        id=deployment_id,
        name=deployment_name,
        version=deployment_version,
    )

    # Model doesn't have jobs relationship in current implementation
    jobs = None

    return ScanResponse(
        id=scan.id,
        deployment=deployment_summary,
        name=None,  # Model doesn't have name field
        profile=scan.profile,
        status=scan.status,
        status_message=scan.error_message,  # Map error_message to status_message
        progress_percent=scan.progress_percent,
        current_phase=scan.current_phase,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=scan.duration_seconds,
        findings_count=scan.total_findings,
        severity_counts=ScanSeverityCounts(
            critical=scan.critical_findings,
            high=scan.high_findings,
            medium=scan.medium_findings,
            low=scan.low_findings,
            info=0,  # Model doesn't track info severity
        ),
        triggered_by=None,  # Model doesn't track triggered_by
        jobs=jobs,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
    )


@router.get(
    "",
    response_model=ScanListResponse,
    summary="List scans",
    description="List all scans for the current tenant.",
)
async def list_scans(
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    pagination: PaginationDep,
    deployment_id: str | None = None,
    status_filter: ScanStatus | None = None,
) -> ScanListResponse:
    """List all scans for the authenticated tenant."""
    filters = {"tenant_id": tenant.tenant_id}
    if deployment_id:
        filters["deployment_id"] = deployment_id
    if status_filter:
        filters["status"] = status_filter

    scans = await scan_repo.list(
        offset=pagination.offset,
        limit=pagination.limit,
        **filters,
    )

    total = await scan_repo.count(**filters)

    items = [_scan_to_response(s) for s in scans]

    return ScanListResponse(
        items=items,
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=pagination.offset + len(items) < total,
        ),
    )


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start scan",
    description="Start a new security scan on a deployment.",
)
async def start_scan(
    request: ScanCreate,
    background_tasks: BackgroundTasks,
    tenant: CurrentTenantDep,
    db: DBSession,
    scan_repo: ScanRepo,
    deployment_repo: DeploymentRepo,
) -> ScanResponse:
    """Start a new scan on a deployment.

    Dispatches the scan to a Redis-backed worker queue for execution
    in a separate container. Falls back to in-process BackgroundTasks
    if Redis is unavailable.

    Enforces the `scan_max_concurrent` configuration limit to prevent
    overloading when many deployments are submitted simultaneously.
    """
    import json
    from mass.core.config import get_settings

    # Verify deployment exists and belongs to tenant
    deployment = await deployment_repo.get(request.deployment_id)
    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    # Enforce concurrent scan limit to prevent overload
    settings = get_settings()
    active_count = await scan_repo.count(
        tenant_id=tenant.tenant_id,
        status="running",
    )
    pending_count = await scan_repo.count(
        tenant_id=tenant.tenant_id,
        status="pending",
    )
    if active_count + pending_count >= settings.scan_max_concurrent:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Concurrent scan limit reached ({settings.scan_max_concurrent}). "
                f"Currently {active_count} running, {pending_count} pending. "
                f"Wait for active scans to complete or increase scan_max_concurrent."
            ),
        )

    # Create the scan (only using fields that exist in model)
    scan = Scan(
        tenant_id=tenant.tenant_id,
        deployment_id=request.deployment_id,
        profile=request.profile.value if hasattr(request.profile, 'value') else request.profile,
        status=ScanStatus.PENDING.value,
        config=json.dumps(request.config) if request.config else None,
        # Initialize findings counters
        total_findings=0,
        critical_findings=0,
        high_findings=0,
        medium_findings=0,
        low_findings=0,
    )

    created = await scan_repo.create(scan)

    # Commit scan to DB before dispatching (worker/background task uses its own session)
    await db.commit()

    # Try to dispatch to worker via Redis queue
    dispatched = False
    queue = await get_scan_queue()
    if queue is not None:
        try:
            from mass.workers.base import Job, JobPriority

            job = Job(
                job_type="full_scan",
                payload={"scan_id": created.id},
                scan_id=created.id,
                tenant_id=tenant.tenant_id,
                queue_name="scans",
                timeout_seconds=1800,
                priority=JobPriority.NORMAL,
            )
            await queue.enqueue(job)
            dispatched = True
            logger.info("Scan %s dispatched to worker queue", created.id)
        except Exception as e:
            logger.warning(
                "Failed to enqueue scan %s to Redis, falling back to in-process: %s",
                created.id, e,
            )

    # Fallback: run in-process via BackgroundTasks
    if not dispatched:
        logger.info("Scan %s running in-process (no worker queue)", created.id)
        scan_service = ScanExecutionService()
        background_tasks.add_task(scan_service.execute_scan, created.id)

    # Return response (scan will be executed in background)
    return _scan_to_response(created)


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan",
    description="Get details of a specific scan.",
)
async def get_scan(
    scan_id: str,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    include_jobs: bool = False,
) -> ScanResponse:
    """Get details of a specific scan."""
    scan = await scan_repo.get_with_findings(scan_id)

    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return _scan_to_response(scan, include_jobs=include_jobs)


@router.get(
    "/{scan_id}/status",
    response_model=ScanStatusResponse,
    summary="Get scan status",
    description="Get the current status and progress of a scan.",
)
async def get_scan_status(
    scan_id: str,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
) -> ScanStatusResponse:
    """Get the current status of a scan."""
    scan = await scan_repo.get(scan_id)

    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return ScanStatusResponse(
        id=scan.id,
        status=scan.status,
        progress_percent=scan.progress_percent,
        current_phase=scan.current_phase,
        status_message=scan.error_message,
        jobs_completed=scan.jobs_completed,
        jobs_total=scan.jobs_total,
    )


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanCancelResponse,
    summary="Cancel scan",
    description="Cancel a running scan.",
)
async def cancel_scan(
    scan_id: str,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
) -> ScanCancelResponse:
    """Cancel a running scan."""
    scan = await scan_repo.get(scan_id)

    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    # Only pending or running scans can be cancelled
    if scan.status not in (ScanStatus.PENDING, ScanStatus.QUEUED, ScanStatus.RUNNING):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan with status: {scan.status}",
        )

    # Update scan status
    await scan_repo.update(
        scan,
        status=ScanStatus.CANCELLED,
        status_message="Cancelled by user",
        completed_at=datetime.now(timezone.utc),
    )

    # TODO: Signal workers to stop processing

    return ScanCancelResponse(
        id=scan.id,
        status=ScanStatus.CANCELLED,
        message="Scan cancelled successfully",
    )


@router.get(
    "/{scan_id}/findings",
    response_model=FindingListResponse,
    summary="Get scan findings",
    description="Get all findings from a scan.",
)
async def get_scan_findings(
    scan_id: str,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    finding_repo: FindingRepo,
    pagination: PaginationDep,
    severity: str | None = None,
    category: str | None = None,
) -> FindingListResponse:
    """Get all findings from a scan."""
    scan = await scan_repo.get(scan_id)

    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    filters = {"scan_id": scan_id}
    if severity:
        filters["severity"] = severity
    if category:
        filters["category"] = category

    findings = await finding_repo.list(
        offset=pagination.offset,
        limit=pagination.limit,
        **filters,
    )

    total = await finding_repo.count(**filters)

    # Convert DB findings to response models
    # DB model has different fields than the schema expects, so we map them
    from mass.api.schemas.finding import ComplianceMapping
    import json

    items = []
    for f in findings:
        # Parse meta JSON for fields stored there by scan_execution
        meta_data = {}
        if f.meta:
            try:
                meta_data = json.loads(f.meta)
            except (json.JSONDecodeError, TypeError):
                pass

        # Map singular DB fields to schema list fields
        cwe_ids = [f.cwe_id] if f.cwe_id else []
        owasp_ids = [f.owasp_category] if f.owasp_category else []
        mitre_ids = [f.mitre_technique] if f.mitre_technique else []
        tags = meta_data.get("tags", [])

        items.append(
            FindingResponse(
                id=f.id,
                scan_id=f.scan_id,
                title=f.title,
                description=f.description,
                severity=f.severity,
                category=f.category,
                component_type=meta_data.get("component_type", "unknown"),
                component_name=meta_data.get("component_name", "unknown"),
                file_path=f.file_path,
                line_number=f.line_number,
                confidence=meta_data.get("confidence", 1.0),
                false_positive=False,
                suppressed=False,
                acknowledged=False,
                acknowledged_by=None,
                acknowledged_at=None,
                compliance=ComplianceMapping(
                    cwe_ids=cwe_ids,
                    owasp_ids=owasp_ids,
                    mitre_ids=mitre_ids,
                ),
                probe_name=meta_data.get("probe_name"),
                detector_name=meta_data.get("detector_name"),
                tags=tags,
                created_at=f.created_at,
                updated_at=f.updated_at,
            )
        )

    return FindingListResponse(
        items=items,
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=pagination.offset + len(items) < total,
        ),
    )


@router.get(
    "/{scan_id}/summary",
    response_model=FindingSummary,
    summary="Get findings summary",
    description="Get a summary of findings from a scan.",
)
async def get_scan_findings_summary(
    scan_id: str,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    finding_repo: FindingRepo,
) -> FindingSummary:
    """Get a summary of findings from a scan."""
    scan = await scan_repo.get(scan_id)

    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    # Build summary from actual DB data
    by_severity = await finding_repo.count_by_severity(scan_id)
    by_category = await finding_repo.count_by_category(scan_id)
    total = await finding_repo.count(scan_id=scan_id)

    return FindingSummary(
        total=total,
        by_severity=by_severity,
        by_category=by_category,
        by_component={},
        false_positives=0,
        suppressed=0,
        acknowledged=0,
    )
