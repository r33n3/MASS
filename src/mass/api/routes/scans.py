"""Scan endpoints.

CRUD operations for security scans and scan management.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status

from mass.api.dependencies import (
    CurrentTenantDep,
    ScanRepo,
    DeploymentRepo,
    FindingRepo,
    PaginationDep,
)
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
from mass.storage.models.scan import Scan

router = APIRouter()


def _scan_to_response(scan: Scan, include_jobs: bool = False) -> ScanResponse:
    """Convert a scan model to response schema."""
    deployment_summary = DeploymentSummary(
        id=scan.deployment.id if scan.deployment else scan.deployment_id,
        name=scan.deployment.name if scan.deployment else "Unknown",
        version=scan.deployment.version if scan.deployment else None,
    )

    jobs = None
    if include_jobs and scan.jobs:
        jobs = [
            ScanJobResponse(
                id=job.id,
                job_type=job.job_type,
                component_id=job.component_id,
                status=job.status,
                progress_percent=job.progress_percent,
                items_total=job.items_total,
                items_completed=job.items_completed,
                started_at=job.started_at,
                completed_at=job.completed_at,
                findings_count=job.findings_count,
                error=job.error,
                created_at=job.created_at,
                updated_at=job.updated_at,
            )
            for job in scan.jobs
        ]

    return ScanResponse(
        id=scan.id,
        deployment=deployment_summary,
        name=scan.name,
        profile=scan.profile,
        status=scan.status,
        status_message=scan.status_message,
        progress_percent=scan.progress_percent,
        current_phase=scan.current_phase,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=scan.duration_seconds,
        findings_count=scan.findings_count,
        severity_counts=ScanSeverityCounts(
            critical=scan.critical_count,
            high=scan.high_count,
            medium=scan.medium_count,
            low=scan.low_count,
            info=scan.info_count,
        ),
        triggered_by=scan.triggered_by,
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
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    deployment_repo: DeploymentRepo,
) -> ScanResponse:
    """Start a new scan on a deployment."""
    import json

    # Verify deployment exists and belongs to tenant
    deployment = await deployment_repo.get(request.deployment_id)
    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    if not deployment.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot scan an inactive deployment",
        )

    # Create the scan
    scan = Scan(
        tenant_id=tenant.tenant_id,
        deployment_id=request.deployment_id,
        name=request.name,
        profile=request.profile,
        config=json.dumps(request.config) if request.config else None,
        status=ScanStatus.PENDING,
        progress_percent=0.0,
        findings_count=0,
        triggered_by=request.triggered_by or "api",
    )

    created = await scan_repo.create(scan)

    # TODO: Queue the scan for processing by workers

    # Reload with deployment relationship
    created = await scan_repo.get_with_deployment(created.id)

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
    scan = await scan_repo.get_with_deployment(scan_id)

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
        status_message=scan.status_message,
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

    # Convert to response models
    from mass.api.schemas.finding import ComplianceMapping
    import json

    items = []
    for f in findings:
        cwe_ids = json.loads(f.cwe_ids) if f.cwe_ids else []
        owasp_ids = json.loads(f.owasp_ids) if f.owasp_ids else []
        mitre_ids = json.loads(f.mitre_ids) if f.mitre_ids else []
        tags = json.loads(f.tags) if f.tags else []

        items.append(
            FindingResponse(
                id=f.id,
                scan_id=f.scan_id,
                title=f.title,
                description=f.description,
                severity=f.severity,
                category=f.category,
                component_type=f.component_type,
                component_name=f.component_name,
                file_path=f.file_path,
                line_number=f.line_number,
                confidence=f.confidence,
                false_positive=f.false_positive,
                suppressed=f.suppressed,
                acknowledged=f.acknowledged,
                acknowledged_by=f.acknowledged_by,
                acknowledged_at=f.acknowledged_at,
                compliance=ComplianceMapping(
                    cwe_ids=cwe_ids,
                    owasp_ids=owasp_ids,
                    mitre_ids=mitre_ids,
                ),
                probe_name=f.probe_name,
                detector_name=f.detector_name,
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

    summary = await finding_repo.get_summary(scan_id)

    return FindingSummary(**summary)
