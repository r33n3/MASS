"""Report endpoints.

Generate and export scan reports.
"""

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, HTTPException, status

from mass.api.dependencies import (
    CurrentTenantDep,
    ScanRepo,
    ReportRepo,
    PaginationDep,
)
from mass.api.schemas.report import (
    ReportCreate,
    ReportResponse,
    ReportListResponse,
    ExportRequest,
    ExportResponse,
    CompareRequest,
    CompareResponse,
    FindingDiff,
)
from mass.api.schemas.common import PaginationMeta
from mass.storage.models.report import Report

router = APIRouter()


def _report_to_response(report: Report) -> ReportResponse:
    """Convert a report model to response schema."""
    return ReportResponse(
        id=report.id,
        scan_id=report.scan_id,
        name=report.name,
        report_type=report.report_type,
        format=report.format,
        status=report.status,
        file_size=report.file_size,
        file_path=report.file_path,
        error_message=report.error_message,
        generated_at=report.generated_at,
        expires_at=report.expires_at,
        created_at=report.created_at,
        updated_at=report.updated_at,
    )


@router.get(
    "",
    response_model=ReportListResponse,
    summary="List reports",
    description="List all reports for the current tenant.",
)
async def list_reports(
    tenant: CurrentTenantDep,
    report_repo: ReportRepo,
    pagination: PaginationDep,
    scan_id: str | None = None,
    status_filter: str | None = None,
) -> ReportListResponse:
    """List all reports for the authenticated tenant."""
    filters = {"tenant_id": tenant.tenant_id}
    if scan_id:
        filters["scan_id"] = scan_id
    if status_filter:
        filters["status"] = status_filter

    reports = await report_repo.list(
        offset=pagination.offset,
        limit=pagination.limit,
        **filters,
    )

    total = await report_repo.count(**filters)

    items = [_report_to_response(r) for r in reports]

    return ReportListResponse(
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
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate report",
    description="Generate a new report from scan results.",
)
async def generate_report(
    request: ReportCreate,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    report_repo: ReportRepo,
) -> ReportResponse:
    """Generate a new report from scan results."""
    # Verify scan exists and belongs to tenant
    scan = await scan_repo.get(request.scan_id)

    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    # Create report record
    report = Report(
        tenant_id=tenant.tenant_id,
        scan_id=request.scan_id,
        name=request.name or f"Report - {scan.name or scan.id}",
        report_type=request.report_type,
        format=request.format,
        status="pending",
    )

    created = await report_repo.create(report)

    # TODO: Queue report generation for async processing

    return _report_to_response(created)


@router.get(
    "/{report_id}",
    response_model=ReportResponse,
    summary="Get report",
    description="Get details of a specific report.",
)
async def get_report(
    report_id: str,
    tenant: CurrentTenantDep,
    report_repo: ReportRepo,
) -> ReportResponse:
    """Get details of a specific report."""
    report = await report_repo.get(report_id)

    if not report or report.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )

    return _report_to_response(report)


@router.post(
    "/{report_id}/export",
    response_model=ExportResponse,
    summary="Export report",
    description="Export a report in a specific format.",
)
async def export_report(
    report_id: str,
    request: ExportRequest,
    tenant: CurrentTenantDep,
    report_repo: ReportRepo,
) -> ExportResponse:
    """Export a report in a specific format."""
    report = await report_repo.get(report_id)

    if not report or report.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )

    if report.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report is not yet completed",
        )

    # TODO: Generate export in requested format
    # For now, return a placeholder response

    return ExportResponse(
        download_url=f"/api/v1/reports/{report_id}/download?format={request.format}",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        format=request.format,
        file_size=0,  # TODO: Calculate actual size
    )


@router.post(
    "/compare",
    response_model=CompareResponse,
    summary="Compare scans",
    description="Compare findings between two scans.",
)
async def compare_scans(
    request: CompareRequest,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
) -> CompareResponse:
    """Compare findings between two scans."""
    # Verify both scans exist and belong to tenant
    scan1 = await scan_repo.get(request.scan_id_1)
    scan2 = await scan_repo.get(request.scan_id_2)

    if not scan1 or scan1.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {request.scan_id_1} not found",
        )

    if not scan2 or scan2.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {request.scan_id_2} not found",
        )

    # TODO: Implement actual comparison logic
    # For now, return a placeholder response

    return CompareResponse(
        scan_id_1=request.scan_id_1,
        scan_id_2=request.scan_id_2,
        scan_1_date=scan1.created_at,
        scan_2_date=scan2.created_at,
        new_findings=0,
        fixed_findings=0,
        unchanged_findings=0,
        changed_findings=0,
        severity_trend={},
        differences=[],
    )


@router.delete(
    "/{report_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete report",
    description="Delete a report.",
)
async def delete_report(
    report_id: str,
    tenant: CurrentTenantDep,
    report_repo: ReportRepo,
) -> None:
    """Delete a report."""
    report = await report_repo.get(report_id)

    if not report or report.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )

    await report_repo.delete(report)

    # TODO: Clean up associated files from blob storage
