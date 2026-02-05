"""Report endpoints.

Generate and export scan reports.
"""

import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import Response

from mass.api.dependencies import (
    CurrentTenantDep,
    ScanRepo,
    ReportRepo,
    FindingRepo,
    PaginationDep,
    SettingsDep,
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
from mass.reporting.generator import ReportGenerator, ReportConfig, ReportFormat
from mass.core.findings import Finding as CoreFinding
from mass.core.types import AttackCategory, ComponentType, Severity

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


def _db_finding_to_core(db_finding) -> CoreFinding:
    """Convert database Finding to core Finding dataclass."""
    # Map severity string to enum
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    severity = severity_map.get(db_finding.severity.lower(), Severity.INFO)

    # Map category string to enum (with fallback to SENSITIVE_INFO)
    try:
        category = AttackCategory(db_finding.category)
    except ValueError:
        category = AttackCategory.SENSITIVE_INFO

    return CoreFinding(
        id=db_finding.id,
        title=db_finding.title,
        description=db_finding.description,
        severity=severity,
        category=category,
        component_type=ComponentType.MODEL,  # Default; could be enhanced
        component_name="deployment",
        file_path=db_finding.file_path,
        line_number=db_finding.line_number,
        cwe_ids=[db_finding.cwe_id] if db_finding.cwe_id else [],
        owasp_ids=[db_finding.owasp_category] if db_finding.owasp_category else [],
        mitre_ids=[db_finding.mitre_technique] if db_finding.mitre_technique else [],
        scan_id=db_finding.scan_id,
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
    finding_repo: FindingRepo,
    settings: SettingsDep,
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
        name=request.name or f"Report - {scan.id[:8]}",
        report_type=request.report_type,
        format=request.format,
        status="pending",
    )

    created = await report_repo.create(report)
    report_id = created.id

    # Load findings for the scan
    db_findings = await finding_repo.list_by_scan(request.scan_id, limit=10000)
    core_findings = [_db_finding_to_core(f) for f in db_findings]

    # Map request format to ReportFormat enum
    format_map = {
        "sarif": ReportFormat.SARIF,
        "html": ReportFormat.HTML,
        "json": ReportFormat.JSON,
        "pdf": ReportFormat.PDF,
    }
    report_format = format_map.get(request.format.lower(), ReportFormat.JSON)

    # Generate the report content (pure computation, no DB)
    try:
        config = ReportConfig(
            title=created.name,
            include_evidence=request.include_evidence,
            include_remediation=request.include_remediation,
        )
        generator = ReportGenerator(config)
        generated = generator.generate(
            format=report_format,
            findings=core_findings,
            scan_id=request.scan_id,
            metadata={"scan_id": scan.id, "profile": scan.profile},
        )

        # Save to data directory
        reports_dir = Path(settings.storage.local_path) / "reports" / tenant.tenant_id
        reports_dir.mkdir(parents=True, exist_ok=True)
        saved_path = generated.save(reports_dir)

        # Calculate file hash
        file_content = saved_path.read_bytes()
        file_hash = hashlib.sha256(file_content).hexdigest()

        # Mark completed
        created.status = "completed"
        created.file_path = str(saved_path)
        created.file_size = generated.size_bytes
        created.file_hash = file_hash
        created.generated_at = datetime.utcnow()
        await report_repo.session.flush()
        await report_repo.session.refresh(created)

    except Exception as e:
        import logging
        logging.getLogger(__name__).exception("Report generation failed")
        # Update status directly on the object to avoid session issues
        created.status = "failed"
        created.error_message = str(e)[:1000]
        try:
            await report_repo.session.flush()
            await report_repo.session.refresh(created)
        except Exception:
            pass  # If session is broken, return what we have

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

    return ExportResponse(
        download_url=f"/api/v1/reports/{report_id}/download",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        format=report.format,
        file_size=report.file_size or 0,
    )


@router.get(
    "/{report_id}/download",
    summary="Download report",
    description="Download the generated report file.",
)
async def download_report(
    report_id: str,
    tenant: CurrentTenantDep,
    report_repo: ReportRepo,
) -> Response:
    """Download a generated report file."""
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

    if not report.file_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file not found",
        )

    file_path = Path(report.file_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file not found on disk",
        )

    # Determine content type
    content_types = {
        "sarif": "application/sarif+json",
        "json": "application/json",
        "html": "text/html",
        "pdf": "application/pdf",
        "markdown": "text/markdown",
    }
    content_type = content_types.get(report.format, "application/octet-stream")

    # Read and return file
    content = file_path.read_bytes()

    return Response(
        content=content,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{file_path.name}"',
            "Content-Length": str(len(content)),
        },
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
