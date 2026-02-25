"""GitHub issue generation endpoints.

Export security findings as GitHub Issues so AI dev tools
(Copilot, Cursor, etc.) can auto-remediate them.
Per ARCHITECTURE.md Section 8.1 — Issue Generation module slot.
"""

import json
import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status

from mass.api.dependencies import (
    CurrentTenantDep,
    DBSession,
    FindingRepo,
    PaginationDep,
    ScanRepo,
)
from mass.api.schemas.common import PaginationMeta, SuccessResponse
from mass.api.schemas.integrations import (
    ExportedIssue,
    ExportedIssueListResponse,
    ExportRequest,
    ExportResponse,
    GitHubConfigCreate,
    GitHubConfigListResponse,
    GitHubConfigResponse,
    GitHubConfigUpdate,
    IntegrationsStatusResponse,
)
from mass.api.services import github_issues as svc

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# GitHub config CRUD
# ---------------------------------------------------------------------------

@router.post(
    "/github",
    response_model=GitHubConfigResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create GitHub integration",
    description="Configure a GitHub repository for issue export.",
)
async def create_github_config(
    body: GitHubConfigCreate,
    tenant: CurrentTenantDep,
) -> GitHubConfigResponse:
    data = body.model_dump()
    record = await svc.create_config(tenant.tenant_id, data)
    return GitHubConfigResponse(**svc.prepare_response(record))


@router.get(
    "/github",
    response_model=GitHubConfigListResponse,
    summary="List GitHub integrations",
)
async def list_github_configs(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
) -> GitHubConfigListResponse:
    items, total = await svc.list_configs(
        tenant_id=tenant.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return GitHubConfigListResponse(
        items=[GitHubConfigResponse(**svc.prepare_response(i)) for i in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


@router.get(
    "/github/{config_id}",
    response_model=GitHubConfigResponse,
    summary="Get GitHub integration",
)
async def get_github_config(
    config_id: str,
    tenant: CurrentTenantDep,
) -> GitHubConfigResponse:
    record = await svc.get_config(config_id)
    if not record or record.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="GitHub config not found")
    return GitHubConfigResponse(**svc.prepare_response(record))


@router.patch(
    "/github/{config_id}",
    response_model=GitHubConfigResponse,
    summary="Update GitHub integration",
)
async def update_github_config(
    config_id: str,
    body: GitHubConfigUpdate,
    tenant: CurrentTenantDep,
) -> GitHubConfigResponse:
    existing = await svc.get_config(config_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="GitHub config not found")

    updates = body.model_dump(exclude_unset=True)
    record = await svc.update_config(config_id, updates)
    return GitHubConfigResponse(**svc.prepare_response(record))


@router.delete(
    "/github/{config_id}",
    response_model=SuccessResponse,
    summary="Delete GitHub integration",
)
async def delete_github_config(
    config_id: str,
    tenant: CurrentTenantDep,
) -> SuccessResponse:
    existing = await svc.get_config(config_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="GitHub config not found")

    await svc.delete_config(config_id)
    return SuccessResponse(message="GitHub integration deleted")


# ---------------------------------------------------------------------------
# Export findings as GitHub Issues
# ---------------------------------------------------------------------------

@router.post(
    "/github/{config_id}/export",
    response_model=ExportResponse,
    summary="Export findings as GitHub Issues",
    description=(
        "Export security findings from a scan as GitHub Issues. "
        "Supports severity filtering, duplicate detection, and dry-run mode."
    ),
)
async def export_findings(
    config_id: str,
    body: ExportRequest,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    finding_repo: FindingRepo,
    background_tasks: BackgroundTasks,
) -> ExportResponse:
    """Export findings as GitHub Issues."""
    config = await svc.get_config(config_id)
    if not config or config.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="GitHub config not found")

    if not config.get("is_active"):
        raise HTTPException(status_code=400, detail="Integration is inactive")

    # Verify scan exists and belongs to tenant
    scan = await scan_repo.get(body.scan_id)
    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan is {scan.status}; export requires a completed scan",
        )

    # Load findings from DB
    finding_models = await finding_repo.list(
        offset=0, limit=10000, scan_id=body.scan_id,
    )

    # Convert DB models to dicts for the service
    findings: list[dict[str, Any]] = []
    for f in finding_models:
        finding_dict: dict[str, Any] = {
            "id": f.id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "category": f.category,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "code_snippet": f.code_snippet,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "cwe_id": f.cwe_id,
            "owasp_category": f.owasp_category,
            "mitre_technique": f.mitre_technique,
            "fingerprint": f.fingerprint,
            "confidence": getattr(f, "confidence", None),
        }

        # Apply category filter
        if body.categories and f.category not in body.categories:
            continue

        findings.append(finding_dict)

    # Run export
    result = await svc.export_findings(
        config=config,
        findings=findings,
        scan_id=body.scan_id,
        min_severity=body.min_severity,
        skip_duplicates=body.skip_duplicates,
        dry_run=body.dry_run,
    )

    # Broadcast event
    try:
        from mass.core.events import Event, EventType, publish_event
        await publish_event(Event(
            type=EventType.ISSUE_EXPORTED,
            data={
                "config_id": config_id,
                "scan_id": body.scan_id,
                "exported": result["exported"],
                "failed": result["failed"],
            },
            tenant_id=tenant.tenant_id,
        ))
    except Exception:
        pass

    logger.info(
        "Exported findings as GitHub Issues",
        extra={
            "config_id": config_id,
            "scan_id": body.scan_id,
            "exported": result["exported"],
            "skipped": result["skipped"],
            "failed": result["failed"],
            "dry_run": body.dry_run,
        },
    )

    return ExportResponse(**result)


# ---------------------------------------------------------------------------
# List exported issues
# ---------------------------------------------------------------------------

@router.get(
    "/github/{config_id}/issues",
    response_model=ExportedIssueListResponse,
    summary="List exported GitHub Issues",
)
async def list_exported_issues(
    config_id: str,
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
) -> ExportedIssueListResponse:
    config = await svc.get_config(config_id)
    if not config or config.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="GitHub config not found")

    items, total = await svc.list_exports(
        config_id=config_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )

    return ExportedIssueListResponse(
        items=[
            ExportedIssue(
                finding_id=e.get("finding_id", ""),
                finding_title=e.get("finding_title", ""),
                severity=e.get("severity", "medium"),
                github_issue_number=e.get("github_issue_number"),
                github_issue_url=e.get("github_issue_url"),
                status=e.get("status", "unknown"),
                error=e.get("error"),
            )
            for e in items
        ],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

@router.get(
    "/status",
    response_model=IntegrationsStatusResponse,
    summary="Integrations module status",
)
async def module_status(
    tenant: CurrentTenantDep,
) -> IntegrationsStatusResponse:
    configs, _ = await svc.list_configs(tenant_id=tenant.tenant_id, limit=1000)
    active = sum(1 for c in configs if c.get("is_active"))
    total_exported = sum(c.get("total_exported", 0) for c in configs)

    return IntegrationsStatusResponse(
        status="healthy",
        active_github_configs=active,
        total_exported=total_exported,
    )
