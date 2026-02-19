"""Privacy risk analysis endpoints.

Run privacy impact assessments, track PII exposure, manage data flows,
and check compliance against GDPR/CCPA/HIPAA and other frameworks.
Per ARCHITECTURE.md Section 8.1 — Privacy module slot.
"""

import logging

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status

from mass.api.dependencies import CurrentTenantDep, PaginationDep
from mass.api.schemas.common import PaginationMeta, SuccessResponse
from mass.api.schemas.privacy import (
    DataFlowCreate,
    DataFlowListResponse,
    DataFlowResponse,
    DataFlowUpdate,
    FrameworkCheckListResponse,
    FrameworkCheckRequest,
    FrameworkCheckResponse,
    PIAListResponse,
    PIARequest,
    PIAResponse,
    PIIExposureResponse,
    PrivacyStatusResponse,
)
from mass.api.services import privacy as svc

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Privacy Impact Assessment
# ---------------------------------------------------------------------------

@router.post(
    "/assess",
    response_model=PIAResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Run privacy impact assessment",
    description=(
        "Start a Privacy Impact Assessment that scans for PII exposure, "
        "analyzes data flows, and checks compliance against selected frameworks."
    ),
)
async def create_assessment(
    body: PIARequest,
    tenant: CurrentTenantDep,
    background_tasks: BackgroundTasks,
) -> PIAResponse:
    frameworks = [f.value for f in body.frameworks]
    pia = await svc.create_pia(tenant.tenant_id, {
        "scan_id": body.scan_id,
        "deployment_id": body.deployment_id,
        "frameworks": frameworks,
        "include_pii_scan": body.include_pii_scan,
        "include_data_flow": body.include_data_flow,
        "include_recommendations": body.include_recommendations,
    })
    background_tasks.add_task(svc.run_pia, pia["id"])
    return PIAResponse(**pia)


@router.get(
    "/assess/{pia_id}",
    response_model=PIAResponse,
    summary="Get privacy assessment",
)
async def get_assessment(
    pia_id: str,
    tenant: CurrentTenantDep,
) -> PIAResponse:
    pia = await svc.get_pia(pia_id)
    if not pia or pia.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return PIAResponse(**pia)


@router.get(
    "/assessments",
    response_model=PIAListResponse,
    summary="List privacy assessments",
)
async def list_assessments(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
) -> PIAListResponse:
    items, total = await svc.list_pias(
        tenant_id=tenant.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return PIAListResponse(
        items=[PIAResponse(**p) for p in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


# ---------------------------------------------------------------------------
# PII Exposure
# ---------------------------------------------------------------------------

@router.get(
    "/pii-exposure",
    response_model=PIIExposureResponse,
    summary="Get PII exposure summary",
    description="Get a summary of PII exposure across scan findings.",
)
async def get_pii_exposure(
    tenant: CurrentTenantDep,
    scan_id: str | None = Query(default=None, description="Filter by scan"),
) -> PIIExposureResponse:
    result = await svc.get_pii_exposure(tenant.tenant_id, scan_id)
    return PIIExposureResponse(**result)


# ---------------------------------------------------------------------------
# Data Flow CRUD
# ---------------------------------------------------------------------------

@router.post(
    "/data-flows",
    response_model=DataFlowResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create data flow",
    description="Document a data flow for privacy analysis and GDPR compliance.",
)
async def create_data_flow(
    body: DataFlowCreate,
    tenant: CurrentTenantDep,
) -> DataFlowResponse:
    record = await svc.create_data_flow(tenant.tenant_id, body.model_dump())
    return DataFlowResponse(**record)


@router.get(
    "/data-flows",
    response_model=DataFlowListResponse,
    summary="List data flows",
)
async def list_data_flows(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
    direction: str | None = Query(default=None, description="Filter: input, output, storage, transfer"),
) -> DataFlowListResponse:
    items, total = await svc.list_data_flows(
        tenant_id=tenant.tenant_id,
        direction=direction,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return DataFlowListResponse(
        items=[DataFlowResponse(**f) for f in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


@router.get(
    "/data-flows/{flow_id}",
    response_model=DataFlowResponse,
    summary="Get data flow",
)
async def get_data_flow(
    flow_id: str,
    tenant: CurrentTenantDep,
) -> DataFlowResponse:
    record = await svc.get_data_flow(flow_id)
    if not record or record.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Data flow not found")
    return DataFlowResponse(**record)


@router.patch(
    "/data-flows/{flow_id}",
    response_model=DataFlowResponse,
    summary="Update data flow",
)
async def update_data_flow(
    flow_id: str,
    body: DataFlowUpdate,
    tenant: CurrentTenantDep,
) -> DataFlowResponse:
    existing = await svc.get_data_flow(flow_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Data flow not found")
    record = await svc.update_data_flow(flow_id, body.model_dump(exclude_unset=True))
    return DataFlowResponse(**record)


@router.delete(
    "/data-flows/{flow_id}",
    response_model=SuccessResponse,
    summary="Delete data flow",
)
async def delete_data_flow(
    flow_id: str,
    tenant: CurrentTenantDep,
) -> SuccessResponse:
    existing = await svc.get_data_flow(flow_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Data flow not found")
    await svc.delete_data_flow(flow_id)
    return SuccessResponse(message="Data flow deleted")


# ---------------------------------------------------------------------------
# Framework compliance checks
# ---------------------------------------------------------------------------

@router.post(
    "/compliance",
    response_model=FrameworkCheckResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Run framework compliance check",
    description="Check compliance against a specific privacy framework (GDPR, OWASP LLM, EU AI Act).",
)
async def run_framework_check(
    body: FrameworkCheckRequest,
    tenant: CurrentTenantDep,
) -> FrameworkCheckResponse:
    record = await svc.run_framework_check(
        tenant_id=tenant.tenant_id,
        framework=body.framework.value,
        scan_id=body.scan_id,
    )
    return FrameworkCheckResponse(**record)


@router.get(
    "/compliance",
    response_model=FrameworkCheckListResponse,
    summary="List compliance checks",
)
async def list_compliance_checks(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
    framework: str | None = Query(default=None, description="Filter by framework"),
) -> FrameworkCheckListResponse:
    items, total = await svc.list_framework_checks(
        tenant_id=tenant.tenant_id,
        framework=framework,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return FrameworkCheckListResponse(
        items=[FrameworkCheckResponse(**c) for c in items],
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
    response_model=PrivacyStatusResponse,
    summary="Privacy module status",
)
async def module_status(tenant: CurrentTenantDep) -> PrivacyStatusResponse:
    pias, total_pias = await svc.list_pias(tenant_id=tenant.tenant_id, limit=5000)
    flows, total_flows = await svc.list_data_flows(tenant_id=tenant.tenant_id, limit=1)

    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    recent = sum(1 for p in pias if p.get("created_at", "") >= cutoff)

    high_risk = sum(
        1 for p in pias
        if p.get("overall_risk") in ("critical", "high")
    )

    return PrivacyStatusResponse(
        status="healthy",
        total_assessments=total_pias,
        total_data_flows=total_flows,
        recent_assessments=recent,
        high_risk_findings=high_risk,
        frameworks_available=list(svc.FRAMEWORK_CATALOG.keys()),
    )
