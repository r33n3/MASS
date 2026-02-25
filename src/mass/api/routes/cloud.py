"""Cloud-native ecosystem endpoints.

Discover cloud-hosted AI resources, assess their security posture,
and manage cloud account integrations across AWS, Azure, GCP, and Kubernetes.
Per ARCHITECTURE.md Section 8.1 — Cloud-Native module slot.
"""

import logging

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status

from mass.api.dependencies import CurrentTenantDep, PaginationDep
from mass.api.schemas.cloud import (
    AssessmentListResponse,
    AssessmentRequest,
    AssessmentResponse,
    CloudAccountCreate,
    CloudAccountListResponse,
    CloudAccountResponse,
    CloudAccountUpdate,
    CloudResourceListResponse,
    CloudResourceResponse,
    CloudStatusResponse,
    DiscoveryListResponse,
    DiscoveryRequest,
    DiscoveryResponse,
)
from mass.api.schemas.common import PaginationMeta, SuccessResponse
from mass.api.services import cloud as svc

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Cloud Account CRUD
# ---------------------------------------------------------------------------

@router.post(
    "/accounts",
    response_model=CloudAccountResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register cloud account",
    description="Register a cloud account (AWS, Azure, GCP, Kubernetes) for resource discovery.",
)
async def create_account(
    body: CloudAccountCreate,
    tenant: CurrentTenantDep,
) -> CloudAccountResponse:
    data = body.model_dump()
    record = await svc.create_account(tenant.tenant_id, data)
    return CloudAccountResponse(**record)


@router.get(
    "/accounts",
    response_model=CloudAccountListResponse,
    summary="List cloud accounts",
)
async def list_accounts(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
) -> CloudAccountListResponse:
    items, total = await svc.list_accounts(
        tenant_id=tenant.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return CloudAccountListResponse(
        items=[CloudAccountResponse(**a) for a in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


@router.get(
    "/accounts/{account_id}",
    response_model=CloudAccountResponse,
    summary="Get cloud account",
)
async def get_account(
    account_id: str,
    tenant: CurrentTenantDep,
) -> CloudAccountResponse:
    account = await svc.get_account(account_id)
    if not account or account.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Account not found")
    return CloudAccountResponse(**account)


@router.patch(
    "/accounts/{account_id}",
    response_model=CloudAccountResponse,
    summary="Update cloud account",
)
async def update_account(
    account_id: str,
    body: CloudAccountUpdate,
    tenant: CurrentTenantDep,
) -> CloudAccountResponse:
    existing = await svc.get_account(account_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Account not found")
    updated = await svc.update_account(account_id, body.model_dump(exclude_none=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Account not found")
    return CloudAccountResponse(**updated)


@router.delete(
    "/accounts/{account_id}",
    response_model=SuccessResponse,
    summary="Delete cloud account",
)
async def delete_account(
    account_id: str,
    tenant: CurrentTenantDep,
) -> SuccessResponse:
    existing = await svc.get_account(account_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Account not found")
    await svc.delete_account(account_id)
    return SuccessResponse(message="Account deleted")


# ---------------------------------------------------------------------------
# Resource Discovery
# ---------------------------------------------------------------------------

@router.post(
    "/discover",
    response_model=DiscoveryResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start resource discovery",
    description=(
        "Discover AI/ML resources in a registered cloud account. "
        "Scans Terraform configs, Kubernetes manifests, and cloud APIs."
    ),
)
async def start_discovery(
    body: DiscoveryRequest,
    tenant: CurrentTenantDep,
    background_tasks: BackgroundTasks,
) -> DiscoveryResponse:
    # Verify account ownership
    account = await svc.get_account(body.account_id)
    if not account or account.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Account not found")

    data = body.model_dump()
    data["resource_types"] = [rt.value if hasattr(rt, "value") else rt for rt in body.resource_types]
    job = await svc.create_discovery(tenant.tenant_id, data)
    background_tasks.add_task(svc.run_discovery, job["id"])
    return DiscoveryResponse(**job)


@router.get(
    "/discover/{job_id}",
    response_model=DiscoveryResponse,
    summary="Get discovery status",
)
async def get_discovery(
    job_id: str,
    tenant: CurrentTenantDep,
) -> DiscoveryResponse:
    job = await svc.get_discovery(job_id)
    if not job or job.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Discovery job not found")
    return DiscoveryResponse(**job)


@router.get(
    "/discoveries",
    response_model=DiscoveryListResponse,
    summary="List discovery jobs",
)
async def list_discoveries(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
) -> DiscoveryListResponse:
    items, total = await svc.list_discoveries(
        tenant_id=tenant.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return DiscoveryListResponse(
        items=[DiscoveryResponse(**d) for d in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


# ---------------------------------------------------------------------------
# Cloud Resources
# ---------------------------------------------------------------------------

@router.get(
    "/resources",
    response_model=CloudResourceListResponse,
    summary="List discovered resources",
)
async def list_resources(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
    account_id: str | None = Query(default=None, description="Filter by account"),
    provider: str | None = Query(default=None, description="Filter by provider"),
    resource_type: str | None = Query(default=None, description="Filter by resource type"),
) -> CloudResourceListResponse:
    items, total = await svc.list_resources(
        tenant_id=tenant.tenant_id,
        account_id=account_id,
        provider=provider,
        resource_type=resource_type,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return CloudResourceListResponse(
        items=[CloudResourceResponse(**r) for r in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


@router.get(
    "/resources/{resource_id}",
    response_model=CloudResourceResponse,
    summary="Get cloud resource",
)
async def get_resource(
    resource_id: str,
    tenant: CurrentTenantDep,
) -> CloudResourceResponse:
    resource = await svc.get_resource(resource_id)
    if not resource or resource.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Resource not found")
    return CloudResourceResponse(**resource)


@router.delete(
    "/resources/{resource_id}",
    response_model=SuccessResponse,
    summary="Delete cloud resource",
)
async def delete_resource(
    resource_id: str,
    tenant: CurrentTenantDep,
) -> SuccessResponse:
    resource = await svc.get_resource(resource_id)
    if not resource or resource.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Resource not found")
    await svc.delete_resource(resource_id)
    return SuccessResponse(message="Resource deleted")


# ---------------------------------------------------------------------------
# Security Assessment
# ---------------------------------------------------------------------------

@router.post(
    "/assess",
    response_model=AssessmentResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Run security assessment",
    description=(
        "Assess security posture of discovered cloud resources. "
        "Runs 15 security checks covering encryption, access control, "
        "container security, data governance, and monitoring."
    ),
)
async def start_assessment(
    body: AssessmentRequest,
    tenant: CurrentTenantDep,
    background_tasks: BackgroundTasks,
) -> AssessmentResponse:
    account = await svc.get_account(body.account_id)
    if not account or account.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Account not found")

    job = await svc.create_assessment(tenant.tenant_id, body.model_dump())
    background_tasks.add_task(svc.run_assessment, job["id"])
    return AssessmentResponse(**job)


@router.get(
    "/assess/{job_id}",
    response_model=AssessmentResponse,
    summary="Get assessment status",
)
async def get_assessment(
    job_id: str,
    tenant: CurrentTenantDep,
) -> AssessmentResponse:
    job = await svc.get_assessment(job_id)
    if not job or job.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return AssessmentResponse(**job)


@router.get(
    "/assessments",
    response_model=AssessmentListResponse,
    summary="List assessments",
)
async def list_assessments(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
) -> AssessmentListResponse:
    items, total = await svc.list_assessments(
        tenant_id=tenant.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return AssessmentListResponse(
        items=[AssessmentResponse(**a) for a in items],
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
    response_model=CloudStatusResponse,
    summary="Cloud-native module status",
)
async def module_status(tenant: CurrentTenantDep) -> CloudStatusResponse:
    accounts, total_accounts = await svc.list_accounts(tenant_id=tenant.tenant_id, limit=5000)
    resources, total_resources = await svc.list_resources(tenant_id=tenant.tenant_id, limit=5000)
    _, total_assessments = await svc.list_assessments(tenant_id=tenant.tenant_id, limit=1)

    by_provider: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for r in resources:
        p = r.get("provider", "unknown")
        t = r.get("resource_type", "unknown")
        by_provider[p] = by_provider.get(p, 0) + 1
        by_type[t] = by_type.get(t, 0) + 1

    return CloudStatusResponse(
        status="healthy",
        total_accounts=total_accounts,
        total_resources=total_resources,
        total_assessments=total_assessments,
        resources_by_provider=by_provider,
        resources_by_type=by_type,
        supported_providers=svc.SUPPORTED_PROVIDERS,
        supported_resource_types=svc.SUPPORTED_RESOURCE_TYPES,
    )
