"""Cross-model collaborative security endpoints.

Run security probes against multiple LLM providers/models in parallel,
compare vulnerability profiles, and rank by security posture.
Per ARCHITECTURE.md Section 8.1 — Cross-Model module slot.
"""

import logging

from fastapi import APIRouter, BackgroundTasks, HTTPException, status

from mass.api.dependencies import CurrentTenantDep, PaginationDep
from mass.api.schemas.common import PaginationMeta, SuccessResponse
from mass.api.schemas.cross_model import (
    ComparisonCreate,
    ComparisonListResponse,
    ComparisonResponse,
    CrossModelStatusResponse,
)
from mass.api.services import cross_model as svc

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Comparison CRUD
# ---------------------------------------------------------------------------

@router.post(
    "/compare",
    response_model=ComparisonResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start cross-model comparison",
    description=(
        "Run the same security probes against multiple LLM models in parallel "
        "and compare their vulnerability profiles."
    ),
)
async def create_comparison(
    body: ComparisonCreate,
    tenant: CurrentTenantDep,
    background_tasks: BackgroundTasks,
) -> ComparisonResponse:
    models = [m.model_dump() for m in body.models]
    job = await svc.create_comparison(tenant.tenant_id, {
        "name": body.name,
        "models": models,
        "categories": body.categories,
        "probe_names": body.probe_names,
        "max_probes": body.max_probes,
        "max_prompts_per_probe": body.max_prompts_per_probe,
        "system_prompt": body.system_prompt,
        "prompt_timeout": body.prompt_timeout,
    })
    background_tasks.add_task(svc.run_comparison, job["id"])
    return ComparisonResponse(**job)


@router.get(
    "/compare/{job_id}",
    response_model=ComparisonResponse,
    summary="Get comparison status",
)
async def get_comparison(
    job_id: str,
    tenant: CurrentTenantDep,
) -> ComparisonResponse:
    job = await svc.get_comparison(job_id)
    if not job or job.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Comparison not found")
    return ComparisonResponse(**job)


@router.get(
    "/comparisons",
    response_model=ComparisonListResponse,
    summary="List comparisons",
)
async def list_comparisons(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
) -> ComparisonListResponse:
    items, total = await svc.list_comparisons(
        tenant_id=tenant.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return ComparisonListResponse(
        items=[ComparisonResponse(**c) for c in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


@router.post(
    "/compare/{job_id}/cancel",
    response_model=SuccessResponse,
    summary="Cancel comparison",
)
async def cancel_comparison(
    job_id: str,
    tenant: CurrentTenantDep,
) -> SuccessResponse:
    job = await svc.get_comparison(job_id)
    if not job or job.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Comparison not found")
    await svc.cancel_comparison(job_id)
    return SuccessResponse(message="Comparison cancelled")


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

@router.get(
    "/status",
    response_model=CrossModelStatusResponse,
    summary="Cross-model module status",
)
async def module_status(tenant: CurrentTenantDep) -> CrossModelStatusResponse:
    items, total = await svc.list_comparisons(tenant_id=tenant.tenant_id, limit=5000)

    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    recent = sum(1 for c in items if c.get("created_at", "") >= cutoff)

    return CrossModelStatusResponse(
        status="healthy",
        total_comparisons=total,
        recent_comparisons=recent,
        available_providers=svc.AVAILABLE_PROVIDERS,
        available_categories=svc.AVAILABLE_CATEGORIES,
    )
