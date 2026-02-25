"""Threat intelligence endpoints.

Manage threat feeds, track MITRE ATLAS techniques, collect threat items,
and generate attack payloads from threat intelligence.
Per ARCHITECTURE.md Section 8.1 — Threat Intel module slot.
"""

import logging

from fastapi import APIRouter, HTTPException, Query, status

from mass.api.dependencies import CurrentTenantDep, PaginationDep
from mass.api.schemas.common import PaginationMeta, SuccessResponse
from mass.api.schemas.threat_intel import (
    CoverageResponse,
    FeedCreate,
    FeedListResponse,
    FeedResponse,
    FeedUpdate,
    GeneratePayloadsRequest,
    GeneratePayloadsResponse,
    GeneratedPayload,
    TechniqueListResponse,
    TechniqueResponse,
    ThreatIntelStatusResponse,
    ThreatItemCreate,
    ThreatItemListResponse,
    ThreatItemResponse,
    ThreatItemUpdate,
)
from mass.api.services import threat_intel as svc

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Feeds CRUD
# ---------------------------------------------------------------------------

@router.post(
    "/feeds",
    response_model=FeedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create threat feed",
    description="Register a new threat intelligence feed source.",
)
async def create_feed(
    body: FeedCreate,
    tenant: CurrentTenantDep,
) -> FeedResponse:
    record = await svc.create_feed(tenant.tenant_id, body.model_dump())
    return FeedResponse(**record)


@router.get(
    "/feeds",
    response_model=FeedListResponse,
    summary="List threat feeds",
)
async def list_feeds(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
) -> FeedListResponse:
    items, total = await svc.list_feeds(
        tenant_id=tenant.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return FeedListResponse(
        items=[FeedResponse(**f) for f in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


@router.get(
    "/feeds/{feed_id}",
    response_model=FeedResponse,
    summary="Get threat feed",
)
async def get_feed(feed_id: str, tenant: CurrentTenantDep) -> FeedResponse:
    record = await svc.get_feed(feed_id)
    if not record or record.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Feed not found")
    return FeedResponse(**record)


@router.patch(
    "/feeds/{feed_id}",
    response_model=FeedResponse,
    summary="Update threat feed",
)
async def update_feed(
    feed_id: str, body: FeedUpdate, tenant: CurrentTenantDep,
) -> FeedResponse:
    existing = await svc.get_feed(feed_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Feed not found")
    record = await svc.update_feed(feed_id, body.model_dump(exclude_unset=True))
    return FeedResponse(**record)


@router.delete(
    "/feeds/{feed_id}",
    response_model=SuccessResponse,
    summary="Delete threat feed",
)
async def delete_feed(feed_id: str, tenant: CurrentTenantDep) -> SuccessResponse:
    existing = await svc.get_feed(feed_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Feed not found")
    await svc.delete_feed(feed_id)
    return SuccessResponse(message="Feed deleted")


# ---------------------------------------------------------------------------
# Threat items
# ---------------------------------------------------------------------------

@router.post(
    "/items",
    response_model=ThreatItemResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create threat item",
    description="Manually add a threat item (CVE, advisory, attack pattern).",
)
async def create_item(
    body: ThreatItemCreate,
    tenant: CurrentTenantDep,
    feed_id: str | None = Query(default=None, description="Associate with a feed"),
) -> ThreatItemResponse:
    record = await svc.create_item(tenant.tenant_id, body.model_dump(), feed_id=feed_id)
    return ThreatItemResponse(**record)


@router.get(
    "/items",
    response_model=ThreatItemListResponse,
    summary="List threat items",
)
async def list_items(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
    feed_id: str | None = Query(default=None),
    item_status: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
) -> ThreatItemListResponse:
    items, total = await svc.list_items(
        tenant_id=tenant.tenant_id,
        feed_id=feed_id,
        status=item_status,
        severity=severity,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return ThreatItemListResponse(
        items=[ThreatItemResponse(**i) for i in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


@router.get(
    "/items/{item_id}",
    response_model=ThreatItemResponse,
    summary="Get threat item",
)
async def get_item(item_id: str, tenant: CurrentTenantDep) -> ThreatItemResponse:
    record = await svc.get_item(item_id)
    if not record or record.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Threat item not found")
    return ThreatItemResponse(**record)


@router.patch(
    "/items/{item_id}",
    response_model=ThreatItemResponse,
    summary="Update threat item",
)
async def update_item(
    item_id: str, body: ThreatItemUpdate, tenant: CurrentTenantDep,
) -> ThreatItemResponse:
    existing = await svc.get_item(item_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Threat item not found")
    record = await svc.update_item(item_id, body.model_dump(exclude_unset=True))
    return ThreatItemResponse(**record)


# ---------------------------------------------------------------------------
# Threat analysis (LLM-powered)
# ---------------------------------------------------------------------------

@router.post(
    "/items/{item_id}/analyze",
    response_model=ThreatItemResponse,
    summary="Analyze threat item",
    description="Use LLM to analyze a threat and generate recommendations.",
)
async def analyze_item(
    item_id: str, tenant: CurrentTenantDep,
) -> ThreatItemResponse:
    item = await svc.get_item(item_id)
    if not item or item.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Threat item not found")

    analysis = await svc.analyze_threat(item)
    item["analysis"] = analysis
    item["status"] = "analyzed"
    record = await svc.update_item(item_id, {"analysis": analysis, "status": "analyzed"})

    try:
        from mass.core.events import Event, EventType, publish_event
        await publish_event(Event(
            type=EventType.THREAT_ANALYZED,
            data={"item_id": item_id, "severity": item.get("severity")},
            tenant_id=tenant.tenant_id,
        ))
    except Exception:
        pass

    return ThreatItemResponse(**record)


# ---------------------------------------------------------------------------
# Payload generation
# ---------------------------------------------------------------------------

@router.post(
    "/items/{item_id}/generate-payloads",
    response_model=GeneratePayloadsResponse,
    summary="Generate payloads from threat",
    description="Generate attack payloads from a threat item for scanner enrichment.",
)
async def generate_payloads(
    item_id: str,
    body: GeneratePayloadsRequest,
    tenant: CurrentTenantDep,
) -> GeneratePayloadsResponse:
    item = await svc.get_item(item_id)
    if not item or item.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Threat item not found")

    payloads = await svc.generate_payloads_from_threat(
        item, count=body.count, target_categories=body.target_categories or None,
    )

    return GeneratePayloadsResponse(
        threat_item_id=item_id,
        payloads=[GeneratedPayload(**p) for p in payloads],
        generated_count=len(payloads),
    )


# ---------------------------------------------------------------------------
# MITRE ATLAS techniques & coverage
# ---------------------------------------------------------------------------

@router.get(
    "/techniques",
    response_model=TechniqueListResponse,
    summary="List MITRE ATLAS techniques",
    description="List MITRE ATLAS techniques with MASS coverage status.",
)
async def list_techniques(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
    tactic: str | None = Query(default=None, description="Filter by ATLAS tactic"),
    coverage: str | None = Query(default=None, description="Filter: covered, not_covered"),
) -> TechniqueListResponse:
    items, total = await svc.list_techniques(
        tenant_id=tenant.tenant_id,
        tactic=tactic,
        coverage_status=coverage,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return TechniqueListResponse(
        items=[TechniqueResponse(**_tech_response(t)) for t in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


@router.get(
    "/coverage",
    response_model=CoverageResponse,
    summary="MITRE ATLAS coverage summary",
    description="Get a summary of MASS scanner coverage of MITRE ATLAS techniques.",
)
async def get_coverage(tenant: CurrentTenantDep) -> CoverageResponse:
    summary = await svc.get_coverage_summary(tenant.tenant_id)
    return CoverageResponse(**summary)


def _tech_response(t: dict) -> dict:
    """Map stored technique record to response fields."""
    return {
        "id": t.get("technique_id", t.get("id", "")),
        "name": t.get("name", ""),
        "tactic": t.get("tactic", ""),
        "description": t.get("description", ""),
        "coverage_status": t.get("coverage_status", "not_covered"),
        "mapped_categories": t.get("mapped_categories", []),
        "mapped_probes": t.get("mapped_probes", []),
        "threat_items_count": t.get("threat_items_count", 0),
        "url": t.get("url"),
    }


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

@router.get(
    "/status",
    response_model=ThreatIntelStatusResponse,
    summary="Threat intelligence module status",
)
async def module_status(tenant: CurrentTenantDep) -> ThreatIntelStatusResponse:
    feeds, _ = await svc.list_feeds(tenant_id=tenant.tenant_id, limit=1000)
    active_feeds = sum(1 for f in feeds if f.get("is_active"))

    items, total_items = await svc.list_items(
        tenant_id=tenant.tenant_id, limit=5000,
    )

    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    new_24h = sum(1 for i in items if i.get("created_at", "") >= cutoff)
    actionable = sum(1 for i in items if i.get("status") == "actionable")

    coverage = await svc.get_coverage_summary(tenant.tenant_id)

    return ThreatIntelStatusResponse(
        status="healthy",
        active_feeds=active_feeds,
        total_items=total_items,
        new_items_24h=new_24h,
        actionable_items=actionable,
        technique_coverage_percent=coverage["coverage_percent"],
    )
