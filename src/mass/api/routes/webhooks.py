"""Webhook endpoints.

Manage webhook subscriptions for event notifications.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from mass.api.dependencies import (
    CurrentTenantDep,
    PaginationDep,
)
from mass.api.schemas.report import (
    WebhookCreate,
    WebhookResponse,
    WebhookListResponse,
)
from mass.api.schemas.common import PaginationMeta, SuccessResponse

router = APIRouter()


# Supported webhook events
WEBHOOK_EVENTS = [
    "scan.started",
    "scan.completed",
    "scan.failed",
    "scan.cancelled",
    "finding.critical",
    "finding.high",
    "report.generated",
    "deployment.created",
    "deployment.updated",
    "deployment.deleted",
]


# In-memory webhook storage (TODO: Move to database)
_webhooks: dict[str, dict] = {}


class WebhookEventInfo(BaseModel):
    """Information about a webhook event type."""

    model_config = ConfigDict(extra="forbid")

    event: str = Field(..., description="Event name")
    description: str = Field(..., description="Event description")


@router.get(
    "/events",
    response_model=list[WebhookEventInfo],
    summary="List webhook events",
    description="List all available webhook event types.",
)
async def list_webhook_events() -> list[WebhookEventInfo]:
    """List all available webhook event types."""
    event_descriptions = {
        "scan.started": "Fired when a scan starts",
        "scan.completed": "Fired when a scan completes successfully",
        "scan.failed": "Fired when a scan fails",
        "scan.cancelled": "Fired when a scan is cancelled",
        "finding.critical": "Fired when a critical finding is discovered",
        "finding.high": "Fired when a high-severity finding is discovered",
        "report.generated": "Fired when a report is generated",
        "deployment.created": "Fired when a deployment is created",
        "deployment.updated": "Fired when a deployment is updated",
        "deployment.deleted": "Fired when a deployment is deleted",
    }

    return [
        WebhookEventInfo(event=e, description=event_descriptions.get(e, ""))
        for e in WEBHOOK_EVENTS
    ]


@router.get(
    "",
    response_model=WebhookListResponse,
    summary="List webhooks",
    description="List all webhooks for the current tenant.",
)
async def list_webhooks(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
) -> WebhookListResponse:
    """List all webhooks for the authenticated tenant."""
    # Filter webhooks by tenant
    tenant_webhooks = [
        w for w in _webhooks.values()
        if w.get("tenant_id") == tenant.tenant_id
    ]

    # Apply pagination
    start = pagination.offset
    end = start + pagination.limit
    paginated = tenant_webhooks[start:end]

    items = [
        WebhookResponse(
            id=w["id"],
            name=w["name"],
            url=w["url"],
            events=w["events"],
            is_active=w["is_active"],
            last_triggered_at=w.get("last_triggered_at"),
            failure_count=w.get("failure_count", 0),
            created_at=w["created_at"],
            updated_at=w["updated_at"],
        )
        for w in paginated
    ]

    return WebhookListResponse(
        items=items,
        pagination=PaginationMeta(
            total=len(tenant_webhooks),
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=end < len(tenant_webhooks),
        ),
    )


@router.post(
    "",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create webhook",
    description="Create a new webhook subscription.",
)
async def create_webhook(
    request: WebhookCreate,
    tenant: CurrentTenantDep,
) -> WebhookResponse:
    """Create a new webhook subscription."""
    import uuid
    from datetime import datetime, timezone

    # Validate events
    for event in request.events:
        if event not in WEBHOOK_EVENTS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown event type: {event}",
            )

    webhook_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    webhook = {
        "id": webhook_id,
        "tenant_id": tenant.tenant_id,
        "name": request.name,
        "url": request.url,
        "events": request.events,
        "secret": request.secret,  # TODO: Hash the secret
        "is_active": request.is_active,
        "failure_count": 0,
        "created_at": now,
        "updated_at": now,
    }

    _webhooks[webhook_id] = webhook

    return WebhookResponse(
        id=webhook["id"],
        name=webhook["name"],
        url=webhook["url"],
        events=webhook["events"],
        is_active=webhook["is_active"],
        failure_count=0,
        created_at=webhook["created_at"],
        updated_at=webhook["updated_at"],
    )


@router.get(
    "/{webhook_id}",
    response_model=WebhookResponse,
    summary="Get webhook",
    description="Get details of a specific webhook.",
)
async def get_webhook(
    webhook_id: str,
    tenant: CurrentTenantDep,
) -> WebhookResponse:
    """Get details of a specific webhook."""
    webhook = _webhooks.get(webhook_id)

    if not webhook or webhook.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )

    return WebhookResponse(
        id=webhook["id"],
        name=webhook["name"],
        url=webhook["url"],
        events=webhook["events"],
        is_active=webhook["is_active"],
        last_triggered_at=webhook.get("last_triggered_at"),
        failure_count=webhook.get("failure_count", 0),
        created_at=webhook["created_at"],
        updated_at=webhook["updated_at"],
    )


@router.delete(
    "/{webhook_id}",
    response_model=SuccessResponse,
    summary="Delete webhook",
    description="Delete a webhook subscription.",
)
async def delete_webhook(
    webhook_id: str,
    tenant: CurrentTenantDep,
) -> SuccessResponse:
    """Delete a webhook subscription."""
    webhook = _webhooks.get(webhook_id)

    if not webhook or webhook.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )

    del _webhooks[webhook_id]

    return SuccessResponse(message="Webhook deleted successfully")


@router.post(
    "/{webhook_id}/test",
    response_model=SuccessResponse,
    summary="Test webhook",
    description="Send a test event to the webhook.",
)
async def test_webhook(
    webhook_id: str,
    tenant: CurrentTenantDep,
) -> SuccessResponse:
    """Send a test event to a webhook."""
    webhook = _webhooks.get(webhook_id)

    if not webhook or webhook.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )

    # TODO: Actually send test webhook
    # import httpx
    # async with httpx.AsyncClient() as client:
    #     response = await client.post(webhook["url"], json={"event": "test", "data": {}})

    return SuccessResponse(message="Test webhook sent successfully")
