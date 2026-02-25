"""CI/CD integration endpoints.

Provides webhook receivers for GitHub/GitLab, integration management,
and quality gate endpoints for CI pipeline pass/fail decisions.
Per ARCHITECTURE.md Section 8.1 — CI/CD module slot.
"""

import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Header, Query, Request, status

from mass.api.dependencies import (
    CurrentTenantDep,
    DBSession,
    PaginationDep,
    ScanRepo,
    FindingRepo,
)
from mass.api.schemas.cicd import (
    CICDBuildListResponse,
    CICDBuildResponse,
    CICDIntegrationCreate,
    CICDIntegrationListResponse,
    CICDIntegrationResponse,
    CICDIntegrationUpdate,
    CICDStatusResponse,
    CICDWebhookResponse,
    GateResponse,
    GateSeverityCounts,
    GateVerdict,
)
from mass.api.schemas.common import PaginationMeta, SuccessResponse
from mass.api.services import cicd_integration as svc

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Integration CRUD
# ---------------------------------------------------------------------------

@router.post(
    "/integrations",
    response_model=CICDIntegrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create CI/CD integration",
    description="Register a new CI/CD integration (GitHub, GitLab, or generic webhook).",
)
async def create_integration(
    body: CICDIntegrationCreate,
    tenant: CurrentTenantDep,
) -> CICDIntegrationResponse:
    """Create a new CI/CD integration."""
    data = body.model_dump()
    record = await svc.create_integration(tenant.tenant_id, data)
    return CICDIntegrationResponse(**record)


@router.get(
    "/integrations",
    response_model=CICDIntegrationListResponse,
    summary="List CI/CD integrations",
)
async def list_integrations(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
) -> CICDIntegrationListResponse:
    """List CI/CD integrations for the current tenant."""
    items, total = await svc.list_integrations(
        tenant_id=tenant.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return CICDIntegrationListResponse(
        items=[CICDIntegrationResponse(**i) for i in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


@router.get(
    "/integrations/{integration_id}",
    response_model=CICDIntegrationResponse,
    summary="Get CI/CD integration",
)
async def get_integration(
    integration_id: str,
    tenant: CurrentTenantDep,
) -> CICDIntegrationResponse:
    """Get a specific CI/CD integration."""
    record = await svc.get_integration(integration_id)
    if not record or record.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Integration not found")
    return CICDIntegrationResponse(**record)


@router.patch(
    "/integrations/{integration_id}",
    response_model=CICDIntegrationResponse,
    summary="Update CI/CD integration",
)
async def update_integration(
    integration_id: str,
    body: CICDIntegrationUpdate,
    tenant: CurrentTenantDep,
) -> CICDIntegrationResponse:
    """Update a CI/CD integration's settings."""
    existing = await svc.get_integration(integration_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Integration not found")

    updates = body.model_dump(exclude_unset=True)
    record = await svc.update_integration(integration_id, updates)
    return CICDIntegrationResponse(**record)


@router.delete(
    "/integrations/{integration_id}",
    response_model=SuccessResponse,
    summary="Delete CI/CD integration",
)
async def delete_integration(
    integration_id: str,
    tenant: CurrentTenantDep,
) -> SuccessResponse:
    """Delete a CI/CD integration."""
    existing = await svc.get_integration(integration_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Integration not found")

    await svc.delete_integration(integration_id)
    return SuccessResponse(message="Integration deleted")


# ---------------------------------------------------------------------------
# Webhook receivers
# ---------------------------------------------------------------------------

@router.post(
    "/webhook/{provider}",
    response_model=CICDWebhookResponse,
    summary="Receive CI/CD webhook",
    description=(
        "Receive webhook events from GitHub, GitLab, or generic CI systems. "
        "Verifies signature, matches to an integration, and triggers a scan."
    ),
)
async def receive_webhook(
    provider: str,
    request: Request,
    background_tasks: BackgroundTasks,
    db: DBSession,
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    x_gitlab_token: str | None = Header(default=None, alias="X-Gitlab-Token"),
    x_webhook_secret: str | None = Header(default=None, alias="X-Webhook-Secret"),
) -> CICDWebhookResponse:
    """Receive and process a CI/CD webhook.

    This endpoint does NOT require API key authentication — it uses
    webhook signature verification instead.
    """
    if provider not in svc.PAYLOAD_PARSERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider: {provider}. Use github, gitlab, or generic.",
        )

    # Read raw body for signature verification
    raw_body = await request.body()
    try:
        body = __import__("json").loads(raw_body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Parse provider-specific payload into normalized format
    parsed = svc.PAYLOAD_PARSERS[provider](body)
    repository = parsed["repository"]

    if not repository:
        raise HTTPException(status_code=400, detail="Could not determine repository from payload")

    # Find matching integration (search across all tenants for webhook matching)
    integration = await svc.find_integration_for_webhook(provider, repository)
    if not integration:
        return CICDWebhookResponse(
            accepted=False,
            integration_id="",
            message=f"No active integration found for {provider}:{repository}",
        )

    # Verify webhook signature
    webhook_secret = integration.get("webhook_secret")
    if webhook_secret:
        if provider == "github" and x_hub_signature_256:
            if not svc.verify_github_signature(raw_body, x_hub_signature_256, webhook_secret):
                raise HTTPException(status_code=401, detail="Invalid webhook signature")
        elif provider == "gitlab" and x_gitlab_token:
            if not svc.verify_gitlab_token(x_gitlab_token, webhook_secret):
                raise HTTPException(status_code=401, detail="Invalid webhook token")
        elif provider == "generic" and x_webhook_secret:
            if not svc.verify_gitlab_token(x_webhook_secret, webhook_secret):
                raise HTTPException(status_code=401, detail="Invalid webhook secret")
        elif webhook_secret:
            # Secret configured but no signature header provided
            raise HTTPException(status_code=401, detail="Missing webhook signature")

    # Check if this event should trigger a scan
    if not svc.should_trigger_scan(integration, parsed):
        build = await svc.create_build_record(integration, parsed, scan_id=None)
        return CICDWebhookResponse(
            accepted=True,
            integration_id=integration["id"],
            message=f"Event {parsed['event_type']} on branch {parsed['branch']} does not match trigger filters",
        )

    # Trigger a scan
    scan_id = await _trigger_scan(integration, parsed, db, background_tasks)

    build = await svc.create_build_record(integration, parsed, scan_id=scan_id)

    logger.info(
        "CI/CD webhook triggered scan",
        extra={
            "integration_id": integration["id"],
            "provider": provider,
            "repository": repository,
            "branch": parsed["branch"],
            "scan_id": scan_id,
            "build_id": build["id"],
        },
    )

    return CICDWebhookResponse(
        accepted=True,
        scan_id=scan_id,
        integration_id=integration["id"],
        message=f"Scan {scan_id} triggered for {parsed['branch']}@{parsed.get('commit_sha', 'HEAD')[:8]}",
    )


async def _trigger_scan(
    integration: dict[str, Any],
    parsed: dict[str, Any],
    db: DBSession,
    background_tasks: BackgroundTasks,
) -> str | None:
    """Trigger a security scan from a CI/CD webhook.

    Reuses the existing scan pipeline (ScanExecutionService).
    """
    try:
        from mass.storage.models.deployment import Scan
        from mass.storage.models.base import generate_id

        deployment_id = integration.get("deployment_id")
        if not deployment_id:
            logger.warning(
                "Integration %s has no deployment_id; cannot trigger scan",
                integration["id"],
            )
            return None

        scan_id = generate_id("scan_")
        scan = Scan(
            id=scan_id,
            tenant_id=integration.get("tenant_id", "default"),
            deployment_id=deployment_id,
            profile=integration.get("scan_profile", "standard"),
            status="pending",
            progress_percent=0.0,
            current_phase="queued",
            total_findings=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
            config=__import__("json").dumps({
                "triggered_by": "cicd",
                "provider": parsed["provider"],
                "repository": parsed["repository"],
                "branch": parsed["branch"],
                "commit_sha": parsed.get("commit_sha"),
            }),
        )
        db.add(scan)
        await db.commit()

        # Dispatch to worker queue or fallback to background task
        from mass.api.dependencies import get_scan_queue

        queue = await get_scan_queue()
        if queue:
            await queue.enqueue(
                "scans",
                {"scan_id": scan_id, "priority": "high"},
            )
        else:
            from mass.orchestration.service import ScanExecutionService

            svc_exec = ScanExecutionService()
            background_tasks.add_task(svc_exec.execute_scan, scan_id)

        # Broadcast event
        try:
            from mass.core.events import Event, EventType, publish_event

            await publish_event(Event(
                type=EventType.SCAN_CREATED,
                data={
                    "scan_id": scan_id,
                    "triggered_by": "cicd",
                    "provider": parsed["provider"],
                    "repository": parsed["repository"],
                    "branch": parsed["branch"],
                },
                tenant_id=integration.get("tenant_id"),
            ))
        except Exception:
            pass

        return scan_id

    except Exception as e:
        logger.error("Failed to trigger scan from CI/CD webhook: %s", e, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------

@router.get(
    "/gate/{scan_id}",
    response_model=GateResponse,
    summary="CI/CD quality gate check",
    description=(
        "Check whether a scan passes the CI/CD quality gate. "
        "CI pipelines poll this endpoint to determine pass/fail."
    ),
)
async def check_gate(
    scan_id: str,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    finding_repo: FindingRepo,
    threshold: str | None = Query(
        default=None,
        description="Override severity threshold (critical, high, medium, low). "
        "Defaults to the integration's configured threshold.",
    ),
) -> GateResponse:
    """Evaluate the quality gate for a scan."""
    scan = await scan_repo.get(scan_id)
    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Determine severity threshold
    gate_threshold = threshold or "high"

    # If the scan comes from a CI/CD integration, use that config's threshold
    scan_config = {}
    if scan.config:
        try:
            scan_config = __import__("json").loads(scan.config) if isinstance(scan.config, str) else scan.config
        except Exception:
            pass

    if scan_config.get("triggered_by") == "cicd" and not threshold:
        # Look up the integration's threshold
        repo = scan_config.get("repository", "")
        provider = scan_config.get("provider", "")
        integration = await svc.find_integration_for_webhook(provider, repo, tenant.tenant_id)
        if integration:
            gate_threshold = integration.get("severity_threshold", "high")

    # Pending/running scans → verdict = pending
    if scan.status in ("pending", "running"):
        return GateResponse(
            scan_id=scan_id,
            verdict=GateVerdict.PENDING,
            scan_status=scan.status,
            severity_threshold=gate_threshold,
            findings=GateSeverityCounts(),
            total_findings=0,
            message=f"Scan is still {scan.status}",
        )

    # Failed scans → verdict = error
    if scan.status == "failed":
        return GateResponse(
            scan_id=scan_id,
            verdict=GateVerdict.ERROR,
            scan_status=scan.status,
            severity_threshold=gate_threshold,
            findings=GateSeverityCounts(),
            total_findings=0,
            message=f"Scan failed: {scan.error_message or 'unknown error'}",
        )

    # Completed — evaluate findings
    severity_counts = {
        "critical": scan.critical_findings or 0,
        "high": scan.high_findings or 0,
        "medium": scan.medium_findings or 0,
        "low": scan.low_findings or 0,
        "info": 0,
    }

    verdict_str, above_count, message = svc.evaluate_gate(severity_counts, gate_threshold)

    return GateResponse(
        scan_id=scan_id,
        verdict=GateVerdict(verdict_str),
        scan_status=scan.status,
        severity_threshold=gate_threshold,
        findings=GateSeverityCounts(**severity_counts),
        total_findings=above_count,
        message=message,
        scan_url=f"/api/v1/scans/{scan_id}",
        sarif_url=f"/api/v1/cicd/gate/{scan_id}/sarif",
        duration_seconds=scan.duration_seconds,
    )


@router.get(
    "/gate/{scan_id}/sarif",
    summary="Download SARIF report for scan",
    description="Generate and download a SARIF report for CI/CD code scanning integration.",
)
async def download_sarif(
    scan_id: str,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    finding_repo: FindingRepo,
) -> Any:
    """Generate SARIF report for a completed scan."""
    from fastapi.responses import Response

    scan = await scan_repo.get(scan_id)
    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan is {scan.status}; SARIF is only available for completed scans",
        )

    # Load findings
    findings_models = await finding_repo.list(
        offset=0, limit=10000, scan_id=scan_id,
    )

    # Convert DB models to Finding dataclass
    from mass.core.findings import Finding

    findings = []
    for f in findings_models:
        findings.append(Finding(
            id=f.id,
            title=f.title or "",
            description=f.description or "",
            severity=f.severity or "medium",
            category=f.category or "general",
            confidence=getattr(f, "confidence", 0.5),
            source=getattr(f, "source", "mass"),
        ))

    # Generate SARIF
    from mass.reporting.generator import ReportConfig, ReportFormat, ReportGenerator

    generator = ReportGenerator(config=ReportConfig(
        tool_name="MASS",
        tool_version="0.1.0",
    ))
    report = generator.generate(
        format=ReportFormat.SARIF,
        findings=findings,
        scan_id=scan_id,
    )

    return Response(
        content=report.content if isinstance(report.content, bytes) else report.content.encode(),
        media_type="application/sarif+json",
        headers={
            "Content-Disposition": f'attachment; filename="{report.filename}"',
        },
    )


# ---------------------------------------------------------------------------
# Builds
# ---------------------------------------------------------------------------

@router.get(
    "/builds",
    response_model=CICDBuildListResponse,
    summary="List CI/CD builds",
    description="List CI/CD-triggered build records.",
)
async def list_builds(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
    integration_id: str | None = Query(default=None, description="Filter by integration"),
) -> CICDBuildListResponse:
    """List CI/CD build records."""
    items, total = await svc.list_builds(
        tenant_id=tenant.tenant_id,
        integration_id=integration_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return CICDBuildListResponse(
        items=[CICDBuildResponse(**b) for b in items],
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
    response_model=CICDStatusResponse,
    summary="CI/CD module status",
)
async def module_status(
    tenant: CurrentTenantDep,
) -> CICDStatusResponse:
    """Check CI/CD module health and activity."""
    integrations, _ = await svc.list_integrations(tenant_id=tenant.tenant_id, limit=1000)
    active = sum(1 for i in integrations if i.get("is_active"))

    builds, total_builds = await svc.list_builds(
        tenant_id=tenant.tenant_id, limit=1000,
    )

    # Count recent (last 24h) — filter by created_at
    from datetime import datetime, timedelta

    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    recent = sum(1 for b in builds if b.get("created_at", "") >= cutoff)

    return CICDStatusResponse(
        status="healthy",
        active_integrations=active,
        total_builds=total_builds,
        recent_scans=recent,
    )
