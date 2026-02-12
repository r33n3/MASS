"""Auto-analysis pipeline service.

Orchestrates the full target analysis workflow:
  register → profile (architecture analysis) → scan

Runs as a background task so the API response returns immediately.
"""

from __future__ import annotations

import json
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from mass.core.types import ScanStatus
from mass.storage.models.deployment import Deployment, Scan

logger = logging.getLogger(__name__)


async def run_auto_pipeline(
    deployment_id: str,
    tenant_id: str,
    provider: str = "ollama",
    model: str | None = None,
    api_key: str | None = None,
    profile: str = "standard",
) -> None:
    """Run the full auto-analysis pipeline for a deployment.

    Steps:
        1. Profile: Run architecture analysis (LLM-powered).
        2. Scan: Dispatch a security scan.

    This function is designed to run as a BackgroundTask.
    It creates its own DB session since background tasks
    outlive the request session.
    """
    from mass.storage.database import async_session_factory

    async with async_session_factory() as db:
        try:
            await _run_pipeline(db, deployment_id, tenant_id, provider, model, api_key, profile)
        except Exception:
            logger.exception("Auto-pipeline failed for deployment %s", deployment_id)
            await _update_pipeline_status(db, deployment_id, "error")


async def _run_pipeline(
    db: AsyncSession,
    deployment_id: str,
    tenant_id: str,
    provider: str,
    model: str | None,
    api_key: str | None,
    profile: str,
) -> None:
    """Execute pipeline steps sequentially."""
    from mass.storage.repositories.deployment import DeploymentRepository

    dep_repo = DeploymentRepository(db)

    deployment = await dep_repo.get(deployment_id)
    if not deployment:
        logger.error("Auto-pipeline: deployment %s not found", deployment_id)
        return

    # ── Step 1: Profile (architecture analysis) ──
    await _update_pipeline_status(db, deployment_id, "profiling")

    if deployment.source_path:
        try:
            from mass.api.services.code_analysis import analyze_target_architecture

            await analyze_target_architecture(
                deployment=deployment,
                provider=provider,
                model=model,
                api_key=api_key,
                db=db,
            )
            logger.info("Auto-pipeline: profiling complete for %s", deployment_id)
        except Exception:
            logger.exception("Auto-pipeline: profiling failed for %s", deployment_id)
            # Continue to scan even if profiling fails

    # ── Step 2: Scan ──
    await _update_pipeline_status(db, deployment_id, "scanning")

    scan = Scan(
        tenant_id=tenant_id,
        deployment_id=deployment_id,
        profile=profile,
        status=ScanStatus.PENDING.value,
        total_findings=0,
        critical_findings=0,
        high_findings=0,
        medium_findings=0,
        low_findings=0,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Try worker queue first, fallback to in-process
    dispatched = False
    try:
        from mass.api.dependencies import get_scan_queue

        queue = await get_scan_queue()
        if queue is not None:
            from mass.workers.base import Job, JobPriority

            job = Job(
                job_type="full_scan",
                payload={"scan_id": scan.id},
                scan_id=scan.id,
                tenant_id=tenant_id,
                queue_name="scans",
                timeout_seconds=1800,
                priority=JobPriority.NORMAL,
            )
            await queue.enqueue(job)
            dispatched = True
            logger.info("Auto-pipeline: scan %s dispatched to queue", scan.id)
    except Exception as e:
        logger.warning("Auto-pipeline: queue dispatch failed: %s", e)

    if not dispatched:
        from mass.api.services.scan_execution import ScanExecutionService

        scan_service = ScanExecutionService()
        await scan_service.execute_scan(scan.id)
        logger.info("Auto-pipeline: scan %s completed in-process", scan.id)

    await _update_pipeline_status(db, deployment_id, "complete")
    logger.info("Auto-pipeline: complete for deployment %s", deployment_id)


async def _update_pipeline_status(
    db: AsyncSession, deployment_id: str, status: str
) -> None:
    """Update the pipeline_status field in deployment meta."""
    from mass.storage.repositories.deployment import DeploymentRepository

    dep_repo = DeploymentRepository(db)
    deployment = await dep_repo.get(deployment_id)
    if not deployment:
        return

    meta: dict = {}
    if deployment.meta:
        try:
            meta = json.loads(deployment.meta)
        except (json.JSONDecodeError, TypeError):
            meta = {}

    meta["auto_pipeline_status"] = status
    deployment.meta = json.dumps(meta)
    await db.commit()
