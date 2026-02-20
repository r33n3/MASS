"""Cron-based scan scheduler for recurring/scheduled scans.

Checks deployments with scan_schedule (cron expression) and
dispatches scan jobs to the Redis queue when the schedule matches.

Runs as a lightweight loop within the worker process or standalone:
    python -m mass.workers.cron_scheduler

Environment variables:
    MASS_SCHEDULER_INTERVAL: Check interval in seconds (default: 60)
    MASS_DB_URL: Database connection string
    MASS_REDIS_URL: Redis connection string
"""

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime
from typing import Any

logger = logging.getLogger("mass.workers.cron_scheduler")


def cron_matches(expression: str, now: datetime) -> bool:
    """Check if a cron expression matches the current time.

    Supports standard 5-field cron: minute hour day_of_month month day_of_week
    Day of week: 0=Monday (Python convention).

    Examples:
        "0 2 * * 1"   -> Monday at 02:00
        "*/15 * * * *" -> Every 15 minutes
        "0 0 1 * *"   -> First day of month at midnight
        "30 9 * * 1-5" -> Weekdays at 09:30

    Args:
        expression: Cron expression string.
        now: Current datetime to check against.

    Returns:
        True if the expression matches the current minute.
    """
    parts = expression.strip().split()
    if len(parts) != 5:
        logger.warning("Invalid cron expression (need 5 fields): %s", expression)
        return False

    minute_expr, hour_expr, dom_expr, month_expr, dow_expr = parts

    def _matches_field(expr: str, value: int) -> bool:
        if expr == "*":
            return True

        for part in expr.split(","):
            if "/" in part:
                range_part, step_str = part.split("/", 1)
                try:
                    step = int(step_str)
                except ValueError:
                    continue
                if range_part == "*":
                    if value % step == 0:
                        return True
                elif "-" in range_part:
                    lo_str, hi_str = range_part.split("-", 1)
                    try:
                        lo, hi = int(lo_str), int(hi_str)
                    except ValueError:
                        continue
                    if lo <= value <= hi and (value - lo) % step == 0:
                        return True
            elif "-" in part:
                lo_str, hi_str = part.split("-", 1)
                try:
                    lo, hi = int(lo_str), int(hi_str)
                except ValueError:
                    continue
                if lo <= value <= hi:
                    return True
            else:
                try:
                    if int(part) == value:
                        return True
                except ValueError:
                    continue

        return False

    return (
        _matches_field(minute_expr, now.minute)
        and _matches_field(hour_expr, now.hour)
        and _matches_field(dom_expr, now.day)
        and _matches_field(month_expr, now.month)
        and _matches_field(dow_expr, now.weekday())
    )


async def _get_scheduled_deployments() -> list[dict[str, Any]]:
    """Query deployments that have a scan_schedule set."""
    from mass.storage.database import get_async_session
    from sqlalchemy import text

    results: list[dict[str, Any]] = []
    async with get_async_session() as session:
        rows = await session.execute(
            text(
                "SELECT id, tenant_id, name, scan_schedule, scan_schedule_profile "
                "FROM deployments WHERE scan_schedule IS NOT NULL "
                "AND scan_schedule != ''"
            )
        )
        for row in rows:
            results.append({
                "id": row[0],
                "tenant_id": row[1],
                "name": row[2],
                "scan_schedule": row[3],
                "scan_schedule_profile": row[4] or "standard",
            })
    return results


async def _dispatch_scan(deployment: dict[str, Any]) -> str | None:
    """Create a scan record and enqueue a job for a scheduled deployment."""
    from mass.storage.database import get_async_session
    from mass.storage.models.deployment import ScanStatus
    from uuid import uuid4
    from sqlalchemy import text

    scan_id = str(uuid4())
    profile = deployment.get("scan_schedule_profile", "standard")

    try:
        async with get_async_session() as session:
            await session.execute(
                text(
                    "INSERT INTO scans (id, tenant_id, deployment_id, profile, status, "
                    "progress_percent, jobs_completed, jobs_total, total_findings, "
                    "critical_findings, high_findings, medium_findings, low_findings, "
                    "created_at, updated_at) "
                    "VALUES (:id, :tenant_id, :deployment_id, :profile, :status, "
                    "0, 0, 0, 0, 0, 0, 0, 0, :now, :now)"
                ),
                {
                    "id": scan_id,
                    "tenant_id": deployment["tenant_id"],
                    "deployment_id": deployment["id"],
                    "profile": profile,
                    "status": ScanStatus.PENDING.value,
                    "now": datetime.utcnow(),
                },
            )
            await session.commit()

        # Enqueue to Redis
        from mass.workers.queue import QueueConfig, RedisQueue
        from mass.workers.base import Job
        from mass.core.config import get_settings

        settings = get_settings()
        queue_config = QueueConfig(
            backend="redis",
            redis_url=settings.redis.url,
            redis_prefix="mass:scans:",
        )
        queue = RedisQueue(queue_config)
        try:
            job = Job(
                job_type="full_scan",
                payload={"scan_id": scan_id},
            )
            await queue.enqueue("scans", job)
            logger.info(
                "Scheduled scan dispatched: deployment=%s scan=%s profile=%s",
                deployment["name"], scan_id, profile,
            )
        finally:
            await queue.close()

        return scan_id

    except Exception as e:
        logger.error(
            "Failed to dispatch scheduled scan for %s: %s",
            deployment["name"], e,
        )
        return None


async def run_cron_loop(interval_seconds: int = 60) -> None:
    """Main cron scheduler loop.

    Every `interval_seconds`, checks which deployments have a cron schedule
    that matches the current time and dispatches scan jobs for them.
    """
    logger.info("Cron scan scheduler started (interval=%ds)", interval_seconds)

    # Track last dispatch time per deployment to avoid duplicate dispatches
    last_dispatched: dict[str, datetime] = {}

    while True:
        try:
            now = datetime.utcnow()
            deployments = await _get_scheduled_deployments()

            for deployment in deployments:
                dep_id = deployment["id"]
                cron_expr = deployment["scan_schedule"]

                if not cron_matches(cron_expr, now):
                    continue

                # Avoid dispatching twice in the same minute
                last = last_dispatched.get(dep_id)
                if last and (now - last).total_seconds() < 90:
                    continue

                scan_id = await _dispatch_scan(deployment)
                if scan_id:
                    last_dispatched[dep_id] = now

        except Exception as e:
            logger.error("Cron scheduler loop error: %s", e, exc_info=True)

        await asyncio.sleep(interval_seconds)


async def main() -> None:
    """Entry point for standalone cron scheduler."""
    from mass.api.routes.settings import load_platform_settings_into_env
    load_platform_settings_into_env()

    interval = int(os.environ.get("MASS_SCHEDULER_INTERVAL", "60"))

    loop = asyncio.get_event_loop()
    stop = asyncio.Event()

    def on_signal(sig: int, frame: Any) -> None:
        logger.info("Received signal %s, stopping cron scheduler...", sig)
        stop.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    scheduler_task = asyncio.create_task(run_cron_loop(interval))

    await stop.wait()
    scheduler_task.cancel()
    try:
        await scheduler_task
    except asyncio.CancelledError:
        pass
    logger.info("Cron scheduler stopped")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    asyncio.run(main())
