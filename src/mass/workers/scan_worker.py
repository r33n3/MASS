"""Scan worker entry point.

Runs as a standalone process (typically in a Docker container) that
polls a Redis queue for scan jobs and executes them using the
existing ScanExecutionService pipeline.

Usage:
    python -m mass.workers.scan_worker

Environment variables:
    MASS_WORKER_CONCURRENCY: Max concurrent scans (default: 2)
    MASS_WORKER_QUEUES: Comma-separated queue names (default: "scans")
    MASS_DB_URL: Database connection string
    MASS_REDIS_URL: Redis connection string
"""

import asyncio
import logging
import os
import signal
import sys
from typing import Any

from mass.core.config import get_settings
from mass.workers.base import Job, WorkerConfig
from mass.workers.queue import QueueConfig, RedisQueue
from mass.workers.worker import Worker

logger = logging.getLogger("mass.workers.scan_worker")


async def handle_full_scan(job: Job) -> dict[str, Any] | None:
    """Handle a full_scan job by delegating to ScanExecutionService.

    ScanExecutionService.execute_scan() already handles:
    - Creating its own DB session
    - Loading scan/deployment from DB
    - Creating ProgressBridge for real-time progress persistence
    - Running ScanService.scan_deployment() in a thread pool
    - Storing findings incrementally
    - Broadcasting WebSocket updates
    - Updating scan status on completion/failure
    """
    from mass.core.metrics import METRICS

    scan_id = job.payload.get("scan_id")
    if not scan_id:
        logger.error("full_scan job missing scan_id in payload")
        METRICS.inc("mass_worker_jobs_failed", help_text="Worker jobs failed")
        return {"status": "failed", "error": "missing scan_id"}

    logger.info("Processing scan %s (job %s)", scan_id, job.id)

    from mass.api.services.scan_execution import ScanExecutionService

    service = ScanExecutionService()
    try:
        await service.execute_scan(scan_id)
        METRICS.inc("mass_worker_jobs_processed", help_text="Worker jobs processed")
    except Exception:
        METRICS.inc("mass_worker_jobs_failed", help_text="Worker jobs failed")
        raise

    logger.info("Scan %s completed (job %s)", scan_id, job.id)
    return {"status": "completed", "scan_id": scan_id}


async def main() -> None:
    """Main worker loop."""
    # Load persisted platform settings before MassSettings reads env vars
    from mass.api.routes.settings import load_platform_settings_into_env
    load_platform_settings_into_env()

    settings = get_settings()

    # Configuration from environment
    concurrency = int(os.environ.get("MASS_WORKER_CONCURRENCY", "5"))
    queue_names = os.environ.get("MASS_WORKER_QUEUES", "scans").split(",")
    queue_names = [q.strip() for q in queue_names if q.strip()]

    logger.info(
        "Starting scan worker (concurrency=%d, queues=%s)",
        concurrency, queue_names,
    )

    # Initialize Redis queue
    queue_config = QueueConfig(
        backend="redis",
        redis_url=settings.redis.url,
        redis_prefix="mass:scans:",
    )
    queue = RedisQueue(queue_config)

    # Create worker
    worker_config = WorkerConfig(
        name="scan-worker",
        queues=queue_names,
        max_concurrent_jobs=concurrency,
        job_timeout_seconds=1800,  # 30 min max per scan
        poll_interval_seconds=1.0,
        empty_queue_sleep_seconds=3.0,
        shutdown_timeout_seconds=60,  # Allow scans to finish on shutdown
    )
    worker = Worker(queue=queue, config=worker_config)

    # Register handler
    worker.register_handler("full_scan", handle_full_scan)

    # Graceful shutdown on SIGTERM/SIGINT
    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()

    def on_signal(sig: int, frame: Any) -> None:
        logger.info("Received signal %s, shutting down...", sig)
        shutdown_event.set()
        loop.call_soon_threadsafe(lambda: asyncio.ensure_future(worker.stop()))

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    # Start the worker (blocks until stopped)
    try:
        await worker.start()
    except asyncio.CancelledError:
        pass
    finally:
        await queue.close()
        logger.info("Scan worker stopped")


if __name__ == "__main__":
    # Configure logging for Docker stdout
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Reduce noise from libraries
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    asyncio.run(main())
