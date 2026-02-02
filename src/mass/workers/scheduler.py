"""Job scheduler for managing job submission and monitoring.

The scheduler provides high-level APIs for submitting jobs,
monitoring their progress, and managing scan workflows.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable
from uuid import uuid4

from mass.workers.base import Job, JobPriority, JobState, WorkerConfig
from mass.workers.queue import JobQueue, MemoryQueue, QueueConfig, get_queue
from mass.workers.worker import Worker, WorkerPool


logger = logging.getLogger(__name__)


# Type for job completion callbacks
JobCallback = Callable[[Job], None]


@dataclass
class SchedulerConfig:
    """Scheduler configuration."""

    # Queue settings
    queue_config: QueueConfig = field(default_factory=QueueConfig)

    # Worker pool settings
    num_workers: int = 4
    worker_config: WorkerConfig = field(default_factory=WorkerConfig)

    # Job settings
    default_timeout_seconds: int = 300
    default_max_retries: int = 3

    # Monitoring
    monitor_interval_seconds: float = 5.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "num_workers": self.num_workers,
            "default_timeout_seconds": self.default_timeout_seconds,
            "default_max_retries": self.default_max_retries,
        }


@dataclass
class ScheduledScan:
    """A scheduled scan with its jobs."""

    scan_id: str
    deployment_id: str
    created_at: datetime = field(default_factory=datetime.utcnow)

    # Jobs
    job_ids: list[str] = field(default_factory=list)
    total_jobs: int = 0
    completed_jobs: int = 0
    failed_jobs: int = 0

    # Status
    status: str = "pending"  # pending, running, completed, failed
    progress: float = 0.0

    # Callbacks
    on_complete: JobCallback | None = None
    on_job_complete: JobCallback | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "deployment_id": self.deployment_id,
            "status": self.status,
            "progress": self.progress,
            "total_jobs": self.total_jobs,
            "completed_jobs": self.completed_jobs,
            "failed_jobs": self.failed_jobs,
        }


class Scheduler:
    """High-level job scheduler.

    The scheduler manages job submission, worker pools, and
    provides monitoring capabilities for scan workflows.
    """

    def __init__(self, config: SchedulerConfig | None = None) -> None:
        """Initialize the scheduler.

        Args:
            config: Scheduler configuration.
        """
        self.config = config or SchedulerConfig()
        self._queue: JobQueue | None = None
        self._pool: WorkerPool | None = None
        self._scans: dict[str, ScheduledScan] = {}
        self._job_to_scan: dict[str, str] = {}
        self._callbacks: dict[str, list[JobCallback]] = {}
        self._monitor_task: asyncio.Task | None = None
        self._running = False

    @property
    def queue(self) -> JobQueue:
        """Get the job queue."""
        if self._queue is None:
            self._queue = get_queue(self.config.queue_config)
        return self._queue

    async def start(self) -> None:
        """Start the scheduler and worker pool."""
        if self._running:
            return

        logger.info("Starting scheduler")

        # Initialize queue
        self._queue = get_queue(self.config.queue_config)

        # Start worker pool
        self._pool = WorkerPool(
            queue=self._queue,
            num_workers=self.config.num_workers,
            config=self.config.worker_config,
        )

        # Register default handlers
        self._register_default_handlers()

        await self._pool.start()

        # Start monitor
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())

        logger.info(f"Scheduler started with {self.config.num_workers} workers")

    async def stop(self) -> None:
        """Stop the scheduler and worker pool."""
        if not self._running:
            return

        logger.info("Stopping scheduler")

        self._running = False

        # Stop monitor
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

        # Stop worker pool
        if self._pool:
            await self._pool.stop()

        logger.info("Scheduler stopped")

    def register_handler(self, job_type: str, handler: Callable) -> None:
        """Register a job handler.

        Args:
            job_type: Type of job to handle.
            handler: Handler function.
        """
        if self._pool:
            self._pool.register_handler(job_type, handler)

    def _register_default_handlers(self) -> None:
        """Register default job handlers."""
        from mass.orchestration.executor import JobExecutor
        from mass.orchestration.planner import JobType

        executor = JobExecutor()

        # Map orchestration job types to handlers
        job_type_mapping = {
            "deployment_scan": JobType.DEPLOYMENT_SCAN,
            "secret_detection": JobType.SECRET_DETECTION,
            "infrastructure_scan": JobType.INFRASTRUCTURE_SCAN,
            "model_file_scan": JobType.MODEL_FILE_SCAN,
            "context_analysis": JobType.CONTEXT_ANALYSIS,
            "mcp_analysis": JobType.MCP_ANALYSIS,
            "attack_surface": JobType.ATTACK_SURFACE,
            "workflow_analysis": JobType.WORKFLOW_ANALYSIS,
            "model_interrogation": JobType.MODEL_INTERROGATION,
        }

        for job_type_str, job_type_enum in job_type_mapping.items():
            def make_handler(jt: JobType):
                def handler(job: Job) -> dict[str, Any]:
                    from mass.orchestration.planner import PlannedJob
                    planned_job = PlannedJob(
                        id=job.id,
                        job_type=jt,
                        name=job.name,
                        config=job.payload.get("config", {}),
                    )
                    result = executor.execute(planned_job, job.payload.get("context", {}))
                    return {
                        "status": result.status.value,
                        "findings_count": result.findings_count,
                        "findings": [f.id for f in result.findings],
                    }
                return handler

            if self._pool:
                self._pool.register_handler(job_type_str, make_handler(job_type_enum))

    async def submit_job(
        self,
        job_type: str,
        payload: dict[str, Any],
        name: str = "",
        priority: JobPriority = JobPriority.NORMAL,
        timeout_seconds: int | None = None,
        max_retries: int | None = None,
        queue_name: str = "default",
        scan_id: str | None = None,
        scheduled_at: datetime | None = None,
    ) -> str:
        """Submit a job for processing.

        Args:
            job_type: Type of job.
            payload: Job payload data.
            name: Optional job name.
            priority: Job priority.
            timeout_seconds: Job timeout.
            max_retries: Maximum retry attempts.
            queue_name: Queue to submit to.
            scan_id: Associated scan ID.
            scheduled_at: Schedule for future execution.

        Returns:
            Job ID.
        """
        job = Job(
            name=name or job_type,
            job_type=job_type,
            payload=payload,
            priority=priority,
            timeout_seconds=timeout_seconds or self.config.default_timeout_seconds,
            max_retries=max_retries or self.config.default_max_retries,
            queue_name=queue_name,
            scan_id=scan_id,
            scheduled_at=scheduled_at,
        )

        job_id = await self.queue.enqueue(job)

        # Track scan association
        if scan_id:
            self._job_to_scan[job_id] = scan_id
            if scan_id in self._scans:
                self._scans[scan_id].job_ids.append(job_id)

        logger.debug(f"Submitted job {job_id} (type: {job_type})")
        return job_id

    async def submit_scan(
        self,
        scan_id: str,
        deployment_id: str,
        jobs: list[dict[str, Any]],
        on_complete: JobCallback | None = None,
        on_job_complete: JobCallback | None = None,
    ) -> ScheduledScan:
        """Submit a scan with multiple jobs.

        Args:
            scan_id: Scan identifier.
            deployment_id: Deployment being scanned.
            jobs: List of job configurations.
            on_complete: Callback when scan completes.
            on_job_complete: Callback for each job completion.

        Returns:
            ScheduledScan object.
        """
        scheduled_scan = ScheduledScan(
            scan_id=scan_id,
            deployment_id=deployment_id,
            total_jobs=len(jobs),
            on_complete=on_complete,
            on_job_complete=on_job_complete,
        )

        self._scans[scan_id] = scheduled_scan

        # Submit jobs (submit_job will append to job_ids via the scan tracking)
        for job_config in jobs:
            await self.submit_job(
                job_type=job_config.get("job_type", ""),
                payload=job_config.get("payload", {}),
                name=job_config.get("name", ""),
                priority=JobPriority(job_config.get("priority", JobPriority.NORMAL.value)),
                scan_id=scan_id,
            )

        scheduled_scan.status = "running"
        logger.info(f"Submitted scan {scan_id} with {len(jobs)} jobs")

        return scheduled_scan

    async def get_job_status(self, job_id: str) -> dict[str, Any] | None:
        """Get the status of a job.

        Args:
            job_id: Job ID.

        Returns:
            Job status dictionary or None if not found.
        """
        job = await self.queue.get_job(job_id)
        if not job:
            return None

        return {
            "id": job.id,
            "state": job.state.value,
            "progress": job.progress,
            "error": job.error,
            "result": job.result,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        }

    async def get_scan_status(self, scan_id: str) -> dict[str, Any] | None:
        """Get the status of a scan.

        Args:
            scan_id: Scan ID.

        Returns:
            Scan status dictionary or None if not found.
        """
        scan = self._scans.get(scan_id)
        if not scan:
            return None

        # Update job counts
        completed = 0
        failed = 0
        running = 0

        for job_id in scan.job_ids:
            job = await self.queue.get_job(job_id)
            if job:
                if job.state == JobState.COMPLETED:
                    completed += 1
                elif job.state == JobState.FAILED:
                    failed += 1
                elif job.state == JobState.RUNNING:
                    running += 1

        scan.completed_jobs = completed
        scan.failed_jobs = failed
        scan.progress = (completed + failed) / scan.total_jobs * 100 if scan.total_jobs > 0 else 0

        # Update status
        if completed + failed == scan.total_jobs:
            scan.status = "failed" if failed > 0 else "completed"
        elif running > 0:
            scan.status = "running"

        return scan.to_dict()

    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a job.

        Args:
            job_id: Job ID.

        Returns:
            True if cancelled, False if not found.
        """
        job = await self.queue.get_job(job_id)
        if not job:
            return False

        job.state = JobState.CANCELLED
        job.completed_at = datetime.utcnow()
        await self.queue.update_job(job)

        logger.info(f"Cancelled job {job_id}")
        return True

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel all jobs in a scan.

        Args:
            scan_id: Scan ID.

        Returns:
            True if cancelled, False if not found.
        """
        scan = self._scans.get(scan_id)
        if not scan:
            return False

        for job_id in scan.job_ids:
            await self.cancel_job(job_id)

        scan.status = "cancelled"
        logger.info(f"Cancelled scan {scan_id}")
        return True

    async def wait_for_job(
        self,
        job_id: str,
        timeout: float | None = None,
        poll_interval: float = 1.0,
    ) -> Job | None:
        """Wait for a job to complete.

        Args:
            job_id: Job ID.
            timeout: Maximum wait time in seconds.
            poll_interval: Polling interval in seconds.

        Returns:
            Completed job or None if timeout.
        """
        start_time = datetime.utcnow()

        while True:
            job = await self.queue.get_job(job_id)
            if not job:
                return None

            if job.state in (JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED):
                return job

            # Check timeout
            if timeout:
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                if elapsed >= timeout:
                    return None

            await asyncio.sleep(poll_interval)

    async def wait_for_scan(
        self,
        scan_id: str,
        timeout: float | None = None,
        poll_interval: float = 1.0,
    ) -> ScheduledScan | None:
        """Wait for a scan to complete.

        Args:
            scan_id: Scan ID.
            timeout: Maximum wait time in seconds.
            poll_interval: Polling interval in seconds.

        Returns:
            Completed scan or None if timeout.
        """
        start_time = datetime.utcnow()

        while True:
            status = await self.get_scan_status(scan_id)
            if not status:
                return None

            if status["status"] in ("completed", "failed", "cancelled"):
                return self._scans.get(scan_id)

            # Check timeout
            if timeout:
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                if elapsed >= timeout:
                    return None

            await asyncio.sleep(poll_interval)

    async def _monitor_loop(self) -> None:
        """Background monitoring loop."""
        while self._running:
            try:
                await self._check_scan_completions()
            except Exception as e:
                logger.error(f"Monitor error: {e}")

            await asyncio.sleep(self.config.monitor_interval_seconds)

    async def _check_scan_completions(self) -> None:
        """Check for completed scans and trigger callbacks."""
        for scan_id, scan in list(self._scans.items()):
            if scan.status in ("completed", "failed", "cancelled"):
                continue

            # Check job statuses
            all_done = True
            for job_id in scan.job_ids:
                job = await self.queue.get_job(job_id)
                if job:
                    if job.state not in (JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED):
                        all_done = False
                    elif job.state == JobState.COMPLETED and scan.on_job_complete:
                        try:
                            scan.on_job_complete(job)
                        except Exception as e:
                            logger.error(f"Job callback error: {e}")

            if all_done:
                await self.get_scan_status(scan_id)  # Update status
                if scan.on_complete and scan.status in ("completed", "failed"):
                    try:
                        # Create a summary job for callback
                        summary_job = Job(
                            id=scan_id,
                            name=f"scan-{scan_id}",
                            result={
                                "status": scan.status,
                                "total_jobs": scan.total_jobs,
                                "completed_jobs": scan.completed_jobs,
                                "failed_jobs": scan.failed_jobs,
                            },
                        )
                        scan.on_complete(summary_job)
                    except Exception as e:
                        logger.error(f"Scan callback error: {e}")

    def get_stats(self) -> dict[str, Any]:
        """Get scheduler statistics."""
        pool_stats = self._pool.get_stats() if self._pool else {}

        return {
            "running": self._running,
            "num_workers": self.config.num_workers,
            "active_scans": len([s for s in self._scans.values() if s.status == "running"]),
            "total_scans": len(self._scans),
            "pool": pool_stats,
        }
