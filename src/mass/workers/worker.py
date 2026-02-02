"""Worker implementation for processing jobs.

Workers are the execution units that pull jobs from queues
and process them using registered handlers.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

from mass.workers.base import (
    Job,
    JobHandler,
    JobState,
    ProgressCallback,
    WorkerConfig,
    WorkerStatus,
)
from mass.workers.queue import JobQueue, MemoryQueue


logger = logging.getLogger(__name__)


@dataclass
class WorkerStats:
    """Statistics for a worker."""

    jobs_processed: int = 0
    jobs_succeeded: int = 0
    jobs_failed: int = 0
    jobs_retried: int = 0
    total_processing_time: float = 0.0
    last_job_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "jobs_processed": self.jobs_processed,
            "jobs_succeeded": self.jobs_succeeded,
            "jobs_failed": self.jobs_failed,
            "jobs_retried": self.jobs_retried,
            "total_processing_time": self.total_processing_time,
            "average_time": (
                self.total_processing_time / self.jobs_processed
                if self.jobs_processed > 0
                else 0
            ),
            "success_rate": (
                self.jobs_succeeded / self.jobs_processed
                if self.jobs_processed > 0
                else 0
            ),
            "last_job_at": self.last_job_at.isoformat() if self.last_job_at else None,
        }


class Worker:
    """Processes jobs from queues.

    Workers continuously poll queues for jobs and process them
    using registered handlers. They support concurrent job
    processing and automatic retry for failed jobs.
    """

    def __init__(
        self,
        queue: JobQueue | None = None,
        config: WorkerConfig | None = None,
    ) -> None:
        """Initialize the worker.

        Args:
            queue: Job queue to process from.
            config: Worker configuration.
        """
        self.queue = queue or MemoryQueue()
        self.config = config or WorkerConfig()

        self._handlers: dict[str, JobHandler] = {}
        self._status = WorkerStatus.STOPPED
        self._stats = WorkerStats()

        self._current_jobs: dict[str, Job] = {}
        self._tasks: set[asyncio.Task] = set()
        self._stop_event = asyncio.Event()
        self._semaphore: asyncio.Semaphore | None = None

    @property
    def status(self) -> WorkerStatus:
        """Get current worker status."""
        return self._status

    @property
    def stats(self) -> WorkerStats:
        """Get worker statistics."""
        return self._stats

    def register_handler(self, job_type: str, handler: JobHandler) -> None:
        """Register a handler for a job type.

        Args:
            job_type: Type of job to handle.
            handler: Handler function.
        """
        self._handlers[job_type] = handler
        logger.debug(f"Registered handler for job type: {job_type}")

    def register_handlers(self, handlers: dict[str, JobHandler]) -> None:
        """Register multiple handlers.

        Args:
            handlers: Dictionary mapping job types to handlers.
        """
        for job_type, handler in handlers.items():
            self.register_handler(job_type, handler)

    async def start(self) -> None:
        """Start the worker.

        Begins polling queues for jobs and processing them.
        """
        if self._status != WorkerStatus.STOPPED:
            return

        self._status = WorkerStatus.IDLE
        self._stop_event.clear()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_jobs)

        logger.info(
            f"Worker {self.config.worker_id} starting "
            f"(queues: {self.config.queues}, concurrency: {self.config.max_concurrent_jobs})"
        )

        # Start the main loop
        try:
            await self._run()
        except asyncio.CancelledError:
            pass
        finally:
            self._status = WorkerStatus.STOPPED
            logger.info(f"Worker {self.config.worker_id} stopped")

    async def stop(self) -> None:
        """Stop the worker gracefully.

        Waits for current jobs to complete up to shutdown timeout.
        """
        if self._status == WorkerStatus.STOPPED:
            return

        logger.info(f"Worker {self.config.worker_id} stopping...")
        self._status = WorkerStatus.STOPPING
        self._stop_event.set()

        # Wait for current jobs to complete
        if self._tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._tasks, return_exceptions=True),
                    timeout=self.config.shutdown_timeout_seconds,
                )
            except asyncio.TimeoutError:
                logger.warning("Shutdown timeout, cancelling remaining tasks")
                for task in self._tasks:
                    task.cancel()

        self._status = WorkerStatus.STOPPED

    def pause(self) -> None:
        """Pause the worker."""
        if self._status == WorkerStatus.IDLE or self._status == WorkerStatus.BUSY:
            self._status = WorkerStatus.PAUSED
            logger.info(f"Worker {self.config.worker_id} paused")

    def resume(self) -> None:
        """Resume a paused worker."""
        if self._status == WorkerStatus.PAUSED:
            self._status = WorkerStatus.IDLE
            logger.info(f"Worker {self.config.worker_id} resumed")

    async def _run(self) -> None:
        """Main worker loop."""
        while not self._stop_event.is_set():
            if self._status == WorkerStatus.PAUSED:
                await asyncio.sleep(self.config.poll_interval_seconds)
                continue

            # Try to get a job from each queue
            job = await self._poll_queues()

            if job:
                # Process job with semaphore to limit concurrency
                await self._semaphore.acquire()
                task = asyncio.create_task(self._process_job_wrapper(job))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            else:
                # No jobs available, sleep longer
                await asyncio.sleep(self.config.empty_queue_sleep_seconds)

    async def _poll_queues(self) -> Job | None:
        """Poll configured queues for jobs."""
        for queue_name in self.config.queues:
            job = await self.queue.dequeue(
                queue_name,
                timeout=self.config.poll_interval_seconds,
            )
            if job:
                return job
        return None

    async def _process_job_wrapper(self, job: Job) -> None:
        """Wrapper for job processing with cleanup."""
        try:
            await self.process_job(job)
        finally:
            self._semaphore.release()
            self._current_jobs.pop(job.id, None)

    async def process_job(self, job: Job) -> None:
        """Process a single job.

        Args:
            job: Job to process.
        """
        start_time = datetime.utcnow()
        self._current_jobs[job.id] = job

        # Update status
        self._status = WorkerStatus.BUSY

        # Mark job as running
        job.state = JobState.RUNNING
        job.started_at = start_time
        job.worker_id = self.config.worker_id
        await self.queue.update_job(job)

        logger.info(f"Processing job {job.id} (type: {job.job_type})")

        try:
            # Get handler
            handler = self._handlers.get(job.job_type)
            if not handler:
                raise ValueError(f"No handler for job type: {job.job_type}")

            # Execute handler
            result = await asyncio.wait_for(
                self._execute_handler(handler, job),
                timeout=job.timeout_seconds,
            )

            # Mark completed
            job.state = JobState.COMPLETED
            job.completed_at = datetime.utcnow()
            job.result = result
            job.progress = 100.0

            self._stats.jobs_succeeded += 1
            logger.info(f"Job {job.id} completed successfully")

        except asyncio.TimeoutError:
            job.state = JobState.TIMEOUT
            job.completed_at = datetime.utcnow()
            job.error = f"Job exceeded timeout of {job.timeout_seconds}s"

            self._stats.jobs_failed += 1
            logger.warning(f"Job {job.id} timed out")

            # Retry if possible
            await self._maybe_retry(job)

        except Exception as e:
            job.state = JobState.FAILED
            job.completed_at = datetime.utcnow()
            job.error = str(e)
            job.error_details = {"exception_type": type(e).__name__}

            self._stats.jobs_failed += 1
            logger.error(f"Job {job.id} failed: {e}")

            # Retry if possible
            await self._maybe_retry(job)

        finally:
            # Update job in queue
            await self.queue.update_job(job)

            # Update stats
            self._stats.jobs_processed += 1
            self._stats.last_job_at = datetime.utcnow()
            processing_time = (job.completed_at - start_time).total_seconds() if job.completed_at else 0
            self._stats.total_processing_time += processing_time

            # Update status if no more jobs
            if not self._current_jobs:
                self._status = WorkerStatus.IDLE

    async def _execute_handler(self, handler: JobHandler, job: Job) -> dict[str, Any] | None:
        """Execute a job handler.

        Args:
            handler: Handler function.
            job: Job to process.

        Returns:
            Handler result.
        """
        # Check if handler is async
        if asyncio.iscoroutinefunction(handler):
            return await handler(job)
        else:
            # Run sync handler in thread pool
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, handler, job)

    async def _maybe_retry(self, job: Job) -> None:
        """Retry a job if possible.

        Args:
            job: Failed job.
        """
        if job.can_retry():
            logger.info(
                f"Retrying job {job.id} "
                f"(attempt {job.retry_count + 1}/{job.max_retries})"
            )
            await self.queue.requeue(job)
            self._stats.jobs_retried += 1

    def get_status(self) -> dict[str, Any]:
        """Get worker status and stats."""
        return {
            "worker_id": self.config.worker_id,
            "name": self.config.name,
            "status": self._status.value,
            "queues": self.config.queues,
            "current_jobs": len(self._current_jobs),
            "stats": self._stats.to_dict(),
        }


class WorkerPool:
    """Pool of workers for distributed processing.

    Manages multiple workers processing from the same queue(s).
    """

    def __init__(
        self,
        queue: JobQueue,
        num_workers: int = 4,
        config: WorkerConfig | None = None,
    ) -> None:
        """Initialize the worker pool.

        Args:
            queue: Shared job queue.
            num_workers: Number of workers in pool.
            config: Base worker configuration.
        """
        self.queue = queue
        self.num_workers = num_workers
        self._base_config = config or WorkerConfig()

        self._workers: list[Worker] = []
        self._tasks: list[asyncio.Task] = []
        self._handlers: dict[str, JobHandler] = {}

    def register_handler(self, job_type: str, handler: JobHandler) -> None:
        """Register a handler for all workers.

        Args:
            job_type: Type of job to handle.
            handler: Handler function.
        """
        self._handlers[job_type] = handler
        for worker in self._workers:
            worker.register_handler(job_type, handler)

    async def start(self) -> None:
        """Start all workers in the pool."""
        logger.info(f"Starting worker pool with {self.num_workers} workers")

        for i in range(self.num_workers):
            # Create worker with unique ID
            from dataclasses import replace
            config = replace(
                self._base_config,
                worker_id=f"{self._base_config.worker_id}-{i}",
                name=f"{self._base_config.name}-{i}",
            )

            worker = Worker(self.queue, config)
            worker.register_handlers(self._handlers)

            self._workers.append(worker)
            task = asyncio.create_task(worker.start())
            self._tasks.append(task)

    async def stop(self) -> None:
        """Stop all workers in the pool."""
        logger.info("Stopping worker pool")

        # Stop all workers
        await asyncio.gather(*[w.stop() for w in self._workers])

        # Cancel tasks
        for task in self._tasks:
            task.cancel()

        self._workers.clear()
        self._tasks.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get aggregated pool statistics."""
        total_processed = sum(w.stats.jobs_processed for w in self._workers)
        total_succeeded = sum(w.stats.jobs_succeeded for w in self._workers)
        total_failed = sum(w.stats.jobs_failed for w in self._workers)

        return {
            "num_workers": self.num_workers,
            "total_processed": total_processed,
            "total_succeeded": total_succeeded,
            "total_failed": total_failed,
            "success_rate": total_succeeded / total_processed if total_processed > 0 else 0,
            "workers": [w.get_status() for w in self._workers],
        }
