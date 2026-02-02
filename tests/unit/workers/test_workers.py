"""Tests for worker system module."""

import asyncio
import pytest
from datetime import datetime, timedelta

from mass.workers.base import (
    Job,
    JobPriority,
    JobState,
    WorkerConfig,
    WorkerStatus,
)
from mass.workers.queue import (
    JobQueue,
    MemoryQueue,
    QueueConfig,
    get_queue,
)
from mass.workers.worker import Worker, WorkerPool, WorkerStats
from mass.workers.scheduler import Scheduler, SchedulerConfig, ScheduledScan


class TestJob:
    """Tests for Job class."""

    def test_job_creation(self):
        """Test creating a job."""
        job = Job(
            name="test-job",
            job_type="test",
            payload={"key": "value"},
        )
        assert job.name == "test-job"
        assert job.job_type == "test"
        assert job.payload["key"] == "value"
        assert job.state == JobState.PENDING
        assert len(job.id) > 0

    def test_job_priority(self):
        """Test job priority."""
        job = Job(priority=JobPriority.HIGH)
        assert job.priority == JobPriority.HIGH
        assert job.priority.value == 2

    def test_job_to_dict(self):
        """Test job serialization."""
        job = Job(name="test", job_type="test")
        data = job.to_dict()
        assert data["name"] == "test"
        assert data["job_type"] == "test"
        assert data["state"] == "pending"

    def test_job_from_dict(self):
        """Test job deserialization."""
        data = {
            "id": "job-123",
            "name": "test",
            "job_type": "test",
            "state": "running",
            "priority": 2,
        }
        job = Job.from_dict(data)
        assert job.id == "job-123"
        assert job.name == "test"
        assert job.state == JobState.RUNNING
        assert job.priority == JobPriority.HIGH

    def test_job_is_expired(self):
        """Test job expiration check."""
        job = Job(timeout_seconds=1)
        assert job.is_expired() is False

        job.state = JobState.RUNNING
        job.started_at = datetime.utcnow() - timedelta(seconds=2)
        assert job.is_expired() is True

    def test_job_can_retry(self):
        """Test retry check."""
        job = Job(max_retries=3)
        assert job.can_retry() is True

        job.retry_count = 3
        assert job.can_retry() is False

    def test_job_next_retry_at(self):
        """Test retry time calculation with exponential backoff."""
        job = Job(retry_delay_seconds=10)
        job.retry_count = 0
        retry_at = job.next_retry_at()
        assert retry_at > datetime.utcnow()

        job.retry_count = 2
        retry_at = job.next_retry_at()
        # Should be longer due to backoff
        assert retry_at > datetime.utcnow() + timedelta(seconds=30)


class TestWorkerConfig:
    """Tests for WorkerConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = WorkerConfig()
        assert "worker-" in config.worker_id
        assert config.max_concurrent_jobs == 4
        assert "default" in config.queues

    def test_custom_config(self):
        """Test custom configuration."""
        config = WorkerConfig(
            worker_id="custom-worker",
            queues=["high", "low"],
            max_concurrent_jobs=8,
        )
        assert config.worker_id == "custom-worker"
        assert "high" in config.queues
        assert config.max_concurrent_jobs == 8


class TestQueueConfig:
    """Tests for QueueConfig."""

    def test_default_config(self):
        """Test default queue configuration."""
        config = QueueConfig()
        assert config.backend == "memory"
        assert config.name == "default"

    def test_redis_config(self):
        """Test Redis queue configuration."""
        config = QueueConfig(
            backend="redis",
            redis_url="redis://localhost:6380/1",
        )
        assert config.backend == "redis"
        assert "6380" in config.redis_url


class TestMemoryQueue:
    """Tests for MemoryQueue."""

    @pytest.fixture
    def queue(self):
        """Create a memory queue."""
        return MemoryQueue()

    @pytest.mark.asyncio
    async def test_enqueue_dequeue(self, queue):
        """Test basic enqueue and dequeue."""
        job = Job(name="test", job_type="test")
        job_id = await queue.enqueue(job)
        assert job_id == job.id

        dequeued = await queue.dequeue()
        assert dequeued is not None
        assert dequeued.id == job.id

    @pytest.mark.asyncio
    async def test_priority_ordering(self, queue):
        """Test jobs are dequeued by priority."""
        low = Job(name="low", job_type="test", priority=JobPriority.LOW)
        high = Job(name="high", job_type="test", priority=JobPriority.HIGH)

        await queue.enqueue(low)
        await queue.enqueue(high)

        # High priority should come first
        first = await queue.dequeue()
        assert first.name == "high"

        second = await queue.dequeue()
        assert second.name == "low"

    @pytest.mark.asyncio
    async def test_peek(self, queue):
        """Test peeking at next job."""
        job = Job(name="test", job_type="test")
        await queue.enqueue(job)

        peeked = await queue.peek()
        assert peeked is not None
        assert peeked.id == job.id

        # Job should still be in queue
        length = await queue.get_queue_length()
        assert length == 1

    @pytest.mark.asyncio
    async def test_get_job(self, queue):
        """Test getting job by ID."""
        job = Job(name="test", job_type="test")
        await queue.enqueue(job)

        fetched = await queue.get_job(job.id)
        assert fetched is not None
        assert fetched.id == job.id

    @pytest.mark.asyncio
    async def test_update_job(self, queue):
        """Test updating a job."""
        job = Job(name="test", job_type="test")
        await queue.enqueue(job)

        job.state = JobState.RUNNING
        await queue.update_job(job)

        fetched = await queue.get_job(job.id)
        assert fetched.state == JobState.RUNNING

    @pytest.mark.asyncio
    async def test_delete_job(self, queue):
        """Test deleting a job."""
        job = Job(name="test", job_type="test")
        await queue.enqueue(job)

        deleted = await queue.delete_job(job.id)
        assert deleted is True

        fetched = await queue.get_job(job.id)
        assert fetched is None

    @pytest.mark.asyncio
    async def test_queue_length(self, queue):
        """Test queue length."""
        assert await queue.get_queue_length() == 0

        await queue.enqueue(Job(name="1", job_type="test"))
        await queue.enqueue(Job(name="2", job_type="test"))

        assert await queue.get_queue_length() == 2

    @pytest.mark.asyncio
    async def test_queue_stats(self, queue):
        """Test queue statistics."""
        await queue.enqueue(Job(name="1", job_type="test", priority=JobPriority.HIGH))
        await queue.enqueue(Job(name="2", job_type="test", priority=JobPriority.LOW))

        stats = await queue.get_queue_stats()
        assert stats["length"] == 2
        assert "by_priority" in stats

    @pytest.mark.asyncio
    async def test_clear(self, queue):
        """Test clearing queue."""
        await queue.enqueue(Job(name="1", job_type="test"))
        await queue.enqueue(Job(name="2", job_type="test"))

        count = await queue.clear()
        assert count == 2
        assert await queue.get_queue_length() == 0

    @pytest.mark.asyncio
    async def test_dequeue_timeout(self, queue):
        """Test dequeue with timeout on empty queue."""
        result = await queue.dequeue(timeout=0.1)
        assert result is None


class TestGetQueue:
    """Tests for get_queue factory function."""

    def test_get_memory_queue(self):
        """Test getting memory queue."""
        queue = get_queue()
        assert isinstance(queue, MemoryQueue)

    def test_get_memory_queue_explicit(self):
        """Test getting memory queue explicitly."""
        config = QueueConfig(backend="memory")
        queue = get_queue(config)
        assert isinstance(queue, MemoryQueue)


class TestWorkerStats:
    """Tests for WorkerStats."""

    def test_stats_creation(self):
        """Test creating worker stats."""
        stats = WorkerStats()
        assert stats.jobs_processed == 0
        assert stats.jobs_succeeded == 0

    def test_stats_to_dict(self):
        """Test stats serialization."""
        stats = WorkerStats(
            jobs_processed=10,
            jobs_succeeded=8,
            jobs_failed=2,
            total_processing_time=100.0,
        )
        data = stats.to_dict()
        assert data["jobs_processed"] == 10
        assert data["success_rate"] == 0.8
        assert data["average_time"] == 10.0


class TestWorker:
    """Tests for Worker class."""

    @pytest.fixture
    def queue(self):
        """Create a memory queue."""
        return MemoryQueue()

    @pytest.fixture
    def worker(self, queue):
        """Create a worker."""
        return Worker(queue=queue)

    def test_worker_creation(self, worker):
        """Test creating a worker."""
        assert worker.status == WorkerStatus.STOPPED
        assert worker.stats.jobs_processed == 0

    def test_register_handler(self, worker):
        """Test registering a handler."""

        def handler(job: Job) -> dict:
            return {"result": "ok"}

        worker.register_handler("test", handler)
        assert "test" in worker._handlers

    def test_register_multiple_handlers(self, worker):
        """Test registering multiple handlers."""
        handlers = {
            "type1": lambda j: {"result": 1},
            "type2": lambda j: {"result": 2},
        }
        worker.register_handlers(handlers)
        assert "type1" in worker._handlers
        assert "type2" in worker._handlers

    def test_get_status(self, worker):
        """Test getting worker status."""
        status = worker.get_status()
        assert "worker_id" in status
        assert status["status"] == "stopped"
        assert "stats" in status


class TestWorkerPool:
    """Tests for WorkerPool."""

    def test_pool_creation(self):
        """Test creating a worker pool."""
        queue = MemoryQueue()
        pool = WorkerPool(queue, num_workers=4)
        assert pool.num_workers == 4

    def test_pool_register_handler(self):
        """Test registering handler on pool."""
        queue = MemoryQueue()
        pool = WorkerPool(queue, num_workers=2)
        pool.register_handler("test", lambda j: None)
        assert "test" in pool._handlers


class TestScheduledScan:
    """Tests for ScheduledScan."""

    def test_scan_creation(self):
        """Test creating a scheduled scan."""
        scan = ScheduledScan(
            scan_id="scan-123",
            deployment_id="deploy-456",
        )
        assert scan.scan_id == "scan-123"
        assert scan.status == "pending"

    def test_scan_to_dict(self):
        """Test scan serialization."""
        scan = ScheduledScan(
            scan_id="scan-123",
            deployment_id="deploy-456",
            total_jobs=5,
            completed_jobs=2,
        )
        data = scan.to_dict()
        assert data["scan_id"] == "scan-123"
        assert data["total_jobs"] == 5
        assert data["completed_jobs"] == 2


class TestSchedulerConfig:
    """Tests for SchedulerConfig."""

    def test_default_config(self):
        """Test default scheduler configuration."""
        config = SchedulerConfig()
        assert config.num_workers == 4
        assert config.default_timeout_seconds == 300

    def test_custom_config(self):
        """Test custom scheduler configuration."""
        config = SchedulerConfig(
            num_workers=8,
            default_timeout_seconds=600,
        )
        assert config.num_workers == 8
        assert config.default_timeout_seconds == 600


class TestScheduler:
    """Tests for Scheduler class."""

    @pytest.fixture
    def scheduler(self):
        """Create a scheduler."""
        config = SchedulerConfig(num_workers=1)
        return Scheduler(config)

    def test_scheduler_creation(self, scheduler):
        """Test creating a scheduler."""
        assert scheduler.config.num_workers == 1
        assert scheduler._running is False

    @pytest.mark.asyncio
    async def test_submit_job(self, scheduler):
        """Test submitting a job."""
        job_id = await scheduler.submit_job(
            job_type="test",
            payload={"key": "value"},
            name="test-job",
        )
        assert job_id is not None
        assert len(job_id) > 0

    @pytest.mark.asyncio
    async def test_submit_job_with_priority(self, scheduler):
        """Test submitting job with priority."""
        job_id = await scheduler.submit_job(
            job_type="test",
            payload={},
            priority=JobPriority.HIGH,
        )

        job = await scheduler.queue.get_job(job_id)
        assert job.priority == JobPriority.HIGH

    @pytest.mark.asyncio
    async def test_submit_scan(self, scheduler):
        """Test submitting a scan."""
        jobs = [
            {"job_type": "test1", "payload": {}, "name": "Job 1"},
            {"job_type": "test2", "payload": {}, "name": "Job 2"},
        ]

        scan = await scheduler.submit_scan(
            scan_id="scan-123",
            deployment_id="deploy-456",
            jobs=jobs,
        )

        assert scan.scan_id == "scan-123"
        assert scan.total_jobs == 2
        assert len(scan.job_ids) == 2

    @pytest.mark.asyncio
    async def test_get_job_status(self, scheduler):
        """Test getting job status."""
        job_id = await scheduler.submit_job(
            job_type="test",
            payload={},
        )

        status = await scheduler.get_job_status(job_id)
        assert status is not None
        assert status["state"] == "pending"

    @pytest.mark.asyncio
    async def test_get_job_status_not_found(self, scheduler):
        """Test getting status of nonexistent job."""
        status = await scheduler.get_job_status("nonexistent")
        assert status is None

    @pytest.mark.asyncio
    async def test_get_scan_status(self, scheduler):
        """Test getting scan status."""
        await scheduler.submit_scan(
            scan_id="scan-123",
            deployment_id="deploy-456",
            jobs=[{"job_type": "test", "payload": {}}],
        )

        status = await scheduler.get_scan_status("scan-123")
        assert status is not None
        assert status["scan_id"] == "scan-123"

    @pytest.mark.asyncio
    async def test_cancel_job(self, scheduler):
        """Test cancelling a job."""
        job_id = await scheduler.submit_job(
            job_type="test",
            payload={},
        )

        result = await scheduler.cancel_job(job_id)
        assert result is True

        job = await scheduler.queue.get_job(job_id)
        assert job.state == JobState.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_job_not_found(self, scheduler):
        """Test cancelling nonexistent job."""
        result = await scheduler.cancel_job("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_scan(self, scheduler):
        """Test cancelling a scan."""
        await scheduler.submit_scan(
            scan_id="scan-123",
            deployment_id="deploy-456",
            jobs=[{"job_type": "test", "payload": {}}],
        )

        result = await scheduler.cancel_scan("scan-123")
        assert result is True

    def test_get_stats(self, scheduler):
        """Test getting scheduler stats."""
        stats = scheduler.get_stats()
        assert "running" in stats
        assert "num_workers" in stats


class TestIntegration:
    """Integration tests for worker system."""

    @pytest.mark.asyncio
    async def test_job_submission_and_retrieval(self):
        """Test complete job submission flow."""
        queue = MemoryQueue()
        scheduler = Scheduler(SchedulerConfig(num_workers=1))
        scheduler._queue = queue

        # Submit jobs
        job_ids = []
        for i in range(3):
            job_id = await scheduler.submit_job(
                job_type=f"type-{i}",
                payload={"index": i},
                name=f"Job {i}",
            )
            job_ids.append(job_id)

        # Verify all jobs are in queue
        length = await queue.get_queue_length()
        assert length == 3

        # Verify each job
        for job_id in job_ids:
            status = await scheduler.get_job_status(job_id)
            assert status is not None
            assert status["state"] == "pending"

    @pytest.mark.asyncio
    async def test_scan_workflow(self):
        """Test complete scan submission workflow."""
        scheduler = Scheduler(SchedulerConfig(num_workers=1))

        # Submit a scan with multiple jobs
        scan = await scheduler.submit_scan(
            scan_id="integration-scan",
            deployment_id="test-deploy",
            jobs=[
                {"job_type": "analysis", "payload": {"step": 1}, "name": "Step 1"},
                {"job_type": "analysis", "payload": {"step": 2}, "name": "Step 2"},
                {"job_type": "report", "payload": {"step": 3}, "name": "Step 3"},
            ],
        )

        assert scan.total_jobs == 3
        assert scan.status == "running"

        # Check status
        status = await scheduler.get_scan_status("integration-scan")
        assert status["total_jobs"] == 3

        # Cancel scan
        await scheduler.cancel_scan("integration-scan")

        # Verify cancelled
        for job_id in scan.job_ids:
            job = await scheduler.queue.get_job(job_id)
            assert job.state == JobState.CANCELLED

    @pytest.mark.asyncio
    async def test_priority_queue_ordering(self):
        """Test jobs are processed by priority."""
        queue = MemoryQueue()

        # Submit jobs in reverse priority order
        await queue.enqueue(Job(name="batch", job_type="t", priority=JobPriority.BATCH))
        await queue.enqueue(Job(name="normal", job_type="t", priority=JobPriority.NORMAL))
        await queue.enqueue(Job(name="critical", job_type="t", priority=JobPriority.CRITICAL))

        # Should get critical first
        job1 = await queue.dequeue()
        assert job1.name == "critical"

        job2 = await queue.dequeue()
        assert job2.name == "normal"

        job3 = await queue.dequeue()
        assert job3.name == "batch"
