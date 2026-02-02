"""Job queue abstraction with pluggable backends.

Provides a unified interface for job queues with support for
in-memory, Redis, and other backend implementations.
"""

import asyncio
import heapq
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mass.workers.base import Job, JobPriority, JobState


@dataclass
class QueueConfig:
    """Queue configuration."""

    backend: str = "memory"  # memory, redis
    name: str = "default"

    # Redis configuration
    redis_url: str = "redis://localhost:6379/0"
    redis_prefix: str = "mass:jobs:"

    # Memory queue settings
    max_size: int = 10000

    # TTL settings
    job_ttl_seconds: int = 86400  # 24 hours
    result_ttl_seconds: int = 3600  # 1 hour

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "backend": self.backend,
            "name": self.name,
            "max_size": self.max_size,
        }


class JobQueue(ABC):
    """Abstract base class for job queues."""

    def __init__(self, config: QueueConfig | None = None) -> None:
        """Initialize the queue.

        Args:
            config: Queue configuration.
        """
        self.config = config or QueueConfig()

    @abstractmethod
    async def enqueue(self, job: Job) -> str:
        """Add a job to the queue.

        Args:
            job: Job to enqueue.

        Returns:
            Job ID.
        """
        pass

    @abstractmethod
    async def dequeue(
        self,
        queue_name: str = "default",
        timeout: float | None = None,
    ) -> Job | None:
        """Remove and return the next job from the queue.

        Args:
            queue_name: Name of the queue.
            timeout: Optional timeout in seconds.

        Returns:
            Next job or None if queue is empty.
        """
        pass

    @abstractmethod
    async def peek(self, queue_name: str = "default") -> Job | None:
        """View the next job without removing it.

        Args:
            queue_name: Name of the queue.

        Returns:
            Next job or None if queue is empty.
        """
        pass

    @abstractmethod
    async def get_job(self, job_id: str) -> Job | None:
        """Get a job by ID.

        Args:
            job_id: Job ID.

        Returns:
            Job or None if not found.
        """
        pass

    @abstractmethod
    async def update_job(self, job: Job) -> None:
        """Update a job's state.

        Args:
            job: Job with updated state.
        """
        pass

    @abstractmethod
    async def delete_job(self, job_id: str) -> bool:
        """Delete a job.

        Args:
            job_id: Job ID.

        Returns:
            True if deleted, False if not found.
        """
        pass

    @abstractmethod
    async def get_queue_length(self, queue_name: str = "default") -> int:
        """Get number of jobs in queue.

        Args:
            queue_name: Name of the queue.

        Returns:
            Number of pending jobs.
        """
        pass

    @abstractmethod
    async def get_queue_stats(self, queue_name: str = "default") -> dict[str, Any]:
        """Get queue statistics.

        Args:
            queue_name: Name of the queue.

        Returns:
            Dictionary with queue statistics.
        """
        pass

    async def enqueue_many(self, jobs: list[Job]) -> list[str]:
        """Enqueue multiple jobs.

        Args:
            jobs: List of jobs to enqueue.

        Returns:
            List of job IDs.
        """
        return [await self.enqueue(job) for job in jobs]

    async def requeue(self, job: Job) -> str:
        """Requeue a failed job for retry.

        Args:
            job: Job to requeue.

        Returns:
            Job ID.
        """
        job.retry_count += 1
        job.state = JobState.RETRYING
        job.scheduled_at = job.next_retry_at()
        job.error = None
        job.started_at = None
        job.completed_at = None
        return await self.enqueue(job)


class MemoryQueue(JobQueue):
    """In-memory job queue implementation.

    Useful for testing and single-process deployments.
    Uses a priority queue for job ordering.
    """

    def __init__(self, config: QueueConfig | None = None) -> None:
        """Initialize the memory queue."""
        super().__init__(config)
        self._queues: dict[str, list[tuple[int, float, str]]] = {}
        self._jobs: dict[str, Job] = {}
        self._lock = asyncio.Lock()

    async def enqueue(self, job: Job) -> str:
        """Add a job to the queue."""
        async with self._lock:
            queue_name = job.queue_name

            # Initialize queue if needed
            if queue_name not in self._queues:
                self._queues[queue_name] = []

            # Check max size
            if len(self._queues[queue_name]) >= self.config.max_size:
                raise ValueError(f"Queue {queue_name} is full")

            # Store job
            self._jobs[job.id] = job

            # Add to priority queue (priority, timestamp, job_id)
            # Lower priority value = higher priority
            heapq.heappush(
                self._queues[queue_name],
                (job.priority.value, job.created_at.timestamp(), job.id),
            )

            return job.id

    async def dequeue(
        self,
        queue_name: str = "default",
        timeout: float | None = None,
    ) -> Job | None:
        """Remove and return the next job from the queue."""
        start_time = datetime.utcnow()

        while True:
            async with self._lock:
                if queue_name in self._queues and self._queues[queue_name]:
                    # Get highest priority job
                    _, _, job_id = heapq.heappop(self._queues[queue_name])
                    job = self._jobs.get(job_id)

                    if job:
                        # Check if scheduled for later
                        if job.scheduled_at and job.scheduled_at > datetime.utcnow():
                            # Put it back
                            heapq.heappush(
                                self._queues[queue_name],
                                (job.priority.value, job.scheduled_at.timestamp(), job.id),
                            )
                        else:
                            return job

            # Check timeout
            if timeout is not None:
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                if elapsed >= timeout:
                    return None

            # Wait before retrying
            await asyncio.sleep(0.1)

    async def peek(self, queue_name: str = "default") -> Job | None:
        """View the next job without removing it."""
        async with self._lock:
            if queue_name not in self._queues or not self._queues[queue_name]:
                return None

            # Get without removing
            _, _, job_id = self._queues[queue_name][0]
            return self._jobs.get(job_id)

    async def get_job(self, job_id: str) -> Job | None:
        """Get a job by ID."""
        return self._jobs.get(job_id)

    async def update_job(self, job: Job) -> None:
        """Update a job's state."""
        async with self._lock:
            self._jobs[job.id] = job

    async def delete_job(self, job_id: str) -> bool:
        """Delete a job."""
        async with self._lock:
            if job_id in self._jobs:
                job = self._jobs.pop(job_id)
                # Remove from queue if still pending
                queue_name = job.queue_name
                if queue_name in self._queues:
                    self._queues[queue_name] = [
                        (p, t, jid)
                        for p, t, jid in self._queues[queue_name]
                        if jid != job_id
                    ]
                    heapq.heapify(self._queues[queue_name])
                return True
            return False

    async def get_queue_length(self, queue_name: str = "default") -> int:
        """Get number of jobs in queue."""
        return len(self._queues.get(queue_name, []))

    async def get_queue_stats(self, queue_name: str = "default") -> dict[str, Any]:
        """Get queue statistics."""
        async with self._lock:
            queue = self._queues.get(queue_name, [])
            jobs = [self._jobs.get(jid) for _, _, jid in queue if jid in self._jobs]

            by_priority = {}
            by_state = {}

            for job in jobs:
                if job:
                    # Count by priority
                    p = job.priority.name
                    by_priority[p] = by_priority.get(p, 0) + 1

                    # Count by state
                    s = job.state.value
                    by_state[s] = by_state.get(s, 0) + 1

            return {
                "queue_name": queue_name,
                "length": len(queue),
                "total_jobs": len(self._jobs),
                "by_priority": by_priority,
                "by_state": by_state,
            }

    async def clear(self, queue_name: str | None = None) -> int:
        """Clear jobs from queue(s).

        Args:
            queue_name: Queue to clear, or None for all.

        Returns:
            Number of jobs removed.
        """
        async with self._lock:
            if queue_name:
                count = len(self._queues.get(queue_name, []))
                if queue_name in self._queues:
                    for _, _, job_id in self._queues[queue_name]:
                        self._jobs.pop(job_id, None)
                    self._queues[queue_name] = []
                return count
            else:
                count = len(self._jobs)
                self._queues.clear()
                self._jobs.clear()
                return count


class RedisQueue(JobQueue):
    """Redis-backed job queue implementation.

    Provides distributed, persistent job queues using Redis.
    Uses sorted sets for priority queue semantics.
    """

    def __init__(self, config: QueueConfig | None = None) -> None:
        """Initialize the Redis queue."""
        super().__init__(config or QueueConfig(backend="redis"))
        self._redis: Any = None

    async def _get_redis(self) -> Any:
        """Get or create Redis connection."""
        if self._redis is None:
            try:
                import redis.asyncio as redis
                self._redis = redis.from_url(self.config.redis_url)
            except ImportError:
                raise ImportError("redis package required for Redis queue backend")
        return self._redis

    def _queue_key(self, queue_name: str) -> str:
        """Get Redis key for queue."""
        return f"{self.config.redis_prefix}queue:{queue_name}"

    def _job_key(self, job_id: str) -> str:
        """Get Redis key for job data."""
        return f"{self.config.redis_prefix}job:{job_id}"

    async def enqueue(self, job: Job) -> str:
        """Add a job to the queue."""
        redis = await self._get_redis()

        # Store job data
        await redis.set(
            self._job_key(job.id),
            json.dumps(job.to_dict()),
            ex=self.config.job_ttl_seconds,
        )

        # Add to sorted set (score = priority * 1e12 + timestamp)
        # This ensures priority ordering with timestamp tiebreaker
        score = job.priority.value * 1e12 + job.created_at.timestamp()
        await redis.zadd(self._queue_key(job.queue_name), {job.id: score})

        return job.id

    async def dequeue(
        self,
        queue_name: str = "default",
        timeout: float | None = None,
    ) -> Job | None:
        """Remove and return the next job from the queue."""
        redis = await self._get_redis()
        timeout = timeout or 0

        # Use BZPOPMIN for blocking pop from sorted set
        if timeout > 0:
            result = await redis.bzpopmin(self._queue_key(queue_name), timeout)
        else:
            result = await redis.zpopmin(self._queue_key(queue_name))

        if not result:
            return None

        # Parse result
        if isinstance(result, tuple):
            job_id = result[0] if timeout == 0 else result[1]
        else:
            return None

        if isinstance(job_id, bytes):
            job_id = job_id.decode()

        # Get job data
        return await self.get_job(job_id)

    async def peek(self, queue_name: str = "default") -> Job | None:
        """View the next job without removing it."""
        redis = await self._get_redis()

        # Get first item from sorted set
        result = await redis.zrange(self._queue_key(queue_name), 0, 0)

        if not result:
            return None

        job_id = result[0]
        if isinstance(job_id, bytes):
            job_id = job_id.decode()

        return await self.get_job(job_id)

    async def get_job(self, job_id: str) -> Job | None:
        """Get a job by ID."""
        redis = await self._get_redis()

        data = await redis.get(self._job_key(job_id))
        if not data:
            return None

        if isinstance(data, bytes):
            data = data.decode()

        return Job.from_dict(json.loads(data))

    async def update_job(self, job: Job) -> None:
        """Update a job's state."""
        redis = await self._get_redis()

        await redis.set(
            self._job_key(job.id),
            json.dumps(job.to_dict()),
            ex=self.config.job_ttl_seconds,
        )

    async def delete_job(self, job_id: str) -> bool:
        """Delete a job."""
        redis = await self._get_redis()

        # Get job to find queue name
        job = await self.get_job(job_id)
        if not job:
            return False

        # Remove from queue and delete data
        await redis.zrem(self._queue_key(job.queue_name), job_id)
        await redis.delete(self._job_key(job_id))

        return True

    async def get_queue_length(self, queue_name: str = "default") -> int:
        """Get number of jobs in queue."""
        redis = await self._get_redis()
        return await redis.zcard(self._queue_key(queue_name))

    async def get_queue_stats(self, queue_name: str = "default") -> dict[str, Any]:
        """Get queue statistics."""
        redis = await self._get_redis()

        length = await redis.zcard(self._queue_key(queue_name))

        return {
            "queue_name": queue_name,
            "length": length,
            "backend": "redis",
        }

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None


def get_queue(config: QueueConfig | None = None) -> JobQueue:
    """Get a queue instance based on configuration.

    Args:
        config: Queue configuration.

    Returns:
        JobQueue instance.
    """
    config = config or QueueConfig()

    if config.backend == "redis":
        return RedisQueue(config)
    else:
        return MemoryQueue(config)
