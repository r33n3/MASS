"""Base types and protocols for the worker system.

Defines the core abstractions for jobs, workers, and queues.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Protocol
from uuid import uuid4


class JobPriority(int, Enum):
    """Job priority levels."""

    CRITICAL = 1  # Immediate processing
    HIGH = 2  # High priority
    NORMAL = 3  # Default priority
    LOW = 4  # Background processing
    BATCH = 5  # Batch/bulk operations


class JobState(str, Enum):
    """Job execution states."""

    PENDING = "pending"  # Waiting in queue
    SCHEDULED = "scheduled"  # Scheduled for future execution
    RUNNING = "running"  # Currently executing
    COMPLETED = "completed"  # Successfully completed
    FAILED = "failed"  # Failed with error
    RETRYING = "retrying"  # Waiting for retry
    CANCELLED = "cancelled"  # Cancelled by user
    TIMEOUT = "timeout"  # Exceeded timeout


class WorkerStatus(str, Enum):
    """Worker status."""

    IDLE = "idle"  # Ready for work
    BUSY = "busy"  # Processing a job
    PAUSED = "paused"  # Temporarily paused
    STOPPING = "stopping"  # Graceful shutdown
    STOPPED = "stopped"  # Not running


@dataclass
class Job:
    """A unit of work to be processed.

    Jobs are the fundamental unit of work in the worker system.
    They contain all information needed to execute a task.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    job_type: str = ""  # e.g., "scan_job", "analysis_job"

    # Payload
    payload: dict[str, Any] = field(default_factory=dict)

    # Execution context
    scan_id: str | None = None
    tenant_id: str | None = None

    # Priority and scheduling
    priority: JobPriority = JobPriority.NORMAL
    scheduled_at: datetime | None = None  # For delayed execution

    # State
    state: JobState = JobState.PENDING
    progress: float = 0.0  # 0-100

    # Timing
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    timeout_seconds: int = 300

    # Retry configuration
    max_retries: int = 3
    retry_count: int = 0
    retry_delay_seconds: int = 60

    # Result
    result: dict[str, Any] | None = None
    error: str | None = None
    error_details: dict[str, Any] | None = None

    # Worker assignment
    worker_id: str | None = None
    queue_name: str = "default"

    # Metadata
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if job has exceeded its timeout."""
        if self.state != JobState.RUNNING or not self.started_at:
            return False
        elapsed = (datetime.utcnow() - self.started_at).total_seconds()
        return elapsed > self.timeout_seconds

    def can_retry(self) -> bool:
        """Check if job can be retried."""
        return self.retry_count < self.max_retries

    def next_retry_at(self) -> datetime:
        """Calculate next retry time with exponential backoff."""
        delay = self.retry_delay_seconds * (2 ** self.retry_count)
        return datetime.utcnow() + timedelta(seconds=delay)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "job_type": self.job_type,
            "payload": self.payload,
            "scan_id": self.scan_id,
            "tenant_id": self.tenant_id,
            "priority": self.priority.value,
            "scheduled_at": self.scheduled_at.isoformat() if self.scheduled_at else None,
            "state": self.state.value,
            "progress": self.progress,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "retry_count": self.retry_count,
            "result": self.result,
            "error": self.error,
            "worker_id": self.worker_id,
            "queue_name": self.queue_name,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Job":
        """Create job from dictionary."""
        job = cls(
            id=data.get("id", str(uuid4())),
            name=data.get("name", ""),
            job_type=data.get("job_type", ""),
            payload=data.get("payload", {}),
            scan_id=data.get("scan_id"),
            tenant_id=data.get("tenant_id"),
            priority=JobPriority(data.get("priority", JobPriority.NORMAL.value)),
            state=JobState(data.get("state", JobState.PENDING.value)),
            progress=data.get("progress", 0.0),
            timeout_seconds=data.get("timeout_seconds", 300),
            max_retries=data.get("max_retries", 3),
            retry_count=data.get("retry_count", 0),
            result=data.get("result"),
            error=data.get("error"),
            worker_id=data.get("worker_id"),
            queue_name=data.get("queue_name", "default"),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )

        # Parse datetime fields
        if data.get("created_at"):
            job.created_at = datetime.fromisoformat(data["created_at"])
        if data.get("started_at"):
            job.started_at = datetime.fromisoformat(data["started_at"])
        if data.get("completed_at"):
            job.completed_at = datetime.fromisoformat(data["completed_at"])
        if data.get("scheduled_at"):
            job.scheduled_at = datetime.fromisoformat(data["scheduled_at"])

        return job


@dataclass
class WorkerConfig:
    """Configuration for a worker."""

    worker_id: str = field(default_factory=lambda: f"worker-{uuid4().hex[:8]}")
    name: str = "worker"

    # Queues to process
    queues: list[str] = field(default_factory=lambda: ["default"])

    # Concurrency
    max_concurrent_jobs: int = 4
    job_timeout_seconds: int = 300

    # Polling
    poll_interval_seconds: float = 1.0
    empty_queue_sleep_seconds: float = 5.0

    # Health
    heartbeat_interval_seconds: float = 30.0
    max_memory_mb: int = 0  # 0 = no limit

    # Graceful shutdown
    shutdown_timeout_seconds: int = 30

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "worker_id": self.worker_id,
            "name": self.name,
            "queues": self.queues,
            "max_concurrent_jobs": self.max_concurrent_jobs,
            "job_timeout_seconds": self.job_timeout_seconds,
            "poll_interval_seconds": self.poll_interval_seconds,
        }


# Type aliases for handlers
JobHandler = Callable[[Job], dict[str, Any] | None]
ProgressCallback = Callable[[Job, float], None]


class QueueProtocol(Protocol):
    """Protocol for queue implementations."""

    async def enqueue(self, job: Job) -> str:
        """Add a job to the queue."""
        ...

    async def dequeue(self, queue_name: str, timeout: float | None = None) -> Job | None:
        """Remove and return the next job from the queue."""
        ...

    async def peek(self, queue_name: str) -> Job | None:
        """View the next job without removing it."""
        ...

    async def get_job(self, job_id: str) -> Job | None:
        """Get a job by ID."""
        ...

    async def update_job(self, job: Job) -> None:
        """Update a job's state."""
        ...

    async def delete_job(self, job_id: str) -> bool:
        """Delete a job."""
        ...

    async def get_queue_length(self, queue_name: str) -> int:
        """Get number of jobs in queue."""
        ...

    async def get_queue_stats(self, queue_name: str) -> dict[str, Any]:
        """Get queue statistics."""
        ...


class WorkerProtocol(Protocol):
    """Protocol for worker implementations."""

    async def start(self) -> None:
        """Start the worker."""
        ...

    async def stop(self) -> None:
        """Stop the worker gracefully."""
        ...

    async def process_job(self, job: Job) -> None:
        """Process a single job."""
        ...

    def register_handler(self, job_type: str, handler: JobHandler) -> None:
        """Register a handler for a job type."""
        ...
