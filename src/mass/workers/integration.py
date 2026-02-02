"""Integration between workers and scan orchestration.

Provides the AsyncScanService that uses the worker system
for distributed scan execution.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

from mass.core.findings import Finding, FindingSummary
from mass.core.types import ScanStatus, Severity
from mass.orchestration.planner import DeploymentInfo, ScanPlan, ScanPlanner
from mass.orchestration.profiles import ScanProfile, get_profile
from mass.orchestration.service import ScanProgress, ScanResult
from mass.workers.base import Job, JobPriority, JobState
from mass.workers.queue import QueueConfig, get_queue
from mass.workers.scheduler import Scheduler, SchedulerConfig


logger = logging.getLogger(__name__)


# Callback types
ProgressCallback = Callable[[ScanProgress], None]


@dataclass
class AsyncScanServiceConfig:
    """Configuration for async scan service."""

    # Scheduler settings
    num_workers: int = 4
    default_profile: str = "standard"

    # Queue settings
    queue_backend: str = "memory"
    redis_url: str = "redis://localhost:6379/0"

    # Timeouts
    job_timeout_seconds: int = 300
    scan_timeout_seconds: int = 1800


class AsyncScanService:
    """Async scan service using worker system.

    Extends the synchronous ScanService with async job processing
    using the worker pool and scheduler.
    """

    def __init__(self, config: AsyncScanServiceConfig | None = None) -> None:
        """Initialize the async scan service.

        Args:
            config: Service configuration.
        """
        self.config = config or AsyncScanServiceConfig()

        # Build scheduler config
        queue_config = QueueConfig(
            backend=self.config.queue_backend,
            redis_url=self.config.redis_url,
        )
        scheduler_config = SchedulerConfig(
            queue_config=queue_config,
            num_workers=self.config.num_workers,
            default_timeout_seconds=self.config.job_timeout_seconds,
        )

        self._scheduler = Scheduler(scheduler_config)
        self._scans: dict[str, ScanProgress] = {}
        self._results: dict[str, ScanResult] = {}
        self._callbacks: dict[str, list[ProgressCallback]] = {}

    async def start(self) -> None:
        """Start the service and worker pool."""
        await self._scheduler.start()
        logger.info("AsyncScanService started")

    async def stop(self) -> None:
        """Stop the service and worker pool."""
        await self._scheduler.stop()
        logger.info("AsyncScanService stopped")

    async def create_scan(
        self,
        deployment: DeploymentInfo,
        profile_name: str | None = None,
        scan_id: str | None = None,
    ) -> ScanPlan:
        """Create a scan plan.

        Args:
            deployment: Deployment to scan.
            profile_name: Scan profile name.
            scan_id: Optional scan ID.

        Returns:
            ScanPlan ready for execution.
        """
        scan_id = scan_id or str(uuid4())
        profile_name = profile_name or self.config.default_profile
        profile = get_profile(profile_name)

        planner = ScanPlanner(profile)
        plan = planner.create_plan(scan_id, deployment)

        # Initialize progress tracking
        self._scans[scan_id] = ScanProgress(
            scan_id=scan_id,
            jobs_total=plan.total_jobs,
        )

        return plan

    async def run_scan(
        self,
        scan_id: str,
        plan: ScanPlan,
        context: dict[str, Any],
        on_progress: ProgressCallback | None = None,
    ) -> ScanResult:
        """Execute a scan using the worker system.

        Args:
            scan_id: Scan ID.
            plan: Scan plan to execute.
            context: Execution context.
            on_progress: Progress callback.

        Returns:
            ScanResult with all findings.
        """
        progress = self._scans.get(scan_id)
        if not progress:
            progress = ScanProgress(scan_id=scan_id, jobs_total=plan.total_jobs)
            self._scans[scan_id] = progress

        if on_progress:
            if scan_id not in self._callbacks:
                self._callbacks[scan_id] = []
            self._callbacks[scan_id].append(on_progress)

        # Update progress
        progress.status = ScanStatus.RUNNING
        progress.started_at = datetime.utcnow()
        self._notify_progress(scan_id)

        # Convert plan jobs to worker jobs
        jobs_config = []
        for planned_job in plan.jobs:
            jobs_config.append({
                "job_type": planned_job.job_type.value,
                "name": planned_job.name,
                "payload": {
                    "context": context,
                    "config": planned_job.config,
                    "component_id": planned_job.component_id,
                },
                "priority": planned_job.priority,
            })

        # Define callbacks
        def on_job_complete(job: Job) -> None:
            progress.jobs_completed += 1
            if job.state == JobState.FAILED:
                progress.jobs_failed += 1
            progress.progress_percent = (
                progress.jobs_completed / progress.jobs_total * 100
                if progress.jobs_total > 0
                else 100
            )
            self._notify_progress(scan_id)

        def on_scan_complete(job: Job) -> None:
            progress.status = ScanStatus.COMPLETED
            progress.progress_percent = 100.0
            self._notify_progress(scan_id)

        # Submit scan to scheduler
        scheduled_scan = await self._scheduler.submit_scan(
            scan_id=scan_id,
            deployment_id=plan.deployment_id,
            jobs=jobs_config,
            on_complete=on_scan_complete,
            on_job_complete=on_job_complete,
        )

        # Wait for completion
        completed_scan = await self._scheduler.wait_for_scan(
            scan_id,
            timeout=self.config.scan_timeout_seconds,
        )

        # Collect results
        all_findings: list[Finding] = []

        for job_id in scheduled_scan.job_ids:
            job = await self._scheduler.queue.get_job(job_id)
            if job and job.result:
                # Findings are stored by ID in job result
                findings_ids = job.result.get("findings", [])
                # In a full implementation, we'd look these up from storage
                # For now, findings are aggregated during job execution

        # Create result
        result = ScanResult(
            scan_id=scan_id,
            deployment_id=plan.deployment_id,
            profile_name=plan.profile_name,
            status=ScanStatus.COMPLETED if progress.jobs_failed == 0 else ScanStatus.FAILED,
            started_at=progress.started_at,
            completed_at=datetime.utcnow(),
            findings=all_findings,
            summary=FindingSummary.from_findings(all_findings),
            jobs_completed=progress.jobs_completed,
            jobs_failed=progress.jobs_failed,
        )

        if result.started_at:
            result.duration_seconds = (
                result.completed_at - result.started_at
            ).total_seconds() if result.completed_at else 0

        self._results[scan_id] = result
        return result

    async def scan_deployment(
        self,
        deployment_path: str,
        profile_name: str = "standard",
        deployment_name: str | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> ScanResult:
        """Convenience method to scan a deployment.

        Args:
            deployment_path: Path to deployment.
            profile_name: Scan profile.
            deployment_name: Optional deployment name.
            on_progress: Progress callback.

        Returns:
            ScanResult with findings.
        """
        from pathlib import Path

        path = Path(deployment_path)
        if not path.exists():
            raise ValueError(f"Deployment path not found: {deployment_path}")

        # Create deployment info
        deployment = DeploymentInfo(
            id=str(uuid4()),
            name=deployment_name or path.name,
            path=str(path),
            has_models=any(path.rglob("*.pt")) or any(path.rglob("*.gguf")),
            has_context=any(path.rglob("*prompt*")) or any(path.rglob("*context*")),
            has_mcp_servers=any(path.rglob("*mcp*")),
            has_workflows=any(path.rglob("*agent*")) or any(path.rglob("*workflow*")),
            has_infrastructure=any(path.rglob("Dockerfile"))
            or any(path.rglob("*.yaml"))
            or any(path.rglob("*.tf")),
            has_secrets_risk=True,
        )

        # Create and run scan
        plan = await self.create_scan(deployment, profile_name)
        context = {"deployment_path": str(path)}
        return await self.run_scan(plan.scan_id, plan, context, on_progress)

    def get_progress(self, scan_id: str) -> ScanProgress | None:
        """Get scan progress."""
        return self._scans.get(scan_id)

    def get_result(self, scan_id: str) -> ScanResult | None:
        """Get scan result."""
        return self._results.get(scan_id)

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan."""
        success = await self._scheduler.cancel_scan(scan_id)
        if success and scan_id in self._scans:
            self._scans[scan_id].status = ScanStatus.CANCELLED
            self._notify_progress(scan_id)
        return success

    def _notify_progress(self, scan_id: str) -> None:
        """Notify progress callbacks."""
        progress = self._scans.get(scan_id)
        callbacks = self._callbacks.get(scan_id, [])

        if progress:
            for callback in callbacks:
                try:
                    callback(progress)
                except Exception:
                    pass

    def get_stats(self) -> dict[str, Any]:
        """Get service statistics."""
        return {
            "active_scans": len([s for s in self._scans.values() if s.status == ScanStatus.RUNNING]),
            "total_scans": len(self._scans),
            "scheduler": self._scheduler.get_stats(),
        }
