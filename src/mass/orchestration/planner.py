"""Scan planning module.

The ScanPlanner analyzes deployments and creates optimal
scan plans based on the profile and discovered components.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from mass.core.types import ComponentType
from mass.orchestration.profiles import ScanProfile


class JobType(str, Enum):
    """Types of scan jobs."""

    DEPLOYMENT_SCAN = "deployment_scan"
    SECRET_DETECTION = "secret_detection"
    INFRASTRUCTURE_SCAN = "infrastructure_scan"
    MODEL_FILE_SCAN = "model_file_scan"
    CONTEXT_ANALYSIS = "context_analysis"
    MCP_ANALYSIS = "mcp_analysis"
    ATTACK_SURFACE = "attack_surface"
    WORKFLOW_ANALYSIS = "workflow_analysis"
    MODEL_INTERROGATION = "model_interrogation"


@dataclass
class PlannedJob:
    """A single job in the scan plan."""

    id: str = field(default_factory=lambda: str(uuid4()))
    job_type: JobType = JobType.DEPLOYMENT_SCAN
    name: str = ""
    description: str = ""
    priority: int = 50
    timeout_seconds: int = 300
    depends_on: list[str] = field(default_factory=list)
    component_id: str | None = None
    component_type: ComponentType | None = None
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "job_type": self.job_type.value,
            "name": self.name,
            "description": self.description,
            "priority": self.priority,
            "timeout_seconds": self.timeout_seconds,
            "depends_on": self.depends_on,
            "component_id": self.component_id,
            "component_type": self.component_type.value if self.component_type else None,
            "config": self.config,
        }


@dataclass
class ScanPlan:
    """Complete scan plan with ordered jobs.

    The plan contains all jobs to execute, their dependencies,
    and estimated resource requirements.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    scan_id: str = ""
    deployment_id: str = ""
    profile_name: str = "standard"
    created_at: datetime = field(default_factory=datetime.utcnow)

    jobs: list[PlannedJob] = field(default_factory=list)

    # Metadata
    total_jobs: int = 0
    estimated_duration_seconds: int = 0
    phases: list[str] = field(default_factory=list)

    def add_job(self, job: PlannedJob) -> None:
        """Add a job to the plan."""
        self.jobs.append(job)
        self.total_jobs = len(self.jobs)
        self._update_estimates()

    def _update_estimates(self) -> None:
        """Update duration estimates based on jobs."""
        # Simple estimate: sum of timeouts with parallelism factor
        total = sum(j.timeout_seconds for j in self.jobs)
        parallelism = 4  # Assume 4 concurrent jobs
        self.estimated_duration_seconds = max(60, total // parallelism)

    def get_jobs_by_phase(self) -> dict[str, list[PlannedJob]]:
        """Group jobs by their type/phase."""
        phases: dict[str, list[PlannedJob]] = {}
        for job in self.jobs:
            phase = job.job_type.value
            if phase not in phases:
                phases[phase] = []
            phases[phase].append(job)
        return phases

    def get_ready_jobs(self, completed: set[str]) -> list[PlannedJob]:
        """Get jobs ready to execute (dependencies met).

        Args:
            completed: Set of completed job IDs.

        Returns:
            List of jobs ready to run.
        """
        ready = []
        for job in self.jobs:
            if job.id in completed:
                continue
            if all(dep in completed for dep in job.depends_on):
                ready.append(job)
        return sorted(ready, key=lambda j: j.priority)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "deployment_id": self.deployment_id,
            "profile_name": self.profile_name,
            "created_at": self.created_at.isoformat(),
            "total_jobs": self.total_jobs,
            "estimated_duration_seconds": self.estimated_duration_seconds,
            "phases": list(self.get_jobs_by_phase().keys()),
            "jobs": [j.to_dict() for j in self.jobs],
        }


@dataclass
class DeploymentInfo:
    """Information about a deployment for planning."""

    id: str
    name: str
    path: str | None = None

    # Discovered components
    has_models: bool = False
    has_context: bool = False
    has_mcp_servers: bool = False
    has_workflows: bool = False
    has_infrastructure: bool = False
    has_secrets_risk: bool = True  # Always check for secrets

    # Component lists
    model_files: list[str] = field(default_factory=list)
    context_files: list[str] = field(default_factory=list)
    mcp_configs: list[str] = field(default_factory=list)
    workflow_files: list[str] = field(default_factory=list)
    infrastructure_files: list[str] = field(default_factory=list)


class ScanPlanner:
    """Plans scans based on deployment and profile.

    The planner analyzes a deployment to discover components
    and creates an optimal execution plan.
    """

    def __init__(self, profile: ScanProfile) -> None:
        """Initialize planner with scan profile.

        Args:
            profile: Scan profile defining what to analyze.
        """
        self.profile = profile

    def create_plan(
        self,
        scan_id: str,
        deployment: DeploymentInfo,
    ) -> ScanPlan:
        """Create a scan plan for a deployment.

        Args:
            scan_id: ID of the scan.
            deployment: Deployment information.

        Returns:
            ScanPlan with all jobs to execute.
        """
        plan = ScanPlan(
            scan_id=scan_id,
            deployment_id=deployment.id,
            profile_name=self.profile.name,
        )

        # Track job IDs for dependencies
        deployment_scan_id: str | None = None
        static_analysis_ids: list[str] = []

        # 1. Deployment scanning (always first)
        if self.profile.deployment_scanner.enabled:
            job = PlannedJob(
                job_type=JobType.DEPLOYMENT_SCAN,
                name="Deployment Discovery",
                description="Scan deployment structure and discover components",
                priority=self.profile.deployment_scanner.priority,
                timeout_seconds=self.profile.deployment_scanner.timeout_seconds,
                config=self.profile.deployment_scanner.options,
            )
            plan.add_job(job)
            deployment_scan_id = job.id

        # 2. Static analysis jobs (depend on deployment scan)
        depends = [deployment_scan_id] if deployment_scan_id else []

        # Secret detection
        if self.profile.secret_detector.enabled and deployment.has_secrets_risk:
            job = PlannedJob(
                job_type=JobType.SECRET_DETECTION,
                name="Secret Detection",
                description="Scan for exposed credentials and secrets",
                priority=self.profile.secret_detector.priority,
                timeout_seconds=self.profile.secret_detector.timeout_seconds,
                depends_on=depends,
                config=self.profile.secret_detector.options,
            )
            plan.add_job(job)
            static_analysis_ids.append(job.id)

        # Infrastructure scanning
        if self.profile.infrastructure_scanner.enabled and deployment.has_infrastructure:
            for infra_file in deployment.infrastructure_files or [None]:
                job = PlannedJob(
                    job_type=JobType.INFRASTRUCTURE_SCAN,
                    name=f"Infrastructure Scan: {infra_file or 'all'}",
                    description="Analyze infrastructure configuration for vulnerabilities",
                    priority=self.profile.infrastructure_scanner.priority,
                    timeout_seconds=self.profile.infrastructure_scanner.timeout_seconds,
                    depends_on=depends,
                    component_id=infra_file,
                    component_type=ComponentType.INFRASTRUCTURE,
                    config=self.profile.infrastructure_scanner.options,
                )
                plan.add_job(job)
                static_analysis_ids.append(job.id)

        # Model file scanning
        if self.profile.model_file_scanner.enabled and deployment.has_models:
            for model_file in deployment.model_files or [None]:
                job = PlannedJob(
                    job_type=JobType.MODEL_FILE_SCAN,
                    name=f"Model File Scan: {model_file or 'all'}",
                    description="Analyze model files for security issues",
                    priority=self.profile.model_file_scanner.priority,
                    timeout_seconds=self.profile.model_file_scanner.timeout_seconds,
                    depends_on=depends,
                    component_id=model_file,
                    component_type=ComponentType.MODEL,
                    config=self.profile.model_file_scanner.options,
                )
                plan.add_job(job)
                static_analysis_ids.append(job.id)

        # Context analysis
        if self.profile.context_analyzer.enabled and deployment.has_context:
            for context_file in deployment.context_files or [None]:
                job = PlannedJob(
                    job_type=JobType.CONTEXT_ANALYSIS,
                    name=f"Context Analysis: {context_file or 'all'}",
                    description="Analyze system prompts and context configuration",
                    priority=self.profile.context_analyzer.priority,
                    timeout_seconds=self.profile.context_analyzer.timeout_seconds,
                    depends_on=depends,
                    component_id=context_file,
                    component_type=ComponentType.CONTEXT,
                    config=self.profile.context_analyzer.options,
                )
                plan.add_job(job)
                static_analysis_ids.append(job.id)

        # MCP analysis
        if self.profile.mcp_analyzer.enabled and deployment.has_mcp_servers:
            for mcp_config in deployment.mcp_configs or [None]:
                job = PlannedJob(
                    job_type=JobType.MCP_ANALYSIS,
                    name=f"MCP Analysis: {mcp_config or 'all'}",
                    description="Analyze MCP server configurations for security issues",
                    priority=self.profile.mcp_analyzer.priority,
                    timeout_seconds=self.profile.mcp_analyzer.timeout_seconds,
                    depends_on=depends,
                    component_id=mcp_config,
                    component_type=ComponentType.MCP_SERVER,
                    config=self.profile.mcp_analyzer.options,
                )
                plan.add_job(job)
                static_analysis_ids.append(job.id)

        # Workflow analysis
        if self.profile.workflow_analyzer.enabled and deployment.has_workflows:
            for workflow_file in deployment.workflow_files or [None]:
                job = PlannedJob(
                    job_type=JobType.WORKFLOW_ANALYSIS,
                    name=f"Workflow Analysis: {workflow_file or 'all'}",
                    description="Analyze agentic workflows for security issues",
                    priority=self.profile.workflow_analyzer.priority,
                    timeout_seconds=self.profile.workflow_analyzer.timeout_seconds,
                    depends_on=depends,
                    component_id=workflow_file,
                    component_type=ComponentType.WORKFLOW,
                    config=self.profile.workflow_analyzer.options,
                )
                plan.add_job(job)
                static_analysis_ids.append(job.id)

        # 3. Attack surface analysis (depends on static analysis)
        if self.profile.attack_surface_analyzer.enabled:
            job = PlannedJob(
                job_type=JobType.ATTACK_SURFACE,
                name="Attack Surface Analysis",
                description="Map attack vectors and vulnerability chains",
                priority=self.profile.attack_surface_analyzer.priority,
                timeout_seconds=self.profile.attack_surface_analyzer.timeout_seconds,
                depends_on=static_analysis_ids,
                config=self.profile.attack_surface_analyzer.options,
            )
            plan.add_job(job)

        # 4. Model interrogation (depends on everything else)
        if self.profile.model_interrogator.enabled and deployment.has_models:
            all_job_ids = [j.id for j in plan.jobs]
            job = PlannedJob(
                job_type=JobType.MODEL_INTERROGATION,
                name="Model Interrogation",
                description="Run security probes against model endpoints",
                priority=self.profile.model_interrogator.priority,
                timeout_seconds=self.profile.model_interrogator.timeout_seconds,
                depends_on=all_job_ids,
                component_type=ComponentType.MODEL,
                config=self.profile.model_interrogator.options,
            )
            plan.add_job(job)

        return plan

    def quick_plan(self, scan_id: str, deployment_id: str) -> ScanPlan:
        """Create a minimal plan for testing.

        Args:
            scan_id: Scan ID.
            deployment_id: Deployment ID.

        Returns:
            Minimal scan plan.
        """
        deployment = DeploymentInfo(
            id=deployment_id,
            name="quick-scan",
            has_secrets_risk=True,
        )
        return self.create_plan(scan_id, deployment)
