"""Tests for scan orchestration module."""

import pytest
from datetime import datetime

from mass.core.types import ComponentType, ScanStatus
from mass.orchestration.profiles import (
    ScanProfile,
    ProfileType,
    AnalyzerConfig,
    get_profile,
    create_custom_profile,
    QUICK_PROFILE,
    STANDARD_PROFILE,
    COMPREHENSIVE_PROFILE,
)
from mass.orchestration.planner import (
    ScanPlanner,
    ScanPlan,
    PlannedJob,
    JobType,
    DeploymentInfo,
)
from mass.orchestration.executor import (
    JobExecutor,
    JobResult,
    JobStatus,
)
from mass.orchestration.service import (
    ScanService,
    ScanServiceConfig,
    ScanProgress,
    ScanResult,
)


class TestAnalyzerConfig:
    """Tests for AnalyzerConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = AnalyzerConfig()
        assert config.enabled is True
        assert config.priority == 50
        assert config.timeout_seconds == 300
        assert config.options == {}

    def test_custom_config(self):
        """Test custom configuration."""
        config = AnalyzerConfig(
            enabled=False,
            priority=10,
            timeout_seconds=600,
            options={"key": "value"},
        )
        assert config.enabled is False
        assert config.priority == 10
        assert config.timeout_seconds == 600
        assert config.options["key"] == "value"


class TestScanProfile:
    """Tests for ScanProfile."""

    def test_quick_profile(self):
        """Test quick profile configuration."""
        profile = QUICK_PROFILE
        assert profile.name == "quick"
        assert profile.profile_type == ProfileType.QUICK
        assert profile.deployment_scanner.enabled is True
        assert profile.model_interrogator.enabled is False

    def test_standard_profile(self):
        """Test standard profile configuration."""
        profile = STANDARD_PROFILE
        assert profile.name == "standard"
        assert profile.profile_type == ProfileType.STANDARD
        enabled = profile.get_enabled_analyzers()
        assert "deployment_scanner" in enabled
        assert "workflow_analyzer" in enabled
        assert "model_interrogator" not in enabled

    def test_comprehensive_profile(self):
        """Test comprehensive profile configuration."""
        profile = COMPREHENSIVE_PROFILE
        assert profile.name == "comprehensive"
        assert profile.model_interrogator.enabled is True
        enabled = profile.get_enabled_analyzers()
        assert "model_interrogator" in enabled

    def test_get_enabled_analyzers_order(self):
        """Test that analyzers are ordered by priority."""
        profile = STANDARD_PROFILE
        enabled = profile.get_enabled_analyzers()
        assert len(enabled) > 0
        # Deployment scanner should be first (lowest priority)
        assert enabled[0] == "deployment_scanner"

    def test_profile_to_dict(self):
        """Test profile serialization."""
        profile = QUICK_PROFILE
        data = profile.to_dict()
        assert data["name"] == "quick"
        assert data["profile_type"] == "quick"
        assert "enabled_analyzers" in data


class TestGetProfile:
    """Tests for get_profile function."""

    def test_get_quick_profile(self):
        """Test retrieving quick profile."""
        profile = get_profile("quick")
        assert profile.name == "quick"

    def test_get_standard_profile(self):
        """Test retrieving standard profile."""
        profile = get_profile("standard")
        assert profile.name == "standard"

    def test_get_comprehensive_profile(self):
        """Test retrieving comprehensive profile."""
        profile = get_profile("comprehensive")
        assert profile.name == "comprehensive"

    def test_get_unknown_profile(self):
        """Test error on unknown profile."""
        with pytest.raises(ValueError, match="Unknown profile"):
            get_profile("nonexistent")


class TestCreateCustomProfile:
    """Tests for create_custom_profile function."""

    def test_create_from_standard(self):
        """Test creating custom profile from standard."""
        profile = create_custom_profile(base="standard")
        assert profile.name == "custom"
        assert profile.profile_type == ProfileType.CUSTOM

    def test_disable_analyzers(self):
        """Test disabling analyzers."""
        profile = create_custom_profile(
            base="standard",
            disabled_analyzers=["workflow_analyzer"],
        )
        assert profile.workflow_analyzer.enabled is False

    def test_enable_analyzers(self):
        """Test enabling analyzers."""
        profile = create_custom_profile(
            base="quick",
            enabled_analyzers=["model_interrogator"],
        )
        assert profile.model_interrogator.enabled is True


class TestPlannedJob:
    """Tests for PlannedJob."""

    def test_job_creation(self):
        """Test creating a planned job."""
        job = PlannedJob(
            job_type=JobType.DEPLOYMENT_SCAN,
            name="Test Job",
            description="A test job",
            priority=10,
        )
        assert job.job_type == JobType.DEPLOYMENT_SCAN
        assert job.name == "Test Job"
        assert job.priority == 10
        assert len(job.id) > 0

    def test_job_to_dict(self):
        """Test job serialization."""
        job = PlannedJob(
            job_type=JobType.SECRET_DETECTION,
            name="Secret Scan",
        )
        data = job.to_dict()
        assert data["job_type"] == "secret_detection"
        assert data["name"] == "Secret Scan"


class TestScanPlan:
    """Tests for ScanPlan."""

    def test_plan_creation(self):
        """Test creating a scan plan."""
        plan = ScanPlan(
            scan_id="test-scan-123",
            deployment_id="deploy-456",
            profile_name="standard",
        )
        assert plan.scan_id == "test-scan-123"
        assert plan.total_jobs == 0

    def test_add_job(self):
        """Test adding jobs to plan."""
        plan = ScanPlan()
        job = PlannedJob(job_type=JobType.DEPLOYMENT_SCAN, name="Test")
        plan.add_job(job)
        assert plan.total_jobs == 1
        assert len(plan.jobs) == 1

    def test_get_ready_jobs(self):
        """Test getting ready jobs."""
        plan = ScanPlan()
        job1 = PlannedJob(job_type=JobType.DEPLOYMENT_SCAN, name="Job1")
        job2 = PlannedJob(
            job_type=JobType.SECRET_DETECTION,
            name="Job2",
            depends_on=[job1.id],
        )
        plan.add_job(job1)
        plan.add_job(job2)

        # Initially only job1 is ready
        ready = plan.get_ready_jobs(set())
        assert len(ready) == 1
        assert ready[0].id == job1.id

        # After job1 completes, job2 is ready
        ready = plan.get_ready_jobs({job1.id})
        assert len(ready) == 1
        assert ready[0].id == job2.id


class TestDeploymentInfo:
    """Tests for DeploymentInfo."""

    def test_deployment_info_creation(self):
        """Test creating deployment info."""
        info = DeploymentInfo(
            id="deploy-123",
            name="test-deployment",
            has_models=True,
            has_workflows=True,
        )
        assert info.id == "deploy-123"
        assert info.has_models is True
        assert info.has_workflows is True
        assert info.has_secrets_risk is True  # Default


class TestScanPlanner:
    """Tests for ScanPlanner."""

    def test_planner_creation(self):
        """Test creating a planner."""
        profile = get_profile("quick")
        planner = ScanPlanner(profile)
        assert planner.profile == profile

    def test_create_minimal_plan(self):
        """Test creating a minimal plan."""
        profile = get_profile("quick")
        planner = ScanPlanner(profile)
        deployment = DeploymentInfo(
            id="deploy-123",
            name="test",
        )
        plan = planner.create_plan("scan-123", deployment)
        assert plan.scan_id == "scan-123"
        assert plan.total_jobs >= 1

    def test_create_comprehensive_plan(self):
        """Test creating a comprehensive plan."""
        profile = get_profile("comprehensive")
        planner = ScanPlanner(profile)
        deployment = DeploymentInfo(
            id="deploy-123",
            name="test",
            has_models=True,
            has_context=True,
            has_mcp_servers=True,
            has_workflows=True,
            has_infrastructure=True,
        )
        plan = planner.create_plan("scan-123", deployment)
        # Should have many jobs
        assert plan.total_jobs >= 5

    def test_quick_plan(self):
        """Test quick plan generation."""
        profile = get_profile("standard")
        planner = ScanPlanner(profile)
        plan = planner.quick_plan("scan-123", "deploy-456")
        assert plan.scan_id == "scan-123"
        assert plan.deployment_id == "deploy-456"


class TestJobResult:
    """Tests for JobResult."""

    def test_result_creation(self):
        """Test creating a job result."""
        result = JobResult(
            job_id="job-123",
            job_type=JobType.DEPLOYMENT_SCAN,
        )
        assert result.job_id == "job-123"
        assert result.status == JobStatus.PENDING

    def test_mark_started(self):
        """Test marking job as started."""
        result = JobResult(job_id="job-123", job_type=JobType.DEPLOYMENT_SCAN)
        result.mark_started()
        assert result.status == JobStatus.RUNNING
        assert result.started_at is not None

    def test_mark_completed(self):
        """Test marking job as completed."""
        result = JobResult(job_id="job-123", job_type=JobType.DEPLOYMENT_SCAN)
        result.mark_started()
        result.mark_completed()
        assert result.status == JobStatus.COMPLETED
        assert result.completed_at is not None
        assert result.duration_seconds >= 0

    def test_mark_failed(self):
        """Test marking job as failed."""
        result = JobResult(job_id="job-123", job_type=JobType.DEPLOYMENT_SCAN)
        result.mark_started()
        result.mark_failed("Test error", {"code": 500})
        assert result.status == JobStatus.FAILED
        assert result.error == "Test error"
        assert result.error_details["code"] == 500

    def test_add_finding(self):
        """Test adding findings to result."""
        from mass.core.findings import Finding
        from mass.core.types import Severity, AttackCategory, ComponentType

        result = JobResult(job_id="job-123", job_type=JobType.DEPLOYMENT_SCAN)
        finding = Finding(
            title="Test Finding",
            description="Test",
            severity=Severity.HIGH,
            category=AttackCategory.PROMPT_INJECTION,
            component_type=ComponentType.MODEL,
            component_name="test-model",
        )
        result.add_finding(finding)
        assert result.findings_count == 1
        assert result.high_count == 1


class TestJobExecutor:
    """Tests for JobExecutor."""

    def test_executor_creation(self):
        """Test creating an executor."""
        executor = JobExecutor()
        assert executor is not None

    def test_get_result(self):
        """Test getting job result."""
        executor = JobExecutor()
        result = executor.get_result("nonexistent")
        assert result is None


class TestScanServiceConfig:
    """Tests for ScanServiceConfig."""

    def test_default_config(self):
        """Test default service configuration."""
        config = ScanServiceConfig()
        assert config.max_concurrent_scans == 10
        assert config.default_profile == "standard"

    def test_custom_config(self):
        """Test custom service configuration."""
        config = ScanServiceConfig(
            max_concurrent_scans=5,
            default_profile="quick",
        )
        assert config.max_concurrent_scans == 5
        assert config.default_profile == "quick"


class TestScanProgress:
    """Tests for ScanProgress."""

    def test_progress_creation(self):
        """Test creating scan progress."""
        progress = ScanProgress(scan_id="scan-123")
        assert progress.scan_id == "scan-123"
        assert progress.status == ScanStatus.PENDING

    def test_progress_to_dict(self):
        """Test progress serialization."""
        progress = ScanProgress(
            scan_id="scan-123",
            status=ScanStatus.RUNNING,
            progress_percent=50.0,
        )
        data = progress.to_dict()
        assert data["scan_id"] == "scan-123"
        assert data["status"] == "running"
        assert data["progress_percent"] == 50.0


class TestScanResult:
    """Tests for ScanResult."""

    def test_result_creation(self):
        """Test creating scan result."""
        result = ScanResult(
            scan_id="scan-123",
            deployment_id="deploy-456",
            profile_name="standard",
        )
        assert result.scan_id == "scan-123"
        assert result.status == ScanStatus.COMPLETED

    def test_result_to_dict(self):
        """Test result serialization."""
        result = ScanResult(
            scan_id="scan-123",
            deployment_id="deploy-456",
            profile_name="standard",
        )
        data = result.to_dict()
        assert data["scan_id"] == "scan-123"
        assert data["deployment_id"] == "deploy-456"


class TestScanService:
    """Tests for ScanService."""

    def test_service_creation(self):
        """Test creating scan service."""
        service = ScanService()
        assert service is not None
        assert service.config.default_profile == "standard"

    def test_service_with_config(self):
        """Test creating service with custom config."""
        config = ScanServiceConfig(default_profile="quick")
        service = ScanService(config)
        assert service.config.default_profile == "quick"

    def test_create_scan(self):
        """Test creating a scan."""
        service = ScanService()
        deployment = DeploymentInfo(
            id="deploy-123",
            name="test",
        )
        plan = service.create_scan(deployment)
        assert plan.deployment_id == "deploy-123"

    def test_get_progress(self):
        """Test getting scan progress."""
        service = ScanService()
        deployment = DeploymentInfo(id="deploy-123", name="test")
        plan = service.create_scan(deployment, scan_id="scan-123")

        progress = service.get_progress("scan-123")
        assert progress is not None
        assert progress.scan_id == "scan-123"

    def test_cancel_nonexistent_scan(self):
        """Test cancelling nonexistent scan."""
        service = ScanService()
        result = service.cancel_scan("nonexistent")
        assert result is False
