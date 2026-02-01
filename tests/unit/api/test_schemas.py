"""Tests for API schemas."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from mass.api.schemas.common import (
    ErrorResponse,
    PaginationMeta,
    SuccessResponse,
)
from mass.api.schemas.auth import (
    TokenRequest,
    TokenResponse,
    APIKeyCreate,
    APIKeyResponse,
)
from mass.api.schemas.deployment import (
    DeploymentCreate,
    DeploymentUpdate,
    DeploymentResponse,
)
from mass.api.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanStatusResponse,
    ScanSeverityCounts,
)
from mass.api.schemas.finding import (
    FindingResponse,
    FindingSummary,
    ComplianceMapping,
)
from mass.api.schemas.compliance import (
    FrameworkResponse,
    AssessmentRequest,
    ControlResponse,
)
from mass.api.schemas.report import (
    ReportCreate,
    ExportRequest,
    CompareRequest,
)
from mass.core.types import (
    ScanStatus,
    Severity,
    AttackCategory,
    ComponentType,
)


class TestCommonSchemas:
    """Tests for common schemas."""

    def test_success_response(self) -> None:
        """Test SuccessResponse schema."""
        response = SuccessResponse()
        assert response.success is True
        assert "successfully" in response.message

        response = SuccessResponse(message="Custom message")
        assert response.message == "Custom message"

    def test_error_response(self) -> None:
        """Test ErrorResponse schema."""
        response = ErrorResponse(
            error="validation_error",
            message="Validation failed",
            details={"field": "name", "error": "required"},
        )
        assert response.error == "validation_error"
        assert response.message == "Validation failed"
        assert response.details is not None

    def test_pagination_meta(self) -> None:
        """Test PaginationMeta schema."""
        meta = PaginationMeta(
            total=100,
            offset=0,
            limit=10,
            has_more=True,
        )
        assert meta.total == 100
        assert meta.has_more is True


class TestAuthSchemas:
    """Tests for auth schemas."""

    def test_token_request(self) -> None:
        """Test TokenRequest schema."""
        request = TokenRequest(
            client_id="test_id",
            client_secret="test_secret",
        )
        assert request.grant_type == "client_credentials"
        assert request.client_id == "test_id"

    def test_token_response(self) -> None:
        """Test TokenResponse schema."""
        response = TokenResponse(
            access_token="token123",
            expires_in=3600,
        )
        assert response.token_type == "Bearer"
        assert response.expires_in == 3600

    def test_api_key_create(self) -> None:
        """Test APIKeyCreate schema."""
        request = APIKeyCreate(name="Test Key")
        assert request.name == "Test Key"
        assert request.expires_at is None

    def test_api_key_create_with_expiration(self) -> None:
        """Test APIKeyCreate with expiration."""
        future = datetime(2030, 1, 1, tzinfo=timezone.utc)
        request = APIKeyCreate(
            name="Expiring Key",
            expires_at=future,
        )
        assert request.expires_at == future


class TestDeploymentSchemas:
    """Tests for deployment schemas."""

    def test_deployment_create(self) -> None:
        """Test DeploymentCreate schema."""
        request = DeploymentCreate(
            name="My Agent",
            description="Test agent",
            source_type="git",
            source_path="https://github.com/org/repo",
        )
        assert request.name == "My Agent"
        assert request.source_type == "git"

    def test_deployment_create_validation(self) -> None:
        """Test DeploymentCreate validation."""
        with pytest.raises(ValidationError):
            DeploymentCreate(name="")  # Too short

    def test_deployment_update(self) -> None:
        """Test DeploymentUpdate schema."""
        update = DeploymentUpdate(name="New Name")
        assert update.name == "New Name"
        assert update.description is None  # Not provided

    def test_deployment_response(self) -> None:
        """Test DeploymentResponse schema."""
        now = datetime.now(timezone.utc)
        response = DeploymentResponse(
            id="deploy-123",
            name="Test Deployment",
            source_type="local",
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        assert response.id == "deploy-123"
        assert response.component_count == 0


class TestScanSchemas:
    """Tests for scan schemas."""

    def test_scan_create(self) -> None:
        """Test ScanCreate schema."""
        request = ScanCreate(deployment_id="deploy-123")
        assert request.profile == "standard"
        assert request.deployment_id == "deploy-123"

    def test_scan_create_custom_profile(self) -> None:
        """Test ScanCreate with custom profile."""
        request = ScanCreate(
            deployment_id="deploy-123",
            profile="comprehensive",
            config={"depth": "deep"},
        )
        assert request.profile == "comprehensive"
        assert request.config == {"depth": "deep"}

    def test_scan_status_response(self) -> None:
        """Test ScanStatusResponse schema."""
        response = ScanStatusResponse(
            id="scan-123",
            status=ScanStatus.RUNNING,
            progress_percent=50.0,
        )
        assert response.status == ScanStatus.RUNNING
        assert response.progress_percent == 50.0

    def test_severity_counts(self) -> None:
        """Test ScanSeverityCounts schema."""
        counts = ScanSeverityCounts(
            critical=1,
            high=5,
            medium=10,
        )
        assert counts.critical == 1
        assert counts.low == 0  # Default


class TestFindingSchemas:
    """Tests for finding schemas."""

    def test_compliance_mapping(self) -> None:
        """Test ComplianceMapping schema."""
        mapping = ComplianceMapping(
            cwe_ids=["CWE-94"],
            owasp_ids=["LLM01"],
        )
        assert "CWE-94" in mapping.cwe_ids
        assert mapping.mitre_ids == []  # Default

    def test_finding_summary(self) -> None:
        """Test FindingSummary schema."""
        summary = FindingSummary(
            total=20,
            by_severity={"critical": 1, "high": 5},
        )
        assert summary.total == 20
        assert summary.false_positives == 0


class TestComplianceSchemas:
    """Tests for compliance schemas."""

    def test_control_response(self) -> None:
        """Test ControlResponse schema."""
        control = ControlResponse(
            id="LLM01",
            name="Prompt Injection",
            description="Manipulating LLMs via crafted inputs",
        )
        assert control.id == "LLM01"
        assert control.severity == "medium"  # Default

    def test_assessment_request(self) -> None:
        """Test AssessmentRequest schema."""
        request = AssessmentRequest(
            scan_id="scan-123",
            frameworks=["owasp:llm", "mitre:atlas"],
        )
        assert len(request.frameworks) == 2
        assert request.include_evidence is True  # Default


class TestReportSchemas:
    """Tests for report schemas."""

    def test_report_create(self) -> None:
        """Test ReportCreate schema."""
        request = ReportCreate(
            scan_id="scan-123",
            format="html",
        )
        assert request.format == "html"
        assert request.report_type == "security"  # Default

    def test_report_create_with_frameworks(self) -> None:
        """Test ReportCreate with compliance frameworks."""
        request = ReportCreate(
            scan_id="scan-123",
            report_type="compliance",
            frameworks=["owasp:llm"],
        )
        assert request.frameworks == ["owasp:llm"]

    def test_export_request(self) -> None:
        """Test ExportRequest schema."""
        request = ExportRequest(format="sarif")
        assert request.format == "sarif"
        assert request.include_evidence is True

    def test_compare_request(self) -> None:
        """Test CompareRequest schema."""
        request = CompareRequest(
            scan_id_1="scan-123",
            scan_id_2="scan-456",
        )
        assert request.format == "json"  # Default
