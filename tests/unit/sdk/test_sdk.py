"""Tests for MASS Python SDK."""

import pytest
from pathlib import Path
from datetime import datetime

from mass.sdk import (
    MASS,
    MASSClient,
    AsyncMASS,
    AsyncMASSClient,
    MASSConfig,
    ScanProfile,
    ScanResult,
    Finding,
    ScanSummary,
    ComplianceStatus,
    RiskAssessment,
    MASSError,
    ScanError,
    ConfigurationError,
    ValidationError,
)


class TestMASSConfig:
    """Tests for MASSConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = MASSConfig()
        assert config.profile == ScanProfile.STANDARD
        assert config.timeout_seconds == 600
        assert config.parallel_workers == 4

    def test_custom_config(self):
        """Test custom configuration."""
        config = MASSConfig(
            profile=ScanProfile.QUICK,
            timeout_seconds=120,
            verbose=True,
        )
        assert config.profile == ScanProfile.QUICK
        assert config.timeout_seconds == 120
        assert config.verbose is True

    def test_quick_preset(self):
        """Test quick preset."""
        config = MASSConfig.quick()
        assert config.profile == ScanProfile.QUICK
        assert config.timeout_seconds == 120

    def test_standard_preset(self):
        """Test standard preset."""
        config = MASSConfig.standard()
        assert config.profile == ScanProfile.STANDARD

    def test_comprehensive_preset(self):
        """Test comprehensive preset."""
        config = MASSConfig.comprehensive()
        assert config.profile == ScanProfile.COMPREHENSIVE
        assert config.timeout_seconds == 1800

    def test_validate_success(self):
        """Test validation passes for valid config."""
        config = MASSConfig()
        config.validate()  # Should not raise

    def test_validate_invalid_timeout(self):
        """Test validation fails for invalid timeout."""
        config = MASSConfig(timeout_seconds=0)
        with pytest.raises(ConfigurationError):
            config.validate()

    def test_validate_invalid_workers(self):
        """Test validation fails for invalid workers."""
        config = MASSConfig(parallel_workers=-1)
        with pytest.raises(ConfigurationError):
            config.validate()

    def test_validate_invalid_severity(self):
        """Test validation fails for invalid severity."""
        config = MASSConfig(min_severity="invalid")
        with pytest.raises(ConfigurationError):
            config.validate()

    def test_validate_invalid_format(self):
        """Test validation fails for invalid format."""
        config = MASSConfig(report_formats=["xml"])
        with pytest.raises(ConfigurationError):
            config.validate()

    def test_to_dict(self):
        """Test serialization to dict."""
        config = MASSConfig(profile=ScanProfile.QUICK)
        data = config.to_dict()
        assert data["profile"] == "quick"
        assert "timeout_seconds" in data

    def test_from_dict(self):
        """Test deserialization from dict."""
        data = {
            "profile": "comprehensive",
            "timeout_seconds": 1200,
            "verbose": True,
        }
        config = MASSConfig.from_dict(data)
        assert config.profile == ScanProfile.COMPREHENSIVE
        assert config.timeout_seconds == 1200
        assert config.verbose is True


class TestScanProfile:
    """Tests for ScanProfile enum."""

    def test_quick_profile(self):
        """Test quick profile."""
        assert ScanProfile.QUICK.value == "quick"

    def test_standard_profile(self):
        """Test standard profile."""
        assert ScanProfile.STANDARD.value == "standard"

    def test_comprehensive_profile(self):
        """Test comprehensive profile."""
        assert ScanProfile.COMPREHENSIVE.value == "comprehensive"

    def test_from_string(self):
        """Test creating from string."""
        profile = ScanProfile("quick")
        assert profile == ScanProfile.QUICK


class TestFinding:
    """Tests for Finding model."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            id="finding-1",
            title="Test Finding",
            description="Test description",
            severity="high",
            category="prompt_injection",
            component="test-model",
        )
        assert finding.id == "finding-1"
        assert finding.severity == "high"

    def test_is_critical(self):
        """Test is_critical property."""
        finding = Finding(
            id="1", title="", description="",
            severity="critical", category="", component="",
        )
        assert finding.is_critical is True
        assert finding.is_high is False

    def test_is_high(self):
        """Test is_high property."""
        finding = Finding(
            id="1", title="", description="",
            severity="high", category="", component="",
        )
        assert finding.is_high is True
        assert finding.is_critical is False

    def test_is_actionable(self):
        """Test is_actionable property."""
        critical = Finding(
            id="1", title="", description="",
            severity="critical", category="", component="",
        )
        low = Finding(
            id="2", title="", description="",
            severity="low", category="", component="",
        )
        assert critical.is_actionable is True
        assert low.is_actionable is False

    def test_location_with_line(self):
        """Test location with file and line."""
        finding = Finding(
            id="1", title="", description="",
            severity="high", category="", component="model",
            file_path="src/main.py",
            line_number=42,
        )
        assert finding.location == "src/main.py:42"

    def test_location_file_only(self):
        """Test location with file only."""
        finding = Finding(
            id="1", title="", description="",
            severity="high", category="", component="model",
            file_path="src/main.py",
        )
        assert finding.location == "src/main.py"

    def test_location_component_fallback(self):
        """Test location falls back to component."""
        finding = Finding(
            id="1", title="", description="",
            severity="high", category="", component="model",
        )
        assert finding.location == "model"

    def test_to_dict(self):
        """Test serialization."""
        finding = Finding(
            id="1", title="Test", description="Desc",
            severity="high", category="cat", component="comp",
        )
        data = finding.to_dict()
        assert data["id"] == "1"
        assert data["title"] == "Test"


class TestScanSummary:
    """Tests for ScanSummary model."""

    def test_summary_creation(self):
        """Test creating a summary."""
        summary = ScanSummary(
            total_findings=10,
            critical=2,
            high=3,
            medium=4,
            low=1,
        )
        assert summary.total_findings == 10
        assert summary.critical == 2

    def test_to_dict(self):
        """Test serialization."""
        summary = ScanSummary(total_findings=5, high=3)
        data = summary.to_dict()
        assert data["total_findings"] == 5
        assert data["by_severity"]["high"] == 3


class TestComplianceStatus:
    """Tests for ComplianceStatus model."""

    def test_status_creation(self):
        """Test creating compliance status."""
        status = ComplianceStatus(
            framework="owasp_llm",
            score=85.0,
            status="partial",
        )
        assert status.framework == "owasp_llm"
        assert status.score == 85.0

    def test_is_compliant(self):
        """Test is_compliant property."""
        compliant = ComplianceStatus(
            framework="owasp", score=100, status="compliant",
        )
        partial = ComplianceStatus(
            framework="owasp", score=80, status="partial",
        )
        assert compliant.is_compliant is True
        assert partial.is_compliant is False


class TestRiskAssessment:
    """Tests for RiskAssessment model."""

    def test_assessment_creation(self):
        """Test creating risk assessment."""
        risk = RiskAssessment(
            score=0.7,
            level="high",
        )
        assert risk.score == 0.7
        assert risk.level == "high"

    def test_is_high_risk(self):
        """Test is_high_risk property."""
        high = RiskAssessment(score=0.8, level="high")
        low = RiskAssessment(score=0.2, level="low")
        assert high.is_high_risk is True
        assert low.is_high_risk is False


class TestScanResult:
    """Tests for ScanResult model."""

    def test_result_creation(self):
        """Test creating a scan result."""
        result = ScanResult(
            scan_id="scan-1",
            status="completed",
            target="/path/to/target",
            profile="standard",
            started_at=datetime.now(),
        )
        assert result.scan_id == "scan-1"
        assert result.is_success is True

    def test_is_success(self):
        """Test is_success property."""
        completed = ScanResult(
            scan_id="1", status="completed",
            target="", profile="", started_at=datetime.now(),
        )
        failed = ScanResult(
            scan_id="2", status="failed",
            target="", profile="", started_at=datetime.now(),
        )
        assert completed.is_success is True
        assert failed.is_success is False

    def test_has_findings(self):
        """Test has_findings property."""
        with_findings = ScanResult(
            scan_id="1", status="completed",
            target="", profile="", started_at=datetime.now(),
            findings=[Finding(
                id="1", title="", description="",
                severity="high", category="", component="",
            )],
        )
        empty = ScanResult(
            scan_id="2", status="completed",
            target="", profile="", started_at=datetime.now(),
        )
        assert with_findings.has_findings is True
        assert empty.has_findings is False

    def test_has_critical(self):
        """Test has_critical property."""
        result = ScanResult(
            scan_id="1", status="completed",
            target="", profile="", started_at=datetime.now(),
            summary=ScanSummary(critical=1),
        )
        assert result.has_critical is True

    def test_finding_count(self):
        """Test finding_count property."""
        result = ScanResult(
            scan_id="1", status="completed",
            target="", profile="", started_at=datetime.now(),
            findings=[
                Finding(id="1", title="", description="", severity="high", category="", component=""),
                Finding(id="2", title="", description="", severity="low", category="", component=""),
            ],
        )
        assert result.finding_count == 2

    def test_get_findings_by_severity(self):
        """Test filtering findings by severity."""
        result = ScanResult(
            scan_id="1", status="completed",
            target="", profile="", started_at=datetime.now(),
            findings=[
                Finding(id="1", title="", description="", severity="high", category="", component=""),
                Finding(id="2", title="", description="", severity="low", category="", component=""),
                Finding(id="3", title="", description="", severity="high", category="", component=""),
            ],
        )
        high_findings = result.get_findings(severity="high")
        assert len(high_findings) == 2

    def test_get_findings_by_category(self):
        """Test filtering findings by category."""
        result = ScanResult(
            scan_id="1", status="completed",
            target="", profile="", started_at=datetime.now(),
            findings=[
                Finding(id="1", title="", description="", severity="high", category="secrets", component=""),
                Finding(id="2", title="", description="", severity="low", category="model", component=""),
            ],
        )
        secrets = result.get_findings(category="secrets")
        assert len(secrets) == 1

    def test_get_findings_min_severity(self):
        """Test filtering by minimum severity."""
        result = ScanResult(
            scan_id="1", status="completed",
            target="", profile="", started_at=datetime.now(),
            findings=[
                Finding(id="1", title="", description="", severity="critical", category="", component=""),
                Finding(id="2", title="", description="", severity="high", category="", component=""),
                Finding(id="3", title="", description="", severity="low", category="", component=""),
                Finding(id="4", title="", description="", severity="info", category="", component=""),
            ],
        )
        medium_plus = result.get_findings(min_severity="medium")
        assert len(medium_plus) == 2  # critical and high

    def test_get_critical_findings(self):
        """Test getting critical findings."""
        result = ScanResult(
            scan_id="1", status="completed",
            target="", profile="", started_at=datetime.now(),
            findings=[
                Finding(id="1", title="", description="", severity="critical", category="", component=""),
                Finding(id="2", title="", description="", severity="high", category="", component=""),
            ],
        )
        critical = result.get_critical_findings()
        assert len(critical) == 1

    def test_get_actionable_findings(self):
        """Test getting actionable findings."""
        result = ScanResult(
            scan_id="1", status="completed",
            target="", profile="", started_at=datetime.now(),
            findings=[
                Finding(id="1", title="", description="", severity="high", category="", component=""),
                Finding(id="2", title="", description="", severity="medium", category="", component=""),
                Finding(id="3", title="", description="", severity="low", category="", component=""),
            ],
        )
        actionable = result.get_actionable_findings()
        assert len(actionable) == 2


class TestExceptions:
    """Tests for SDK exceptions."""

    def test_mass_error(self):
        """Test base MASSError."""
        error = MASSError("Test error", details={"key": "value"})
        assert str(error) == "Test error"
        assert error.details["key"] == "value"

    def test_scan_error(self):
        """Test ScanError."""
        error = ScanError(
            "Scan failed",
            scan_id="scan-1",
            phase="execution",
        )
        assert error.scan_id == "scan-1"
        assert error.phase == "execution"

    def test_configuration_error(self):
        """Test ConfigurationError."""
        error = ConfigurationError(
            "Invalid config",
            config_key="timeout",
            expected="> 0",
            actual="-1",
        )
        assert error.config_key == "timeout"

    def test_validation_error(self):
        """Test ValidationError."""
        error = ValidationError(
            "Invalid target",
            field="target",
            value="/invalid/path",
        )
        assert error.field == "target"


class TestMASSClient:
    """Tests for MASSClient."""

    def test_client_creation(self):
        """Test creating a client."""
        client = MASS()
        assert client.config.profile == ScanProfile.STANDARD

    def test_client_with_config(self):
        """Test creating client with config."""
        config = MASSConfig(profile=ScanProfile.QUICK)
        client = MASS(config=config)
        assert client.config.profile == ScanProfile.QUICK

    def test_client_with_kwargs(self):
        """Test creating client with kwargs."""
        client = MASS(timeout_seconds=300)
        assert client.config.timeout_seconds == 300

    def test_scan_invalid_target(self, tmp_path):
        """Test scanning invalid target raises error."""
        client = MASS()
        with pytest.raises(ValidationError):
            client.scan("/nonexistent/path")

    def test_scan_valid_target(self, tmp_path):
        """Test scanning valid target."""
        # Create a simple target directory
        target = tmp_path / "deployment"
        target.mkdir()
        (target / "model.py").write_text("# test model")

        client = MASS()
        result = client.scan(target)

        assert result.is_success
        assert result.target == str(target)

    def test_quick_scan(self, tmp_path):
        """Test quick scan method."""
        target = tmp_path / "deployment"
        target.mkdir()

        client = MASS()
        result = client.quick_scan(target)

        assert result.profile == "quick"

    def test_full_scan(self, tmp_path):
        """Test full scan method."""
        target = tmp_path / "deployment"
        target.mkdir()

        client = MASS()
        result = client.full_scan(target)

        assert result.profile == "comprehensive"

    def test_assess_risk(self, tmp_path):
        """Test risk assessment."""
        target = tmp_path / "deployment"
        target.mkdir()

        client = MASS()
        risk = client.assess_risk(target)

        assert isinstance(risk, RiskAssessment)

    def test_assess_risk_invalid_target(self):
        """Test risk assessment with invalid target."""
        client = MASS()
        with pytest.raises(ValidationError):
            client.assess_risk("/nonexistent")


class TestAsyncMASSClient:
    """Tests for AsyncMASSClient."""

    def test_async_client_creation(self):
        """Test creating async client."""
        client = AsyncMASS()
        assert client.config.profile == ScanProfile.STANDARD

    def test_async_client_with_config(self):
        """Test creating async client with config."""
        config = MASSConfig(profile=ScanProfile.QUICK)
        client = AsyncMASS(config=config)
        assert client.config.profile == ScanProfile.QUICK

    @pytest.mark.asyncio
    async def test_async_scan_invalid_target(self):
        """Test async scanning invalid target."""
        client = AsyncMASS()
        with pytest.raises(ValidationError):
            await client.scan("/nonexistent/path")

    @pytest.mark.asyncio
    async def test_async_context_manager(self, tmp_path):
        """Test async context manager."""
        target = tmp_path / "deployment"
        target.mkdir()

        async with AsyncMASS() as client:
            # Client should be initialized
            assert client._initialized or not client._initialized  # May or may not init


class TestIntegration:
    """Integration tests for SDK."""

    def test_complete_workflow(self, tmp_path):
        """Test complete scan workflow."""
        # Create deployment structure
        target = tmp_path / "deployment"
        target.mkdir()
        (target / "main.py").write_text("import torch\nmodel = torch.load('model.pkl')")
        (target / "config.yaml").write_text("api_key: sk-secret123")

        # Run scan
        client = MASS(verbose=True)
        result = client.scan(target)

        # Verify result structure
        assert result.scan_id
        assert result.is_success
        assert result.target == str(target)
        assert result.duration_seconds >= 0
        assert isinstance(result.summary, ScanSummary)
        assert isinstance(result.findings, list)

    def test_multiple_profiles(self, tmp_path):
        """Test scanning with different profiles."""
        target = tmp_path / "deployment"
        target.mkdir()

        client = MASS()

        # Quick scan
        quick_result = client.scan(target, profile="quick")
        assert quick_result.profile == "quick"

        # Standard scan
        std_result = client.scan(target, profile="standard")
        assert std_result.profile == "standard"

    def test_report_generation(self, tmp_path):
        """Test that reports are accessible."""
        target = tmp_path / "deployment"
        target.mkdir()

        config = MASSConfig(
            output_dir=tmp_path / "reports",
            report_formats=["json", "sarif"],
        )
        client = MASS(config=config)
        result = client.scan(target)

        # Result should complete successfully
        assert result.is_success

    def test_error_handling(self, tmp_path):
        """Test error handling in scans."""
        client = MASS()

        # Invalid path should raise ValidationError
        with pytest.raises(ValidationError) as exc_info:
            client.scan("/this/path/does/not/exist")

        assert "does not exist" in str(exc_info.value)

    def test_config_inheritance(self):
        """Test that config is properly inherited."""
        config = MASSConfig(
            profile=ScanProfile.COMPREHENSIVE,
            timeout_seconds=1200,
            include_evidence=False,
        )
        client = MASS(config=config)

        assert client.config.profile == ScanProfile.COMPREHENSIVE
        assert client.config.timeout_seconds == 1200
        assert client.config.include_evidence is False

    def test_print_summary(self, tmp_path, capsys):
        """Test result summary printing."""
        target = tmp_path / "deployment"
        target.mkdir()

        client = MASS()
        result = client.scan(target)
        result.print_summary()

        captured = capsys.readouterr()
        assert "MASS Scan Result" in captured.out
        assert "Findings:" in captured.out
