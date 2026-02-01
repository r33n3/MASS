"""Tests for mass.core.exceptions module."""

import pytest

from mass.core.exceptions import (
    AnalysisError,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    MassError,
    NotFoundError,
    PluginError,
    ProviderError,
    RateLimitError,
    ScanError,
    ValidationError,
)


class TestMassError:
    """Tests for base MassError."""

    def test_basic_error(self) -> None:
        """Test basic error creation."""
        error = MassError("Something went wrong")
        assert str(error) == "Something went wrong"
        assert error.message == "Something went wrong"
        assert error.code == "MASS_ERROR"
        assert error.details == {}

    def test_error_with_code_and_details(self) -> None:
        """Test error with custom code and details."""
        error = MassError(
            "Custom error",
            code="CUSTOM_CODE",
            details={"key": "value"},
        )
        assert error.code == "CUSTOM_CODE"
        assert error.details == {"key": "value"}

    def test_to_dict(self) -> None:
        """Test dictionary conversion."""
        error = MassError("Test", code="TEST", details={"foo": "bar"})
        result = error.to_dict()
        assert result == {
            "error": {
                "code": "TEST",
                "message": "Test",
                "details": {"foo": "bar"},
            }
        }


class TestConfigurationError:
    """Tests for ConfigurationError."""

    def test_configuration_error(self) -> None:
        """Test configuration error."""
        error = ConfigurationError("Missing API key")
        assert error.code == "CONFIGURATION_ERROR"
        assert "Missing API key" in str(error)


class TestValidationError:
    """Tests for ValidationError."""

    def test_validation_error_with_field(self) -> None:
        """Test validation error with field."""
        error = ValidationError("Invalid email", field="email")
        assert error.code == "VALIDATION_ERROR"
        assert error.details["field"] == "email"

    def test_validation_error_without_field(self) -> None:
        """Test validation error without field."""
        error = ValidationError("Invalid input")
        assert "field" not in error.details


class TestScanError:
    """Tests for ScanError."""

    def test_scan_error_with_scan_id(self) -> None:
        """Test scan error with scan ID."""
        error = ScanError("Scan timed out", scan_id="scan_123")
        assert error.code == "SCAN_ERROR"
        assert error.details["scan_id"] == "scan_123"


class TestAnalysisError:
    """Tests for AnalysisError."""

    def test_analysis_error_with_component(self) -> None:
        """Test analysis error with component type."""
        error = AnalysisError("Analysis failed", component_type="model")
        assert error.code == "ANALYSIS_ERROR"
        assert error.details["component_type"] == "model"


class TestAuthenticationError:
    """Tests for AuthenticationError."""

    def test_default_message(self) -> None:
        """Test default authentication error message."""
        error = AuthenticationError()
        assert error.message == "Authentication failed"
        assert error.code == "AUTHENTICATION_ERROR"

    def test_custom_message(self) -> None:
        """Test custom authentication error message."""
        error = AuthenticationError("Invalid token")
        assert error.message == "Invalid token"


class TestAuthorizationError:
    """Tests for AuthorizationError."""

    def test_default_message(self) -> None:
        """Test default authorization error message."""
        error = AuthorizationError()
        assert error.message == "Access denied"
        assert error.code == "AUTHORIZATION_ERROR"

    def test_with_resource(self) -> None:
        """Test authorization error with resource."""
        error = AuthorizationError(resource="deployment_123")
        assert error.details["resource"] == "deployment_123"


class TestNotFoundError:
    """Tests for NotFoundError."""

    def test_not_found_error(self) -> None:
        """Test not found error message format."""
        error = NotFoundError("Deployment", "dep_123")
        assert error.code == "NOT_FOUND"
        assert "Deployment" in error.message
        assert "dep_123" in error.message
        assert error.details["resource_type"] == "Deployment"
        assert error.details["resource_id"] == "dep_123"


class TestRateLimitError:
    """Tests for RateLimitError."""

    def test_default_retry_after(self) -> None:
        """Test default retry after value."""
        error = RateLimitError()
        assert error.retry_after == 60
        assert error.details["retry_after"] == 60

    def test_custom_retry_after(self) -> None:
        """Test custom retry after value."""
        error = RateLimitError(retry_after=120)
        assert error.retry_after == 120


class TestProviderError:
    """Tests for ProviderError."""

    def test_provider_error(self) -> None:
        """Test provider error."""
        error = ProviderError("API call failed", provider="openai")
        assert error.code == "PROVIDER_ERROR"
        assert error.details["provider"] == "openai"


class TestPluginError:
    """Tests for PluginError."""

    def test_plugin_error(self) -> None:
        """Test plugin error."""
        error = PluginError(
            "Plugin initialization failed",
            plugin_name="jailbreak_dan",
            plugin_type="probe",
        )
        assert error.code == "PLUGIN_ERROR"
        assert error.details["plugin_name"] == "jailbreak_dan"
        assert error.details["plugin_type"] == "probe"
