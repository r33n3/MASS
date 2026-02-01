"""Exception hierarchy for MASS.

Defines a structured exception hierarchy for consistent error handling
throughout the MASS platform.
"""

from typing import Any


class MassError(Exception):
    """Base exception for all MASS errors.

    All MASS-specific exceptions inherit from this class, allowing
    for catch-all exception handling when needed.

    Attributes:
        message: Human-readable error message.
        code: Machine-readable error code.
        details: Additional error context.
    """

    def __init__(
        self,
        message: str,
        code: str = "MASS_ERROR",
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize MassError.

        Args:
            message: Human-readable error message.
            code: Machine-readable error code.
            details: Additional error context.
        """
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for API responses.

        Returns:
            Dictionary representation of the error.
        """
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details,
            }
        }


class ConfigurationError(MassError):
    """Raised when configuration is invalid or missing.

    Examples:
        - Missing required environment variable
        - Invalid configuration value
        - Incompatible configuration options
    """

    def __init__(
        self, message: str, details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message, code="CONFIGURATION_ERROR", details=details)


class ValidationError(MassError):
    """Raised when input validation fails.

    Examples:
        - Invalid request body
        - Invalid query parameters
        - Schema validation failure
    """

    def __init__(
        self,
        message: str,
        field: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if field:
            details["field"] = field
        super().__init__(message, code="VALIDATION_ERROR", details=details)


class ScanError(MassError):
    """Raised when a scan operation fails.

    Examples:
        - Scan timeout
        - Worker failure
        - Invalid scan target
    """

    def __init__(
        self,
        message: str,
        scan_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if scan_id:
            details["scan_id"] = scan_id
        super().__init__(message, code="SCAN_ERROR", details=details)


class AnalysisError(MassError):
    """Raised when analysis of a component fails.

    Examples:
        - Model interrogation failure
        - Context parsing error
        - MCP connection failure
    """

    def __init__(
        self,
        message: str,
        component_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if component_type:
            details["component_type"] = component_type
        super().__init__(message, code="ANALYSIS_ERROR", details=details)


class AuthenticationError(MassError):
    """Raised when authentication fails.

    Examples:
        - Invalid API key
        - Expired token
        - Missing credentials
    """

    def __init__(
        self, message: str = "Authentication failed", details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message, code="AUTHENTICATION_ERROR", details=details)


class AuthorizationError(MassError):
    """Raised when authorization fails.

    Examples:
        - Insufficient permissions
        - Resource not accessible
        - Tenant isolation violation
    """

    def __init__(
        self,
        message: str = "Access denied",
        resource: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if resource:
            details["resource"] = resource
        super().__init__(message, code="AUTHORIZATION_ERROR", details=details)


class NotFoundError(MassError):
    """Raised when a requested resource is not found.

    Examples:
        - Deployment not found
        - Scan not found
        - Report not found
    """

    def __init__(
        self,
        resource_type: str,
        resource_id: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        message = f"{resource_type} with id '{resource_id}' not found"
        details = details or {}
        details["resource_type"] = resource_type
        details["resource_id"] = resource_id
        super().__init__(message, code="NOT_FOUND", details=details)


class RateLimitError(MassError):
    """Raised when rate limit is exceeded.

    Attributes:
        retry_after: Seconds until the rate limit resets.
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: int = 60,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        details["retry_after"] = retry_after
        self.retry_after = retry_after
        super().__init__(message, code="RATE_LIMIT_EXCEEDED", details=details)


class ProviderError(MassError):
    """Raised when a model provider API fails.

    Examples:
        - OpenAI API error
        - Anthropic API error
        - Rate limiting from provider
    """

    def __init__(
        self,
        message: str,
        provider: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        details["provider"] = provider
        super().__init__(message, code="PROVIDER_ERROR", details=details)


class PluginError(MassError):
    """Raised when a probe or detector plugin fails.

    Examples:
        - Plugin initialization failure
        - Plugin execution error
        - Invalid plugin configuration
    """

    def __init__(
        self,
        message: str,
        plugin_name: str,
        plugin_type: str = "probe",
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        details["plugin_name"] = plugin_name
        details["plugin_type"] = plugin_type
        super().__init__(message, code="PLUGIN_ERROR", details=details)
