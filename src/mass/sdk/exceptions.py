"""SDK exceptions for MASS.

Provides clear, actionable error messages for common
issues encountered when using the SDK.
"""


class MASSError(Exception):
    """Base exception for all MASS SDK errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        """Initialize the error.

        Args:
            message: Human-readable error message.
            details: Additional error context.
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ScanError(MASSError):
    """Error during scan execution."""

    def __init__(
        self,
        message: str,
        scan_id: str | None = None,
        phase: str | None = None,
        details: dict | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Error message.
            scan_id: ID of the failed scan.
            phase: Scan phase where error occurred.
            details: Additional context.
        """
        super().__init__(message, details)
        self.scan_id = scan_id
        self.phase = phase


class ConfigurationError(MASSError):
    """Error in SDK configuration."""

    def __init__(
        self,
        message: str,
        config_key: str | None = None,
        expected: str | None = None,
        actual: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Error message.
            config_key: Configuration key with issue.
            expected: Expected value or format.
            actual: Actual value received.
        """
        super().__init__(message, {
            "config_key": config_key,
            "expected": expected,
            "actual": actual,
        })
        self.config_key = config_key


class ValidationError(MASSError):
    """Error validating input data."""

    def __init__(
        self,
        message: str,
        field: str | None = None,
        value: str | None = None,
        constraint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Error message.
            field: Field that failed validation.
            value: Value that was invalid.
            constraint: Constraint that was violated.
        """
        super().__init__(message, {
            "field": field,
            "value": value,
            "constraint": constraint,
        })
        self.field = field


class TimeoutError(MASSError):
    """Scan timed out."""

    def __init__(
        self,
        message: str,
        timeout_seconds: int,
        elapsed_seconds: float,
    ) -> None:
        """Initialize the error.

        Args:
            message: Error message.
            timeout_seconds: Configured timeout.
            elapsed_seconds: Time elapsed before timeout.
        """
        super().__init__(message, {
            "timeout_seconds": timeout_seconds,
            "elapsed_seconds": elapsed_seconds,
        })
        self.timeout_seconds = timeout_seconds
        self.elapsed_seconds = elapsed_seconds


class NotFoundError(MASSError):
    """Resource not found."""

    def __init__(
        self,
        message: str,
        resource_type: str,
        resource_id: str,
    ) -> None:
        """Initialize the error.

        Args:
            message: Error message.
            resource_type: Type of resource.
            resource_id: ID of missing resource.
        """
        super().__init__(message, {
            "resource_type": resource_type,
            "resource_id": resource_id,
        })
        self.resource_type = resource_type
        self.resource_id = resource_id
