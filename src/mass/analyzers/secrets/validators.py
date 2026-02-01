"""Secret validators.

Validates detected secrets to reduce false positives and determine if
secrets are live/active.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Protocol


@dataclass
class ValidationResult:
    """Result of secret validation."""
    is_valid: bool
    is_active: bool | None = None
    confidence: float = 1.0
    message: str = ""


class SecretValidator(Protocol):
    """Protocol for secret validators."""

    @abstractmethod
    def validate(self, secret: str) -> ValidationResult:
        """Validate a detected secret.

        Args:
            secret: The secret value to validate.

        Returns:
            ValidationResult with validation details.
        """
        ...


class BaseValidator(ABC):
    """Base class for secret validators."""

    @abstractmethod
    def validate(self, secret: str) -> ValidationResult:
        """Validate a detected secret."""
        ...


class OpenAIKeyValidator(BaseValidator):
    """Validator for OpenAI API keys."""

    # Pattern for valid OpenAI keys
    PATTERN = re.compile(r"^sk-[A-Za-z0-9]{48,}$")
    PROJECT_PATTERN = re.compile(r"^sk-proj-[A-Za-z0-9\-_]{80,}$")

    def validate(self, secret: str) -> ValidationResult:
        """Validate an OpenAI API key format."""
        if self.PROJECT_PATTERN.match(secret):
            return ValidationResult(
                is_valid=True,
                confidence=0.95,
                message="Valid OpenAI project key format",
            )

        if self.PATTERN.match(secret):
            return ValidationResult(
                is_valid=True,
                confidence=0.9,
                message="Valid OpenAI key format",
            )

        return ValidationResult(
            is_valid=False,
            confidence=0.8,
            message="Invalid OpenAI key format",
        )


class AnthropicKeyValidator(BaseValidator):
    """Validator for Anthropic API keys."""

    PATTERN = re.compile(r"^sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{93}$")

    def validate(self, secret: str) -> ValidationResult:
        """Validate an Anthropic API key format."""
        if self.PATTERN.match(secret):
            return ValidationResult(
                is_valid=True,
                confidence=0.95,
                message="Valid Anthropic key format",
            )

        return ValidationResult(
            is_valid=False,
            confidence=0.8,
            message="Invalid Anthropic key format",
        )


class AWSAccessKeyValidator(BaseValidator):
    """Validator for AWS access keys."""

    ACCESS_KEY_PATTERN = re.compile(r"^AKIA[0-9A-Z]{16}$")

    def validate(self, secret: str) -> ValidationResult:
        """Validate an AWS access key format."""
        if self.ACCESS_KEY_PATTERN.match(secret):
            return ValidationResult(
                is_valid=True,
                confidence=0.95,
                message="Valid AWS access key format",
            )

        return ValidationResult(
            is_valid=False,
            confidence=0.8,
            message="Invalid AWS access key format",
        )


class GitHubTokenValidator(BaseValidator):
    """Validator for GitHub tokens."""

    PATTERNS = {
        "ghp": re.compile(r"^ghp_[A-Za-z0-9]{36,}$"),  # Personal access token
        "gho": re.compile(r"^gho_[A-Za-z0-9]{36,}$"),  # OAuth token
        "ghu": re.compile(r"^ghu_[A-Za-z0-9]{36,}$"),  # User-to-server token
        "ghs": re.compile(r"^ghs_[A-Za-z0-9]{36,}$"),  # Server-to-server token
        "ghr": re.compile(r"^ghr_[A-Za-z0-9]{36,}$"),  # Refresh token
    }

    def validate(self, secret: str) -> ValidationResult:
        """Validate a GitHub token format."""
        for token_type, pattern in self.PATTERNS.items():
            if pattern.match(secret):
                return ValidationResult(
                    is_valid=True,
                    confidence=0.95,
                    message=f"Valid GitHub {token_type} token format",
                )

        return ValidationResult(
            is_valid=False,
            confidence=0.7,
            message="Invalid GitHub token format",
        )


class JWTValidator(BaseValidator):
    """Validator for JSON Web Tokens."""

    PATTERN = re.compile(r"^eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*$")

    def validate(self, secret: str) -> ValidationResult:
        """Validate a JWT format."""
        if self.PATTERN.match(secret):
            # Try to decode header to verify it's valid JSON
            try:
                import base64
                import json

                # Decode header
                header = secret.split(".")[0]
                # Add padding if needed
                padding = 4 - len(header) % 4
                if padding != 4:
                    header += "=" * padding
                decoded = base64.urlsafe_b64decode(header)
                json.loads(decoded)

                return ValidationResult(
                    is_valid=True,
                    confidence=0.95,
                    message="Valid JWT format with valid header",
                )
            except Exception:
                return ValidationResult(
                    is_valid=True,
                    confidence=0.7,
                    message="JWT-like format but header not decodable",
                )

        return ValidationResult(
            is_valid=False,
            confidence=0.8,
            message="Invalid JWT format",
        )


class PrivateKeyValidator(BaseValidator):
    """Validator for private keys."""

    MARKERS = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ]

    def validate(self, secret: str) -> ValidationResult:
        """Validate a private key format."""
        for marker in self.MARKERS:
            if marker in secret:
                # Check for end marker
                end_marker = marker.replace("BEGIN", "END")
                if end_marker in secret:
                    return ValidationResult(
                        is_valid=True,
                        confidence=0.99,
                        message="Valid private key format",
                    )
                return ValidationResult(
                    is_valid=True,
                    confidence=0.8,
                    message="Private key header found but incomplete",
                )

        return ValidationResult(
            is_valid=False,
            confidence=0.9,
            message="Not a private key",
        )


class DatabaseURIValidator(BaseValidator):
    """Validator for database connection URIs."""

    PATTERNS = {
        "postgres": re.compile(r"^postgres(?:ql)?://[^:]+:[^@]+@.+/.+$"),
        "mysql": re.compile(r"^mysql://[^:]+:[^@]+@.+/.+$"),
        "mongodb": re.compile(r"^mongodb(?:\+srv)?://[^:]+:[^@]+@.+$"),
        "redis": re.compile(r"^redis://[^:]*:[^@]+@.+$"),
    }

    def validate(self, secret: str) -> ValidationResult:
        """Validate a database URI format."""
        for db_type, pattern in self.PATTERNS.items():
            if pattern.match(secret):
                return ValidationResult(
                    is_valid=True,
                    confidence=0.95,
                    message=f"Valid {db_type} connection URI",
                )

        return ValidationResult(
            is_valid=False,
            confidence=0.7,
            message="Invalid database URI format",
        )


class GenericSecretValidator(BaseValidator):
    """Generic validator for untyped secrets."""

    # Common false positive patterns
    FALSE_POSITIVES = [
        re.compile(r"^[0-9]+$"),  # Pure numbers
        re.compile(r"^[a-z]+$"),  # Pure lowercase
        re.compile(r"^[A-Z]+$"),  # Pure uppercase
        re.compile(r"^example", re.IGNORECASE),
        re.compile(r"^test", re.IGNORECASE),
        re.compile(r"^placeholder", re.IGNORECASE),
        re.compile(r"^YOUR_", re.IGNORECASE),
        re.compile(r"^<.*>$"),
        re.compile(r"^\$\{.*\}$"),
        re.compile(r"^{{.*}}$"),
        re.compile(r"^%.*%$"),
    ]

    def validate(self, secret: str) -> ValidationResult:
        """Validate a generic secret."""
        # Check for false positives
        for pattern in self.FALSE_POSITIVES:
            if pattern.match(secret):
                return ValidationResult(
                    is_valid=False,
                    confidence=0.9,
                    message="Matches false positive pattern",
                )

        # Check minimum length
        if len(secret) < 8:
            return ValidationResult(
                is_valid=False,
                confidence=0.7,
                message="Too short to be a secret",
            )

        # Check for some complexity
        has_upper = any(c.isupper() for c in secret)
        has_lower = any(c.islower() for c in secret)
        has_digit = any(c.isdigit() for c in secret)

        complexity = sum([has_upper, has_lower, has_digit])

        if complexity < 2:
            return ValidationResult(
                is_valid=True,
                confidence=0.4,
                message="Low complexity, might be false positive",
            )

        return ValidationResult(
            is_valid=True,
            confidence=0.6,
            message="Generic secret with some complexity",
        )


class ValidatorRegistry:
    """Registry of secret validators."""

    def __init__(self):
        """Initialize validator registry with default validators."""
        self._validators: dict[str, BaseValidator] = {
            "openai": OpenAIKeyValidator(),
            "anthropic": AnthropicKeyValidator(),
            "aws": AWSAccessKeyValidator(),
            "github": GitHubTokenValidator(),
            "jwt": JWTValidator(),
            "private_key": PrivateKeyValidator(),
            "database": DatabaseURIValidator(),
            "generic": GenericSecretValidator(),
        }

    def register(self, name: str, validator: BaseValidator) -> None:
        """Register a validator.

        Args:
            name: Validator name.
            validator: Validator instance.
        """
        self._validators[name] = validator

    def get(self, name: str) -> BaseValidator | None:
        """Get a validator by name.

        Args:
            name: Validator name.

        Returns:
            Validator instance or None if not found.
        """
        return self._validators.get(name)

    def validate(self, secret: str, validator_names: list[str] | None = None) -> ValidationResult:
        """Validate a secret using specified validators.

        Args:
            secret: Secret to validate.
            validator_names: List of validator names to use. Uses generic if None.

        Returns:
            Best validation result.
        """
        if validator_names is None:
            validator_names = ["generic"]

        best_result = ValidationResult(is_valid=False, confidence=0)

        for name in validator_names:
            validator = self.get(name)
            if validator:
                result = validator.validate(secret)
                if result.confidence > best_result.confidence:
                    best_result = result

        return best_result


# Global registry instance
_registry = ValidatorRegistry()


def get_validator(name: str) -> BaseValidator | None:
    """Get a validator by name from the global registry."""
    return _registry.get(name)


def validate_secret(secret: str, validator_names: list[str] | None = None) -> ValidationResult:
    """Validate a secret using the global registry."""
    return _registry.validate(secret, validator_names)
