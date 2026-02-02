"""SDK configuration for MASS.

Provides configuration options for the MASS client including
scan profiles, output settings, and runtime behavior.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from mass.sdk.exceptions import ConfigurationError


class ScanProfile(Enum):
    """Pre-defined scan profiles."""

    QUICK = "quick"  # Fast scan, essential analyzers only
    STANDARD = "standard"  # Balanced scan (default)
    COMPREHENSIVE = "comprehensive"  # Full scan, all analyzers
    SECRETS = "secrets"  # Focus on secret detection
    MODEL = "model"  # Focus on model security
    INFRASTRUCTURE = "infrastructure"  # Focus on infrastructure


@dataclass
class MASSConfig:
    """Configuration for MASS client.

    Attributes:
        profile: Scan profile to use.
        output_dir: Directory for scan outputs.
        timeout_seconds: Maximum scan duration.
        parallel_workers: Number of parallel workers.
        include_evidence: Include evidence in findings.
        include_remediation: Include remediation steps.
        frameworks: Compliance frameworks to assess.
        report_formats: Report formats to generate.
        verbose: Enable verbose logging.
    """

    # Scan settings
    profile: ScanProfile = ScanProfile.STANDARD
    timeout_seconds: int = 600
    parallel_workers: int = 4

    # Output settings
    output_dir: Path | None = None
    include_evidence: bool = True
    include_remediation: bool = True

    # Compliance
    frameworks: list[str] = field(default_factory=lambda: ["owasp_llm"])

    # Reports
    report_formats: list[str] = field(default_factory=lambda: ["json"])

    # Runtime
    verbose: bool = False
    fail_on_findings: bool = False
    min_severity: str = "low"

    # Analyzer settings
    analyzers: list[str] | None = None  # None = all for profile
    excluded_analyzers: list[str] = field(default_factory=list)

    # Paths
    ignore_patterns: list[str] = field(default_factory=lambda: [
        "**/.git/**",
        "**/node_modules/**",
        "**/__pycache__/**",
        "**/*.pyc",
    ])

    def validate(self) -> None:
        """Validate configuration.

        Raises:
            ConfigurationError: If configuration is invalid.
        """
        if self.timeout_seconds <= 0:
            raise ConfigurationError(
                "Timeout must be positive",
                config_key="timeout_seconds",
                expected="> 0",
                actual=str(self.timeout_seconds),
            )

        if self.parallel_workers <= 0:
            raise ConfigurationError(
                "Workers must be positive",
                config_key="parallel_workers",
                expected="> 0",
                actual=str(self.parallel_workers),
            )

        valid_severities = {"critical", "high", "medium", "low", "info"}
        if self.min_severity.lower() not in valid_severities:
            raise ConfigurationError(
                f"Invalid severity: {self.min_severity}",
                config_key="min_severity",
                expected=", ".join(valid_severities),
                actual=self.min_severity,
            )

        valid_formats = {"json", "sarif", "html"}
        for fmt in self.report_formats:
            if fmt.lower() not in valid_formats:
                raise ConfigurationError(
                    f"Invalid report format: {fmt}",
                    config_key="report_formats",
                    expected=", ".join(valid_formats),
                    actual=fmt,
                )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "profile": self.profile.value,
            "timeout_seconds": self.timeout_seconds,
            "parallel_workers": self.parallel_workers,
            "output_dir": str(self.output_dir) if self.output_dir else None,
            "include_evidence": self.include_evidence,
            "include_remediation": self.include_remediation,
            "frameworks": self.frameworks,
            "report_formats": self.report_formats,
            "verbose": self.verbose,
            "fail_on_findings": self.fail_on_findings,
            "min_severity": self.min_severity,
            "analyzers": self.analyzers,
            "excluded_analyzers": self.excluded_analyzers,
            "ignore_patterns": self.ignore_patterns,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MASSConfig":
        """Create from dictionary.

        Args:
            data: Configuration dictionary.

        Returns:
            MASSConfig instance.
        """
        # Handle profile conversion
        profile = data.get("profile", "standard")
        if isinstance(profile, str):
            profile = ScanProfile(profile)

        # Handle output_dir conversion
        output_dir = data.get("output_dir")
        if isinstance(output_dir, str):
            output_dir = Path(output_dir)

        return cls(
            profile=profile,
            timeout_seconds=data.get("timeout_seconds", 600),
            parallel_workers=data.get("parallel_workers", 4),
            output_dir=output_dir,
            include_evidence=data.get("include_evidence", True),
            include_remediation=data.get("include_remediation", True),
            frameworks=data.get("frameworks", ["owasp_llm"]),
            report_formats=data.get("report_formats", ["json"]),
            verbose=data.get("verbose", False),
            fail_on_findings=data.get("fail_on_findings", False),
            min_severity=data.get("min_severity", "low"),
            analyzers=data.get("analyzers"),
            excluded_analyzers=data.get("excluded_analyzers", []),
            ignore_patterns=data.get("ignore_patterns", [
                "**/.git/**",
                "**/node_modules/**",
                "**/__pycache__/**",
                "**/*.pyc",
            ]),
        )

    @classmethod
    def quick(cls) -> "MASSConfig":
        """Create quick scan configuration."""
        return cls(profile=ScanProfile.QUICK, timeout_seconds=120)

    @classmethod
    def standard(cls) -> "MASSConfig":
        """Create standard scan configuration."""
        return cls(profile=ScanProfile.STANDARD)

    @classmethod
    def comprehensive(cls) -> "MASSConfig":
        """Create comprehensive scan configuration."""
        return cls(profile=ScanProfile.COMPREHENSIVE, timeout_seconds=1800)
