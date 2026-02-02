"""SDK data models for MASS.

Provides simplified, user-friendly models for scan results
and findings, abstracting internal implementation details.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Finding:
    """A security finding from a scan.

    Provides easy access to finding details with helpful
    methods for common operations.
    """

    id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str
    component: str
    file_path: str | None = None
    line_number: int | None = None

    # Classification
    cwe_ids: list[str] = field(default_factory=list)
    owasp_ids: list[str] = field(default_factory=list)

    # Evidence and remediation
    evidence: list[dict[str, Any]] = field(default_factory=list)
    remediation: dict[str, Any] | None = None

    # Metadata
    analyzer: str = ""
    confidence: float = 1.0
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_critical(self) -> bool:
        """Check if finding is critical severity."""
        return self.severity.lower() == "critical"

    @property
    def is_high(self) -> bool:
        """Check if finding is high severity."""
        return self.severity.lower() == "high"

    @property
    def is_actionable(self) -> bool:
        """Check if finding is actionable (medium or above)."""
        return self.severity.lower() in ("critical", "high", "medium")

    @property
    def location(self) -> str:
        """Get formatted location string."""
        if self.file_path and self.line_number:
            return f"{self.file_path}:{self.line_number}"
        elif self.file_path:
            return self.file_path
        return self.component

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "component": self.component,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "cwe_ids": self.cwe_ids,
            "owasp_ids": self.owasp_ids,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "analyzer": self.analyzer,
            "confidence": self.confidence,
        }

    @classmethod
    def from_internal(cls, finding: Any) -> "Finding":
        """Create from internal Finding object.

        Args:
            finding: Internal mass.core.findings.Finding object.

        Returns:
            SDK Finding instance.
        """
        return cls(
            id=finding.id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity.value,
            category=finding.category.value,
            component=finding.component_name,
            file_path=finding.file_path,
            line_number=finding.line_number,
            cwe_ids=finding.cwe_ids,
            owasp_ids=finding.owasp_ids,
            evidence=[e.to_dict() for e in (finding.evidence or [])],
            remediation=finding.remediation.to_dict() if finding.remediation else None,
            raw=finding.to_dict(),
        )


@dataclass
class ScanSummary:
    """Summary statistics for a scan."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    by_category: dict[str, int] = field(default_factory=dict)
    by_analyzer: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_findings": self.total_findings,
            "by_severity": {
                "critical": self.critical,
                "high": self.high,
                "medium": self.medium,
                "low": self.low,
                "info": self.info,
            },
            "by_category": self.by_category,
            "by_analyzer": self.by_analyzer,
        }


@dataclass
class ComplianceStatus:
    """Compliance assessment status."""

    framework: str
    score: float  # 0.0 to 100.0
    status: str  # compliant, partial, non-compliant
    violations: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def is_compliant(self) -> bool:
        """Check if fully compliant."""
        return self.status == "compliant"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework,
            "score": self.score,
            "status": self.status,
            "violations": self.violations,
            "recommendations": self.recommendations,
        }


@dataclass
class RiskAssessment:
    """Risk assessment for a deployment."""

    score: float  # 0.0 to 1.0
    level: str  # critical, high, medium, low, info
    factors: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def is_high_risk(self) -> bool:
        """Check if high risk or above."""
        return self.level.lower() in ("critical", "high")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "score": self.score,
            "level": self.level,
            "factors": self.factors,
            "recommendations": self.recommendations,
        }


@dataclass
class ScanResult:
    """Complete result from a scan.

    Provides access to findings, summary, compliance,
    and risk assessment in a convenient structure.
    """

    scan_id: str
    status: str  # completed, failed, cancelled
    target: str
    profile: str

    # Timing
    started_at: datetime
    completed_at: datetime | None = None
    duration_seconds: float = 0.0

    # Results
    findings: list[Finding] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)
    compliance: list[ComplianceStatus] = field(default_factory=list)
    risk: RiskAssessment | None = None

    # Reports
    reports: dict[str, str] = field(default_factory=dict)  # format -> path

    # Errors
    errors: list[str] = field(default_factory=list)

    @property
    def is_success(self) -> bool:
        """Check if scan completed successfully."""
        return self.status == "completed"

    @property
    def has_findings(self) -> bool:
        """Check if any findings were discovered."""
        return len(self.findings) > 0

    @property
    def has_critical(self) -> bool:
        """Check if any critical findings exist."""
        return self.summary.critical > 0

    @property
    def has_high(self) -> bool:
        """Check if any high severity findings exist."""
        return self.summary.high > 0

    @property
    def finding_count(self) -> int:
        """Get total finding count."""
        return len(self.findings)

    def get_findings(
        self,
        severity: str | None = None,
        category: str | None = None,
        min_severity: str | None = None,
    ) -> list[Finding]:
        """Get filtered findings.

        Args:
            severity: Exact severity to match.
            category: Category to match.
            min_severity: Minimum severity level.

        Returns:
            Filtered list of findings.
        """
        result = self.findings

        if severity:
            result = [f for f in result if f.severity.lower() == severity.lower()]

        if category:
            result = [f for f in result if f.category.lower() == category.lower()]

        if min_severity:
            severity_order = ["critical", "high", "medium", "low", "info"]
            min_index = severity_order.index(min_severity.lower())
            result = [
                f for f in result
                if severity_order.index(f.severity.lower()) <= min_index
            ]

        return result

    def get_critical_findings(self) -> list[Finding]:
        """Get critical severity findings."""
        return self.get_findings(severity="critical")

    def get_high_findings(self) -> list[Finding]:
        """Get high severity findings."""
        return self.get_findings(severity="high")

    def get_actionable_findings(self) -> list[Finding]:
        """Get findings that need action (medium+)."""
        return self.get_findings(min_severity="medium")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary.to_dict(),
            "compliance": [c.to_dict() for c in self.compliance],
            "risk": self.risk.to_dict() if self.risk else None,
            "reports": self.reports,
            "errors": self.errors,
        }

    def print_summary(self) -> None:
        """Print a human-readable summary."""
        print(f"\n{'='*60}")
        print(f"MASS Scan Result: {self.scan_id}")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"Profile: {self.profile}")
        print(f"Status: {self.status}")
        print(f"Duration: {self.duration_seconds:.1f}s")
        print(f"\nFindings: {self.finding_count}")
        print(f"  Critical: {self.summary.critical}")
        print(f"  High: {self.summary.high}")
        print(f"  Medium: {self.summary.medium}")
        print(f"  Low: {self.summary.low}")
        print(f"  Info: {self.summary.info}")

        if self.compliance:
            print("\nCompliance:")
            for c in self.compliance:
                print(f"  {c.framework}: {c.score:.0f}% ({c.status})")

        if self.risk:
            print(f"\nRisk: {self.risk.level} ({self.risk.score:.2f})")

        print(f"{'='*60}\n")
