"""Synchronous MASS client for scanning AI deployments.

Provides a simple, Pythonic interface for running security
scans on AI/ML deployments and analyzing results.
"""

from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4
from collections import defaultdict

from mass.sdk.config import MASSConfig, ScanProfile
from mass.sdk.models import (
    ScanResult,
    Finding,
    ScanSummary,
    ComplianceStatus,
    RiskAssessment,
    VerdictSummary,
    ThreatModelSummary,
)
from mass.sdk.exceptions import ScanError, ConfigurationError, ValidationError


class MASSClient:
    """MASS client for synchronous scanning.

    This is the main entry point for using MASS programmatically.
    It provides a clean, high-level API for scanning deployments.

    Example:
        client = MASS()
        result = client.scan("/path/to/deployment")

        if result.has_critical:
            for finding in result.get_critical_findings():
                print(f"CRITICAL: {finding.title}")
    """

    def __init__(
        self,
        config: MASSConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the MASS client.

        Args:
            config: Configuration object.
            **kwargs: Configuration overrides.
        """
        if config:
            self.config = config
        else:
            self.config = MASSConfig(**kwargs) if kwargs else MASSConfig()

        self.config.validate()
        self._scan_service = None
        self._initialized = False

    def _ensure_initialized(self) -> None:
        """Ensure internal services are initialized."""
        if self._initialized:
            return

        try:
            from mass.orchestration.service import ScanService, ScanServiceConfig

            # Map SDK profile to orchestration profile name
            profile_map = {
                ScanProfile.QUICK: "quick",
                ScanProfile.STANDARD: "standard",
                ScanProfile.COMPREHENSIVE: "comprehensive",
                ScanProfile.SECRETS: "standard",
                ScanProfile.MODEL: "standard",
                ScanProfile.INFRASTRUCTURE: "standard",
            }

            profile_name = profile_map.get(self.config.profile, "standard")

            service_config = ScanServiceConfig(default_profile=profile_name)
            self._scan_service = ScanService(config=service_config)
            self._initialized = True

        except Exception as e:
            raise ConfigurationError(f"Failed to initialize: {e}")

    def scan(
        self,
        target: str | Path,
        name: str | None = None,
        profile: ScanProfile | str | None = None,
        **options: Any,
    ) -> ScanResult:
        """Scan a deployment for security issues.

        Args:
            target: Path to deployment directory or file.
            name: Optional scan name.
            profile: Override scan profile.
            **options: Additional scan options.

        Returns:
            ScanResult with findings and metadata.

        Raises:
            ValidationError: If target is invalid.
            ScanError: If scan fails.
        """
        # Validate target
        target_path = Path(target)
        if not target_path.exists():
            raise ValidationError(
                f"Target does not exist: {target}",
                field="target",
                value=str(target),
            )

        # Override profile if provided
        if profile:
            if isinstance(profile, str):
                profile = ScanProfile(profile)
            self.config.profile = profile

        self._ensure_initialized()

        scan_id = str(uuid4())
        started_at = datetime.utcnow()

        try:
            # Get the profile name for the scan
            profile_map = {
                ScanProfile.QUICK: "quick",
                ScanProfile.STANDARD: "standard",
                ScanProfile.COMPREHENSIVE: "comprehensive",
                ScanProfile.SECRETS: "standard",
                ScanProfile.MODEL: "standard",
                ScanProfile.INFRASTRUCTURE: "standard",
            }
            profile_name = profile_map.get(self.config.profile, "standard")

            # Run the scan
            internal_result = self._scan_service.scan_deployment(
                deployment_path=str(target_path),
                profile_name=profile_name,
                deployment_name=name or target_path.name,
            )

            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()

            # Convert internal findings to SDK findings
            findings = [
                Finding.from_internal(f) for f in internal_result.findings
            ]

            # Build summary
            summary = self._build_summary(findings)

            # Get compliance status
            compliance = self._get_compliance(internal_result)

            # Get risk assessment
            risk = self._get_risk_assessment(target_path)

            return ScanResult(
                scan_id=scan_id,
                status="completed",
                target=str(target_path),
                profile=self.config.profile.value,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                findings=findings,
                summary=summary,
                compliance=compliance,
                risk=risk,
            )

        except Exception as e:
            raise ScanError(
                f"Scan failed: {e}",
                scan_id=scan_id,
                phase="execution",
            )

    def _build_summary(self, findings: list[Finding]) -> ScanSummary:
        """Build summary from findings."""
        summary = ScanSummary(total_findings=len(findings))

        by_category: dict[str, int] = defaultdict(int)
        by_analyzer: dict[str, int] = defaultdict(int)

        for f in findings:
            severity = f.severity.lower()
            if severity == "critical":
                summary.critical += 1
            elif severity == "high":
                summary.high += 1
            elif severity == "medium":
                summary.medium += 1
            elif severity == "low":
                summary.low += 1
            else:
                summary.info += 1

            by_category[f.category] += 1
            if f.analyzer:
                by_analyzer[f.analyzer] += 1

        summary.by_category = dict(by_category)
        summary.by_analyzer = dict(by_analyzer)

        return summary

    def _get_compliance(self, internal_result: Any) -> list[ComplianceStatus]:
        """Get compliance status from result."""
        compliance = []

        try:
            from mass.compliance.assessor import ComplianceAssessor
            from mass.core.types import FrameworkType

            for framework_str in self.config.frameworks:
                try:
                    framework = FrameworkType(framework_str)
                    assessor = ComplianceAssessor(frameworks=[framework])
                    result = assessor.assess(internal_result.findings)

                    if result.assessments:
                        assessment = result.assessments[0]
                        compliance.append(ComplianceStatus(
                            framework=framework_str,
                            score=assessment.compliance_score,
                            status=assessment.status.value,
                            violations=[v.requirement_id for v in assessment.violations],
                            recommendations=assessment.recommendations,
                        ))
                except ValueError:
                    pass  # Skip unknown frameworks

        except Exception:
            pass  # Compliance is optional

        return compliance

    def _get_risk_assessment(self, target: Path) -> RiskAssessment | None:
        """Get risk assessment for target."""
        try:
            from mass.planner.risk import RiskAssessor

            assessor = RiskAssessor()
            deployment_info = {
                "id": str(target),
                "deployment": {"external": False},
            }

            profile = assessor.assess(deployment_info)

            return RiskAssessment(
                score=profile.overall_score,
                level=profile.risk_level.value,
                factors=[s.to_dict() for s in profile.get_top_risks(5)],
                recommendations=profile.recommendations,
            )

        except Exception:
            return None

    def quick_scan(self, target: str | Path) -> ScanResult:
        """Run a quick scan.

        Args:
            target: Path to scan.

        Returns:
            ScanResult with findings.
        """
        return self.scan(target, profile=ScanProfile.QUICK)

    def full_scan(self, target: str | Path) -> ScanResult:
        """Run a comprehensive scan.

        Args:
            target: Path to scan.

        Returns:
            ScanResult with findings.
        """
        return self.scan(target, profile=ScanProfile.COMPREHENSIVE)

    def scan_secrets(self, target: str | Path) -> list[Finding]:
        """Scan for secrets only.

        Args:
            target: Path to scan.

        Returns:
            List of secret-related findings.
        """
        result = self.scan(target, profile=ScanProfile.SECRETS)
        return [f for f in result.findings if "secret" in f.category.lower()]

    def scan_models(self, target: str | Path) -> list[Finding]:
        """Scan model files only.

        Args:
            target: Path to scan.

        Returns:
            List of model-related findings.
        """
        result = self.scan(target, profile=ScanProfile.MODEL)
        return [f for f in result.findings if "model" in f.category.lower()]

    def assess_risk(self, target: str | Path) -> RiskAssessment:
        """Assess risk for a deployment.

        Args:
            target: Path to deployment.

        Returns:
            Risk assessment.

        Raises:
            ValidationError: If target is invalid.
        """
        target_path = Path(target)
        if not target_path.exists():
            raise ValidationError(
                f"Target does not exist: {target}",
                field="target",
            )

        risk = self._get_risk_assessment(target_path)
        if not risk:
            return RiskAssessment(
                score=0.0,
                level="info",
                factors=[],
                recommendations=[],
            )
        return risk

    def get_scan_verdict(self, scan_id: str) -> VerdictSummary | None:
        """Get the verdict for a completed scan.

        Loads the full verdict from the API/database for a scan
        that has completed the Final Judge phase.

        Args:
            scan_id: The scan ID to retrieve verdict for.

        Returns:
            VerdictSummary if available, None otherwise.
        """
        try:
            import json
            from mass.storage.database import get_sync_session
            from mass.storage.models.deployment import Scan

            with get_sync_session() as session:
                scan = session.query(Scan).filter(Scan.id == scan_id).first()
                if not scan or not scan.verdict:
                    return None
                data = json.loads(scan.verdict)
                return VerdictSummary(
                    risk_level=data.get("risk_level", "unknown"),
                    confidence=data.get("confidence", 0.0),
                    overall_assessment=data.get("overall_assessment", ""),
                    executive_summary=data.get("executive_summary", ""),
                    narrative=data.get("narrative", ""),
                    key_themes=data.get("key_themes", []),
                    recommendations_count=len(data.get("recommendations", [])),
                    attack_chains_count=len(data.get("attack_chains", [])),
                    raw=data,
                )
        except Exception:
            return None

    def get_scan_threat_model(self, scan_id: str) -> ThreatModelSummary | None:
        """Get the threat model for a completed scan.

        Loads the STRIDE-AI threat model from the API/database for a scan
        that has completed the threat modeling phase.

        Args:
            scan_id: The scan ID to retrieve threat model for.

        Returns:
            ThreatModelSummary if available, None otherwise.
        """
        try:
            import json
            from mass.storage.database import get_sync_session
            from mass.storage.models.deployment import Scan

            with get_sync_session() as session:
                scan = session.query(Scan).filter(Scan.id == scan_id).first()
                if not scan or not scan.threat_model:
                    return None
                data = json.loads(scan.threat_model)
                return ThreatModelSummary(
                    overall_risk_level=data.get("overall_risk_level", "unknown"),
                    total_threats=len(data.get("threats", [])),
                    data_classification=data.get("data_classification", "internal"),
                    threats_by_stride=data.get("threat_counts_by_stride", {}),
                    threats_by_severity=data.get("threat_counts_by_severity", {}),
                    top_risks=data.get("top_risks", []),
                    phases_completed=data.get("phases_completed", []),
                    raw=data,
                )
        except Exception:
            return None


# Alias for convenience
MASS = MASSClient
