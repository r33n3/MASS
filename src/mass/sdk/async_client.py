"""Asynchronous MASS client for scanning AI deployments.

Provides an async interface for running security scans,
suitable for use in async web frameworks and services.
"""

import asyncio
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


class AsyncMASSClient:
    """Async MASS client for asynchronous scanning.

    This provides the same functionality as MASSClient but
    with async/await support for non-blocking operations.

    Example:
        async def main():
            client = AsyncMASS()
            result = await client.scan("/path/to/deployment")

            async for finding in result.findings:
                print(finding.title)
    """

    def __init__(
        self,
        config: MASSConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the async MASS client.

        Args:
            config: Configuration object.
            **kwargs: Configuration overrides.
        """
        if config:
            self.config = config
        else:
            self.config = MASSConfig(**kwargs) if kwargs else MASSConfig()

        self.config.validate()
        self._async_service = None
        self._initialized = False

    async def _ensure_initialized(self) -> None:
        """Ensure internal services are initialized."""
        if self._initialized:
            return

        try:
            from mass.workers.integration import AsyncScanService, AsyncScanServiceConfig

            profile_map = {
                ScanProfile.QUICK: "quick",
                ScanProfile.STANDARD: "standard",
                ScanProfile.COMPREHENSIVE: "comprehensive",
                ScanProfile.SECRETS: "standard",
                ScanProfile.MODEL: "standard",
                ScanProfile.INFRASTRUCTURE: "standard",
            }

            profile_name = profile_map.get(self.config.profile, "standard")

            config = AsyncScanServiceConfig(
                num_workers=self.config.parallel_workers,
                default_profile=profile_name,
            )

            self._async_service = AsyncScanService(config=config)
            await self._async_service.start()
            self._initialized = True

        except Exception as e:
            raise ConfigurationError(f"Failed to initialize: {e}")

    async def close(self) -> None:
        """Close the client and release resources."""
        if self._async_service:
            await self._async_service.stop()
            self._initialized = False

    async def __aenter__(self) -> "AsyncMASSClient":
        """Async context manager entry."""
        await self._ensure_initialized()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    async def scan(
        self,
        target: str | Path,
        name: str | None = None,
        profile: ScanProfile | str | None = None,
        **options: Any,
    ) -> ScanResult:
        """Scan a deployment asynchronously.

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
        target_path = Path(target)
        if not target_path.exists():
            raise ValidationError(
                f"Target does not exist: {target}",
                field="target",
                value=str(target),
            )

        if profile:
            if isinstance(profile, str):
                profile = ScanProfile(profile)
            self.config.profile = profile

        await self._ensure_initialized()

        scan_id = str(uuid4())
        started_at = datetime.utcnow()

        try:
            # Submit async scan
            async_scan_id = await self._async_service.submit_scan(
                deployment_path=str(target_path),
                deployment_id=name or target_path.name,
            )

            # Wait for completion
            internal_result = await self._async_service.wait_for_scan(
                async_scan_id,
                timeout=self.config.timeout_seconds,
            )

            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()

            if internal_result is None:
                raise ScanError(
                    "Scan timed out",
                    scan_id=scan_id,
                    phase="execution",
                )

            # Convert to SDK format
            findings = [
                Finding.from_internal(f) for f in internal_result.findings
            ]

            summary = self._build_summary(findings)
            compliance = await self._get_compliance(internal_result)
            risk = await self._get_risk_assessment(target_path)

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

        except ScanError:
            raise
        except Exception as e:
            raise ScanError(
                f"Async scan failed: {e}",
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

    async def _get_compliance(self, internal_result: Any) -> list[ComplianceStatus]:
        """Get compliance status asynchronously."""
        # Run in executor to not block
        return await asyncio.get_event_loop().run_in_executor(
            None,
            self._get_compliance_sync,
            internal_result,
        )

    def _get_compliance_sync(self, internal_result: Any) -> list[ComplianceStatus]:
        """Get compliance status (sync helper)."""
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
                    pass

        except Exception:
            pass

        return compliance

    async def _get_risk_assessment(self, target: Path) -> RiskAssessment | None:
        """Get risk assessment asynchronously."""
        return await asyncio.get_event_loop().run_in_executor(
            None,
            self._get_risk_sync,
            target,
        )

    def _get_risk_sync(self, target: Path) -> RiskAssessment | None:
        """Get risk assessment (sync helper)."""
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

    async def quick_scan(self, target: str | Path) -> ScanResult:
        """Run a quick async scan."""
        return await self.scan(target, profile=ScanProfile.QUICK)

    async def full_scan(self, target: str | Path) -> ScanResult:
        """Run a comprehensive async scan."""
        return await self.scan(target, profile=ScanProfile.COMPREHENSIVE)

    async def scan_multiple(
        self,
        targets: list[str | Path],
        concurrency: int = 3,
    ) -> list[ScanResult]:
        """Scan multiple targets concurrently.

        Args:
            targets: List of paths to scan.
            concurrency: Maximum concurrent scans.

        Returns:
            List of scan results.
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def scan_with_semaphore(target):
            async with semaphore:
                return await self.scan(target)

        tasks = [scan_with_semaphore(t) for t in targets]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def get_scan_verdict(self, scan_id: str) -> VerdictSummary | None:
        """Get the verdict for a completed scan.

        Args:
            scan_id: The scan ID to retrieve verdict for.

        Returns:
            VerdictSummary if available, None otherwise.
        """
        return await asyncio.get_event_loop().run_in_executor(
            None, self._get_verdict_sync, scan_id
        )

    def _get_verdict_sync(self, scan_id: str) -> VerdictSummary | None:
        """Get verdict synchronously (helper)."""
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

    async def get_scan_threat_model(self, scan_id: str) -> ThreatModelSummary | None:
        """Get the threat model for a completed scan.

        Args:
            scan_id: The scan ID to retrieve threat model for.

        Returns:
            ThreatModelSummary if available, None otherwise.
        """
        return await asyncio.get_event_loop().run_in_executor(
            None, self._get_threat_model_sync, scan_id
        )

    def _get_threat_model_sync(self, scan_id: str) -> ThreatModelSummary | None:
        """Get threat model synchronously (helper)."""
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
AsyncMASS = AsyncMASSClient
