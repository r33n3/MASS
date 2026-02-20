"""Repositories for finding-related models."""

from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from mass.core.types import AttackCategory, Severity
from mass.storage.models.finding import Finding
from mass.storage.repositories.base import BaseRepository


class FindingRepository(BaseRepository[Finding]):
    """Repository for Finding."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Finding, session)

    async def get_with_evidence(self, id: str) -> Finding | None:
        """Get finding by ID.

        Note: Evidence is stored as JSON text in the evidence column,
        not as a separate relationship.

        Args:
            id: Finding ID.

        Returns:
            Finding or None.
        """
        return await self.get(id)

    async def list_by_scan(
        self,
        scan_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        severity: Severity | None = None,
        category: AttackCategory | None = None,
    ) -> Sequence[Finding]:
        """List findings for a scan.

        Args:
            scan_id: Scan ID.
            offset: Pagination offset.
            limit: Pagination limit.
            severity: Filter by severity.
            category: Filter by category.

        Returns:
            List of findings.
        """
        stmt = select(Finding).where(Finding.scan_id == scan_id)

        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if category:
            stmt = stmt.where(Finding.category == category)

        stmt = stmt.order_by(Finding.severity, Finding.created_at.desc())
        stmt = stmt.offset(offset).limit(limit)

        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_critical_and_high(
        self,
        scan_id: str,
        *,
        limit: int = 100,
    ) -> Sequence[Finding]:
        """List critical and high severity findings.

        Args:
            scan_id: Scan ID.
            limit: Maximum results.

        Returns:
            Critical and high findings.
        """
        stmt = (
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .where(Finding.severity.in_(["critical", "high"]))
            .order_by(Finding.severity, Finding.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_by_severity(self, scan_id: str) -> dict[str, int]:
        """Get finding counts grouped by severity.

        Args:
            scan_id: Scan ID.

        Returns:
            Dictionary of severity -> count.
        """
        stmt = (
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.severity)
        )
        result = await self.session.execute(stmt)
        return {str(row[0]): row[1] for row in result.all()}

    async def count_by_category(self, scan_id: str) -> dict[str, int]:
        """Get finding counts grouped by category.

        Args:
            scan_id: Scan ID.

        Returns:
            Dictionary of category -> count.
        """
        stmt = (
            select(Finding.category, func.count(Finding.id))
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.category)
        )
        result = await self.session.execute(stmt)
        return {str(row[0]): row[1] for row in result.all()}

    async def mark_false_positive(
        self,
        finding: Finding,
    ) -> Finding:
        """Mark finding as false positive.

        Uses the status field since the model doesn't have
        separate false_positive/acknowledged fields.

        Args:
            finding: Finding to mark.

        Returns:
            Updated finding.
        """
        return await self.update(
            finding,
            status="false_positive",
        )

    async def mark_accepted(self, finding: Finding) -> Finding:
        """Mark finding as accepted risk.

        Args:
            finding: Finding to mark.

        Returns:
            Updated finding.
        """
        return await self.update(finding, status="accepted")

    async def mark_fixed(
        self,
        finding: Finding,
        closed_by_scan_id: str | None = None,
    ) -> Finding:
        """Mark finding as fixed.

        Args:
            finding: Finding to mark.
            closed_by_scan_id: Scan that caused the closure.

        Returns:
            Updated finding.
        """
        update_kwargs: dict = {"status": "fixed"}
        if closed_by_scan_id:
            update_kwargs["closed_by_scan_id"] = closed_by_scan_id
        return await self.update(finding, **update_kwargs)

    async def list_open_by_deployment(
        self,
        deployment_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        severity: str | None = None,
    ) -> Sequence[Finding]:
        """List findings from the latest completed scan for a deployment.

        Args:
            deployment_id: Deployment ID.
            offset: Pagination offset.
            limit: Pagination limit.
            severity: Optional severity filter.

        Returns:
            List of findings.
        """
        from mass.storage.models.deployment import Scan

        latest_scan_stmt = (
            select(Scan.id)
            .where(Scan.deployment_id == deployment_id)
            .where(Scan.status == "completed")
            .order_by(Scan.completed_at.desc())
            .limit(1)
        )
        latest_result = await self.session.execute(latest_scan_stmt)
        latest_scan_id = latest_result.scalar_one_or_none()

        if not latest_scan_id:
            return []

        stmt = select(Finding).where(Finding.scan_id == latest_scan_id)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        stmt = stmt.order_by(Finding.severity, Finding.created_at.desc())
        stmt = stmt.offset(offset).limit(limit)

        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_triaged(
        self,
        *,
        tenant_id: str | None = None,
        limit: int = 5000,
    ) -> Sequence[Finding]:
        """List findings that have been triaged (status != open).

        Used by the confidence calibration engine to compute precision
        per analyzer × category.

        Args:
            tenant_id: Optional tenant filter.
            limit: Maximum results.

        Returns:
            Findings with a triage decision.
        """
        stmt = select(Finding).where(Finding.status != "open")
        if tenant_id:
            stmt = stmt.where(Finding.tenant_id == tenant_id)
        stmt = stmt.order_by(Finding.updated_at.desc()).limit(limit)

        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_all_for_scan(
        self,
        scan_id: str,
        *,
        severity: str | None = None,
        category: str | None = None,
    ) -> Sequence[Finding]:
        """Fetch all findings for a scan without pagination.

        Used for in-memory grouping/deduplication.

        Args:
            scan_id: Scan ID.
            severity: Optional severity filter.
            category: Optional category filter.

        Returns:
            All matching findings.
        """
        stmt = select(Finding).where(Finding.scan_id == scan_id)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if category:
            stmt = stmt.where(Finding.category == category)
        stmt = stmt.order_by(Finding.severity, Finding.created_at.desc())

        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_by_fingerprint(
        self,
        fingerprint: str,
        *,
        deployment_id: str | None = None,
        limit: int = 20,
    ) -> Sequence[Finding]:
        """Get all findings with a given fingerprint (finding history).

        Args:
            fingerprint: Finding fingerprint hash.
            deployment_id: Optional deployment filter.
            limit: Max results.

        Returns:
            Findings matching the fingerprint, ordered newest first.
        """
        from mass.storage.models.deployment import Scan

        stmt = select(Finding).where(Finding.fingerprint == fingerprint)
        if deployment_id:
            stmt = (
                stmt.join(Scan, Finding.scan_id == Scan.id)
                .where(Scan.deployment_id == deployment_id)
            )
        stmt = stmt.order_by(Finding.created_at.desc()).limit(limit)

        result = await self.session.execute(stmt)
        return result.scalars().all()


# EvidenceRepository removed - Evidence model doesn't exist in current schema
