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


# EvidenceRepository removed - Evidence model doesn't exist in current schema
