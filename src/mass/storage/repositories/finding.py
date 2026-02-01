"""Repositories for finding-related models."""

from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from mass.core.types import AttackCategory, Severity
from mass.storage.models.finding import EvidenceModel, FindingModel
from mass.storage.repositories.base import BaseRepository


class FindingRepository(BaseRepository[FindingModel]):
    """Repository for FindingModel."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(FindingModel, session)

    async def get_with_evidence(self, id: str) -> FindingModel | None:
        """Get finding with its evidence eagerly loaded.

        Args:
            id: Finding ID.

        Returns:
            Finding with evidence or None.
        """
        stmt = (
            select(FindingModel)
            .where(FindingModel.id == id)
            .options(selectinload(FindingModel.evidence))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_scan(
        self,
        scan_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        severity: Severity | None = None,
        category: AttackCategory | None = None,
        include_suppressed: bool = False,
    ) -> Sequence[FindingModel]:
        """List findings for a scan.

        Args:
            scan_id: Scan ID.
            offset: Pagination offset.
            limit: Pagination limit.
            severity: Filter by severity.
            category: Filter by category.
            include_suppressed: Include suppressed findings.

        Returns:
            List of findings.
        """
        stmt = select(FindingModel).where(FindingModel.scan_id == scan_id)

        if severity:
            stmt = stmt.where(FindingModel.severity == severity)
        if category:
            stmt = stmt.where(FindingModel.category == category)
        if not include_suppressed:
            stmt = stmt.where(FindingModel.suppressed == False)

        # Order by severity (critical first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        stmt = stmt.order_by(FindingModel.severity, FindingModel.created_at.desc())
        stmt = stmt.offset(offset).limit(limit)

        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_critical_and_high(
        self,
        scan_id: str,
        *,
        limit: int = 100,
    ) -> Sequence[FindingModel]:
        """List critical and high severity findings.

        Args:
            scan_id: Scan ID.
            limit: Maximum results.

        Returns:
            Critical and high findings.
        """
        stmt = (
            select(FindingModel)
            .where(FindingModel.scan_id == scan_id)
            .where(FindingModel.severity.in_([Severity.CRITICAL, Severity.HIGH]))
            .where(FindingModel.suppressed == False)
            .where(FindingModel.false_positive == False)
            .order_by(FindingModel.severity, FindingModel.created_at.desc())
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
            select(FindingModel.severity, func.count(FindingModel.id))
            .where(FindingModel.scan_id == scan_id)
            .where(FindingModel.suppressed == False)
            .group_by(FindingModel.severity)
        )
        result = await self.session.execute(stmt)
        return {str(row[0].value): row[1] for row in result.all()}

    async def count_by_category(self, scan_id: str) -> dict[str, int]:
        """Get finding counts grouped by category.

        Args:
            scan_id: Scan ID.

        Returns:
            Dictionary of category -> count.
        """
        stmt = (
            select(FindingModel.category, func.count(FindingModel.id))
            .where(FindingModel.scan_id == scan_id)
            .where(FindingModel.suppressed == False)
            .group_by(FindingModel.category)
        )
        result = await self.session.execute(stmt)
        return {str(row[0].value): row[1] for row in result.all()}

    async def mark_false_positive(
        self,
        finding: FindingModel,
        user_id: str,
    ) -> FindingModel:
        """Mark finding as false positive.

        Args:
            finding: Finding to mark.
            user_id: User marking it.

        Returns:
            Updated finding.
        """
        from datetime import datetime, timezone

        return await self.update(
            finding,
            false_positive=True,
            acknowledged=True,
            acknowledged_by=user_id,
            acknowledged_at=datetime.now(timezone.utc),
        )

    async def suppress(self, finding: FindingModel) -> FindingModel:
        """Suppress a finding from reports.

        Args:
            finding: Finding to suppress.

        Returns:
            Suppressed finding.
        """
        return await self.update(finding, suppressed=True)

    async def unsuppress(self, finding: FindingModel) -> FindingModel:
        """Unsuppress a finding.

        Args:
            finding: Finding to unsuppress.

        Returns:
            Unsuppressed finding.
        """
        return await self.update(finding, suppressed=False)


class EvidenceRepository(BaseRepository[EvidenceModel]):
    """Repository for EvidenceModel."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(EvidenceModel, session)

    async def list_by_finding(self, finding_id: str) -> Sequence[EvidenceModel]:
        """List evidence for a finding.

        Args:
            finding_id: Finding ID.

        Returns:
            List of evidence.
        """
        stmt = (
            select(EvidenceModel)
            .where(EvidenceModel.finding_id == finding_id)
            .order_by(EvidenceModel.created_at)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def delete_by_finding(self, finding_id: str) -> int:
        """Delete all evidence for a finding.

        Args:
            finding_id: Finding ID.

        Returns:
            Number of deleted evidence records.
        """
        evidence_list = await self.list_by_finding(finding_id)
        for evidence in evidence_list:
            await self.delete(evidence)
        return len(evidence_list)
