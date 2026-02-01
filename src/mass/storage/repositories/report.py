"""Repository for report model."""

from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mass.storage.models.report import Report
from mass.storage.repositories.base import BaseRepository


class ReportRepository(BaseRepository[Report]):
    """Repository for Report model."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Report, session)

    async def list_by_tenant(
        self,
        tenant_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        report_type: str | None = None,
        format: str | None = None,
    ) -> Sequence[Report]:
        """List reports for a tenant.

        Args:
            tenant_id: Tenant ID.
            offset: Pagination offset.
            limit: Pagination limit.
            report_type: Filter by report type.
            format: Filter by format.

        Returns:
            List of reports.
        """
        stmt = select(Report).where(Report.tenant_id == tenant_id)

        if report_type:
            stmt = stmt.where(Report.report_type == report_type)
        if format:
            stmt = stmt.where(Report.format == format)

        stmt = stmt.order_by(Report.created_at.desc())
        stmt = stmt.offset(offset).limit(limit)

        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_by_scan(
        self,
        scan_id: str,
        *,
        format: str | None = None,
    ) -> Sequence[Report]:
        """List reports for a scan.

        Args:
            scan_id: Scan ID.
            format: Filter by format.

        Returns:
            List of reports.
        """
        stmt = select(Report).where(Report.scan_id == scan_id)

        if format:
            stmt = stmt.where(Report.format == format)

        stmt = stmt.order_by(Report.created_at.desc())

        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_latest_by_scan(
        self,
        scan_id: str,
        format: str | None = None,
    ) -> Report | None:
        """Get the most recent report for a scan.

        Args:
            scan_id: Scan ID.
            format: Optional format filter.

        Returns:
            Most recent report or None.
        """
        stmt = (
            select(Report)
            .where(Report.scan_id == scan_id)
            .where(Report.status == "completed")
        )

        if format:
            stmt = stmt.where(Report.format == format)

        stmt = stmt.order_by(Report.created_at.desc()).limit(1)

        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def mark_generating(self, report: Report) -> Report:
        """Mark report as generating.

        Args:
            report: Report to update.

        Returns:
            Updated report.
        """
        return await self.update(report, status="generating")

    async def mark_completed(
        self,
        report: Report,
        file_path: str,
        file_size: int,
        file_hash: str | None = None,
    ) -> Report:
        """Mark report as completed.

        Args:
            report: Report to complete.
            file_path: Path to generated file.
            file_size: File size in bytes.
            file_hash: Optional file hash.

        Returns:
            Completed report.
        """
        return await self.update(
            report,
            status="completed",
            file_path=file_path,
            file_size=file_size,
            file_hash=file_hash,
            generated_at=datetime.now(timezone.utc),
        )

    async def mark_failed(self, report: Report, error_message: str) -> Report:
        """Mark report as failed.

        Args:
            report: Report that failed.
            error_message: Error description.

        Returns:
            Failed report.
        """
        return await self.update(
            report,
            status="failed",
            status_message=error_message,
        )

    async def delete_expired(self) -> int:
        """Delete expired reports.

        Returns:
            Number of deleted reports.
        """
        now = datetime.now(timezone.utc)
        stmt = (
            select(Report)
            .where(Report.expires_at != None)
            .where(Report.expires_at < now)
        )
        result = await self.session.execute(stmt)
        reports = result.scalars().all()

        for report in reports:
            await self.delete(report)

        return len(reports)
