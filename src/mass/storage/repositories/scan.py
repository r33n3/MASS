"""Repositories for scan-related models."""

from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from mass.core.types import ScanStatus
from mass.storage.models.deployment import Scan
from mass.storage.repositories.base import BaseRepository


class ScanRepository(BaseRepository[Scan]):
    """Repository for Scan model."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Scan, session)

    async def get_with_jobs(self, id: str) -> Scan | None:
        """Get scan with its jobs eagerly loaded.

        Args:
            id: Scan ID.

        Returns:
            Scan with jobs or None.
        """
        stmt = (
            select(Scan)
            .where(Scan.id == id)
            .options(selectinload(Scan.jobs))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_with_findings(self, id: str) -> Scan | None:
        """Get scan with its findings eagerly loaded.

        Args:
            id: Scan ID.

        Returns:
            Scan with findings or None.
        """
        stmt = (
            select(Scan)
            .where(Scan.id == id)
            .options(selectinload(Scan.findings))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_tenant(
        self,
        tenant_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        status: ScanStatus | None = None,
    ) -> Sequence[Scan]:
        """List scans for a tenant.

        Args:
            tenant_id: Tenant ID.
            offset: Pagination offset.
            limit: Pagination limit.
            status: Filter by status.

        Returns:
            List of scans.
        """
        stmt = select(Scan).where(Scan.tenant_id == tenant_id)
        if status:
            stmt = stmt.where(Scan.status == status)
        stmt = stmt.order_by(Scan.created_at.desc())
        stmt = stmt.offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_by_deployment(
        self,
        deployment_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Sequence[Scan]:
        """List scans for a deployment.

        Args:
            deployment_id: Deployment ID.
            offset: Pagination offset.
            limit: Pagination limit.

        Returns:
            List of scans.
        """
        stmt = (
            select(Scan)
            .where(Scan.deployment_id == deployment_id)
            .order_by(Scan.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_latest_by_deployment(self, deployment_id: str) -> Scan | None:
        """Get the most recent scan for a deployment.

        Args:
            deployment_id: Deployment ID.

        Returns:
            Most recent scan or None.
        """
        stmt = (
            select(Scan)
            .where(Scan.deployment_id == deployment_id)
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_latest_by_deployments(
        self, deployment_ids: list[str]
    ) -> dict[str, "Scan"]:
        """Get the most recent scan for each deployment in a single query.

        Returns a dict mapping deployment_id -> latest Scan.
        """
        if not deployment_ids:
            return {}

        # Subquery: max created_at per deployment
        subq = (
            select(
                Scan.deployment_id,
                func.max(Scan.created_at).label("max_created"),
            )
            .where(Scan.deployment_id.in_(deployment_ids))
            .group_by(Scan.deployment_id)
            .subquery()
        )
        stmt = select(Scan).join(
            subq,
            (Scan.deployment_id == subq.c.deployment_id)
            & (Scan.created_at == subq.c.max_created),
        )
        result = await self.session.execute(stmt)
        return {s.deployment_id: s for s in result.scalars().all()}

    async def count_by_deployments(
        self, deployment_ids: list[str]
    ) -> dict[str, int]:
        """Count scans per deployment in a single query.

        Returns a dict mapping deployment_id -> scan count.
        """
        if not deployment_ids:
            return {}

        stmt = (
            select(Scan.deployment_id, func.count(Scan.id).label("cnt"))
            .where(Scan.deployment_id.in_(deployment_ids))
            .group_by(Scan.deployment_id)
        )
        result = await self.session.execute(stmt)
        return {row.deployment_id: row.cnt for row in result}

    async def list_running(self, tenant_id: str | None = None) -> Sequence[Scan]:
        """List currently running scans.

        Args:
            tenant_id: Optional tenant filter.

        Returns:
            List of running scans.
        """
        stmt = select(Scan).where(Scan.status == ScanStatus.RUNNING)
        if tenant_id:
            stmt = stmt.where(Scan.tenant_id == tenant_id)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def start_scan(self, scan: Scan) -> Scan:
        """Mark scan as started.

        Args:
            scan: Scan to start.

        Returns:
            Updated scan.
        """
        return await self.update(
            scan,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )

    async def complete_scan(
        self,
        scan: Scan,
        findings_count: int = 0,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        low_count: int = 0,
        info_count: int = 0,
    ) -> Scan:
        """Mark scan as completed.

        Args:
            scan: Scan to complete.
            findings_count: Total findings.
            critical_count: Critical findings.
            high_count: High findings.
            medium_count: Medium findings.
            low_count: Low findings.
            info_count: Info findings.

        Returns:
            Updated scan.
        """
        now = datetime.now(timezone.utc)
        duration = None
        if scan.started_at:
            duration = int((now - scan.started_at).total_seconds())

        return await self.update(
            scan,
            status=ScanStatus.COMPLETED,
            completed_at=now,
            duration_seconds=duration,
            progress_percent=100.0,
            findings_count=findings_count,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
        )

    async def fail_scan(self, scan: Scan, error_message: str) -> Scan:
        """Mark scan as failed.

        Args:
            scan: Scan that failed.
            error_message: Error description.

        Returns:
            Updated scan.
        """
        return await self.update(
            scan,
            status=ScanStatus.FAILED,
            completed_at=datetime.now(timezone.utc),
            status_message=error_message,
        )

    async def cancel_scan(self, scan: Scan) -> Scan:
        """Mark scan as cancelled.

        Args:
            scan: Scan to cancel.

        Returns:
            Updated scan.
        """
        return await self.update(
            scan,
            status=ScanStatus.CANCELLED,
            completed_at=datetime.now(timezone.utc),
        )


# ScanJobRepository removed - ScanJob model doesn't exist in current schema
