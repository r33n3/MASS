"""Repositories for deployment-related models."""

from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from mass.storage.models.deployment import Deployment
from mass.storage.repositories.base import BaseRepository


class DeploymentRepository(BaseRepository[Deployment]):
    """Repository for Deployment model."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Deployment, session)

    async def get_with_components(self, id: str) -> Deployment | None:
        """Get deployment with its components eagerly loaded.

        Args:
            id: Deployment ID.

        Returns:
            Deployment with components or None.
        """
        stmt = (
            select(Deployment)
            .where(Deployment.id == id)
            .options(selectinload(Deployment.components))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_tenant(
        self,
        tenant_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        include_deleted: bool = False,
    ) -> Sequence[Deployment]:
        """List deployments for a tenant.

        Args:
            tenant_id: Tenant ID.
            offset: Pagination offset.
            limit: Pagination limit.
            include_deleted: Include soft-deleted deployments.

        Returns:
            List of deployments.
        """
        stmt = select(Deployment).where(Deployment.tenant_id == tenant_id)
        if not include_deleted:
            stmt = stmt.where(Deployment.is_deleted == False)
        stmt = stmt.order_by(Deployment.created_at.desc())
        stmt = stmt.offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def search_by_name(
        self,
        tenant_id: str,
        query: str,
        *,
        limit: int = 10,
    ) -> Sequence[Deployment]:
        """Search deployments by name.

        Args:
            tenant_id: Tenant ID.
            query: Search query.
            limit: Maximum results.

        Returns:
            Matching deployments.
        """
        stmt = (
            select(Deployment)
            .where(Deployment.tenant_id == tenant_id)
            .where(Deployment.is_deleted == False)
            .where(Deployment.name.ilike(f"%{query}%"))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def update_last_scanned(self, deployment: Deployment) -> Deployment:
        """Update deployment's last scanned timestamp.

        Args:
            deployment: Deployment to update.

        Returns:
            Updated deployment.
        """
        from datetime import datetime, timezone

        return await self.update(
            deployment,
            last_scanned_at=datetime.now(timezone.utc),
        )


# ComponentRepository removed - Components are ephemeral during scanning, not stored in DB
