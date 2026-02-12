"""Repositories for deployment-related models."""

from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from mass.storage.models.deployment import Deployment
from mass.storage.repositories.base import BaseRepository


class DeploymentRepository(BaseRepository[Deployment]):
    """Repository for Deployment model."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Deployment, session)

    async def get_with_components(self, id: str) -> Deployment | None:
        """Get deployment by ID.

        Args:
            id: Deployment ID.

        Returns:
            Deployment or None.
        """
        stmt = select(Deployment).where(Deployment.id == id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def find_by_source_path(
        self, tenant_id: str, source_path: str
    ) -> Deployment | None:
        """Find existing non-deleted deployment by normalized source path."""
        normalized = source_path.replace("\\", "/").rstrip("/").lower()
        stmt = (
            select(Deployment)
            .where(Deployment.tenant_id == tenant_id)
            .where(Deployment.source_path.isnot(None))
            .order_by(Deployment.created_at.desc())
        )
        result = await self.session.execute(stmt)
        for dep in result.scalars():
            if dep.source_path and dep.source_path.replace("\\", "/").rstrip("/").lower() == normalized:
                return dep
        return None

    async def find_by_name(
        self, tenant_id: str, name: str
    ) -> Deployment | None:
        """Find existing non-deleted deployment by exact name."""
        stmt = (
            select(Deployment)
            .where(Deployment.tenant_id == tenant_id)
            .where(Deployment.name == name)
            .order_by(Deployment.created_at.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_tenant(
        self,
        tenant_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Sequence[Deployment]:
        """List deployments for a tenant.

        Args:
            tenant_id: Tenant ID.
            offset: Pagination offset.
            limit: Pagination limit.

        Returns:
            List of deployments.
        """
        stmt = select(Deployment).where(Deployment.tenant_id == tenant_id)
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
