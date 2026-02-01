"""Repositories for tenant-related models."""

from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mass.storage.models.tenant import APIKey, Role, Tenant, User
from mass.storage.repositories.base import BaseRepository


class TenantRepository(BaseRepository[Tenant]):
    """Repository for Tenant model."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Tenant, session)

    async def get_by_slug(self, slug: str) -> Tenant | None:
        """Get tenant by slug.

        Args:
            slug: Tenant slug.

        Returns:
            Tenant or None.
        """
        return await self.get_by(slug=slug)

    async def list_active(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Sequence[Tenant]:
        """List active tenants.

        Args:
            offset: Pagination offset.
            limit: Pagination limit.

        Returns:
            List of active tenants.
        """
        stmt = (
            select(Tenant)
            .where(Tenant.is_active == True)
            .where(Tenant.is_deleted == False)
            .offset(offset)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()


class UserRepository(BaseRepository[User]):
    """Repository for User model."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(User, session)

    async def get_by_email(self, tenant_id: str, email: str) -> User | None:
        """Get user by email within a tenant.

        Args:
            tenant_id: Tenant ID.
            email: User email.

        Returns:
            User or None.
        """
        return await self.get_by(tenant_id=tenant_id, email=email)

    async def list_by_tenant(
        self,
        tenant_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        include_inactive: bool = False,
    ) -> Sequence[User]:
        """List users in a tenant.

        Args:
            tenant_id: Tenant ID.
            offset: Pagination offset.
            limit: Pagination limit.
            include_inactive: Include inactive users.

        Returns:
            List of users.
        """
        stmt = (
            select(User)
            .where(User.tenant_id == tenant_id)
            .where(User.is_deleted == False)
        )
        if not include_inactive:
            stmt = stmt.where(User.is_active == True)
        stmt = stmt.offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def update_last_login(self, user: User) -> User:
        """Update user's last login timestamp.

        Args:
            user: User to update.

        Returns:
            Updated user.
        """
        from datetime import datetime, timezone

        return await self.update(user, last_login_at=datetime.now(timezone.utc))


class RoleRepository(BaseRepository[Role]):
    """Repository for Role model."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Role, session)

    async def get_by_name(self, name: str) -> Role | None:
        """Get role by name.

        Args:
            name: Role name.

        Returns:
            Role or None.
        """
        return await self.get_by(name=name)

    async def list_system_roles(self) -> Sequence[Role]:
        """List system-defined roles.

        Returns:
            List of system roles.
        """
        stmt = select(Role).where(Role.is_system == True)
        result = await self.session.execute(stmt)
        return result.scalars().all()


class APIKeyRepository(BaseRepository[APIKey]):
    """Repository for APIKey model."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(APIKey, session)

    async def get_by_prefix(self, prefix: str) -> APIKey | None:
        """Get API key by prefix.

        Args:
            prefix: Key prefix (first 8 chars).

        Returns:
            APIKey or None.
        """
        return await self.get_by(key_prefix=prefix, is_active=True)

    async def list_by_tenant(
        self,
        tenant_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        include_revoked: bool = False,
    ) -> Sequence[APIKey]:
        """List API keys for a tenant.

        Args:
            tenant_id: Tenant ID.
            offset: Pagination offset.
            limit: Pagination limit.
            include_revoked: Include revoked keys.

        Returns:
            List of API keys.
        """
        stmt = (
            select(APIKey)
            .where(APIKey.tenant_id == tenant_id)
        )
        if not include_revoked:
            stmt = stmt.where(APIKey.is_active == True)
            stmt = stmt.where(APIKey.revoked_at == None)
        stmt = stmt.offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def increment_use_count(self, api_key: APIKey) -> APIKey:
        """Increment API key usage counter.

        Args:
            api_key: API key to update.

        Returns:
            Updated API key.
        """
        from datetime import datetime, timezone

        return await self.update(
            api_key,
            use_count=api_key.use_count + 1,
            last_used_at=datetime.now(timezone.utc),
        )

    async def revoke(self, api_key: APIKey) -> APIKey:
        """Revoke an API key.

        Args:
            api_key: API key to revoke.

        Returns:
            Revoked API key.
        """
        from datetime import datetime, timezone

        return await self.update(
            api_key,
            is_active=False,
            revoked_at=datetime.now(timezone.utc),
        )
