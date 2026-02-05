"""Bootstrap script to create initial tenant and API key.

This script creates the first tenant, user, and API key directly in the database,
bypassing the authentication requirement for initial setup.
"""

import asyncio
import hashlib
import secrets
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from mass.storage.models.tenant import Tenant, User, APIKey


async def bootstrap():
    """Create initial tenant, user, and API key."""
    # Database URL (use postgres service name in Docker)
    db_url = "postgresql+asyncpg://mass:mass@postgres:5432/mass"

    # Create engine
    engine = create_async_engine(db_url, echo=False)

    # Create async session
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session() as session:
        from sqlalchemy import select

        # Check if tenant already exists
        result = await session.execute(
            select(Tenant).where(Tenant.slug == "adios-security")
        )
        existing_tenant = result.scalars().first()

        if existing_tenant:
            print(f"✓ Tenant already exists: {existing_tenant.name} (ID: {existing_tenant.id})")
            tenant_id = existing_tenant.id
        else:
            # Create tenant
            tenant = Tenant(
                id=str(uuid4()),
                name="aDiOS Security Team",
                slug="adios-security",
                is_active=True,
                settings=None,
            )
            session.add(tenant)
            await session.flush()
            tenant_id = tenant.id
            print(f"✓ Created tenant: {tenant.name} (ID: {tenant_id})")

        # Check if user already exists
        result = await session.execute(
            select(User).where(User.tenant_id == tenant_id)
        )
        existing_user = result.scalars().first()

        if existing_user:
            print(f"✓ User already exists: {existing_user.email} (ID: {existing_user.id})")
            user_id = existing_user.id
        else:
            # Create user
            user = User(
                id=str(uuid4()),
                tenant_id=tenant_id,
                email="admin@adios-security.local",
                username="admin",
                hashed_password=hashlib.sha256("changeme".encode()).hexdigest(),
                is_active=True,
                is_superuser=True,
                full_name="aDiOS Administrator",
                last_login=None,
            )
            session.add(user)
            await session.flush()
            user_id = user.id
            print(f"✓ Created user: {user.email} (ID: {user_id})")

        # Check if API key already exists
        result = await session.execute(
            select(APIKey).where(APIKey.tenant_id == tenant_id)
        )
        existing_key = result.scalars().first()

        if existing_key:
            print(f"✓ API key already exists: {existing_key.name}")
            print(f"  Key prefix: {existing_key.prefix}")
            print("\n⚠️  The full API key cannot be retrieved. If you need a new key, delete the existing one first.")
        else:
            # Generate API key
            raw_key = f"mass_{secrets.token_urlsafe(32)}"
            key_prefix = raw_key[:12]  # Store prefix for lookup

            # Create API key (in production, you'd hash the full key)
            api_key = APIKey(
                id=str(uuid4()),
                tenant_id=tenant_id,
                user_id=user_id,
                name="Bootstrap API Key",
                prefix=key_prefix,
                key_hash=raw_key,  # In production, use proper hashing
                is_active=True,
                expires_at=None,  # No expiration
                last_used=None,
            )
            session.add(api_key)
            await session.flush()

            print(f"✓ Created API key: {api_key.name}")
            print(f"\n{'='*60}")
            print(f"🔑 API KEY (save this - you won't see it again!):")
            print(f"{'='*60}")
            print(f"{raw_key}")
            print(f"{'='*60}\n")
            print(f"Key prefix: {key_prefix}")
            print(f"Tenant ID: {tenant_id}")
            print(f"User ID: {user_id}")

        # Commit changes
        await session.commit()

    await engine.dispose()
    print("\n✅ Bootstrap complete!")


if __name__ == "__main__":
    asyncio.run(bootstrap())
