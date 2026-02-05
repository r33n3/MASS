"""Initialize the database schema.

This script creates all database tables based on the SQLAlchemy models.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sqlalchemy.ext.asyncio import create_async_engine
from mass.core.config import get_settings
from mass.storage.models import Base


async def init_db():
    """Initialize database tables."""
    db_url = "sqlite+aiosqlite:///./data/mass.db"

    print(f"Initializing database at: {db_url}")

    # Create async engine
    engine = create_async_engine(
        db_url,
        echo=False,
    )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    await engine.dispose()

    print("✓ Database tables created successfully!")


if __name__ == "__main__":
    asyncio.run(init_db())
