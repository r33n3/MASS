"""Base repository with generic CRUD operations.

Provides a type-safe, async repository pattern for database access.
"""

from typing import Any, Generic, Sequence, TypeVar

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from mass.storage.models.base import Base

# Type variable for the model type
ModelT = TypeVar("ModelT", bound=Base)


class BaseRepository(Generic[ModelT]):
    """Generic repository with CRUD operations.

    Provides type-safe async database operations for any SQLAlchemy model.

    Example:
        ```python
        class UserRepository(BaseRepository[User]):
            def __init__(self, session: AsyncSession):
                super().__init__(User, session)

            async def get_by_email(self, email: str) -> User | None:
                return await self.get_by(email=email)

        # Usage
        repo = UserRepository(session)
        user = await repo.create(User(email="test@example.com"))
        users = await repo.list(limit=10)
        ```
    """

    def __init__(self, model: type[ModelT], session: AsyncSession) -> None:
        """Initialize repository.

        Args:
            model: The SQLAlchemy model class.
            session: Async database session.
        """
        self.model = model
        self.session = session

    async def create(self, obj: ModelT) -> ModelT:
        """Create a new record.

        Args:
            obj: Model instance to create.

        Returns:
            The created model instance with ID populated.
        """
        self.session.add(obj)
        await self.session.flush()
        await self.session.refresh(obj)
        return obj

    async def create_many(self, objects: list[ModelT]) -> list[ModelT]:
        """Create multiple records.

        Args:
            objects: List of model instances to create.

        Returns:
            List of created model instances.
        """
        self.session.add_all(objects)
        await self.session.flush()
        for obj in objects:
            await self.session.refresh(obj)
        return objects

    async def get(self, id: str) -> ModelT | None:
        """Get a record by ID.

        Args:
            id: Primary key value.

        Returns:
            Model instance or None if not found.
        """
        return await self.session.get(self.model, id)

    async def get_by(self, **kwargs: Any) -> ModelT | None:
        """Get a single record by attributes.

        Args:
            **kwargs: Filter attributes.

        Returns:
            Model instance or None if not found.
        """
        stmt = select(self.model).filter_by(**kwargs)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_or_create(
        self,
        defaults: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> tuple[ModelT, bool]:
        """Get existing record or create new one.

        Args:
            defaults: Default values for creation.
            **kwargs: Filter attributes.

        Returns:
            Tuple of (model instance, created flag).
        """
        existing = await self.get_by(**kwargs)
        if existing:
            return existing, False

        create_kwargs = {**kwargs, **(defaults or {})}
        obj = self.model(**create_kwargs)
        created = await self.create(obj)
        return created, True

    async def list(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        order_by: str | None = None,
        order_desc: bool = False,
        **filters: Any,
    ) -> Sequence[ModelT]:
        """List records with pagination and filtering.

        Args:
            offset: Number of records to skip.
            limit: Maximum number of records to return.
            order_by: Column name to order by.
            order_desc: If True, order descending.
            **filters: Filter attributes.

        Returns:
            List of model instances.
        """
        stmt = select(self.model)

        # Apply filters
        if filters:
            stmt = stmt.filter_by(**filters)

        # Apply ordering
        if order_by:
            column = getattr(self.model, order_by)
            stmt = stmt.order_by(column.desc() if order_desc else column)

        # Apply pagination
        stmt = stmt.offset(offset).limit(limit)

        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count(self, **filters: Any) -> int:
        """Count records matching filters.

        Args:
            **filters: Filter attributes.

        Returns:
            Number of matching records.
        """
        stmt = select(func.count()).select_from(self.model)
        if filters:
            stmt = stmt.filter_by(**filters)
        result = await self.session.execute(stmt)
        return result.scalar() or 0

    async def exists(self, **filters: Any) -> bool:
        """Check if any record matches filters.

        Args:
            **filters: Filter attributes.

        Returns:
            True if at least one record matches.
        """
        count = await self.count(**filters)
        return count > 0

    async def update(self, obj: ModelT, **kwargs: Any) -> ModelT:
        """Update a record.

        Args:
            obj: Model instance to update.
            **kwargs: Attributes to update.

        Returns:
            Updated model instance.
        """
        for key, value in kwargs.items():
            setattr(obj, key, value)
        await self.session.flush()
        await self.session.refresh(obj)
        return obj

    async def delete(self, obj: ModelT) -> None:
        """Delete a record.

        Args:
            obj: Model instance to delete.
        """
        await self.session.delete(obj)
        await self.session.flush()

    async def delete_by_id(self, id: str) -> bool:
        """Delete a record by ID.

        Args:
            id: Primary key value.

        Returns:
            True if record was deleted, False if not found.
        """
        obj = await self.get(id)
        if obj:
            await self.delete(obj)
            return True
        return False

    async def soft_delete(self, obj: ModelT) -> ModelT:
        """Soft delete a record (if model supports it).

        Args:
            obj: Model instance to soft delete.

        Returns:
            Updated model instance.

        Raises:
            AttributeError: If model doesn't support soft delete.
        """
        from datetime import datetime, timezone

        obj.is_deleted = True  # type: ignore
        obj.deleted_at = datetime.now(timezone.utc)  # type: ignore
        await self.session.flush()
        await self.session.refresh(obj)
        return obj
