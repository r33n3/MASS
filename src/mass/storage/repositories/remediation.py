"""Repository for remediation templates."""

from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mass.storage.models.remediation import RemediationTemplate
from mass.storage.repositories.base import BaseRepository


class RemediationTemplateRepository(BaseRepository[RemediationTemplate]):
    """Repository for RemediationTemplate model."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(RemediationTemplate, session)

    async def get_by_category(
        self,
        category: str,
        subcategory: str | None = None,
    ) -> RemediationTemplate | None:
        """Look up a template by category and optional subcategory.

        Falls back to the category-level template (subcategory=None)
        if a specific subcategory template is not found.
        """
        if subcategory:
            template = await self.get_by(
                category=category, subcategory=subcategory
            )
            if template and template.is_active:
                return template

        # Fallback to category-level template
        stmt = (
            select(RemediationTemplate)
            .where(RemediationTemplate.category == category)
            .where(RemediationTemplate.subcategory.is_(None))
        )
        result = await self.session.execute(stmt)
        template = result.scalar_one_or_none()
        if template and template.is_active:
            return template
        return None

    async def list_by_category(
        self,
        category: str,
    ) -> Sequence[RemediationTemplate]:
        """List all templates for a category (including subcategories)."""
        stmt = (
            select(RemediationTemplate)
            .where(RemediationTemplate.category == category)
            .where(RemediationTemplate.is_active == True)
            .order_by(RemediationTemplate.subcategory)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_all_active(self) -> Sequence[RemediationTemplate]:
        """Get all active templates (for cache pre-loading)."""
        stmt = (
            select(RemediationTemplate)
            .where(RemediationTemplate.is_active == True)
            .order_by(RemediationTemplate.category, RemediationTemplate.subcategory)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
