"""Repositories for AI artifact models (GuardrailSet, Explanation)."""

from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mass.storage.models.ai_artifacts import Explanation, GuardrailSet
from mass.storage.repositories.base import BaseRepository


class GuardrailSetRepository(BaseRepository[GuardrailSet]):
    """Repository for persisted guardrail generation results."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(GuardrailSet, session)

    async def list_by_tenant(
        self,
        tenant_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Sequence[GuardrailSet]:
        stmt = (
            select(GuardrailSet)
            .where(GuardrailSet.tenant_id == tenant_id)
            .order_by(GuardrailSet.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_by_scan(
        self,
        scan_id: str,
        *,
        tenant_id: str | None = None,
    ) -> Sequence[GuardrailSet]:
        stmt = (
            select(GuardrailSet)
            .where(GuardrailSet.scan_id == scan_id)
            .order_by(GuardrailSet.created_at.desc())
        )
        if tenant_id:
            stmt = stmt.where(GuardrailSet.tenant_id == tenant_id)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_by_tenant(self, tenant_id: str) -> int:
        return await self.count(tenant_id=tenant_id)


class ExplanationRepository(BaseRepository[Explanation]):
    """Repository for persisted explainability outputs."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Explanation, session)

    async def list_by_tenant(
        self,
        tenant_id: str,
        *,
        explanation_type: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> Sequence[Explanation]:
        stmt = (
            select(Explanation)
            .where(Explanation.tenant_id == tenant_id)
        )
        if explanation_type:
            stmt = stmt.where(Explanation.explanation_type == explanation_type)
        stmt = stmt.order_by(Explanation.created_at.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_by_finding(
        self,
        finding_id: str,
        *,
        tenant_id: str | None = None,
    ) -> Sequence[Explanation]:
        stmt = (
            select(Explanation)
            .where(Explanation.finding_id == finding_id)
            .order_by(Explanation.created_at.desc())
        )
        if tenant_id:
            stmt = stmt.where(Explanation.tenant_id == tenant_id)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_by_scan(
        self,
        scan_id: str,
        *,
        explanation_type: str | None = None,
        tenant_id: str | None = None,
    ) -> Sequence[Explanation]:
        stmt = (
            select(Explanation)
            .where(Explanation.scan_id == scan_id)
        )
        if explanation_type:
            stmt = stmt.where(Explanation.explanation_type == explanation_type)
        if tenant_id:
            stmt = stmt.where(Explanation.tenant_id == tenant_id)
        stmt = stmt.order_by(Explanation.created_at.desc())
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_by_tenant(self, tenant_id: str) -> int:
        return await self.count(tenant_id=tenant_id)
