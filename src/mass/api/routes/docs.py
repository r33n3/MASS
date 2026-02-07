"""Documentation endpoints.

Serves help documentation from the docs/ directory for the UI docs panel.
Supports listing, searching, and retrieving documentation sections.
"""

from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict, Field

from mass.api.dependencies import CurrentTenantDep
from mass.api.services.docs_loader import (
    list_all_docs,
    list_categories,
    reload_docs,
    search_docs,
)

router = APIRouter()


class DocSection(BaseModel):
    """A single documentation section."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(description="Section heading")
    body: str = Field(description="Section content (markdown)")
    file: str = Field(description="Source file path relative to docs/")
    category: str = Field(description="Documentation category")


class DocsListResponse(BaseModel):
    """Response containing documentation sections."""

    model_config = ConfigDict(extra="forbid")

    sections: list[DocSection] = Field(description="Documentation sections")
    total: int = Field(description="Total number of sections")
    categories: list[str] = Field(description="Available categories")


class DocsSearchResponse(BaseModel):
    """Response from documentation search."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(description="The search query")
    results: list[DocSection] = Field(description="Matching sections")
    total: int = Field(description="Number of results")


@router.get(
    "",
    response_model=DocsListResponse,
    summary="List all documentation",
    description="Returns all available documentation sections, optionally filtered by category.",
)
async def list_docs(
    tenant: CurrentTenantDep,
    category: str | None = Query(None, description="Filter by category"),
) -> DocsListResponse:
    """List all documentation sections."""
    all_docs = list_all_docs()
    categories = list_categories()

    if category:
        all_docs = [d for d in all_docs if d["category"] == category]

    return DocsListResponse(
        sections=[DocSection(**d) for d in all_docs],
        total=len(all_docs),
        categories=categories,
    )


@router.get(
    "/search",
    response_model=DocsSearchResponse,
    summary="Search documentation",
    description="Search documentation sections by keyword query.",
)
async def search_documentation(
    tenant: CurrentTenantDep,
    q: str = Query(..., min_length=1, description="Search query"),
    limit: int = Query(10, ge=1, le=50, description="Max results"),
) -> DocsSearchResponse:
    """Search documentation by keyword."""
    results = search_docs(q, limit=limit)
    return DocsSearchResponse(
        query=q,
        results=[DocSection(**r) for r in results],
        total=len(results),
    )


@router.post(
    "/reload",
    summary="Reload documentation",
    description="Force reload all documentation files from disk.",
)
async def reload_documentation(
    tenant: CurrentTenantDep,
) -> dict[str, Any]:
    """Reload documentation from disk."""
    count = reload_docs()
    return {"status": "reloaded", "sections_loaded": count}
