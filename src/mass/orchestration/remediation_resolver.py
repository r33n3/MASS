"""Remediation resolver for looking up templates during scans.

Bridges the async database layer with the synchronous scan pipeline
by pre-loading all remediation templates into an in-memory cache.
"""

import json
import logging
from typing import Any

from mass.core.findings import Remediation
from mass.core.types import AttackCategory

logger = logging.getLogger(__name__)

# Context key for passing cache through scan pipeline
REMEDIATION_CACHE_KEY = "_remediation_cache"


class RemediationCache:
    """In-memory cache of remediation templates.

    Loaded once at the start of a scan on the async side,
    then passed through context for sync consumers.
    """

    def __init__(self) -> None:
        self._templates: dict[tuple[str, str | None], dict[str, Any]] = {}

    def add(self, template: Any) -> None:
        """Add a template (SQLAlchemy model instance) to the cache."""
        key = (template.category, template.subcategory)
        self._templates[key] = {
            "id": template.id,
            "title": template.title,
            "summary": template.summary,
            "description": template.description,
            "steps": _safe_json_loads(template.steps),
            "guardrail_examples": _safe_json_loads(template.guardrail_examples),
            "code_examples": _safe_json_loads(template.code_examples),
            "cwe_ids": _safe_json_loads(template.cwe_ids),
            "owasp_ids": _safe_json_loads(template.owasp_ids),
            "mitre_ids": _safe_json_loads(template.mitre_ids),
            "references": _safe_json_loads(template.references),
            "estimated_effort": template.estimated_effort,
        }

    def resolve(
        self,
        category: AttackCategory | str,
        subcategory: str | None = None,
    ) -> dict[str, Any] | None:
        """Look up a template, with subcategory fallback to category-level."""
        cat_val = category.value if isinstance(category, AttackCategory) else category
        if subcategory:
            template = self._templates.get((cat_val, subcategory))
            if template:
                return template
        return self._templates.get((cat_val, None))

    def build_remediation(
        self,
        category: AttackCategory | str,
        subcategory: str | None = None,
        environment: dict | None = None,
        fallback_summary: str = "Review and apply appropriate security controls.",
        fallback_steps: list[str] | None = None,
        fallback_references: list[str] | None = None,
    ) -> Remediation:
        """Build a Remediation object from template or fallback.

        When ``environment`` is provided (from discovery phase), the resolver
        will first try a cloud-specific subcategory template (e.g.
        ``secrets_exposure/aws``) before falling back to the generic one.

        Args:
            category: Attack category to look up.
            subcategory: Optional subcategory for more specific guidance.
            environment: Optional environment dict from discovery phase.
            fallback_summary: Summary to use if no template found.
            fallback_steps: Steps to use if no template found.
            fallback_references: References to use if no template found.

        Returns:
            Remediation object with template data or fallback content.
        """
        # Try cloud-specific subcategory first when environment is known
        template = None
        cloud = None
        if environment:
            cloud = environment.get("cloud_provider")
            if cloud and cloud not in ("unknown", "hybrid"):
                template = self.resolve(category, subcategory=cloud)

        # Fall back to explicit subcategory, then generic
        if not template:
            template = self.resolve(category, subcategory)

        if template:
            refs = []
            if template.get("references"):
                refs = [r["url"] for r in template["references"] if "url" in r]
            return Remediation(
                summary=template["summary"],
                steps=template["steps"] or [],
                references=refs,
                estimated_effort=template.get("estimated_effort"),
            )
        cat_val = category.value if isinstance(category, AttackCategory) else category
        logger.debug(
            "No remediation template found for category=%s subcategory=%s, using fallback",
            cat_val,
            subcategory,
        )
        return Remediation(
            summary=fallback_summary,
            steps=fallback_steps or [],
            references=fallback_references or [],
        )

    def get_template_id(
        self,
        category: AttackCategory | str,
        subcategory: str | None = None,
    ) -> str | None:
        """Get the template ID for a category, if available."""
        template = self.resolve(category, subcategory)
        return template["id"] if template else None

    @property
    def is_loaded(self) -> bool:
        return len(self._templates) > 0

    @property
    def count(self) -> int:
        return len(self._templates)


def _safe_json_loads(value: str | None) -> Any:
    """Parse JSON string, returning None if invalid."""
    if not value:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None


async def load_remediation_cache(session) -> RemediationCache:
    """Load all active templates into a cache.

    Called from async context (ScanExecutionService) before
    delegating to the synchronous scan pipeline.

    Args:
        session: Async database session.

    Returns:
        Populated RemediationCache instance.
    """
    from mass.storage.repositories.remediation import RemediationTemplateRepository

    cache = RemediationCache()
    try:
        repo = RemediationTemplateRepository(session)
        templates = await repo.get_all_active()
        for template in templates:
            cache.add(template)
        logger.info(f"Loaded {cache.count} remediation templates into cache")
    except Exception as e:
        logger.error(
            "Failed to load remediation templates: %s. "
            "Scan findings will use hardcoded fallback remediation.",
            e,
        )
    if not cache.is_loaded:
        logger.warning("Remediation cache is empty; all findings will use fallback guidance")
    return cache
