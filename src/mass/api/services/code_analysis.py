"""Code architecture analysis service.

Orchestrates the static file selection + LLM analysis pipeline,
stores the resulting ArchitectureMap in deployment metadata.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from mass.analyzers.code.file_selector import select_files
from mass.analyzers.code.llm_analyzer import CodeArchitectureAnalyzer
from mass.analyzers.code.models import ArchitectureMap
from mass.core.filesystem import detect_ai_frameworks, scan_directory_quick
from mass.storage.models.deployment import Deployment

logger = logging.getLogger(__name__)


async def analyze_target_architecture(
    deployment: Deployment,
    provider: str = "ollama",
    model: str | None = None,
    api_key: str | None = None,
    db: AsyncSession | None = None,
    progress_cb: Callable[[str], None] | None = None,
) -> ArchitectureMap:
    """Run full architecture analysis on a deployment target.

    1. Static pass: select high-signal files
    2. LLM pass: analyze those files for AI architecture
    3. Store results in deployment metadata

    Args:
        deployment: Deployment model instance.
        provider: LLM provider (ollama, openai, anthropic).
        model: Model name (auto-resolved from provider defaults if None).
        api_key: API key for cloud providers.
        db: Database session for persisting results.
        progress_cb: Optional callback for progress messages.

    Returns:
        ArchitectureMap with analysis results.
    """
    source_path = deployment.source_path
    if not source_path:
        return ArchitectureMap(errors=["No source path configured for this target"])

    target_path = Path(source_path)
    if not target_path.is_dir():
        return ArchitectureMap(errors=[f"Source path is not a directory: {source_path}"])

    # ── Step 1: Static file selection ──
    if progress_cb:
        progress_cb("Scanning files for AI architecture signals...")

    scored_files = select_files(target_path, max_files=30)

    if not scored_files:
        # Fall back to basic discovery info
        arch = ArchitectureMap(
            total_files=0,
            errors=["No files with AI signals found — static analysis only"],
        )
        # Still run filesystem discovery for basic metadata
        info = scan_directory_quick(target_path)
        if info:
            arch.total_files = info.get("file_count", 0)
        frameworks = detect_ai_frameworks(target_path)
        if frameworks:
            arch.summary = f"Detected frameworks: {', '.join(frameworks)}"
        _persist_results(deployment, arch, db)
        return arch

    if progress_cb:
        progress_cb(f"Selected {len(scored_files)} high-signal files for LLM analysis")

    # ── Step 2: LLM analysis ──
    analyzer = CodeArchitectureAnalyzer(
        provider=provider,
        model=model,
        api_key=api_key,
    )

    arch = await analyzer.analyze(scored_files, progress_cb=progress_cb)

    # Enrich with filesystem discovery
    info = scan_directory_quick(target_path)
    if info:
        arch.total_files = info.get("file_count", 0)

    # ── Step 3: Persist results ──
    await _persist_results(deployment, arch, db)

    if progress_cb:
        progress_cb(
            f"Analysis complete: {arch.pattern} pattern, "
            f"{len(arch.entry_points)} entry points, "
            f"{len(arch.model_connections)} model connections, "
            f"{len(arch.tool_definitions)} tools"
        )

    return arch


async def _persist_results(
    deployment: Deployment,
    arch: ArchitectureMap,
    db: AsyncSession | None,
) -> None:
    """Store architecture map and topology in deployment metadata."""
    if db is None:
        return

    try:
        meta: dict[str, Any] = {}
        if deployment.meta:
            meta = json.loads(deployment.meta)
    except (json.JSONDecodeError, TypeError):
        meta = {}

    meta["architecture_map"] = arch.to_dict()
    meta["topology"] = arch.build_topology()
    meta["pipeline_status"] = "profiled"

    # Also store basic discovery info for compatibility
    if "discovery" not in meta:
        meta["discovery"] = {
            "file_count": arch.total_files,
            "has_models": bool(arch.model_connections),
            "has_code": arch.total_files > 0,
            "ai_frameworks": [],
            "recommended_profile": "comprehensive" if arch.tool_definitions else "standard",
        }

    deployment.meta = json.dumps(meta)
    await db.commit()

    logger.info(
        "Architecture analysis stored for deployment %s: %s pattern, %.0f%% confidence",
        deployment.id, arch.pattern, arch.confidence * 100,
    )
