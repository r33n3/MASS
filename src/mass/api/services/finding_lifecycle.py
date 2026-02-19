"""Finding lifecycle service: comparison and auto-closure.

Provides cross-scan finding comparison using fingerprints and
automatic closure of findings that no longer appear in rescans.
"""

import json
import logging

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from mass.core.filesystem import filter_by_patterns
from mass.storage.models.deployment import Scan
from mass.storage.models.finding import Finding, FindingStatus

logger = logging.getLogger(__name__)


async def compare_scan_findings(
    session: AsyncSession,
    scan_1_id: str,
    scan_2_id: str,
) -> dict:
    """Compare findings between two scans using fingerprints.

    Args:
        session: Database session.
        scan_1_id: First (older) scan ID.
        scan_2_id: Second (newer) scan ID.

    Returns:
        Dict with keys: new, fixed, unchanged, changed, severity_trend.
    """
    stmt1 = select(Finding).where(Finding.scan_id == scan_1_id)
    result1 = await session.execute(stmt1)
    findings_1 = {f.fingerprint: f for f in result1.scalars().all() if f.fingerprint}

    stmt2 = select(Finding).where(Finding.scan_id == scan_2_id)
    result2 = await session.execute(stmt2)
    findings_2 = {f.fingerprint: f for f in result2.scalars().all() if f.fingerprint}

    fps_1 = set(findings_1.keys())
    fps_2 = set(findings_2.keys())

    new_fps = fps_2 - fps_1
    fixed_fps = fps_1 - fps_2
    common_fps = fps_1 & fps_2

    changed = []
    unchanged = []
    for fp in common_fps:
        f1 = findings_1[fp]
        f2 = findings_2[fp]
        if f1.severity != f2.severity:
            changed.append((f1, f2))
        else:
            unchanged.append((f1, f2))

    new = [findings_2[fp] for fp in new_fps]
    fixed = [findings_1[fp] for fp in fixed_fps]

    # Severity trend: count delta per severity level
    sev_counts_1: dict[str, int] = {}
    for f in findings_1.values():
        sev_counts_1[f.severity] = sev_counts_1.get(f.severity, 0) + 1
    sev_counts_2: dict[str, int] = {}
    for f in findings_2.values():
        sev_counts_2[f.severity] = sev_counts_2.get(f.severity, 0) + 1

    all_sevs = set(sev_counts_1.keys()) | set(sev_counts_2.keys())
    severity_trend = {
        sev: sev_counts_2.get(sev, 0) - sev_counts_1.get(sev, 0)
        for sev in all_sevs
    }

    return {
        "new": new,
        "fixed": fixed,
        "unchanged": [pair[1] for pair in unchanged],
        "changed": changed,
        "severity_trend": severity_trend,
    }


async def auto_close_findings(
    session: AsyncSession,
    completed_scan_id: str,
    deployment_id: str,
) -> int:
    """Mark findings from previous scan as FIXED if not present in new scan.

    Called after a scan completes. Only closes OPEN/CONFIRMED findings,
    respecting manual triage (FALSE_POSITIVE, ACCEPTED).

    Args:
        session: Database session.
        completed_scan_id: ID of the just-completed scan.
        deployment_id: Deployment ID.

    Returns:
        Number of findings auto-closed.
    """
    # Load exclude_paths from scan config so we don't close findings
    # on files that were simply excluded from this scan's scope.
    current_scan_stmt = select(Scan).where(Scan.id == completed_scan_id)
    result = await session.execute(current_scan_stmt)
    current_scan = result.scalar_one_or_none()

    exclude_patterns: list[str] = []
    if current_scan and current_scan.config:
        try:
            scan_config = json.loads(current_scan.config)
            exclude_patterns = scan_config.get("exclude_paths", []) or []
        except (ValueError, TypeError):
            pass

    # Find the previous completed scan for this deployment
    prev_scan_stmt = (
        select(Scan)
        .where(Scan.deployment_id == deployment_id)
        .where(Scan.status == "completed")
        .where(Scan.id != completed_scan_id)
        .order_by(Scan.completed_at.desc())
        .limit(1)
    )
    result = await session.execute(prev_scan_stmt)
    prev_scan = result.scalar_one_or_none()

    if not prev_scan:
        logger.debug(
            "No previous scan for deployment %s; skipping auto-close",
            deployment_id,
        )
        return 0

    # Get fingerprints from the new scan
    new_fps_stmt = (
        select(Finding.fingerprint)
        .where(Finding.scan_id == completed_scan_id)
        .where(Finding.fingerprint.isnot(None))
    )
    result = await session.execute(new_fps_stmt)
    new_fingerprints = {row[0] for row in result.all()}

    if not new_fingerprints:
        logger.debug("New scan %s has no fingerprinted findings", completed_scan_id)
        return 0

    # Get OPEN/CONFIRMED findings from previous scan not in new scan
    prev_findings_stmt = (
        select(Finding)
        .where(Finding.scan_id == prev_scan.id)
        .where(Finding.fingerprint.isnot(None))
        .where(Finding.status.in_([
            FindingStatus.OPEN.value,
            FindingStatus.CONFIRMED.value,
        ]))
        .where(Finding.fingerprint.notin_(new_fingerprints))
    )
    result = await session.execute(prev_findings_stmt)
    to_close = result.scalars().all()

    if not to_close:
        return 0

    # Don't close findings on files that were excluded from this scan
    if exclude_patterns:
        excluded_paths = [f.file_path for f in to_close if f.file_path]
        if excluded_paths:
            surviving = filter_by_patterns(excluded_paths, exclude_patterns)
            surviving_set = set(surviving)
            before_filter = len(to_close)
            to_close = [
                f for f in to_close
                if not f.file_path or f.file_path in surviving_set
            ]
            skipped = before_filter - len(to_close)
            if skipped:
                logger.info(
                    "Skipped auto-close for %d findings on excluded paths",
                    skipped,
                )

    if not to_close:
        return 0

    # Batch update
    ids_to_close = [f.id for f in to_close]
    close_stmt = (
        update(Finding)
        .where(Finding.id.in_(ids_to_close))
        .values(
            status=FindingStatus.FIXED.value,
            closed_by_scan_id=completed_scan_id,
        )
    )
    await session.execute(close_stmt)

    logger.info(
        "Auto-closed %d findings from scan %s (deployment %s)",
        len(ids_to_close),
        prev_scan.id,
        deployment_id,
    )

    return len(ids_to_close)
