"""Chat context gathering service.

Queries the database for deployments, scans, findings, and other
environment data relevant to the user's chat message.  The gathered
context is injected into the LLM system prompt so the assistant can
answer from local knowledge before falling back to general reasoning.
"""

import json
import logging
import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from mass.storage.models.deployment import Deployment, Scan
from mass.storage.models.finding import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Keyword patterns used to decide which DB context to fetch
# ---------------------------------------------------------------------------

_DEPLOYMENT_KEYWORDS = re.compile(
    r"\b(deploy|deployment|target|project|agent|endpoint|service)\b", re.I
)
_SCAN_KEYWORDS = re.compile(
    r"\b(scan|scans|scanning|profile|progress|running|pending|completed|quick|standard|comprehensive)\b", re.I
)
_FINDING_KEYWORDS = re.compile(
    r"\b(finding|findings|vuln|vulnerability|vulnerabilities|issue|issues|"
    r"critical|high|medium|low|severity|remediat|fix|inject|secret|xss|sqli|"
    r"prompt.?injection|deserialization|command.?injection|hardcoded|"
    r"ssrf|path.?traversal)\b", re.I
)
_STATS_KEYWORDS = re.compile(
    r"\b(stats|statistics|summary|overview|dashboard|how many|count|total|score)\b", re.I
)


async def gather_chat_context(
    session: AsyncSession,
    tenant_id: str,
    message: str,
) -> str:
    """Return a context block string to prepend to the LLM system prompt.

    Inspects *message* for keyword signals and fetches only the relevant
    slices of data so the context stays compact.
    """
    sections: list[str] = []

    want_stats = bool(_STATS_KEYWORDS.search(message))
    want_deployments = bool(_DEPLOYMENT_KEYWORDS.search(message))
    want_scans = bool(_SCAN_KEYWORDS.search(message))
    want_findings = bool(_FINDING_KEYWORDS.search(message))

    # If the message is generic / conversational, provide a light summary
    if not (want_stats or want_deployments or want_scans or want_findings):
        want_stats = True  # always give a baseline

    # ---- Environment summary (always) ----
    try:
        summary = await _get_environment_summary(session, tenant_id)
        sections.append(summary)
    except Exception as exc:
        logger.debug("Failed to gather env summary: %s", exc)

    # ---- Deployments / targets ----
    if want_deployments:
        try:
            dep_ctx = await _get_deployments_context(session, tenant_id)
            if dep_ctx:
                sections.append(dep_ctx)
        except Exception as exc:
            logger.debug("Failed to gather deployment context: %s", exc)

    # ---- Scans ----
    if want_scans:
        try:
            scan_ctx = await _get_scans_context(session, tenant_id)
            if scan_ctx:
                sections.append(scan_ctx)
        except Exception as exc:
            logger.debug("Failed to gather scan context: %s", exc)

    # ---- Findings ----
    if want_findings:
        try:
            findings_ctx = await _get_findings_context(session, tenant_id)
            if findings_ctx:
                sections.append(findings_ctx)
        except Exception as exc:
            logger.debug("Failed to gather findings context: %s", exc)

    if not sections:
        return ""

    header = (
        "\n\n--- ENVIRONMENT CONTEXT (from local MASS database) ---\n"
        "Use the following real-time data when answering. "
        "Cite specific numbers, names, and statuses.\n"
    )
    return header + "\n".join(sections) + "\n--- END CONTEXT ---\n"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _get_environment_summary(session: AsyncSession, tenant_id: str) -> str:
    """High-level counts: deployments, scans, findings, severity breakdown."""
    dep_count = (
        await session.execute(
            select(func.count()).select_from(Deployment).where(Deployment.tenant_id == tenant_id)
        )
    ).scalar() or 0

    scan_count = (
        await session.execute(
            select(func.count()).select_from(Scan).where(Scan.tenant_id == tenant_id)
        )
    ).scalar() or 0

    active_scans = (
        await session.execute(
            select(func.count()).select_from(Scan)
            .where(Scan.tenant_id == tenant_id)
            .where(Scan.status.in_(["running", "pending"]))
        )
    ).scalar() or 0

    total_findings = (
        await session.execute(
            select(func.count()).select_from(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.tenant_id == tenant_id)
        )
    ).scalar() or 0

    # Severity breakdown
    sev_rows = (
        await session.execute(
            select(Finding.severity, func.count())
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.tenant_id == tenant_id)
            .group_by(Finding.severity)
        )
    ).all()
    sev_map = {row[0]: row[1] for row in sev_rows}

    # Status breakdown
    status_rows = (
        await session.execute(
            select(Finding.status, func.count())
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.tenant_id == tenant_id)
            .group_by(Finding.status)
        )
    ).all()
    status_map = {row[0]: row[1] for row in status_rows}

    lines = [
        "ENVIRONMENT SUMMARY:",
        f"  Deployments/Targets: {dep_count}",
        f"  Total Scans: {scan_count}  (active: {active_scans})",
        f"  Total Findings: {total_findings}",
        f"    Critical: {sev_map.get('critical', 0)}, High: {sev_map.get('high', 0)}, "
        f"Medium: {sev_map.get('medium', 0)}, Low: {sev_map.get('low', 0)}, Info: {sev_map.get('info', 0)}",
        f"    Open: {status_map.get('open', 0)}, Confirmed: {status_map.get('confirmed', 0)}, "
        f"Fixed: {status_map.get('fixed', 0)}, False Positive: {status_map.get('false_positive', 0)}, "
        f"Accepted: {status_map.get('accepted', 0)}",
    ]
    return "\n".join(lines)


async def _get_deployments_context(session: AsyncSession, tenant_id: str) -> str:
    """List recent deployments with their type and scan count."""
    stmt = (
        select(Deployment)
        .where(Deployment.tenant_id == tenant_id)
        .order_by(Deployment.created_at.desc())
        .limit(15)
    )
    result = await session.execute(stmt)
    deployments = result.scalars().all()
    if not deployments:
        return ""

    lines = ["DEPLOYMENTS/TARGETS:"]
    for d in deployments:
        meta: dict[str, Any] = {}
        if d.meta:
            try:
                meta = json.loads(d.meta)
            except (json.JSONDecodeError, TypeError):
                pass
        target_type = meta.get("target_type", d.deployment_type)
        path = d.source_path or d.source_url or ""
        lines.append(f"  - {d.name} (type={target_type}, path={path}, id={d.id[:8]}...)")
    return "\n".join(lines)


async def _get_scans_context(session: AsyncSession, tenant_id: str) -> str:
    """List recent scans with status, profile, and findings count."""
    stmt = (
        select(Scan)
        .where(Scan.tenant_id == tenant_id)
        .order_by(Scan.created_at.desc())
        .limit(10)
    )
    result = await session.execute(stmt)
    scans = result.scalars().all()
    if not scans:
        return ""

    # Get deployment names
    dep_ids = list({s.deployment_id for s in scans})
    dep_stmt = select(Deployment.id, Deployment.name).where(Deployment.id.in_(dep_ids))
    dep_result = await session.execute(dep_stmt)
    dep_names = {row[0]: row[1] for row in dep_result.all()}

    lines = ["RECENT SCANS:"]
    for s in scans:
        target_name = dep_names.get(s.deployment_id, s.deployment_id[:8])
        duration = f"{s.duration_seconds}s" if s.duration_seconds else "in-progress"
        lines.append(
            f"  - [{s.status}] {target_name} | profile={s.profile} | "
            f"findings={s.total_findings} (C:{s.critical_findings} H:{s.high_findings} "
            f"M:{s.medium_findings} L:{s.low_findings}) | duration={duration} | id={s.id[:8]}..."
        )
    return "\n".join(lines)


async def _get_findings_context(session: AsyncSession, tenant_id: str) -> str:
    """List top findings by severity (critical/high first), limited to keep context compact."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.tenant_id == tenant_id)
        .where(Finding.status.in_(["open", "confirmed"]))
        .order_by(
            # Critical first, then high, etc.
            func.case(
                (Finding.severity == "critical", 0),
                (Finding.severity == "high", 1),
                (Finding.severity == "medium", 2),
                (Finding.severity == "low", 3),
                else_=4,
            )
        )
        .limit(20)
    )
    result = await session.execute(stmt)
    findings = result.scalars().all()
    if not findings:
        return ""

    lines = ["TOP OPEN FINDINGS (by severity):"]
    for f in findings:
        location = f.file_path or ""
        if f.line_number and location:
            location += f":{f.line_number}"
        lines.append(
            f"  - [{f.severity.upper()}] {f.title} | category={f.category} | "
            f"status={f.status} | file={location or 'n/a'}"
        )
    return "\n".join(lines)
