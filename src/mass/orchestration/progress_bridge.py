"""Progress bridge for sync-to-async communication during scans.

Bridges the synchronous scan pipeline (running in a thread pool) back
to the async event loop for DB persistence, WebSocket broadcasts, and
incremental finding storage.
"""

import asyncio
import json
import logging
from typing import Any

from mass.core.findings import Finding as CoreFinding
from mass.core.fingerprint import compute_fingerprint
from mass.core.types import Severity
from mass.orchestration.service import ScanProgress

logger = logging.getLogger(__name__)

# Code snippet context lines
_SNIPPET_CONTEXT = 3


def _extract_code_snippet(file_path: str | None, line_number: int | None) -> str | None:
    """Extract a code snippet from a file around a given line number."""
    if not file_path or not line_number:
        return None
    try:
        import os
        if not os.path.isfile(file_path):
            return None
        # Don't read huge files
        if os.path.getsize(file_path) > 2 * 1024 * 1024:
            return None
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        if not all_lines:
            return None
        idx = min(line_number - 1, len(all_lines) - 1)
        start = max(0, idx - _SNIPPET_CONTEXT)
        end = min(len(all_lines), idx + _SNIPPET_CONTEXT + 1)
        snippet_lines = []
        for i in range(start, end):
            marker = ">>>" if i == idx else "   "
            snippet_lines.append(f"{marker} {i + 1:4d} | {all_lines[i].rstrip()}")
        return "\n".join(snippet_lines)
    except Exception:
        return None


# Minimum progress change (%) before persisting to DB
PROGRESS_THROTTLE_PERCENT = 5.0


class ProgressBridge:
    """Bridges sync scan callbacks to async DB writes and WebSocket broadcasts.

    Created on the async side (scan_execution.py), then passed as a callback
    to the sync scan pipeline. Uses asyncio.run_coroutine_threadsafe() to
    schedule async work from the sync thread.
    """

    def __init__(
        self,
        scan_id: str,
        tenant_id: str,
        loop: asyncio.AbstractEventLoop,
        session_factory: Any,
    ) -> None:
        self._scan_id = scan_id
        self._tenant_id = tenant_id
        self._loop = loop
        self._session_factory = session_factory
        self._last_persisted_percent: float = -1.0
        self._last_persisted_phase: str = ""

    def on_progress(self, progress: ScanProgress) -> None:
        """Sync callback invoked by ScanService after each job.

        Schedules async DB persistence and WebSocket broadcast
        if progress has changed enough to warrant it.
        """
        should_persist = (
            abs(progress.progress_percent - self._last_persisted_percent) >= PROGRESS_THROTTLE_PERCENT
            or progress.current_phase != self._last_persisted_phase
            or progress.progress_percent >= 100.0
        )

        if should_persist:
            self._last_persisted_percent = progress.progress_percent
            self._last_persisted_phase = progress.current_phase
            try:
                future = asyncio.run_coroutine_threadsafe(
                    self._persist_progress(progress),
                    self._loop,
                )
                # Don't block waiting for result - fire and forget
                future.add_done_callback(self._handle_async_error)
            except Exception:
                logger.warning("Failed to schedule progress persistence", exc_info=True)

    def store_findings(self, findings: list[CoreFinding]) -> None:
        """Sync callback to store findings incrementally after each job.

        Args:
            findings: List of core Finding objects from a completed job.
        """
        if not findings:
            return

        try:
            future = asyncio.run_coroutine_threadsafe(
                self._store_findings_async(findings),
                self._loop,
            )
            future.add_done_callback(self._handle_async_error)
        except Exception:
            logger.warning("Failed to schedule finding storage", exc_info=True)

    async def _persist_progress(self, progress: ScanProgress) -> None:
        """Async: update Scan row with current progress."""
        from sqlalchemy import update
        from mass.storage.models.deployment import Scan

        async with self._session_factory() as session:
            try:
                stmt = (
                    update(Scan)
                    .where(Scan.id == self._scan_id)
                    .values(
                        progress_percent=progress.progress_percent,
                        current_phase=progress.current_phase,
                        jobs_completed=progress.jobs_completed,
                        jobs_total=progress.jobs_total,
                    )
                )
                await session.execute(stmt)
                await session.commit()
            except Exception:
                await session.rollback()
                logger.warning("Failed to persist progress for scan %s", self._scan_id, exc_info=True)
                return

        # Broadcast via WebSocket (non-blocking, best-effort)
        try:
            from mass.dashboard.websocket import broadcast_scan_update
            await broadcast_scan_update(
                scan_id=self._scan_id,
                status=progress.status.value,
                progress=progress.progress_percent,
                findings_count=progress.findings_count,
                message=progress.message,
                current_phase=progress.current_phase,
                jobs_completed=progress.jobs_completed,
                jobs_total=progress.jobs_total,
            )
        except Exception:
            logger.debug("Failed to broadcast progress", exc_info=True)

    async def _store_findings_async(self, findings: list[CoreFinding]) -> None:
        """Async: store findings and atomically update counts on Scan."""
        from sqlalchemy import update, text
        from mass.storage.models.deployment import Scan
        from mass.storage.models.finding import Finding as DBFinding

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        db_findings = []

        for finding in findings:
            meta_data: dict[str, Any] = {}
            if finding.confidence and finding.confidence != 1.0:
                meta_data["confidence"] = finding.confidence
            if finding.component_type:
                meta_data["component_type"] = finding.component_type.value
            if finding.component_name:
                meta_data["component_name"] = finding.component_name
            if finding.tags:
                meta_data["tags"] = finding.tags
            if finding.remediation and finding.remediation.steps:
                meta_data["remediation_steps"] = finding.remediation.steps
            if finding.metadata:
                meta_data.update(finding.metadata)

            fp = compute_fingerprint(
                category=finding.category.value,
                title=finding.title,
                file_path=finding.file_path,
                rule_id=None,
                component_name=finding.component_name,
            )

            # Extract code snippet from source file if available
            snippet = _extract_code_snippet(finding.file_path, finding.line_number)

            db_finding = DBFinding(
                scan_id=self._scan_id,
                tenant_id=self._tenant_id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity.value,
                category=finding.category.value,
                file_path=finding.file_path,
                line_number=finding.line_number,
                code_snippet=snippet,
                cwe_id=finding.cwe_ids[0] if finding.cwe_ids else None,
                owasp_category=finding.owasp_ids[0] if finding.owasp_ids else None,
                mitre_technique=finding.mitre_ids[0] if finding.mitre_ids else None,
                remediation=finding.remediation.summary if finding.remediation else None,
                evidence=json.dumps([e.model_dump(mode="json") for e in finding.evidence]) if finding.evidence else None,
                references=json.dumps(finding.remediation.references) if finding.remediation and finding.remediation.references else None,
                meta=json.dumps(meta_data) if meta_data else None,
                fingerprint=fp,
            )
            db_findings.append(db_finding)

            sev = finding.severity.value
            if sev in severity_counts:
                severity_counts[sev] += 1

        async with self._session_factory() as session:
            try:
                session.add_all(db_findings)
                await session.flush()

                # Atomically increment finding counts on the Scan record
                total = len(db_findings)
                stmt = (
                    update(Scan)
                    .where(Scan.id == self._scan_id)
                    .values(
                        total_findings=Scan.total_findings + total,
                        critical_findings=Scan.critical_findings + severity_counts["critical"],
                        high_findings=Scan.high_findings + severity_counts["high"],
                        medium_findings=Scan.medium_findings + severity_counts["medium"],
                        low_findings=Scan.low_findings + severity_counts["low"],
                    )
                )
                await session.execute(stmt)
                await session.commit()

                logger.debug(
                    "Stored %d findings incrementally for scan %s",
                    total, self._scan_id,
                )
            except Exception:
                await session.rollback()
                logger.warning(
                    "Failed to store findings incrementally for scan %s",
                    self._scan_id, exc_info=True,
                )
                return

        # Broadcast each finding via WebSocket
        try:
            from mass.dashboard.websocket import broadcast_finding
            for finding in findings:
                await broadcast_finding(
                    scan_id=self._scan_id,
                    finding={
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "category": finding.category.value,
                        "description": finding.description[:200],
                    },
                )
        except Exception:
            logger.debug("Failed to broadcast findings", exc_info=True)

        # Publish FINDING_CREATED events
        try:
            from mass.core.events import get_event_bus, Event, EventType
            bus = get_event_bus()
            for finding in findings:
                await bus.publish(Event(
                    type=EventType.FINDING_CREATED,
                    data={
                        "scan_id": self._scan_id,
                        "finding_title": finding.title,
                        "severity": finding.severity.value,
                        "category": finding.category.value,
                    },
                    tenant_id=self._tenant_id,
                ))
        except Exception:
            logger.debug("Failed to publish FINDING_CREATED events", exc_info=True)

    @staticmethod
    def _handle_async_error(future: asyncio.Future) -> None:
        """Log errors from fire-and-forget async tasks."""
        try:
            future.result()
        except Exception:
            logger.warning("Async bridge task failed", exc_info=True)
