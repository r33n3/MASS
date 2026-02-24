"""Code security audit orchestrator.

Ties Phase A (static scan) -> Phase B (LLM verification) -> Finding conversion.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from mass.core.findings import Evidence, Finding, Remediation
from mass.core.fingerprint import compute_fingerprint
from mass.core.types import AttackCategory, ComponentType, Severity

from mass.analyzers.code_security.patterns import CATEGORY_MAPPING, SecurityCategory
from mass.analyzers.code_security.scanner import CodeSecurityScanner, SecurityCandidate
from mass.analyzers.code_security.verifier import CodeSecurityVerifier, VerificationResult

logger = logging.getLogger(__name__)


@dataclass
class AuditConfig:
    """Configuration for the code security audit."""

    llm_verification: bool = True
    llm_severity_threshold: Severity = Severity.MEDIUM
    max_candidates_for_llm: int = 50
    min_confidence: float = 0.7
    provider: str = "ollama"
    model: str | None = None
    api_key: str | None = None
    endpoint: str | None = None


@dataclass
class AuditResult:
    """Result of a code security audit."""

    candidates_found: int = 0
    candidates_verified: int = 0
    findings_confirmed: int = 0
    findings_static_only: int = 0
    findings: list[Finding] = field(default_factory=list)
    duration_phase_a: float = 0.0
    duration_phase_b: float = 0.0
    errors: list[str] = field(default_factory=list)


# Severity ranking for threshold comparison
_SEV_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class CodeSecurityAuditor:
    """Orchestrates the two-phase code security audit."""

    async def audit(
        self,
        directory: Path | str,
        architecture_map: dict[str, Any] | None = None,
        config: AuditConfig | None = None,
        progress_cb: Callable[[str, int, int], None] | None = None,
    ) -> AuditResult:
        """Run the full code security audit.

        Args:
            directory: Root directory to scan.
            architecture_map: Architecture map from LLM code analysis.
            config: Audit configuration.
            progress_cb: Callback(phase, current, total).

        Returns:
            AuditResult with findings and metrics.
        """
        cfg = config or AuditConfig()
        directory = Path(directory)
        result = AuditResult()

        # Phase A: Static scanning
        t0 = time.monotonic()
        try:
            scanner = CodeSecurityScanner(
                architecture_map=architecture_map,
            )
            candidates = scanner.scan_directory(directory)
            result.candidates_found = len(candidates)

            if progress_cb:
                progress_cb("static_scan", len(candidates), len(candidates))

        except Exception as e:
            logger.error("Phase A (static scan) failed: %s", e)
            result.errors.append(f"Static scan error: {e}")
            result.duration_phase_a = time.monotonic() - t0
            return result

        result.duration_phase_a = time.monotonic() - t0
        logger.info(
            "Phase A complete: %d candidates in %.1fs",
            len(candidates), result.duration_phase_a,
        )

        if not candidates:
            return result

        # Split candidates: those needing LLM verification vs static-only
        llm_candidates: list[SecurityCandidate] = []
        static_candidates: list[SecurityCandidate] = []

        threshold_val = _SEV_ORDER.get(cfg.llm_severity_threshold, 2)

        for c in candidates:
            sev_val = _SEV_ORDER.get(c.severity, 0)
            if (
                cfg.llm_verification
                and c.requires_llm_verification
                and sev_val >= threshold_val
            ):
                llm_candidates.append(c)
            else:
                static_candidates.append(c)

        # Cap LLM candidates
        if len(llm_candidates) > cfg.max_candidates_for_llm:
            # Sort by severity descending, keep top N
            llm_candidates.sort(
                key=lambda c: _SEV_ORDER.get(c.severity, 0), reverse=True
            )
            overflow = llm_candidates[cfg.max_candidates_for_llm:]
            llm_candidates = llm_candidates[:cfg.max_candidates_for_llm]
            static_candidates.extend(overflow)

        # Convert static-only candidates to findings
        for c in static_candidates:
            confidence = 0.5 if not c.requires_llm_verification else 0.4
            finding = self._candidate_to_finding(c, confidence=confidence)
            result.findings.append(finding)
            result.findings_static_only += 1

        # Phase B: LLM verification
        if llm_candidates:
            t1 = time.monotonic()
            try:
                verifier = CodeSecurityVerifier(
                    provider=cfg.provider,
                    model=cfg.model,
                    endpoint=cfg.endpoint,
                    api_key=cfg.api_key,
                    min_confidence=cfg.min_confidence,
                )

                def _progress(current: int, total: int) -> None:
                    if progress_cb:
                        progress_cb("llm_verify", current, total)

                verified = await verifier.verify_candidates(
                    llm_candidates,
                    architecture_map=architecture_map,
                    progress_cb=_progress,
                )
                result.candidates_verified = len(verified)

                for candidate, vresult in verified:
                    if vresult.keep_finding:
                        severity = vresult.severity_adjustment or candidate.severity
                        finding = self._candidate_to_finding(
                            candidate,
                            confidence=vresult.confidence,
                            severity_override=severity,
                            exploit_scenario=vresult.exploit_scenario,
                            data_flow_trace=vresult.data_flow_trace,
                            remediation_text=vresult.remediation,
                            detection_method="llm_verified",
                        )
                        result.findings.append(finding)
                        result.findings_confirmed += 1

            except Exception as e:
                logger.error("Phase B (LLM verification) failed: %s", e)
                result.errors.append(f"LLM verification error: {e}")
                # Fall back: add unverified candidates as static findings
                for c in llm_candidates:
                    finding = self._candidate_to_finding(c, confidence=0.4)
                    result.findings.append(finding)
                    result.findings_static_only += 1

            result.duration_phase_b = time.monotonic() - t1
            logger.info(
                "Phase B complete: %d verified, %d confirmed in %.1fs",
                result.candidates_verified, result.findings_confirmed,
                result.duration_phase_b,
            )

        return result

    @staticmethod
    def _candidate_to_finding(
        candidate: SecurityCandidate,
        confidence: float = 0.5,
        severity_override: Severity | None = None,
        exploit_scenario: str = "",
        data_flow_trace: str = "",
        remediation_text: str = "",
        detection_method: str = "static",
    ) -> Finding:
        """Convert a SecurityCandidate to a core Finding."""
        severity = severity_override or candidate.severity
        category = CATEGORY_MAPPING.get(
            candidate.category, AttackCategory.SENSITIVE_INFO
        )

        # Build evidence
        context_lines = (
            candidate.context_before[-5:]
            + [f">>> {candidate.matched_line}"]
            + candidate.context_after[:5]
        )
        evidence_content = "\n".join(context_lines)

        evidence = [
            Evidence(
                type="code",
                content=evidence_content,
                source_file=candidate.file_path,
                source_line=candidate.line_number,
                metadata={
                    "rule_id": candidate.rule_id,
                    "pattern_name": candidate.pattern_name,
                },
            )
        ]

        # Build remediation
        rem_text = remediation_text or candidate.remediation_hint
        remediation = Remediation(
            summary=rem_text,
            steps=[rem_text] if rem_text else [],
            references=[
                f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"
                for cwe in candidate.cwe_ids
                if "-" in cwe
            ],
        )

        # Build title
        title = f"{candidate.category.value}: {candidate.description}"

        # Metadata
        metadata: dict[str, Any] = {
            "detection_method": detection_method,
            "rule_id": candidate.rule_id,
            "pattern_name": candidate.pattern_name,
        }
        if exploit_scenario:
            metadata["exploit_scenario"] = exploit_scenario
        if data_flow_trace:
            metadata["data_flow_trace"] = data_flow_trace
        if candidate.file_role:
            metadata["file_role"] = candidate.file_role

        fingerprint = compute_fingerprint(
            category=category.value,
            title=title,
            file_path=candidate.file_path,
            rule_id=candidate.rule_id,
        )

        return Finding(
            id=fingerprint[:36],  # Use first 36 chars as deterministic UUID-like ID
            title=title,
            description=(
                f"{candidate.description}\n\n"
                f"File: {candidate.file_path}:{candidate.line_number}\n"
                f"Rule: {candidate.rule_id} ({candidate.pattern_name})"
            ),
            severity=severity,
            category=category,
            component_type=ComponentType.CODE,
            component_name=candidate.file_path,
            file_path=candidate.file_path,
            line_number=candidate.line_number,
            evidence=evidence,
            remediation=remediation,
            cwe_ids=candidate.cwe_ids,
            owasp_ids=candidate.owasp_ids,
            confidence=confidence,
            tags=["code_security", detection_method],
            metadata=metadata,
        )
