"""Phase B: LLM verification of security candidates.

Sends candidate vulnerabilities with surrounding code context to an LLM
for confirmation, false positive filtering, and exploit scenario generation.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable

from mass.core.types import Severity

from mass.analyzers.code_security.scanner import SecurityCandidate

logger = logging.getLogger(__name__)

# Batch size: candidates per LLM call
_BATCH_SIZE = 5

# LLM timeout
_TIMEOUT = 120.0

_VERIFICATION_PROMPT = """\
You are a senior application security engineer verifying potential vulnerabilities.

Application architecture:
{architecture_summary}

For each candidate below, determine if it is a real, exploitable vulnerability by \
tracing the data flow. Respond with JSON only — a JSON array of objects.

{candidate_sections}

Respond with ONLY a JSON array:
[{{"candidate_index": 0, "keep_finding": true, "confidence": 0.85, \
"severity": "high", \
"exploit_scenario": "How an attacker exploits this...", \
"data_flow_trace": "untrusted_input -> function_X -> sink_Y", \
"remediation": "Specific fix..."}}]

Rules:
- keep_finding=false for: test files, dead code, properly sanitized inputs, false positives
- confidence < 0.7 -> set keep_finding=false
- Trace the actual data flow: does untrusted input reach the sink?
- Be precise about severity: critical=RCE/auth bypass, high=data breach, medium=limited impact, low=minor
"""

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


@dataclass
class VerificationResult:
    """Result of LLM verification for a single candidate."""

    keep_finding: bool
    confidence: float
    severity_adjustment: Severity | None = None
    exploit_scenario: str = ""
    data_flow_trace: str = ""
    remediation: str = ""


class CodeSecurityVerifier:
    """Phase B: LLM-based verification of security candidates."""

    def __init__(
        self,
        provider: str = "ollama",
        model: str | None = None,
        endpoint: str | None = None,
        api_key: str | None = None,
        min_confidence: float = 0.7,
    ) -> None:
        self._provider = provider
        self._model = model
        self._endpoint = endpoint
        self._api_key = api_key
        self._min_confidence = min_confidence

    async def verify_candidates(
        self,
        candidates: list[SecurityCandidate],
        architecture_map: dict[str, Any] | None = None,
        progress_cb: Callable[[int, int], None] | None = None,
    ) -> list[tuple[SecurityCandidate, VerificationResult]]:
        """Verify a list of candidates with LLM.

        Args:
            candidates: Candidates to verify.
            architecture_map: Optional architecture context.
            progress_cb: Callback(verified_count, total_count).

        Returns:
            List of (candidate, verification_result) tuples.
        """
        if not candidates:
            return []

        arch_summary = self._summarize_architecture(architecture_map or {})

        results: list[tuple[SecurityCandidate, VerificationResult]] = []
        batches = [
            candidates[i:i + _BATCH_SIZE]
            for i in range(0, len(candidates), _BATCH_SIZE)
        ]

        verified = 0
        for batch in batches:
            try:
                batch_results = await self._verify_batch(batch, arch_summary)
                results.extend(batch_results)
            except Exception as e:
                logger.warning("LLM verification batch failed: %s", e)
                # On failure, keep candidates with reduced confidence
                for c in batch:
                    results.append((c, VerificationResult(
                        keep_finding=True,
                        confidence=0.4,
                        exploit_scenario="LLM verification failed; manual review recommended.",
                    )))

            verified += len(batch)
            if progress_cb:
                progress_cb(verified, len(candidates))

        return results

    async def _verify_batch(
        self,
        batch: list[SecurityCandidate],
        arch_summary: str,
    ) -> list[tuple[SecurityCandidate, VerificationResult]]:
        """Verify a batch of candidates with a single LLM call."""
        sections = []
        for i, c in enumerate(batch):
            ctx_before = "\n".join(c.context_before[-10:]) if c.context_before else ""
            ctx_after = "\n".join(c.context_after[:10]) if c.context_after else ""
            sections.append(
                f"--- Candidate {i} [{c.rule_id}] {c.description} ---\n"
                f"File: {c.file_path}:{c.line_number}\n"
                f"Category: {c.category.value}\n"
                f"Severity: {c.severity.value}\n"
                f"CWE: {', '.join(c.cwe_ids)}\n"
                f"Context:\n{ctx_before}\n>>> {c.matched_line}\n{ctx_after}"
            )

        prompt = _VERIFICATION_PROMPT.format(
            architecture_summary=arch_summary or "Not available",
            candidate_sections="\n\n".join(sections),
        )

        raw = await self._call_llm(prompt)
        parsed = _parse_llm_response(raw)

        results: list[tuple[SecurityCandidate, VerificationResult]] = []

        if parsed is None:
            logger.warning("Failed to parse LLM verification response")
            for c in batch:
                results.append((c, VerificationResult(
                    keep_finding=True,
                    confidence=0.4,
                    exploit_scenario="LLM response unparseable; manual review recommended.",
                )))
            return results

        # Parse array response
        items = parsed if isinstance(parsed, list) else [parsed]

        # Build index map
        item_map: dict[int, dict] = {}
        for item in items:
            if isinstance(item, dict):
                idx = item.get("candidate_index", -1)
                if isinstance(idx, int) and 0 <= idx < len(batch):
                    item_map[idx] = item

        for i, c in enumerate(batch):
            item = item_map.get(i)
            if item is None:
                results.append((c, VerificationResult(
                    keep_finding=True,
                    confidence=0.4,
                )))
                continue

            confidence = float(item.get("confidence", 0.5))
            keep = bool(item.get("keep_finding", True))

            if confidence < self._min_confidence:
                keep = False

            sev_str = str(item.get("severity", "")).lower()
            sev_adj = _SEVERITY_MAP.get(sev_str)

            results.append((c, VerificationResult(
                keep_finding=keep,
                confidence=confidence,
                severity_adjustment=sev_adj,
                exploit_scenario=str(item.get("exploit_scenario", "")),
                data_flow_trace=str(item.get("data_flow_trace", "")),
                remediation=str(item.get("remediation", "")),
            )))

        return results

    async def _call_llm(self, prompt: str) -> str:
        """Call LLM provider. Reuses patterns from llm_analyzer."""
        from mass.api.utils.llm_config import PROVIDER_DEFAULTS, resolve_llm_config

        config = resolve_llm_config(self._provider, self._model, self._endpoint, self._api_key)
        provider = config["provider"]
        model = config["model"]
        endpoint = config["endpoint"]
        api_key = config["api_key"]

        if provider == "ollama":
            from mass.analyzers.code.llm_analyzer import _call_ollama
            return await _call_ollama(prompt, model, endpoint)
        elif provider == "anthropic":
            from mass.analyzers.code.llm_analyzer import _call_anthropic
            return await _call_anthropic(prompt, model, endpoint, api_key)
        else:
            from mass.analyzers.code.llm_analyzer import _call_openai
            return await _call_openai(prompt, model, endpoint, api_key)

    @staticmethod
    def _summarize_architecture(arch: dict[str, Any]) -> str:
        """Create a concise architecture summary for the verification prompt."""
        parts = []

        entry_points = arch.get("entry_points", [])
        if entry_points:
            eps = [f"  - {ep.get('type', '?')}: {ep.get('location', '?')}" for ep in entry_points[:10]]
            parts.append("Entry points:\n" + "\n".join(eps))

        conns = arch.get("model_connections", [])
        if conns:
            mcs = [f"  - {mc.get('provider', '?')} at {mc.get('call_location', '?')}" for mc in conns[:5]]
            parts.append("Model connections:\n" + "\n".join(mcs))

        tools = arch.get("tool_definitions", [])
        if tools:
            tds = [f"  - {t.get('name', '?')} [{', '.join(t.get('capabilities', []))}]" for t in tools[:5]]
            parts.append("Tools:\n" + "\n".join(tds))

        pattern = arch.get("pattern")
        if pattern:
            parts.append(f"Architecture pattern: {pattern}")

        return "\n\n".join(parts) if parts else "No architecture information available."


def _parse_llm_response(raw: str) -> list[dict[str, Any]] | None:
    """Parse LLM response as JSON array, using multiple strategies."""
    if not raw or not raw.strip():
        return None

    text = raw.strip()

    # Strategy 1: Direct JSON parse
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return [result]
    except json.JSONDecodeError:
        pass

    # Strategy 2: Extract from markdown code block
    match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group(1))
            if isinstance(result, list):
                return result
            if isinstance(result, dict):
                return [result]
        except json.JSONDecodeError:
            pass

    # Strategy 3: Find JSON array in text (first [ to last ])
    bracket_start = text.find("[")
    bracket_end = text.rfind("]")
    if bracket_start >= 0 and bracket_end > bracket_start:
        try:
            result = json.loads(text[bracket_start:bracket_end + 1])
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    # Strategy 4: Find JSON object
    brace_start = text.find("{")
    brace_end = text.rfind("}")
    if brace_start >= 0 and brace_end > brace_start:
        try:
            result = json.loads(text[brace_start:brace_end + 1])
            if isinstance(result, dict):
                return [result]
        except json.JSONDecodeError:
            pass

    return None
