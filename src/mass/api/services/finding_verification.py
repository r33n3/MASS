"""LLM-powered finding verification.

Reads the current source code at a finding's file/line location and asks
an LLM to determine whether the vulnerability has been fixed, is still
present, or cannot be determined.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from mass.analyzers.code.llm_analyzer import (
    PROVIDER_DEFAULTS,
    _call_anthropic,
    _call_ollama,
    _call_openai,
    _parse_llm_response,
)
from mass.storage.models.finding import Finding as DBFinding

logger = logging.getLogger(__name__)

# Lines of context around the finding location
_VERIFY_CONTEXT = 15


async def _detect_ollama_model(endpoint: str) -> str | None:
    """Auto-detect first available Ollama model from the instance."""
    import httpx

    try:
        url = f"{endpoint.rstrip('/')}/api/tags"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            models = resp.json().get("models", [])
            if not models:
                return None
            # Return the first model name
            return models[0].get("name") or models[0].get("model")
    except Exception:
        return None


def _resolve_file_path(file_path: str) -> str | None:
    """Try to resolve a file path, checking common container mount points."""
    if os.path.isfile(file_path):
        return file_path

    # Common container mount prefixes where targets live
    prefixes = ["/app/targets", "/app", "/targets"]

    # If path is relative, try prepending common prefixes
    if not os.path.isabs(file_path):
        for prefix in prefixes:
            candidate = os.path.join(prefix, file_path)
            if os.path.isfile(candidate):
                return candidate

    # If path is absolute but doesn't exist, try stripping known prefixes
    # and re-resolving (e.g. path stored as /home/user/project/file.py
    # but mounted at /app/targets/project/file.py)
    basename = os.path.basename(file_path)
    dirparts = file_path.replace("\\", "/").split("/")
    for i in range(len(dirparts)):
        tail = "/".join(dirparts[i:])
        for prefix in prefixes:
            candidate = os.path.join(prefix, tail)
            if os.path.isfile(candidate):
                return candidate

    return None


def _read_current_code(
    file_path: str, line_number: int | None, context: int = _VERIFY_CONTEXT,
) -> str | None:
    """Read current source code around a finding's location.

    Enhanced version of progress_bridge._extract_code_snippet with more
    context for verification analysis.
    """
    if not file_path or not line_number:
        return None
    resolved = _resolve_file_path(file_path)
    if not resolved:
        return None
    file_path = resolved
    if os.path.getsize(file_path) > 5 * 1024 * 1024:
        return None
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        if not all_lines:
            return None
        idx = min(line_number - 1, len(all_lines) - 1)
        start = max(0, idx - context)
        end = min(len(all_lines), idx + context + 1)
        numbered = []
        for i in range(start, end):
            marker = ">>>" if i == idx else "   "
            numbered.append(f"{marker} {i + 1:4d} | {all_lines[i].rstrip()}")
        return "\n".join(numbered)
    except Exception:
        return None


_VERIFICATION_PROMPT = """\
You are a senior security engineer performing verification of a security finding.
Determine whether the vulnerability has been FIXED in the current code, is STILL PRESENT,
or if the determination is INCONCLUSIVE.

=== ORIGINAL FINDING ===
Title: {title}
Severity: {severity}
Category: {category}
Description:
{description}

File: {file_path}:{line_number}

Original Code Snippet (from scan time):
```
{original_code}
```

=== CURRENT CODE (live from file system) ===
File: {file_path}
```
{current_code}
```

Respond with a JSON object (no markdown, no explanation) containing:
{{
  "verdict": "still_present" or "fixed" or "inconclusive",
  "confidence": 0.0 to 1.0,
  "explanation": "Detailed explanation of why you reached this verdict",
  "evidence": "Specific code lines or patterns that support your conclusion",
  "recommendation": "What to do next"
}}

Rules:
- "fixed": The specific vulnerability described is no longer present in the current code.
- "still_present": The vulnerability is clearly still present.
- "inconclusive": The file changed significantly, relevant code moved/refactored, \
or there is not enough context to determine fix status.
- Be conservative: only say "fixed" if you are confident the specific issue is resolved.
- Assess confidence honestly (0.5 = uncertain, 0.8+ = high confidence)."""


async def verify_finding(
    finding: DBFinding,
    provider: str = "ollama",
    model: str | None = None,
    api_key: str | None = None,
    endpoint: str | None = None,
) -> dict[str, Any]:
    """Verify a single finding against the current source code.

    Returns a dict with: verdict, confidence, explanation, evidence,
    recommendation, current_code, error, llm_prompt, llm_response.
    """
    # Resolve provider config
    defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["ollama"])
    resolved_model = model or defaults.get("model", "")
    resolved_endpoint = endpoint or (
        os.getenv(defaults.get("endpoint_env", ""), "")
        or defaults.get("endpoint_fallback", "")
    )
    resolved_key = api_key or os.getenv(defaults.get("key_env", ""), "") or None

    # For Ollama: auto-detect first available model if none specified
    if provider == "ollama" and not model:
        detected = await _detect_ollama_model(resolved_endpoint)
        if detected:
            resolved_model = detected

    # Extract file/line with meta fallback
    meta_data: dict[str, Any] = {}
    if finding.meta:
        try:
            meta_data = json.loads(finding.meta)
        except (json.JSONDecodeError, TypeError):
            pass

    file_path = finding.file_path or meta_data.get("file")
    line_number = finding.line_number
    if line_number is None:
        line_number = meta_data.get("line")

    # Read current source code
    current_code = _read_current_code(file_path, line_number) if file_path else None

    if not current_code:
        reason = "No file path on finding" if not file_path else f"Source file not found: {file_path}"
        return {
            "verdict": "inconclusive",
            "confidence": 0.0,
            "explanation": f"Cannot verify — {reason}. The file may have been deleted, moved, or the finding has no source location.",
            "evidence": "",
            "recommendation": "Run a full rescan to check if this issue persists.",
            "current_code": None,
            "provider": provider,
            "model": resolved_model,
            "llm_prompt": None,
            "llm_response": None,
        }

    original_code = finding.code_snippet or "(no original snippet captured)"

    prompt = _VERIFICATION_PROMPT.format(
        title=finding.title or "",
        severity=finding.severity or "",
        category=finding.category or "",
        description=finding.description or "",
        file_path=file_path,
        line_number=line_number or "?",
        original_code=original_code,
        current_code=current_code,
    )

    try:
        if provider == "ollama":
            raw = await _call_ollama(prompt, resolved_model, resolved_endpoint)
        elif provider in ("openai", "grok"):
            raw = await _call_openai(prompt, resolved_model, resolved_endpoint, resolved_key)
        elif provider == "anthropic":
            raw = await _call_anthropic(prompt, resolved_model, resolved_endpoint, resolved_key)
        else:
            return {
                "verdict": "inconclusive",
                "confidence": 0.0,
                "explanation": f"Unsupported provider: {provider}",
                "evidence": "",
                "recommendation": "",
                "current_code": current_code,
                "provider": provider,
                "model": resolved_model,
                "error": f"Unsupported provider: {provider}",
                "llm_prompt": prompt,
                "llm_response": None,
            }

        parsed = _parse_llm_response(raw)
        if not parsed:
            logger.warning("Failed to parse verification response: %s", raw[:300])
            return {
                "verdict": "inconclusive",
                "confidence": 0.0,
                "explanation": "LLM returned an unparseable response.",
                "evidence": raw[:500] if raw else "",
                "recommendation": "Try again with a different model.",
                "current_code": current_code,
                "provider": provider,
                "model": resolved_model,
                "error": "Failed to parse LLM response",
                "llm_prompt": prompt,
                "llm_response": raw,
            }

        # Normalize verdict
        verdict = parsed.get("verdict", "inconclusive").lower().strip()
        if verdict not in ("still_present", "fixed", "inconclusive"):
            verdict = "inconclusive"

        return {
            "verdict": verdict,
            "confidence": min(1.0, max(0.0, float(parsed.get("confidence", 0.5)))),
            "explanation": parsed.get("explanation", ""),
            "evidence": parsed.get("evidence", ""),
            "recommendation": parsed.get("recommendation", ""),
            "current_code": current_code,
            "provider": provider,
            "model": resolved_model,
            "llm_prompt": prompt,
            "llm_response": raw,
        }

    except Exception as e:
        logger.exception("LLM verification failed for finding %s: %s", finding.id, e)
        return {
            "verdict": "inconclusive",
            "confidence": 0.0,
            "explanation": f"LLM call failed: {e}",
            "evidence": "",
            "recommendation": "Check provider connectivity and try again.",
            "current_code": current_code,
            "provider": provider,
            "model": resolved_model,
            "error": str(e),
            "llm_prompt": prompt,
            "llm_response": None,
        }


async def verify_findings_batch(
    findings: list[DBFinding],
    provider: str = "ollama",
    model: str | None = None,
    api_key: str | None = None,
    endpoint: str | None = None,
) -> list[dict[str, Any]]:
    """Verify multiple findings sequentially.

    Returns a list of verification results in the same order as input.
    """
    results: list[dict[str, Any]] = []
    for finding in findings:
        result = await verify_finding(finding, provider, model, api_key, endpoint)
        result["finding_id"] = finding.id
        result["finding_title"] = finding.title or ""
        results.append(result)
    return results


def build_verification_meta(result: dict[str, Any]) -> dict[str, Any]:
    """Build the metadata dict to store in finding.meta under 'last_verification'."""
    return {
        "verdict": result.get("verdict", "inconclusive"),
        "confidence": result.get("confidence", 0.0),
        "explanation": result.get("explanation", ""),
        "evidence": result.get("evidence", ""),
        "recommendation": result.get("recommendation", ""),
        "provider": result.get("provider", ""),
        "model": result.get("model", ""),
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }
