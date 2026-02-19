"""LLM-powered instruction file security review.

Sends instruction content (system prompts, rules files, CLAUDE.md, etc.)
to an LLM for semantic security analysis and structured recommendations.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from mass.analyzers.code.llm_analyzer import (
    _call_anthropic,
    _call_ollama,
    _call_openai,
    _parse_llm_response,
)
from mass.api.utils.llm_config import resolve_llm_config
from mass.analyzers.context.instruction import InstructionAnalyzer
from mass.storage.models.deployment import Deployment

logger = logging.getLogger(__name__)

# ── Review prompt ──────────────────────────────────────────────────

_REVIEW_PROMPT = """\
You are a senior AI security engineer reviewing an AI system's instruction file \
(system prompt, rules file, or context configuration). Analyze the following \
instruction content for security risks, missing controls, and provide hardening \
recommendations.

=== INSTRUCTION CONTENT ===
{content}
=== END CONTENT ===

Respond with a JSON object (no markdown, no explanation) containing:
{{
  "risk_level": "critical|high|medium|low",
  "executive_summary": "2-3 sentence overall assessment of instruction security posture",
  "issues": [
    {{
      "severity": "critical|high|medium|low",
      "title": "Short issue title",
      "description": "Detailed explanation of the security risk",
      "line_reference": "approximate line number or null",
      "category": "jailbreak_vulnerability|prompt_injection|data_exfiltration|privilege_escalation|missing_guardrail|unsafe_capability|information_disclosure|deceptive_behavior"
    }}
  ],
  "missing_controls": [
    "Description of each missing security control that should be present"
  ],
  "recommendations": [
    {{
      "priority": 1,
      "title": "Short recommendation title",
      "description": "Specific actionable steps to implement this recommendation",
      "effort": "low|medium|high"
    }}
  ],
  "completeness": {{
    "has_security_constraints": true,
    "has_output_formatting": true,
    "has_error_handling": true,
    "has_scope_limits": true,
    "has_data_handling_rules": true,
    "has_refusal_patterns": true,
    "score": 0.75
  }}
}}

Focus on:
- Jailbreak vulnerabilities (can the instructions be overridden?)
- Prompt injection vectors (do instructions guard against injected instructions?)
- Data exfiltration risks (could the model be tricked into leaking data?)
- Privilege escalation (are capabilities properly scoped?)
- Missing guardrails (what security constraints are absent?)
- Output safety (are there controls on what the model can produce?)
- Tool use safety (if tools are mentioned, are they properly constrained?)

Rate the overall risk_level based on the most severe issue found.
Only include items you find evidence for. If none found for a category, use an empty array.
Be thorough but avoid false positives — only flag genuine security concerns."""


# ── Content retrieval ──────────────────────────────────────────────

def get_instruction_content(deployment: Deployment, meta: dict[str, Any]) -> str | None:
    """Retrieve instruction content from a deployment.

    Priority: inline_content → system_prompt → read source_path file.
    """
    # 1. Inline content stored in meta
    content = meta.get("inline_content")
    if content:
        return content

    # 2. System prompt field
    content = meta.get("system_prompt")
    if content:
        return content

    # 3. Read from source_path if it points to a file
    source_path = deployment.source_path
    if source_path:
        p = Path(source_path)
        if p.is_file() and p.stat().st_size < 512_000:  # Max 512KB
            try:
                return p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                logger.warning("Failed to read instruction file: %s", source_path)

    return None


# ── Main review function ──────────────────────────────────────────

async def review_instruction_content(
    content: str,
    deployment: Deployment,
    provider: str = "ollama",
    model: str | None = None,
    api_key: str | None = None,
    db: AsyncSession | None = None,
) -> dict[str, Any]:
    """Run LLM-powered security review on instruction content.

    1. Sends content to the configured LLM for semantic analysis.
    2. Runs local InstructionAnalyzer for structural breakdown.
    3. Merges both results and persists to deployment metadata.

    Returns:
        Combined review result dict.
    """
    # Resolve provider config via shared resolver
    cfg = resolve_llm_config(provider, model, api_key)
    resolved_model = cfg.model
    endpoint = cfg.endpoint
    resolved_key = cfg.api_key

    # Truncate very long content to stay within context limits
    max_chars = 15_000
    truncated = len(content) > max_chars
    review_content = content[:max_chars] if truncated else content

    # ── LLM semantic review ──
    resolved_provider = cfg.provider
    llm_review: dict[str, Any] = {}
    try:
        prompt = _REVIEW_PROMPT.format(content=review_content)

        if resolved_provider == "ollama":
            raw = await _call_ollama(prompt, resolved_model, endpoint)
        elif resolved_provider in ("openai", "grok"):
            raw = await _call_openai(prompt, resolved_model, endpoint, resolved_key)
        elif resolved_provider == "anthropic":
            raw = await _call_anthropic(prompt, resolved_model, endpoint, resolved_key)
        else:
            raise ValueError(f"Unsupported provider: {resolved_provider}")

        parsed = _parse_llm_response(raw)
        if parsed:
            llm_review = parsed
        else:
            logger.warning("Failed to parse instruction review response: %s", raw[:200])
            llm_review = {"error": "Failed to parse LLM response"}

    except Exception as e:
        logger.exception("LLM instruction review failed: %s", e)
        llm_review = {"error": str(e)}

    # ── Structural analysis (local, no LLM) ──
    structural: dict[str, Any] = {}
    try:
        analyzer = InstructionAnalyzer()
        result = analyzer.analyze(content)
        structural = {
            "total_instructions": result.summary.get("total_instructions", 0),
            "by_type": result.summary.get("by_type", {}),
            "by_risk": result.summary.get("by_risk", {}),
            "risk_score": result.risk_score,
            "dangerous_count": len(result.dangerous_instructions),
            "high_risk_count": len(result.high_risk_instructions),
            "instructions": [
                {
                    "text": inst.text,
                    "type": inst.instruction_type.value,
                    "risk": inst.risk.value,
                    "line_number": inst.line_number,
                }
                for inst in result.instructions[:50]  # Cap at 50
            ],
        }
    except Exception as e:
        logger.warning("Structural instruction analysis failed: %s", e)
        structural = {"error": str(e)}

    # ── Merge results ──
    combined: dict[str, Any] = {
        "risk_level": llm_review.get("risk_level", "unknown"),
        "executive_summary": llm_review.get("executive_summary", ""),
        "issues": llm_review.get("issues", []),
        "missing_controls": llm_review.get("missing_controls", []),
        "recommendations": llm_review.get("recommendations", []),
        "completeness": llm_review.get("completeness", {}),
        "structural_analysis": structural,
        "model_used": resolved_model,
        "provider_used": provider,
        "content_length": len(content),
        "truncated": truncated,
    }

    # Preserve errors
    if "error" in llm_review:
        combined["llm_error"] = llm_review["error"]

    # ── Persist to metadata ──
    if db is not None:
        await _persist_review(deployment, combined, db)

    return combined


async def _persist_review(
    deployment: Deployment,
    review: dict[str, Any],
    db: AsyncSession,
) -> None:
    """Store instruction review results in deployment metadata."""
    try:
        meta: dict[str, Any] = {}
        if deployment.meta:
            meta = json.loads(deployment.meta)
    except (json.JSONDecodeError, TypeError):
        meta = {}

    meta["instruction_review"] = review
    deployment.meta = json.dumps(meta)
    await db.commit()

    logger.info(
        "Instruction review stored for deployment %s: risk=%s, %d issues, %d recommendations",
        deployment.id,
        review.get("risk_level", "unknown"),
        len(review.get("issues", [])),
        len(review.get("recommendations", [])),
    )
