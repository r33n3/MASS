"""Guardrails & Policies generation endpoint.

Matches scan findings to the built-in guardrail registry and optionally
generates additional guardrails and organizational policies via LLM.
Risk context from the deployment questionnaire adjusts severity ratings.
"""

import json
import logging
import os
from typing import Any

from fastapi import APIRouter, HTTPException, status

from mass.api.dependencies import CurrentTenantDep
from mass.api.schemas.guardrails_policies import (
    GenerateGuardrailsRequest,
    GenerateGuardrailsResponse,
    GuardrailItem,
    PolicyItem,
    RiskContextInput,
)
from mass.api.schemas.questionnaire import RiskQuestionnaire, compute_risk_factors
from mass.core.types import AttackCategory
from mass.policy.guardrails import get_default_guardrails

logger = logging.getLogger(__name__)

router = APIRouter()


# ---- Severity adjustment ----

_SEVERITY_LADDER = ["advisory", "low", "medium", "high", "critical"]


def _adjust_severity(severity: str, multiplier: float) -> str:
    """Bump severity up based on risk multiplier.

    >=2.5  → +2 steps
    >=1.8  → +1 step
    <1.8   → no change
    """
    sev = severity.lower()
    try:
        idx = _SEVERITY_LADDER.index(sev)
    except ValueError:
        idx = 2  # default to medium
    if multiplier >= 2.5:
        idx = min(idx + 2, 4)
    elif multiplier >= 1.8:
        idx = min(idx + 1, 4)
    return _SEVERITY_LADDER[idx]


def _compute_risk(
    risk_ctx: RiskContextInput | None,
) -> tuple[float | None, list[str] | None, str | None]:
    """Compute risk multiplier from risk context input.

    Returns (multiplier, factors, level) or (None, None, None) if no context.
    """
    if not risk_ctx:
        return None, None, None

    q = RiskQuestionnaire(
        is_public_facing=risk_ctx.is_public_facing,
        deployment_environment=risk_ctx.deployment_environment,
        user_count=risk_ctx.user_count,
        data_sensitivity=risk_ctx.data_sensitivity,
        handles_pii=risk_ctx.handles_pii,
        has_payment_data=risk_ctx.has_payment_data,
        compliance_frameworks=risk_ctx.compliance_frameworks,
    )
    multiplier, factors = compute_risk_factors(q)

    if multiplier >= 3.0:
        level = "critical"
    elif multiplier >= 2.0:
        level = "high"
    elif multiplier >= 1.5:
        level = "medium"
    else:
        level = "low"

    return multiplier, factors, level


def _apply_guardrail_adjustment(
    guardrails: list[GuardrailItem], multiplier: float
) -> list[GuardrailItem]:
    """Apply severity adjustment to a list of guardrail items."""
    for g in guardrails:
        original = g.severity
        adjusted = _adjust_severity(original, multiplier)
        if adjusted != original:
            g.original_severity = original
            g.severity = adjusted
            g.severity_adjusted = True
    return guardrails


def _apply_policy_adjustment(
    policies: list[PolicyItem], multiplier: float
) -> list[PolicyItem]:
    """Apply severity adjustment to a list of policy items."""
    for p in policies:
        original = p.violation_severity
        adjusted = _adjust_severity(original, multiplier)
        if adjusted != original:
            p.original_severity = original
            p.violation_severity = adjusted
            p.severity_adjusted = True
    return policies


# ---- Registry matching (no LLM) ----


def _match_registry_guardrails(categories: set[str]) -> list[GuardrailItem]:
    """Match finding categories to built-in guardrail registry."""
    registry = get_default_guardrails()
    matched: dict[str, GuardrailItem] = {}

    for cat_str in categories:
        try:
            category = AttackCategory(cat_str)
        except ValueError:
            continue
        for g in registry.get_for_category(category):
            if g.id not in matched:
                matched[g.id] = GuardrailItem(
                    id=g.id,
                    name=g.name,
                    description=g.description,
                    guardrail_type=g.guardrail_type.value,
                    severity=g.severity.value,
                    implementation_steps=g.implementation_steps,
                    code_examples=g.code_examples,
                    configuration_examples=g.configuration_examples,
                    mitigates=[c.value for c in g.mitigates_categories],
                    compliance=g.required_for_compliance,
                    effort=g.effort,
                    effectiveness=g.effectiveness,
                    source="registry",
                )

    return list(matched.values())


# ---- LLM prompt templates ----

_GUARDRAIL_PROMPT = """You are an AI security architect reviewing the scan results for a specific deployment. Your job is to generate guardrail recommendations that are SPECIFIC to the vulnerabilities found — not generic best practices.

TARGET DEPLOYMENT: {target_name}

SCAN FINDINGS (ordered by severity):
{findings_text}

REGISTRY GUARDRAILS ALREADY PROVIDED (do NOT repeat these — they cover generic proxy controls):
{existing_ids}
{risk_context_section}
INSTRUCTIONS:
- Generate 3-5 guardrails that are DIRECTLY tied to the specific findings above
- Reference the actual finding titles and categories in your descriptions
- For each guardrail, provide working code examples that address the specific attack patterns found
- If a finding mentions a specific technique (e.g. "roleplay extraction", "delimiter confusion"), the guardrail should counter THAT technique specifically
- Code examples should be production-ready Python (FastAPI middleware or standalone functions) and/or nginx/yaml configs
- Focus on what a proxy/gateway operator would deploy to block the specific attacks that were found{risk_severity_instruction}

Respond with ONLY a valid JSON array. Each item must have:
- "id": unique string like "ai-grd-xxx" (use a descriptive suffix matching the finding)
- "name": specific name referencing what this counters (not generic like "Input Validation")
- "description": 2-3 sentences explaining what specific attack this blocks and why it matters for this deployment
- "guardrail_type": one of input_validation, output_filtering, rate_limiting, access_control, data_protection, model_protection, audit_logging, content_moderation, resource_limits
- "severity": one of critical, high, medium, low, advisory
- "implementation_steps": array of 3-6 actionable steps (not generic — reference the deployment)
- "code_examples": object mapping language (e.g. "python", "nginx", "yaml") to working code string
- "mitigates": array of attack categories from the findings above
- "compliance": array of compliance IDs (e.g. "LLM01", "NIST-GV", "OWASP-LLM")
- "effort": low, medium, or high
- "effectiveness": low, medium, or high

Return ONLY the JSON array, no markdown fencing."""


_POLICY_PROMPT = """You are an organizational security policy advisor. Based on actual scan findings from this AI deployment, draft organizational policies that address the specific risks discovered.

TARGET DEPLOYMENT: {target_name}

SCAN FINDINGS (ordered by severity):
{findings_text}
{risk_context_section}
INSTRUCTIONS:
- Generate 4-6 organizational policies tied to the SPECIFIC vulnerabilities found above
- Each policy should name the risk it addresses (e.g. "System Prompt Protection Policy" if prompt leakage was found)
- Assign realistic owner groups based on who would actually enforce the policy
- Remediation actions should be concrete steps (not vague like "review and update")
- Assets covered should reference the actual deployment type (AI model, API endpoint, proxy, data pipeline, etc.){risk_severity_instruction}

Respond with ONLY a valid JSON array. Each item must have:
- "name": policy name that references the specific risk (e.g. "Prompt Injection Response Policy for {target_name}")
- "owner_group": one of "Security", "Dev", "Legal", "HR", "IR" (Incident Response)
- "description": 2-3 sentence policy description referencing the specific findings
- "assets_covered": array of assets/systems this applies to (be specific to this deployment)
- "violation_severity": one of "critical", "high", "medium", "low"
- "remediation_actions": array of 3-5 concrete remediation actions when violated

Return ONLY the JSON array, no markdown fencing."""


def _build_risk_context_prompt_section(
    multiplier: float | None, level: str | None, factors: list[str] | None
) -> tuple[str, str]:
    """Build the risk context section and severity instruction for LLM prompts.

    Returns (risk_context_section, risk_severity_instruction).
    """
    if not multiplier or not factors:
        return "", ""

    factors_text = "\n".join(f"- {f}" for f in factors)
    section = f"""
DEPLOYMENT RISK CONTEXT (multiplier: {multiplier}x, level: {level}):
{factors_text}
"""
    instruction = (
        f"\n- This is a {level}-risk deployment ({multiplier}x multiplier). "
        "Factor this risk profile into your severity assessments — "
        "lean toward higher severities for findings that intersect with "
        "the risk factors above"
    )
    return section, instruction


# ---- LLM helpers ----


async def _call_llm(
    prompt: str,
    provider: str,
    model: str | None,
    api_key: str | None,
    endpoint: str | None,
) -> tuple[str, str]:
    """Send a prompt to the LLM and return (response_text, model_used).

    Reuses provider dispatchers from the chat route.
    """
    from mass.api.routes.chat import _PROVIDER_DEFAULTS, _PROVIDERS

    defaults = _PROVIDER_DEFAULTS.get(provider, {})
    resolved_model = model or defaults.get("model", "")
    resolved_endpoint = (
        endpoint
        or os.getenv(defaults.get("endpoint_env", ""), "")
        or defaults.get("endpoint_fallback", "")
    )
    resolved_key = api_key or os.getenv(defaults.get("key_env", ""), "")

    messages: list[dict[str, str]] = [
        {"role": "system", "content": "You are a JSON-only response AI. Return only valid JSON arrays."},
        {"role": "user", "content": prompt},
    ]

    handler = _PROVIDERS.get(provider)
    if not handler:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {provider}",
        )

    if provider == "ollama":
        result = await handler(
            messages=messages,
            model=resolved_model,
            endpoint=resolved_endpoint,
            temperature=0.4,
        )
    else:
        if not resolved_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"API key required for {provider}",
            )
        result = await handler(
            messages=messages,
            model=resolved_model,
            endpoint=resolved_endpoint,
            api_key=resolved_key,
            temperature=0.4,
        )

    return result.get("content", ""), resolved_model


def _parse_json_array(text: str) -> list[dict[str, Any]]:
    """Best-effort parse a JSON array from LLM response text."""
    text = text.strip()

    # Strip markdown code fencing if present
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
    if text.endswith("```"):
        text = text.rsplit("```", 1)[0]
    text = text.strip()

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass

    # Try to find array within the text
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            pass

    return []


# ---- Endpoint ----


@router.post(
    "/generate",
    response_model=GenerateGuardrailsResponse,
    summary="Generate guardrails and policies from findings",
    description=(
        "Matches findings to the built-in guardrail registry and optionally "
        "generates additional guardrails and organizational policies via LLM. "
        "Risk context adjusts severity ratings when provided."
    ),
)
async def generate_guardrails_policies(
    request: GenerateGuardrailsRequest,
    tenant: CurrentTenantDep,
) -> GenerateGuardrailsResponse:
    """Generate guardrail and policy recommendations from scan findings."""

    # 0. Compute risk context if provided
    risk_multiplier, risk_factors, risk_level = _compute_risk(request.risk_context)
    risk_section, risk_instruction = _build_risk_context_prompt_section(
        risk_multiplier, risk_level, risk_factors
    )

    # 1. Always: match registry guardrails from finding categories
    categories = {f.category for f in request.findings}
    registry_guardrails = _match_registry_guardrails(categories)

    # Apply severity adjustment from risk context
    if risk_multiplier and risk_multiplier >= 1.8:
        _apply_guardrail_adjustment(registry_guardrails, risk_multiplier)

    # Build findings text for LLM prompts (limit to top 50 by severity)
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        request.findings,
        key=lambda f: severity_rank.get(f.severity.lower(), 5),
    )[:50]

    def _finding_line(f: "FindingSummaryItem") -> str:
        parts = [f"- [{f.severity.upper()}] {f.title} (category: {f.category})"]
        if f.cwe_ids:
            parts.append(f"  CWE: {', '.join(f.cwe_ids[:3])}")
        if f.owasp_ids:
            parts.append(f"  OWASP: {', '.join(f.owasp_ids[:3])}")
        if f.description:
            parts.append(f"  Detail: {f.description[:300]}")
        return "\n".join(parts)

    findings_text = "\n".join(_finding_line(f) for f in sorted_findings)
    existing_ids = ", ".join(g.id for g in registry_guardrails) or "none"

    ai_guardrails: list[GuardrailItem] = []
    policies: list[PolicyItem] = []
    model_used = ""

    # 2. Optional: generate AI guardrails
    if request.generate_ai_guardrails:
        prompt = _GUARDRAIL_PROMPT.format(
            target_name=request.target_name or "Unknown",
            findings_text=findings_text,
            existing_ids=existing_ids,
            risk_context_section=risk_section,
            risk_severity_instruction=risk_instruction,
        )
        try:
            response_text, model_used = await _call_llm(
                prompt,
                request.provider,
                request.model,
                request.api_key,
                request.endpoint,
            )
            items = _parse_json_array(response_text)
            for item in items:
                try:
                    item["source"] = "ai_generated"
                    ai_guardrails.append(GuardrailItem(**item))
                except Exception:
                    continue
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("AI guardrail generation failed: %s", e)

        # Apply severity adjustment to AI guardrails too
        if risk_multiplier and risk_multiplier >= 1.8:
            _apply_guardrail_adjustment(ai_guardrails, risk_multiplier)

    # 3. Optional: generate policies
    if request.generate_policies:
        prompt = _POLICY_PROMPT.format(
            target_name=request.target_name or "Unknown",
            findings_text=findings_text,
            risk_context_section=risk_section,
            risk_severity_instruction=risk_instruction,
        )
        try:
            response_text, model_used = await _call_llm(
                prompt,
                request.provider,
                request.model,
                request.api_key,
                request.endpoint,
            )
            items = _parse_json_array(response_text)
            finding_ids = [f.id for f in request.findings[:5]]
            for item in items:
                try:
                    item.setdefault("related_findings", finding_ids)
                    item["source"] = "ai_generated"
                    policies.append(PolicyItem(**item))
                except Exception:
                    continue
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("Policy generation failed: %s", e)

        # Apply severity adjustment to policies too
        if risk_multiplier and risk_multiplier >= 1.8:
            _apply_policy_adjustment(policies, risk_multiplier)

    return GenerateGuardrailsResponse(
        registry_guardrails=registry_guardrails,
        ai_guardrails=ai_guardrails,
        policies=policies,
        provider=request.provider,
        model_used=model_used,
        findings_analyzed=len(request.findings),
        risk_multiplier=risk_multiplier,
        risk_factors=risk_factors,
        risk_level=risk_level,
    )
