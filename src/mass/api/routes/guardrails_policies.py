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
- Focus on what a proxy/gateway operator would deploy to block the specific attacks that were found
- IMPORTANT: For each guardrail, also provide platform_configs with YAML configurations for deploying the guardrail in AWS Bedrock and LiteLLM proxy{risk_severity_instruction}

Respond with ONLY a valid JSON array. Each item must have:
- "id": unique string like "ai-grd-xxx" (use a descriptive suffix matching the finding)
- "name": specific name referencing what this counters (not generic like "Input Validation")
- "description": 2-3 sentences explaining what specific attack this blocks and why it matters for this deployment
- "guardrail_type": one of input_validation, output_filtering, rate_limiting, access_control, data_protection, model_protection, audit_logging, content_moderation, resource_limits
- "severity": one of critical, high, medium, low, advisory
- "implementation_steps": array of 3-6 actionable steps (not generic — reference the deployment)
- "code_examples": object mapping language (e.g. "python", "nginx", "yaml") to working code string
- "platform_configs": object mapping platform name to YAML config string. MUST include these two keys:
  - "aws_bedrock": A valid AWS CloudFormation YAML snippet for AWS::Bedrock::Guardrail. Always include the required top-level properties (Name, BlockedInputMessaging, BlockedOutputsMessaging) plus the relevant policy configs. Use ONLY these verified CloudFormation properties:
    * ContentPolicyConfig.FiltersConfig[] — Type: PROMPT_ATTACK|HATE|INSULTS|SEXUAL|VIOLENCE|MISCONDUCT; InputStrength/OutputStrength: NONE|LOW|MEDIUM|HIGH; optional InputAction/OutputAction: BLOCK|NONE; optional InputEnabled/OutputEnabled: boolean
    * TopicPolicyConfig.TopicsConfig[] — Name (string), Definition (string, 1-1000 chars), Examples (string array), Type: DENY; optional InputAction/OutputAction: BLOCK|NONE; optional InputEnabled/OutputEnabled: boolean
    * SensitiveInformationPolicyConfig.PiiEntitiesConfig[] — Type: ADDRESS|AGE|NAME|EMAIL|PHONE|USERNAME|PASSWORD|DRIVER_ID|LICENSE_PLATE|CREDIT_DEBIT_CARD_CVV|CREDIT_DEBIT_CARD_EXPIRY|CREDIT_DEBIT_CARD_NUMBER|PIN|IP_ADDRESS|MAC_ADDRESS|URL|AWS_ACCESS_KEY|AWS_SECRET_KEY|US_SOCIAL_SECURITY_NUMBER|US_BANK_ACCOUNT_NUMBER|US_PASSPORT_NUMBER (and other country-specific types); Action: BLOCK|ANONYMIZE|NONE; optional InputAction/OutputAction, InputEnabled/OutputEnabled
    * SensitiveInformationPolicyConfig.RegexesConfig[] — Name (string), Pattern (regex string), Description (string), Action: BLOCK|ANONYMIZE|NONE
    * WordPolicyConfig.WordsConfig[] — Text (string); optional InputAction/OutputAction: BLOCK|NONE
    * WordPolicyConfig.ManagedWordListsConfig[] — Type: PROFANITY; optional InputAction/OutputAction: BLOCK|NONE
    * ContextualGroundingPolicyConfig.FiltersConfig[] — Type: GROUNDING|RELEVANCE; Threshold: 0.0-1.0
    Example skeleton:
      Type: AWS::Bedrock::Guardrail
      Properties:
        Name: guardrail-name
        BlockedInputMessaging: "Request blocked."
        BlockedOutputsMessaging: "Response blocked."
        ContentPolicyConfig:
          FiltersConfig:
            - Type: PROMPT_ATTACK
              InputStrength: HIGH
              OutputStrength: HIGH
        TopicPolicyConfig:
          TopicsConfig:
            - Name: topic-name
              Definition: "Description of denied topic"
              Examples: ["example prompt"]
              Type: DENY
  - "litellm": A valid LiteLLM proxy config.yaml snippet showing the guardrails section with guardrail_name, litellm_params (guardrail type like bedrock/presidio/custom_guardrail, mode: pre_call/post_call/during_call, relevant params). For content filters use bedrock guardrail type with guardrailIdentifier placeholder. For PII use presidio with pii_entities_config. For custom logic use custom_guardrail with the module path.
- "mitigates": array of attack categories from the findings above
- "compliance": array of compliance IDs (e.g. "LLM01", "NIST-GV", "OWASP-LLM")
- "effort": low, medium, or high
- "effectiveness": low, medium, or high

Return ONLY the JSON array, no markdown fencing."""


_POLICY_PROMPT = """You are an AI governance and security policy advisor with deep expertise in AI regulatory frameworks. Based on actual scan findings from this AI deployment, draft organizational policies that address the specific risks discovered AND map to established AI governance frameworks.

TARGET DEPLOYMENT: {target_name}

SCAN FINDINGS (ordered by severity):
{findings_text}
{risk_context_section}
REFERENCE FRAMEWORKS (map every policy to at least 2 of these):
1. NIST AI RMF (AI 100-1) — Functions: GOVERN (GV), MAP (MP), MEASURE (MS), MANAGE (MG)
   Key controls: GV-1 (governance policies), GV-1.1 (legal/regulatory requirements), GV-1.2 (trustworthiness), GV-3 (workforce diversity), GV-4 (org practices), GV-6 (feedback), MP-2 (AI categorization), MP-3 (AI benefits/costs), MP-4 (risks & impacts), MP-5 (likelihood), MS-1 (risk metrics), MS-2 (AI system evaluation), MS-3 (risk tracking), MS-4 (output feedback), MG-1 (risk prioritization), MG-2 (risk response), MG-3 (risk management), MG-4 (risk treatment)
2. ISO/IEC 42001 — AI Management System clauses: 4.1 (org context), 5.1 (leadership), 6.1 (risk actions), 6.2 (objectives), 7.2 (competence), 7.4 (communication), 8.1 (operational planning), 8.2 (AI risk assessment), 8.3 (AI risk treatment), 8.4 (AI system lifecycle), 9.1 (monitoring), 9.2 (internal audit), 10.1 (nonconformity), 10.2 (continual improvement), A.2 (AI policies), A.3 (internal org), A.4 (resources), A.5 (AI system lifecycle), A.6 (data), A.7 (AI system)
3. EU AI Act — Risk tiers: Prohibited (Art.5), High-Risk (Art.6-7, Annex III), Limited (Art.52), Minimal. Key requirements: Art.9 (risk management), Art.10 (data governance), Art.11 (technical documentation), Art.13 (transparency), Art.14 (human oversight), Art.15 (accuracy/robustness/cybersecurity), Art.17 (quality management), Art.29 (user obligations)
4. OWASP LLM Top 10 (2025) — LLM01 (Prompt Injection), LLM02 (Sensitive Info Disclosure), LLM03 (Supply Chain), LLM04 (Data/Model Poisoning), LLM05 (Improper Output Handling), LLM06 (Excessive Agency), LLM07 (System Prompt Leakage), LLM08 (Vector/Embedding Weaknesses), LLM09 (Misinformation), LLM10 (Unbounded Consumption)
5. MITRE ATLAS — Tactics: Reconnaissance (AML.TA0002), Resource Development (AML.TA0001), ML Model Access (AML.TA0000), Execution (AML.TA0003), Persistence (AML.TA0004), Evasion (AML.TA0005), Impact (AML.TA0006). Key techniques: AML.T0043 (Craft Adversarial Data), AML.T0040 (ML Model Inference API Access), AML.T0024 (Exfiltration via ML Inference API), AML.T0047 (ML-Enabled Product Abuse), AML.T0048 (Prompt Injection)

INSTRUCTIONS:
- Generate 4-6 organizational policies tied to the SPECIFIC vulnerabilities found above
- Each policy should name the risk it addresses (e.g. "System Prompt Protection Policy" if prompt leakage was found)
- EVERY policy MUST include framework_mappings with specific control IDs from at least 2 of the 5 frameworks listed above — cite exact clause numbers, not just framework names
- Assign realistic owner groups based on who would actually enforce the policy
- Remediation actions should be concrete steps (not vague like "review and update")
- Assets covered should reference the actual deployment type (AI model, API endpoint, proxy, data pipeline, etc.)
- Set policy_category to reflect the primary area: governance, risk_management, compliance, technical_controls, incident_response, data_protection, model_lifecycle, or monitoring
- Set review_frequency based on risk: critical/high → quarterly, medium → semi_annual, low → annual
- Set implementation_priority: critical findings → immediate, high → short_term, medium → medium_term, low → long_term{risk_severity_instruction}

Respond with ONLY a valid JSON array. Each item must have:
- "name": policy name that references the specific risk (e.g. "Prompt Injection Response Policy for {target_name}")
- "owner_group": one of "Security", "Dev", "Legal", "HR", "IR" (Incident Response)
- "description": 2-3 sentence policy description referencing the specific findings AND citing relevant framework requirements
- "policy_category": one of "governance", "risk_management", "compliance", "technical_controls", "incident_response", "data_protection", "model_lifecycle", "monitoring"
- "assets_covered": array of assets/systems this applies to (be specific to this deployment)
- "violation_severity": one of "critical", "high", "medium", "low"
- "remediation_actions": array of 3-5 concrete remediation actions when violated
- "framework_mappings": object mapping framework keys to arrays of specific control IDs. Keys must be from: "nist_ai_rmf", "iso_42001", "eu_ai_act", "owasp_llm_top10", "mitre_atlas". Example: {{"nist_ai_rmf": ["GV-1.1", "MG-2"], "owasp_llm_top10": ["LLM01"], "eu_ai_act": ["Art.9", "Art.15"]}}
- "review_frequency": one of "quarterly", "semi_annual", "annual"
- "implementation_priority": one of "immediate", "short_term", "medium_term", "long_term"

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

    Reuses provider dispatchers from the chat route with model-aware
    parameter adjustment (temperature clamping, reasoning model handling).
    """
    from mass.api.routes.chat import _PROVIDERS
    from mass.api.utils.llm_config import (
        PROVIDER_DEFAULTS,
        is_reasoning_model,
        resolve_api_key,
        resolve_llm_config,
    )

    cfg = resolve_llm_config(provider=provider, model=model, api_key=api_key, endpoint=endpoint, activity="guardrails")
    resolved_model = cfg.model
    resolved_endpoint = cfg.endpoint
    resolved_key = cfg.api_key

    # OpenAI reasoning models (o-series, GPT-5) require "developer" role
    # instead of "system" — fold system instruction into the user prompt.
    system_instruction = "You are a JSON-only response AI. Return only valid JSON arrays."
    if provider in ("openai", "grok") and is_reasoning_model(resolved_model):
        messages: list[dict[str, str]] = [
            {"role": "user", "content": system_instruction + "\n\n" + prompt},
        ]
    else:
        messages = [
            {"role": "system", "content": system_instruction},
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

    content = result.get("content", "")
    logger.info(
        "LLM raw response (provider=%s, model=%s): length=%d, first_200=%.200s",
        provider, resolved_model, len(content), content[:200] if content else "(empty)",
    )
    return content, resolved_model


def _parse_json_array(text: str) -> list[dict[str, Any]]:
    """Best-effort parse a JSON array from LLM response text."""
    if not text or not text.strip():
        logger.warning("_parse_json_array: empty input")
        return []

    text = text.strip()

    import re

    # Strip reasoning/thinking tags (Qwen, DeepSeek, etc.)
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    text = re.sub(r"<reasoning>.*?</reasoning>", "", text, flags=re.DOTALL).strip()

    # Strip markdown code fencing (```json ... ``` or ``` ... ```)
    fenced = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()

    # Try direct parse first
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            # Some models wrap in {"guardrails": [...]} or similar
            for key in ("guardrails", "items", "data", "results"):
                if key in parsed and isinstance(parsed[key], list):
                    return parsed[key]
    except json.JSONDecodeError:
        pass

    # Try to find array within the text using bracket matching
    start = text.find("[")
    if start != -1:
        # Find matching closing bracket by counting nesting
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            c = text[i]
            if escape:
                escape = False
                continue
            if c == "\\":
                escape = True
                continue
            if c == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break

    # Last resort: try rfind approach
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            pass

    logger.warning("_parse_json_array: could not parse JSON from text (len=%d)", len(text))
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
            logger.info(
                "Generating AI guardrails: provider=%s, model=%s, findings=%d",
                request.provider,
                request.model or "(default)",
                len(request.findings),
            )
            response_text, model_used = await _call_llm(
                prompt,
                request.provider,
                request.model,
                request.api_key,
                request.endpoint,
            )
            logger.info(
                "AI guardrail LLM response length=%d, preview=%.200s",
                len(response_text),
                response_text[:200] if response_text else "(empty)",
            )
            if not response_text or not response_text.strip():
                logger.warning("AI guardrail LLM returned empty response")
            items = _parse_json_array(response_text)
            logger.info("Parsed %d guardrail items from LLM response", len(items))
            for item in items:
                try:
                    item["source"] = "ai_generated"
                    # Ensure required fields have defaults
                    item.setdefault("implementation_steps", [])
                    item.setdefault("code_examples", {})
                    item.setdefault("configuration_examples", {})
                    item.setdefault("platform_configs", {})
                    item.setdefault("mitigates", [])
                    item.setdefault("compliance", [])
                    item.setdefault("effort", "medium")
                    item.setdefault("effectiveness", "medium")
                    ai_guardrails.append(GuardrailItem(**item))
                except Exception as item_err:
                    logger.warning(
                        "Failed to validate guardrail item: %s — data: %s",
                        item_err,
                        str(item)[:200],
                    )
                    continue
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("AI guardrail generation failed: %s", e, exc_info=True)

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
                    item.setdefault("framework_mappings", {})
                    item.setdefault("policy_category", "governance")
                    item.setdefault("review_frequency", "quarterly")
                    item.setdefault("implementation_priority", "short_term")
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
