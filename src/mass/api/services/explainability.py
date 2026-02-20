"""Explainability service.

Generates human-readable explanations for findings, attack chains,
and remediation guidance.  Uses LLM with template fallback.
Cache-only state via Redis (Rule 1 compliant).
Per ARCHITECTURE.md Section 8.1 — Explainability module slot.
"""

import json
import logging
from datetime import datetime
from uuid import uuid4

from mass.api.utils.job_store import JobStore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis cache for generated explanations
# ---------------------------------------------------------------------------
_cache_store = JobStore("explain_cache", ttl=24 * 3600)  # 24h cache
_stats_store = JobStore("explain_stats", ttl=365 * 24 * 3600)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ---------------------------------------------------------------------------
# Compliance mapping (category → frameworks)
# ---------------------------------------------------------------------------
CATEGORY_COMPLIANCE: dict[str, list[dict]] = {
    "prompt_injection": [
        {"framework": "OWASP LLM", "control_id": "LLM01", "control_name": "Prompt Injection",
         "relevance": "Direct prompt injection allows attackers to manipulate LLM behavior"},
        {"framework": "MITRE ATLAS", "control_id": "AML.T0051", "control_name": "LLM Prompt Injection",
         "relevance": "Technique for manipulating LLM outputs via crafted inputs"},
    ],
    "sensitive_info": [
        {"framework": "OWASP LLM", "control_id": "LLM02", "control_name": "Sensitive Information Disclosure",
         "relevance": "LLM may reveal confidential data, PII, or system internals"},
        {"framework": "GDPR", "control_id": "Art.5(1)(f)", "control_name": "Integrity & Confidentiality",
         "relevance": "Personal data must be protected with appropriate security"},
    ],
    "supply_chain": [
        {"framework": "OWASP LLM", "control_id": "LLM03", "control_name": "Supply Chain Vulnerabilities",
         "relevance": "Vulnerable or malicious dependencies in the AI pipeline"},
    ],
    "data_model_poisoning": [
        {"framework": "OWASP LLM", "control_id": "LLM04", "control_name": "Data and Model Poisoning",
         "relevance": "Training data manipulation affects model integrity"},
        {"framework": "MITRE ATLAS", "control_id": "AML.T0020", "control_name": "Poison Training Data",
         "relevance": "Attacker manipulates training data to influence model behavior"},
    ],
    "improper_output": [
        {"framework": "OWASP LLM", "control_id": "LLM05", "control_name": "Improper Output Handling",
         "relevance": "Unvalidated LLM output may cause downstream vulnerabilities"},
    ],
    "excessive_agency": [
        {"framework": "OWASP LLM", "control_id": "LLM06", "control_name": "Excessive Agency",
         "relevance": "LLM granted overly broad permissions or tool access"},
    ],
    "system_prompt_leakage": [
        {"framework": "OWASP LLM", "control_id": "LLM07", "control_name": "System Prompt Leakage",
         "relevance": "System prompts exposed, revealing internal logic and secrets"},
    ],
    "vector_embedding": [
        {"framework": "OWASP LLM", "control_id": "LLM08", "control_name": "Vector and Embedding Weaknesses",
         "relevance": "Embedding manipulation enables data poisoning or retrieval bypass"},
    ],
    "misinformation": [
        {"framework": "OWASP LLM", "control_id": "LLM09", "control_name": "Misinformation",
         "relevance": "LLM generates factually incorrect or misleading content"},
    ],
    "unbounded_consumption": [
        {"framework": "OWASP LLM", "control_id": "LLM10", "control_name": "Unbounded Consumption",
         "relevance": "Resource exhaustion via excessive LLM API consumption"},
    ],
    "jailbreak": [
        {"framework": "OWASP LLM", "control_id": "LLM01", "control_name": "Prompt Injection",
         "relevance": "Jailbreak is a form of prompt injection bypassing safety guardrails"},
    ],
    "secrets_exposure": [
        {"framework": "CWE", "control_id": "CWE-798", "control_name": "Hard-coded Credentials",
         "relevance": "Secrets exposed in code, config, or model artifacts"},
    ],
}

# ---------------------------------------------------------------------------
# Attack chain templates
# ---------------------------------------------------------------------------
CHAIN_TEMPLATES: dict[str, dict] = {
    "rag_poisoning": {
        "name": "RAG Poisoning Chain",
        "severity": "high",
        "summary": "Attacker injects malicious content into the knowledge base to manipulate RAG responses.",
        "steps": [
            {"step_number": 1, "step_type": "injection", "description": "Attacker submits malicious document to knowledge base", "risk": "medium"},
            {"step_number": 2, "step_type": "persistence", "description": "Malicious content gets embedded and indexed", "risk": "medium"},
            {"step_number": 3, "step_type": "exploitation", "description": "User query retrieves poisoned chunks", "risk": "high"},
            {"step_number": 4, "step_type": "exfiltration", "description": "LLM generates response based on poisoned context", "risk": "high"},
        ],
    },
    "tool_chaining": {
        "name": "Tool Chaining Exploit",
        "severity": "critical",
        "summary": "Attacker chains multiple tool calls to achieve unauthorized access or data exfiltration.",
        "steps": [
            {"step_number": 1, "step_type": "injection", "description": "Crafted prompt triggers first tool call", "risk": "medium"},
            {"step_number": 2, "step_type": "lateral_movement", "description": "First tool output used to invoke second tool", "risk": "high"},
            {"step_number": 3, "step_type": "privilege_escalation", "description": "Chained tools escalate access beyond intended scope", "risk": "critical"},
            {"step_number": 4, "step_type": "exfiltration", "description": "Sensitive data extracted via tool output", "risk": "critical"},
        ],
    },
    "prompt_leak": {
        "name": "System Prompt Extraction",
        "severity": "medium",
        "summary": "Attacker extracts the system prompt, revealing internal logic and potential secrets.",
        "steps": [
            {"step_number": 1, "step_type": "injection", "description": "Crafted prompt requests system instruction disclosure", "risk": "low"},
            {"step_number": 2, "step_type": "exploitation", "description": "LLM reveals portions of system prompt", "risk": "medium"},
            {"step_number": 3, "step_type": "data_access", "description": "Attacker identifies internal tools, APIs, or secrets", "risk": "high"},
        ],
    },
    "data_exfiltration": {
        "name": "Data Exfiltration via Agent",
        "severity": "critical",
        "summary": "Attacker uses the AI agent to access and extract sensitive data through tool abuse.",
        "steps": [
            {"step_number": 1, "step_type": "injection", "description": "Indirect prompt injection via user-controlled data", "risk": "medium"},
            {"step_number": 2, "step_type": "exploitation", "description": "Agent follows injected instructions", "risk": "high"},
            {"step_number": 3, "step_type": "data_access", "description": "Agent queries sensitive data stores", "risk": "critical"},
            {"step_number": 4, "step_type": "exfiltration", "description": "Data sent to attacker via tool or output", "risk": "critical"},
        ],
    },
}

# Audience-specific templates
AUDIENCE_TEMPLATES: dict[str, dict] = {
    "developer": {
        "risk_prefix": "This vulnerability could allow an attacker to",
        "remediation_prefix": "To fix this, you should",
        "impact_prefix": "If exploited, this would",
    },
    "security_engineer": {
        "risk_prefix": "Attack vector:",
        "remediation_prefix": "Recommended mitigations:",
        "impact_prefix": "Threat assessment:",
    },
    "executive": {
        "risk_prefix": "Business risk:",
        "remediation_prefix": "Recommended action:",
        "impact_prefix": "Potential business impact:",
    },
    "compliance_officer": {
        "risk_prefix": "Regulatory risk:",
        "remediation_prefix": "Compliance requirement:",
        "impact_prefix": "Non-compliance impact:",
    },
}

# Category descriptions for template-based explanations
CATEGORY_DESCRIPTIONS: dict[str, dict] = {
    "prompt_injection": {
        "explanation": "The system is vulnerable to prompt injection, where an attacker crafts input that causes the LLM to deviate from its intended behavior. This can lead to unauthorized actions, data disclosure, or bypassing safety controls.",
        "risk": "execute arbitrary instructions through the LLM, potentially accessing internal tools, exposing sensitive data, or performing unauthorized actions.",
        "business_impact": "Unauthorized access to systems and data, potential data breach, loss of customer trust, and regulatory violations.",
    },
    "sensitive_info": {
        "explanation": "The system may disclose sensitive information such as PII, credentials, or internal system details in its responses. This occurs when the LLM fails to recognize and filter sensitive content.",
        "risk": "extract personally identifiable information, API keys, database credentials, or other confidential data from model responses.",
        "business_impact": "Data breach liability, GDPR/CCPA violations, identity theft risk, and reputational damage.",
    },
    "jailbreak": {
        "explanation": "The system's safety guardrails can be bypassed through carefully crafted prompts, allowing the model to generate content it was designed to refuse.",
        "risk": "bypass content filters and safety mechanisms to generate harmful, unethical, or policy-violating content.",
        "business_impact": "Brand reputation damage, liability for generated harmful content, and erosion of user trust.",
    },
    "system_prompt_leakage": {
        "explanation": "The system prompt — containing internal instructions, logic, and potentially sensitive configuration — can be extracted by users through targeted prompting.",
        "risk": "extract the full system prompt, revealing internal business logic, tool configurations, API endpoints, and potentially embedded credentials.",
        "business_impact": "Intellectual property exposure, security architecture disclosure, and increased attack surface from revealed internals.",
    },
    "excessive_agency": {
        "explanation": "The AI agent has been granted broader permissions or tool access than necessary for its intended function, creating opportunities for misuse.",
        "risk": "leverage over-privileged tools to access data, modify systems, or perform actions beyond the intended scope.",
        "business_impact": "Unauthorized system modifications, data integrity issues, and potential for cascading failures from misused tool access.",
    },
    "secrets_exposure": {
        "explanation": "Hard-coded secrets, API keys, or credentials have been found in the codebase, configuration files, or model artifacts.",
        "risk": "find and abuse exposed credentials to access external services, databases, or APIs with the application's privileges.",
        "business_impact": "Unauthorized access to cloud resources, financial exposure from API abuse, and potential for lateral movement in infrastructure.",
    },
    "supply_chain": {
        "explanation": "A dependency or model artifact in the AI supply chain has a known vulnerability, licensing concern, or suspicious provenance.",
        "risk": "exploit known vulnerabilities in dependencies, inject malicious code through compromised packages, or use tampered model files.",
        "business_impact": "Remote code execution risk, data theft, regulatory non-compliance from license violations, and infrastructure compromise.",
    },
    "data_leakage": {
        "explanation": "The system unintentionally exposes data through model outputs, logs, error messages, or tool interactions that should remain confidential.",
        "risk": "extract training data, user data, or system internals through carefully crafted queries or by observing model behavior patterns.",
        "business_impact": "Privacy violations, competitive intelligence loss, and regulatory penalties under data protection regulations.",
    },
}

# Effort mapping
SEVERITY_EFFORT: dict[str, str] = {
    "critical": "high",
    "high": "medium",
    "medium": "medium",
    "low": "low",
    "info": "low",
}


# ---------------------------------------------------------------------------
# Explain a single finding
# ---------------------------------------------------------------------------

async def explain_finding(
    finding: dict,
    audience: str = "developer",
    depth: str = "standard",
    include_attack_chain: bool = True,
    include_remediation: bool = True,
    include_compliance: bool = True,
) -> dict:
    """Generate explanation for a finding."""
    cache_key = f"{finding.get('id', '')}:{audience}:{depth}"
    cached = await _cache_store.load(cache_key)
    if cached:
        return cached

    category = finding.get("category", "")
    severity = finding.get("severity", "medium")
    cat_info = CATEGORY_DESCRIPTIONS.get(category, {})
    aud_tmpl = AUDIENCE_TEMPLATES.get(audience, AUDIENCE_TEMPLATES["developer"])

    # Try LLM explanation first
    llm_result = await _try_llm_explanation(finding, audience, depth)
    generated_by = "llm" if llm_result else "template"

    if llm_result:
        summary = llm_result.get("summary", "")
        explanation = llm_result.get("explanation", "")
        risk_description = llm_result.get("risk_description", "")
        business_impact = llm_result.get("business_impact", "")
        remediation_summary = llm_result.get("remediation_summary", "")
        remediation_steps = llm_result.get("remediation_steps", [])
        code_example = llm_result.get("code_example")
        attack_chain_narrative = llm_result.get("attack_chain_narrative", "")
    else:
        # Template-based explanation
        summary = f"{severity.upper()} severity {category.replace('_', ' ')} finding: {finding.get('title', '')}"
        explanation = cat_info.get("explanation", f"A {category.replace('_', ' ')} issue was detected.")
        risk_description = f"{aud_tmpl['risk_prefix']} {cat_info.get('risk', 'exploit this vulnerability.')}".strip()
        business_impact = f"{aud_tmpl['impact_prefix']} {cat_info.get('business_impact', 'potential security exposure.')}".strip()
        remediation_summary = finding.get("remediation", "Review and address the finding based on the category guidance.")
        remediation_steps = _get_remediation_steps(category, severity)
        code_example = None
        attack_chain_narrative = ""

    # Attack chain
    attack_chain: list[dict] = []
    if include_attack_chain:
        attack_chain = _get_attack_chain(category)
        if not attack_chain_narrative and attack_chain:
            attack_chain_narrative = _build_chain_narrative(attack_chain, category)

    # Compliance context
    compliance_context: list[dict] = []
    if include_compliance:
        compliance_context = CATEGORY_COMPLIANCE.get(category, [])

    result = {
        "finding_id": finding.get("id", ""),
        "title": finding.get("title", ""),
        "severity": severity,
        "category": category,
        "summary": summary,
        "explanation": explanation,
        "risk_description": risk_description,
        "business_impact": business_impact,
        "attack_chain": attack_chain,
        "attack_chain_narrative": attack_chain_narrative,
        "remediation_summary": remediation_summary,
        "remediation_steps": remediation_steps,
        "code_example": code_example,
        "estimated_effort": SEVERITY_EFFORT.get(severity, "medium"),
        "compliance_context": compliance_context,
        "similar_findings": [],
        "audience": audience,
        "depth": depth,
        "generated_by": generated_by,
    }

    await _cache_store.save(cache_key, result)
    await _increment_stats()
    return result


# ---------------------------------------------------------------------------
# Explain attack chains for a scan
# ---------------------------------------------------------------------------

async def explain_chains(
    scan_id: str,
    findings: list[dict],
    audience: str = "developer",
    max_chains: int = 5,
) -> dict:
    """Generate attack chain explanations from scan findings."""
    categories = set()
    for f in findings:
        cat = f.get("category", "")
        if cat:
            categories.add(cat)

    chains: list[dict] = []
    chain_idx = 0

    # Map findings to known chain patterns
    chain_mapping = {
        "prompt_injection": "tool_chaining",
        "excessive_agency": "tool_chaining",
        "system_prompt_leakage": "prompt_leak",
        "sensitive_info": "data_exfiltration",
        "data_leakage": "data_exfiltration",
        "vector_embedding": "rag_poisoning",
    }

    seen_chains: set[str] = set()
    for cat in categories:
        chain_key = chain_mapping.get(cat)
        if chain_key and chain_key not in seen_chains and chain_idx < max_chains:
            seen_chains.add(chain_key)
            template = CHAIN_TEMPLATES.get(chain_key, {})
            if template:
                chain_idx += 1
                related = [f.get("id", "") for f in findings if f.get("category") == cat]
                chains.append({
                    "chain_id": f"chain-{scan_id[:8]}-{chain_idx}",
                    "name": template["name"],
                    "severity": template["severity"],
                    "risk_score": _chain_risk_score(template["severity"]),
                    "summary": template["summary"],
                    "narrative": _build_chain_narrative(template.get("steps", []), chain_key),
                    "steps": template.get("steps", []),
                    "entry_point": template.get("steps", [{}])[0].get("description", "") if template.get("steps") else "",
                    "final_target": template.get("steps", [{}])[-1].get("description", "") if template.get("steps") else "",
                    "mitre_mapping": [],
                    "remediation_priority": [f"Address {cat.replace('_', ' ')} findings ({len(related)} found)"],
                })

    # Overall assessment
    severities = [c["severity"] for c in chains]
    overall = "critical" if "critical" in severities else "high" if "high" in severities else "medium" if chains else "low"

    recommendations: list[str] = []
    if chains:
        recommendations.append(f"Found {len(chains)} potential attack chain(s) — prioritize by risk score")
        for c in sorted(chains, key=lambda x: -x["risk_score"])[:3]:
            recommendations.append(f"Address '{c['name']}' ({c['severity']}): {c['remediation_priority'][0] if c['remediation_priority'] else ''}")

    return {
        "scan_id": scan_id,
        "chains_found": len(chains),
        "chains": chains,
        "overall_risk": overall,
        "recommendations": recommendations,
    }


# ---------------------------------------------------------------------------
# Explain scan results
# ---------------------------------------------------------------------------

async def explain_scan(
    scan_id: str,
    findings: list[dict],
    audience: str = "developer",
    depth: str = "standard",
    max_findings: int = 10,
) -> dict:
    """Generate full scan explanation."""
    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        cat = f.get("category", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        category_counts[cat] = category_counts.get(cat, 0) + 1

    # Sort findings by severity for top-N
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4),
    )
    top_findings = sorted_findings[:max_findings]

    # Explain each top finding
    explained: list[dict] = []
    for f in top_findings:
        exp = await explain_finding(f, audience, depth)
        explained.append(exp)

    # Chain analysis
    chain_result = await explain_chains(scan_id, findings, audience)

    # Executive summary
    total = len(findings)
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)

    if audience == "executive":
        exec_summary = (
            f"Security scan identified {total} finding(s). "
            f"{critical} critical and {high} high-severity issues require immediate attention. "
            f"Top risk areas: {', '.join(list(category_counts.keys())[:3])}."
        )
    else:
        exec_summary = (
            f"Scan completed with {total} findings: "
            f"{critical} critical, {high} high, "
            f"{severity_counts.get('medium', 0)} medium, "
            f"{severity_counts.get('low', 0)} low, "
            f"{severity_counts.get('info', 0)} info."
        )

    risk_overview = ""
    if critical > 0:
        risk_overview = "CRITICAL risk level — immediate remediation required for critical findings."
    elif high > 0:
        risk_overview = "HIGH risk level — high-severity findings should be addressed promptly."
    elif severity_counts.get("medium", 0) > 0:
        risk_overview = "MODERATE risk level — review and plan remediation for medium-severity findings."
    else:
        risk_overview = "LOW risk level — no high-priority findings detected."

    # Key recommendations
    key_recs: list[str] = []
    if critical:
        key_recs.append(f"Immediately address {critical} critical finding(s)")
    if high:
        key_recs.append(f"Plan remediation for {high} high-severity finding(s)")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1])[:3]:
        key_recs.append(f"Review {count} {cat.replace('_', ' ')} finding(s)")

    return {
        "scan_id": scan_id,
        "executive_summary": exec_summary,
        "risk_overview": risk_overview,
        "severity_breakdown": severity_counts,
        "category_breakdown": category_counts,
        "top_findings": explained,
        "attack_chains": chain_result.get("chains", []),
        "key_recommendations": key_recs,
        "compliance_summary": {},
        "audience": audience,
    }


# ---------------------------------------------------------------------------
# Remediation plan
# ---------------------------------------------------------------------------

async def generate_remediation_plan(
    scan_id: str,
    findings: list[dict],
    max_items: int = 20,
    group_by: str = "severity",
) -> dict:
    """Generate a prioritized remediation plan."""
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4),
    )

    # Group findings
    groups: dict[str, list[dict]] = {}
    for f in sorted_findings:
        key = f.get(group_by if group_by != "component" else "category", "other")
        groups.setdefault(key, []).append(f)

    items: list[dict] = []
    priority = 0
    quick_wins: list[str] = []

    for group_key, group_findings in groups.items():
        if priority >= max_items:
            break
        priority += 1

        top_severity = group_findings[0].get("severity", "medium")
        category = group_findings[0].get("category", "unknown")
        effort = SEVERITY_EFFORT.get(top_severity, "medium")

        steps = _get_remediation_steps(category, top_severity)

        item = {
            "priority": priority,
            "finding_ids": [f.get("id", "") for f in group_findings],
            "title": f"Remediate {category.replace('_', ' ')} findings ({len(group_findings)})",
            "description": f"{len(group_findings)} {top_severity}-severity {category.replace('_', ' ')} finding(s)",
            "category": category,
            "severity": top_severity,
            "effort": effort,
            "steps": steps,
            "code_example": None,
            "dependencies": [],
        }
        items.append(item)

        if effort == "low" and top_severity in ("critical", "high"):
            quick_wins.append(f"#{priority}: {item['title']} (low effort, {top_severity} impact)")

    total_effort = "high" if any(i["effort"] == "high" for i in items) else "medium" if items else "low"

    return {
        "scan_id": scan_id,
        "total_findings": len(findings),
        "items": items,
        "estimated_total_effort": total_effort,
        "quick_wins": quick_wins,
    }


# ---------------------------------------------------------------------------
# LLM explanation (with template fallback)
# ---------------------------------------------------------------------------

async def _try_llm_explanation(finding: dict, audience: str, depth: str) -> dict | None:
    """Try to generate LLM-powered explanation.  Returns None on failure."""
    try:
        from mass.api.utils.llm_config import resolve_llm_config, is_reasoning_model

        cfg = resolve_llm_config(activity="explainability")
        if not cfg.provider or cfg.provider == "none":
            return None

        import httpx
        prompt = _build_llm_prompt(finding, audience, depth)

        if cfg.provider == "ollama":
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{cfg.endpoint}/api/generate",
                    json={"model": cfg.model, "prompt": prompt, "stream": False},
                )
                if resp.status_code == 200:
                    text = resp.json().get("response", "")
                    return _parse_llm_response(text)

        elif cfg.provider in ("openai", "grok"):
            _reasoning = is_reasoning_model(cfg.model)
            messages = [{"role": "user", "content": prompt}]
            payload: dict = {"model": cfg.model, "messages": messages}
            if _reasoning:
                payload["max_completion_tokens"] = 16384
            else:
                payload["temperature"] = 0.3
                payload["max_tokens"] = 4096
            headers = {"Authorization": f"Bearer {cfg.api_key}"}
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{cfg.endpoint}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                    return _parse_llm_response(text)
                else:
                    logger.debug("OpenAI explainability call failed: %s %s", resp.status_code, resp.text[:200])

        elif cfg.provider == "anthropic":
            headers = {
                "x-api-key": cfg.api_key,
                "content-type": "application/json",
                "anthropic-version": "2023-06-01",
            }
            payload = {
                "model": cfg.model,
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}],
            }
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{cfg.endpoint}/v1/messages",
                    json=payload,
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    blocks = data.get("content", [])
                    text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
                    return _parse_llm_response(text)
                else:
                    logger.debug("Anthropic explainability call failed: %s %s", resp.status_code, resp.text[:200])

    except Exception as e:
        logger.debug("LLM explanation failed: %s", e)
    return None


def _build_llm_prompt(finding: dict, audience: str, depth: str) -> str:
    detail_level = {
        "brief": "Keep it to 2-3 sentences.",
        "standard": "Provide a clear explanation in 1-2 paragraphs.",
        "detailed": "Provide a comprehensive explanation with examples.",
    }
    return f"""You are an AI security expert. Explain this security finding for a {audience}.

Finding:
- Title: {finding.get('title', '')}
- Severity: {finding.get('severity', '')}
- Category: {finding.get('category', '')}
- Description: {finding.get('description', '')}
- Evidence: {finding.get('evidence', '')}
- Remediation: {finding.get('remediation', '')}

{detail_level.get(depth, '')}

Respond in JSON format:
{{
  "summary": "1-2 sentence summary",
  "explanation": "Full explanation",
  "risk_description": "What could go wrong",
  "business_impact": "Business impact",
  "remediation_summary": "How to fix",
  "remediation_steps": ["step 1", "step 2"],
  "code_example": "optional code fix or null",
  "attack_chain_narrative": "How an attacker would exploit this"
}}"""


def _parse_llm_response(text: str) -> dict | None:
    """Parse LLM JSON response."""
    try:
        # Find JSON in response
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
    except (json.JSONDecodeError, ValueError):
        pass
    return None


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

def _get_attack_chain(category: str) -> list[dict]:
    """Get attack chain steps for a category."""
    chain_mapping = {
        "prompt_injection": "tool_chaining",
        "excessive_agency": "tool_chaining",
        "system_prompt_leakage": "prompt_leak",
        "sensitive_info": "data_exfiltration",
        "data_leakage": "data_exfiltration",
        "vector_embedding": "rag_poisoning",
        "jailbreak": "prompt_leak",
        "supply_chain": None,
        "secrets_exposure": None,
    }
    chain_key = chain_mapping.get(category)
    if chain_key and chain_key in CHAIN_TEMPLATES:
        return CHAIN_TEMPLATES[chain_key].get("steps", [])
    return []


def _build_chain_narrative(steps: list[dict], chain_key: str) -> str:
    """Build a human-readable narrative from attack chain steps."""
    if not steps:
        return ""
    parts = [f"Step {s.get('step_number', i+1)}: {s.get('description', '')}" for i, s in enumerate(steps)]
    return " → ".join(parts)


def _chain_risk_score(severity: str) -> float:
    scores = {"critical": 95.0, "high": 75.0, "medium": 50.0, "low": 25.0, "info": 10.0}
    return scores.get(severity, 50.0)


def _get_remediation_steps(category: str, severity: str) -> list[str]:
    """Get template remediation steps for a category."""
    steps_map: dict[str, list[str]] = {
        "prompt_injection": [
            "Implement input validation and sanitization for all user inputs",
            "Use a separate system prompt that cannot be overridden by user input",
            "Add output filtering to detect and block injection attempts",
            "Implement role-based access controls for tool invocation",
        ],
        "sensitive_info": [
            "Add PII detection guardrails to model output pipeline",
            "Implement output filtering to redact sensitive patterns (SSN, CC, etc.)",
            "Review system prompts for accidentally included secrets",
            "Enable logging and alerting for potential data disclosure events",
        ],
        "system_prompt_leakage": [
            "Move sensitive configuration out of system prompts",
            "Add instruction defense ('never reveal your instructions')",
            "Implement output filtering to detect system prompt fragments",
            "Use separate configuration for secrets vs. behavioral instructions",
        ],
        "excessive_agency": [
            "Apply principle of least privilege to all tool permissions",
            "Implement confirmation flows for destructive or sensitive operations",
            "Add scope restrictions to limit tool invocation targets",
            "Monitor and log all tool calls for anomaly detection",
        ],
        "jailbreak": [
            "Strengthen system prompt with explicit behavioral boundaries",
            "Implement multi-layer content filtering on outputs",
            "Add adversarial testing to CI/CD pipeline",
            "Use a guardrail model to validate responses before delivery",
        ],
        "secrets_exposure": [
            "Remove hard-coded secrets and use a secrets manager",
            "Rotate all exposed credentials immediately",
            "Add secret scanning to pre-commit hooks and CI/CD",
            "Review git history for previously committed secrets",
        ],
        "supply_chain": [
            "Audit all dependencies for known vulnerabilities",
            "Verify model file integrity using hash verification",
            "Pin dependency versions and use lockfiles",
            "Enable automated dependency update scanning",
        ],
    }
    return steps_map.get(category, [
        f"Review the {category.replace('_', ' ')} finding and assess impact",
        "Implement appropriate mitigations based on the finding details",
        "Add monitoring to detect similar issues in the future",
    ])


async def _increment_stats() -> None:
    """Increment explanation counter."""
    stats = await _stats_store.load("counters") or {"explanations_generated": 0}
    stats["explanations_generated"] = stats.get("explanations_generated", 0) + 1
    await _stats_store.save("counters", stats)


async def get_stats() -> dict:
    """Get explainability stats."""
    stats = await _stats_store.load("counters") or {"explanations_generated": 0}
    cache_items = await _cache_store.list_jobs(limit=1)
    return {
        "explanations_generated": stats.get("explanations_generated", 0),
        "cache_size": len(cache_items) if cache_items else 0,
    }
