"""Chat endpoints.

Provides a conversational AI assistant for the dashboard.
Routes chat messages to configurable LLM providers:
Ollama (default), OpenAI, Anthropic, Gemini, Grok.

Supports tool calling: the assistant can search, inspect findings,
start scans, and query stats through MASS tools. Tool calling is
enabled by default for providers that support it.

The chat maintains conversation context via client-supplied history
and adds a MASS-specific system prompt for security expertise.
"""

import json
import logging
import os
import time
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from mass.api.dependencies import CurrentTenantDep, DBSession
from mass.api.services.chat_context import gather_chat_context
from mass.api.services.docs_loader import get_docs_for_chat

logger = logging.getLogger(__name__)

router = APIRouter()

# Default system prompt for the MASS security assistant
MASS_SYSTEM_PROMPT = (
    "You are MASS (Model & Application Security Suite), an expert AI security assistant "
    "built into a comprehensive AI deployment security platform.\n\n"
    "PLATFORM CAPABILITIES:\n"
    "- Discovery: Scans directories and GitHub repos to inventory AI components "
    "(models, MCP servers, agent frameworks, infrastructure configs)\n"
    "- Static Analysis: 8 concurrent analyzers covering secrets detection, prompt injection patterns, "
    "MCP server config risks, workflow/agent architecture, model file supply chain, "
    "infrastructure (Docker/K8s/Terraform), attack surface mapping, and context/persona analysis\n"
    "- Dynamic Interrogation: 25+ adversarial probes (jailbreak, injection, leakage, harmful output) "
    "against live model endpoints via OpenAI, Ollama, Anthropic, Bedrock, HuggingFace runners\n"
    "- MCP Server Testing: Active interrogation of MCP tool servers with command injection, "
    "path traversal, SSRF, SQLi, and prompt injection payloads\n"
    "- Compliance Mapping: OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, EU AI Act\n"
    "- Remediation: Code examples, guardrail templates, and cloud-specific guidance per finding\n"
    "- Reporting: SARIF, HTML, JSON, PDF export\n"
    "- Scan Profiles: quick (secrets + basic), standard (full static), comprehensive (static + dynamic)\n\n"
    "FINDING SEVERITIES: critical, high, medium, low, info\n"
    "FINDING STATUSES: open, confirmed, false_positive, accepted, fixed\n\n"
    "You have access to tools that let you query the MASS database directly. "
    "Use them to look up specific targets, scans, findings, and statistics "
    "when answering questions. Prefer tools over guessing.\n\n"
    "You also have a lookup_model tool that searches HuggingFace for AI model information. "
    "Use it when users ask about a model found in their project, mention a model name or "
    "GGUF filename, or need to understand model capabilities and architecture. It handles "
    "GGUF filenames (like 'model-Q4_K_M.gguf'), Ollama tags (like 'qwen3:8b'), and "
    "HuggingFace IDs (like 'Qwen/Qwen2.5-VL-7B-Instruct'). It also cross-references "
    "the model against scanned project architectures to show where it is used.\n\n"
    "You also have a read_file tool that finds and reads files from scanned project directories. "
    "Use it when users ask about a specific file (e.g. 'what does config.py do?'), want to see "
    "file contents, or reference a filename from the project. It searches across all scanned "
    "target directories and returns the file content. You can optionally specify a target_name "
    "to narrow the search to a specific project.\n\n"
    "When answering, be concise, technical, and actionable. Reference specific severity levels, "
    "categories, and compliance frameworks. Provide remediation guidance when discussing findings. "
    "If real-time environment context is provided below, cite specific numbers, names, and statuses."
)


# ---- Schemas ----

class ChatMessage(BaseModel):
    """A single chat message."""

    model_config = ConfigDict(extra="forbid")

    role: str = Field(description="Message role: user, assistant, system, or tool")
    content: str = Field(description="Message content")


class ChatRequest(BaseModel):
    """Request to send a chat message."""

    model_config = ConfigDict(extra="forbid")

    message: str = Field(..., min_length=1, description="The user message")
    history: list[ChatMessage] = Field(
        default_factory=list,
        description="Previous conversation messages for context",
    )
    provider: str = Field(
        default="ollama",
        description="LLM provider: ollama, openai, anthropic, gemini, grok",
    )
    model: str | None = Field(
        default=None,
        description="Model name (e.g., llama3.2:1b, gpt-4o, claude-sonnet-4-6). Defaults per provider.",
    )
    endpoint: str | None = Field(
        default=None,
        description="Custom API endpoint URL. Uses env defaults if not set.",
    )
    api_key: str | None = Field(
        default=None,
        description="Provider API key. Uses env defaults if not set.",
    )
    system_prompt: str | None = Field(
        default=None,
        description="Custom system prompt. Uses MASS default if not set.",
    )
    temperature: float = Field(
        default=0.7,
        ge=0.0,
        le=2.0,
        description="Sampling temperature. Clamped per provider (Anthropic: 0-1). Ignored for reasoning models (o-series, GPT-5).",
    )
    max_tokens: int | None = Field(
        default=None,
        ge=1,
        le=65536,
        description="Max tokens in response. Default varies by provider (Ollama/OpenAI: 4096, Anthropic/Gemini: 8192). For reasoning models, maps to max_completion_tokens.",
    )
    enable_tools: bool = Field(
        default=True,
        description="Enable tool calling (search, findings, scans, stats). Requires model support.",
    )
    file_context: str | None = Field(
        default=None,
        description="Optional file path and content to include as context for the conversation.",
    )


class ChatResponse(BaseModel):
    """Response from the chat endpoint."""

    model_config = ConfigDict(extra="forbid")

    response: str = Field(description="The assistant's reply")
    provider: str = Field(description="Provider that generated the response")
    model: str = Field(description="Model that generated the response")
    latency_ms: float = Field(default=0.0, description="Response latency in ms")
    tokens_used: int = Field(default=0, description="Approximate tokens used")
    tools_used: list[str] = Field(
        default_factory=list,
        description="Names of tools called during this response",
    )


class ChatProvidersResponse(BaseModel):
    """Available chat providers and their configuration."""

    model_config = ConfigDict(extra="forbid")

    providers: list[dict[str, Any]] = Field(description="Available providers")


# ---- Provider defaults (shared) ----
# Canonical defaults live in mass.api.utils.llm_config.PROVIDER_DEFAULTS.
# Chat overrides the Ollama endpoint to use the attacker host.

from mass.api.utils.llm_config import (
    PROVIDER_DEFAULTS,
    adjust_params_for_model,
    is_reasoning_model,
    resolve_api_key,
    resolve_llm_config,
)

# Chat Ollama resolution order:
# 1. OLLAMA_CHAT_HOST (dedicated chat instance — recommended when using --profile chat-ollama)
# 2. OLLAMA_ATTACKER_HOST (shared with interrogation attacker — default)
# 3. Fallback to ollama-attacker:11434
_CHAT_OLLAMA_ENDPOINT_ENV = "OLLAMA_CHAT_HOST"
_CHAT_OLLAMA_ENDPOINT_ENV_FALLBACK = "OLLAMA_ATTACKER_HOST"
_CHAT_OLLAMA_ENDPOINT_FALLBACK = "http://ollama-attacker:11434"


# ---- Provider dispatchers (text-only, original) ----

async def _chat_ollama(
    messages: list[dict[str, str]],
    model: str,
    endpoint: str,
    temperature: float,
    **kwargs: Any,
) -> dict[str, Any]:
    """Send chat to Ollama."""
    url = f"{endpoint.rstrip('/')}/api/chat"
    options: dict[str, Any] = {"temperature": temperature}
    # Ollama uses num_predict for max output tokens
    max_tok = kwargs.get("max_tokens")
    if max_tok:
        options["num_predict"] = max_tok
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": options,
    }

    async with httpx.AsyncClient(timeout=300.0) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()

    content = data.get("message", {}).get("content", "")
    tokens = data.get("prompt_eval_count", 0) + data.get("eval_count", 0)

    return {"content": content, "tokens": tokens}


async def _chat_openai_compatible(
    messages: list[dict[str, str]],
    model: str,
    endpoint: str,
    api_key: str,
    temperature: float,
    **kwargs: Any,
) -> dict[str, Any]:
    """Send chat via OpenAI-compatible API (OpenAI, Grok, etc.)."""
    url = f"{endpoint.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    # Model-aware parameter adjustment (reasoning models need different params)
    params = adjust_params_for_model("openai", model, temperature, kwargs.get("max_tokens"))

    # Reasoning models (o-series, GPT-5) require "developer" role instead of "system"
    api_messages = messages
    if params.get("is_reasoning"):
        api_messages = []
        for msg in messages:
            if msg["role"] == "system":
                api_messages.append({"role": "developer", "content": msg["content"]})
            else:
                api_messages.append(msg)

    payload: dict[str, Any] = {
        "model": model,
        "messages": api_messages,
    }
    if not params.get("skip_temperature"):
        payload["temperature"] = params.get("temperature", temperature)
    # Use correct max_tokens key for the model
    payload[str(params["max_tokens_key"])] = params["max_tokens_value"]

    import logging as _logging
    _chat_logger = _logging.getLogger(__name__)

    _timeout = 300.0 if is_reasoning_model(model) else 120.0
    async with httpx.AsyncClient(timeout=_timeout) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    # Log raw response keys for debugging reasoning model responses
    _chat_logger.debug("OpenAI raw response keys: %s", list(data.keys()))

    # GPT-5 / o-series reasoning models may use "output" instead of "choices"
    content = ""
    tokens = 0

    if "choices" in data:
        choice = data["choices"][0] if data["choices"] else {}
        content = choice.get("message", {}).get("content", "")
        tokens = data.get("usage", {}).get("total_tokens", 0)
    elif "output" in data:
        # New OpenAI Responses API format (GPT-5, o-series)
        for item in data.get("output", []):
            if item.get("type") == "message":
                for part in item.get("content", []):
                    if part.get("type") == "output_text":
                        content += part.get("text", "")
                    elif part.get("type") == "text":
                        content += part.get("text", "")
        tokens = data.get("usage", {}).get("total_tokens", 0)

    if not content:
        # Last resort: log the full response structure for debugging
        _chat_logger.warning(
            "OpenAI returned empty content for model=%s. Response keys=%s, full=%s",
            model, list(data.keys()), str(data)[:1000],
        )

    return {"content": content, "tokens": tokens}


async def _chat_anthropic(
    messages: list[dict[str, str]],
    model: str,
    endpoint: str,
    api_key: str,
    temperature: float,
    **kwargs: Any,
) -> dict[str, Any]:
    """Send chat via Anthropic Messages API."""
    url = f"{endpoint.rstrip('/')}/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }

    # Anthropic requires system prompt separately
    system_text = ""
    api_messages = []
    for msg in messages:
        if msg["role"] == "system":
            system_text += msg["content"] + "\n"
        else:
            api_messages.append({"role": msg["role"], "content": msg["content"]})

    # Model-aware parameter adjustment (Anthropic: temp clamped to 0-1, higher max_tokens)
    params = adjust_params_for_model("anthropic", model, temperature, kwargs.get("max_tokens"))
    payload: dict[str, Any] = {
        "model": model,
        "messages": api_messages,
        "max_tokens": params["max_tokens_value"],
        "temperature": params.get("temperature", min(temperature, 1.0)),
    }
    if system_text.strip():
        payload["system"] = system_text.strip()

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    content_blocks = data.get("content", [])
    content = "".join(b.get("text", "") for b in content_blocks if b.get("type") == "text")
    usage = data.get("usage", {})
    tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

    return {"content": content, "tokens": tokens}


async def _chat_gemini(
    messages: list[dict[str, str]],
    model: str,
    endpoint: str,
    api_key: str,
    temperature: float,
    **kwargs: Any,
) -> dict[str, Any]:
    """Send chat via Google Gemini API."""
    url = f"{endpoint.rstrip('/')}/models/{model}:generateContent?key={api_key}"

    # Convert messages to Gemini format
    system_text = ""
    contents = []
    for msg in messages:
        if msg["role"] == "system":
            system_text += msg["content"] + "\n"
        else:
            role = "user" if msg["role"] == "user" else "model"
            contents.append({"role": role, "parts": [{"text": msg["content"]}]})

    gen_config: dict[str, Any] = {"temperature": temperature}
    max_tok = kwargs.get("max_tokens")
    if max_tok:
        gen_config["maxOutputTokens"] = max_tok
    payload: dict[str, Any] = {
        "contents": contents,
        "generationConfig": gen_config,
    }
    if system_text.strip():
        payload["systemInstruction"] = {"parts": [{"text": system_text.strip()}]}

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()

    candidates = data.get("candidates", [])
    content = ""
    if candidates:
        parts = candidates[0].get("content", {}).get("parts", [])
        content = "".join(p.get("text", "") for p in parts)

    usage = data.get("usageMetadata", {})
    tokens = usage.get("totalTokenCount", 0)

    return {"content": content, "tokens": tokens}


# Provider dispatch table (text-only, no tools)
_PROVIDERS = {
    "ollama": _chat_ollama,
    "openai": _chat_openai_compatible,
    "anthropic": _chat_anthropic,
    "gemini": _chat_gemini,
    "grok": _chat_openai_compatible,  # Grok uses OpenAI-compatible API
}


# ---- Raw-response dispatchers (for tool calling loop) ----

async def _raw_ollama(
    messages: list[dict[str, Any]],
    model: str,
    endpoint: str,
    temperature: float,
    tools: list[dict[str, Any]],
) -> dict[str, Any]:
    """Send chat to Ollama and return raw response (for tool calling)."""
    url = f"{endpoint.rstrip('/')}/api/chat"
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature},
    }
    if tools:
        payload["tools"] = tools

    async with httpx.AsyncClient(timeout=300.0) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()


async def _raw_openai(
    messages: list[dict[str, Any]],
    model: str,
    endpoint: str,
    api_key: str,
    temperature: float,
    tools: list[dict[str, Any]],
    max_tokens: int | None = None,
) -> dict[str, Any]:
    """Send chat via OpenAI-compatible API and return raw response."""
    url = f"{endpoint.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    # Model-aware parameter adjustment for reasoning models
    params = adjust_params_for_model("openai", model, temperature, max_tokens)

    # Reasoning models require "developer" role instead of "system"
    api_messages = messages
    if params.get("is_reasoning"):
        api_messages = []
        for msg in messages:
            if msg.get("role") == "system":
                api_messages.append({**msg, "role": "developer"})
            else:
                api_messages.append(msg)

    payload: dict[str, Any] = {
        "model": model,
        "messages": api_messages,
    }
    if not params.get("skip_temperature"):
        payload["temperature"] = params.get("temperature", temperature)
    payload[str(params["max_tokens_key"])] = params["max_tokens_value"]
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"

    _timeout = 300.0 if is_reasoning_model(model) else 120.0
    async with httpx.AsyncClient(timeout=_timeout) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()


async def _raw_anthropic(
    messages: list[dict[str, Any]],
    model: str,
    endpoint: str,
    api_key: str,
    temperature: float,
    tools: list[dict[str, Any]],
    max_tokens: int | None = None,
) -> dict[str, Any]:
    """Send chat via Anthropic Messages API and return raw response."""
    url = f"{endpoint.rstrip('/')}/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }

    # Separate system prompt from messages
    system_text = ""
    api_messages: list[dict[str, Any]] = []
    for msg in messages:
        if msg.get("role") == "system":
            content = msg.get("content", "")
            if isinstance(content, str):
                system_text += content + "\n"
        else:
            api_messages.append(msg)

    # Model-aware parameter adjustment
    params = adjust_params_for_model("anthropic", model, temperature, max_tokens)
    payload: dict[str, Any] = {
        "model": model,
        "messages": api_messages,
        "max_tokens": params["max_tokens_value"],
        "temperature": params.get("temperature", min(temperature, 1.0)),
    }
    if system_text.strip():
        payload["system"] = system_text.strip()
    if tools:
        payload["tools"] = tools

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()


async def _raw_gemini(
    messages: list[dict[str, Any]],
    model: str,
    endpoint: str,
    api_key: str,
    temperature: float,
    tools: list[dict[str, Any]],
) -> dict[str, Any]:
    """Send chat via Gemini API and return raw response."""
    url = f"{endpoint.rstrip('/')}/models/{model}:generateContent?key={api_key}"

    system_text = ""
    contents: list[dict[str, Any]] = []
    for msg in messages:
        if msg.get("role") == "system":
            content = msg.get("content", "")
            if isinstance(content, str):
                system_text += content + "\n"
        elif msg.get("role") == "user":
            parts = msg.get("parts", [{"text": msg.get("content", "")}])
            contents.append({"role": "user", "parts": parts})
        elif msg.get("role") in ("assistant", "model"):
            parts = msg.get("parts", [{"text": msg.get("content", "")}])
            contents.append({"role": "model", "parts": parts})

    payload: dict[str, Any] = {
        "contents": contents,
        "generationConfig": {"temperature": temperature},
    }
    if system_text.strip():
        payload["systemInstruction"] = {"parts": [{"text": system_text.strip()}]}
    if tools:
        payload["tools"] = tools

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()


async def _call_provider_raw(
    provider: str,
    messages: list[dict[str, Any]],
    model: str,
    endpoint: str,
    api_key: str,
    temperature: float,
    tools: list[dict[str, Any]],
    max_tokens: int | None = None,
) -> dict[str, Any]:
    """Dispatch a raw (tool-enabled) chat call to the right provider."""
    if provider == "ollama":
        return await _raw_ollama(messages, model, endpoint, temperature, tools)
    elif provider in ("openai", "grok"):
        return await _raw_openai(messages, model, endpoint, api_key, temperature, tools, max_tokens=max_tokens)
    elif provider == "anthropic":
        return await _raw_anthropic(messages, model, endpoint, api_key, temperature, tools, max_tokens=max_tokens)
    elif provider == "gemini":
        return await _raw_gemini(messages, model, endpoint, api_key, temperature, tools)
    else:
        raise ValueError(f"No raw dispatcher for provider: {provider}")


# ---- Endpoints ----

@router.post(
    "",
    response_model=ChatResponse,
    summary="Send a chat message",
    description=(
        "Sends a message to the configured LLM provider and returns the response. "
        "Supports Ollama (default), OpenAI, Anthropic, Gemini, and Grok. "
        "When tools are enabled, the assistant can search, inspect findings, "
        "start scans, and query stats. "
        "Conversation history is maintained client-side and passed with each request."
    ),
)
async def chat(
    request: ChatRequest,
    tenant: CurrentTenantDep,
    db: DBSession,
) -> ChatResponse:
    """Process a chat message through the configured LLM provider."""
    provider = request.provider.lower()

    if provider not in _PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {provider}. "
                   f"Supported: {', '.join(_PROVIDERS.keys())}",
        )

    # Resolve configuration via platform defaults
    # Chat Ollama priority: OLLAMA_CHAT_HOST > OLLAMA_ATTACKER_HOST > fallback
    chat_endpoint = request.endpoint
    if not chat_endpoint and provider == "ollama":
        chat_endpoint = (
            os.getenv(_CHAT_OLLAMA_ENDPOINT_ENV, "")
            or os.getenv(_CHAT_OLLAMA_ENDPOINT_ENV_FALLBACK, "")
            or _CHAT_OLLAMA_ENDPOINT_FALLBACK
        )

    cfg = resolve_llm_config(
        provider=provider,
        model=request.model,
        api_key=request.api_key,
        endpoint=chat_endpoint,
        activity="chat",
    )
    provider, model, api_key, endpoint = cfg
    system_prompt = request.system_prompt or MASS_SYSTEM_PROMPT

    # Validate API key for providers that need one
    if provider != "ollama" and not api_key:
        defaults = PROVIDER_DEFAULTS.get(provider, {})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"API key required for provider '{provider}'. "
                   f"Set via request body, {defaults.get('key_env', 'env var')} env var, "
                   f"or MASS_{defaults.get('key_env', '')} in .env.",
        )

    # Gather database context (deployments, scans, findings)
    try:
        db_context = await gather_chat_context(db, tenant.tenant_id, request.message)
    except Exception as exc:
        logger.warning("Failed to gather DB context: %s", exc)
        db_context = ""

    # Gather documentation context
    try:
        docs_context = get_docs_for_chat(request.message)
    except Exception as exc:
        logger.warning("Failed to gather docs context: %s", exc)
        docs_context = ""

    # Gather file context if provided
    file_ctx = ""
    if request.file_context:
        file_ctx = (
            "\n\n--- FILE CONTEXT (user is asking about this file) ---\n"
            + request.file_context
            + "\n--- END FILE CONTEXT ---\n"
        )

    # Combine system prompt with gathered context
    full_system_prompt = system_prompt + db_context + docs_context + file_ctx

    # Build messages list
    messages: list[dict[str, Any]] = [{"role": "system", "content": full_system_prompt}]
    for msg in request.history:
        messages.append({"role": msg.role, "content": msg.content})
    messages.append({"role": "user", "content": request.message})

    # Ensure Ollama model is ready if using Ollama provider
    if provider == "ollama":
        try:
            from mass.api.services.ollama_manager import ensure_model_ready

            ok, setup_msg, resolved = await ensure_model_ready(endpoint, model)
            if not ok:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Ollama model setup failed: {setup_msg}",
                )
            if resolved and resolved != model:
                model = resolved
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("Ollama model readiness check failed: %s", e)

    start = time.time()

    try:
        # ---- Tool calling path ----
        if request.enable_tools:
            response_text, tokens, tools_used = await _chat_with_tools(
                provider=provider,
                messages=messages,
                model=model,
                endpoint=endpoint,
                api_key=api_key,
                temperature=request.temperature,
                db=db,
                tenant_id=tenant.tenant_id,
                max_tokens=request.max_tokens,
            )
        else:
            # ---- Original text-only path ----
            handler = _PROVIDERS[provider]
            if provider == "ollama":
                result = await handler(
                    messages=messages,
                    model=model,
                    endpoint=endpoint,
                    temperature=request.temperature,
                    max_tokens=request.max_tokens,
                )
            else:
                result = await handler(
                    messages=messages,
                    model=model,
                    endpoint=endpoint,
                    api_key=api_key,
                    temperature=request.temperature,
                    max_tokens=request.max_tokens,
                )
            response_text = result.get("content", "")
            tokens = result.get("tokens", 0)
            tools_used = []

    except httpx.ConnectError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Cannot connect to {provider} at {endpoint}. Is the service running?",
        )
    except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout):
        is_reasoning = is_reasoning_model(model)
        hint = " Reasoning models (GPT-5, o-series) may need extra time to think." if is_reasoning else ""
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Request to {provider} ({model}) timed out.{hint} Try again.",
        )
    except httpx.HTTPStatusError as e:
        detail = e.response.text[:500] if e.response else str(e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"{provider} returned error {e.response.status_code}: {detail}",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Chat error with provider %s", provider)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Chat error: {str(e)}",
        )

    latency_ms = (time.time() - start) * 1000

    return ChatResponse(
        response=response_text,
        provider=provider,
        model=model,
        latency_ms=round(latency_ms, 1),
        tokens_used=tokens,
        tools_used=tools_used,
    )


async def _chat_with_tools(
    provider: str,
    messages: list[dict[str, Any]],
    model: str,
    endpoint: str,
    api_key: str,
    temperature: float,
    db: Any,
    tenant_id: str,
    max_tokens: int | None = None,
) -> tuple[str, int, list[str]]:
    """Run the tool calling loop.

    Returns (response_text, total_tokens, tools_used_names).
    """
    from mass.api.services.tool_executor import ToolExecutor
    from mass.api.services.tool_formats import (
        extract_text_content,
        extract_token_count,
        extract_tool_calls,
        format_assistant_message,
        format_tool_result_messages,
        tools_for_provider,
    )

    # Get tool definitions for this provider
    tool_defs = tools_for_provider(provider)
    if not tool_defs:
        # Provider doesn't support tools — fall back to text-only
        handler = _PROVIDERS[provider]
        if provider == "ollama":
            result = await handler(messages=messages, model=model,
                                   endpoint=endpoint, temperature=temperature,
                                   max_tokens=max_tokens)
        else:
            result = await handler(messages=messages, model=model,
                                   endpoint=endpoint, api_key=api_key,
                                   temperature=temperature, max_tokens=max_tokens)
        return result.get("content", ""), result.get("tokens", 0), []

    executor = ToolExecutor(db, tenant_id)
    tools_used: list[str] = []
    total_tokens = 0
    max_rounds = 5

    for round_num in range(max_rounds):
        # Call provider with tools
        raw_response = await _call_provider_raw(
            provider, messages, model, endpoint, api_key, temperature, tool_defs,
            max_tokens=max_tokens,
        )

        total_tokens += extract_token_count(provider, raw_response)

        # Check for tool calls
        tool_calls = extract_tool_calls(provider, raw_response)
        if not tool_calls:
            # No tool calls — model is done, extract text
            text = extract_text_content(provider, raw_response)
            return text, total_tokens, tools_used

        # Append the assistant message (including tool_calls) to history
        assistant_msgs = format_assistant_message(provider, raw_response)
        messages.extend(assistant_msgs)

        # Execute each tool call and add results to messages
        for tc in tool_calls:
            tool_name = tc["name"]
            tool_args = tc.get("arguments", {})
            logger.info(
                "Tool call: %s(%s)",
                tool_name,
                json.dumps(tool_args, default=str)[:200],
            )

            tool_result = await executor.execute(tool_name, tool_args)
            tools_used.append(tool_name)

            # Format and append tool result messages
            result_msgs = format_tool_result_messages(provider, tc, tool_result)
            messages.extend(result_msgs)

    # Exhausted rounds — make one final call without tools to get a response
    logger.info("Tool calling loop hit max rounds (%d), making final call", max_rounds)
    raw_response = await _call_provider_raw(
        provider, messages, model, endpoint, api_key, temperature, [],
        max_tokens=max_tokens,
    )
    total_tokens += extract_token_count(provider, raw_response)
    text = extract_text_content(provider, raw_response)
    return text, total_tokens, tools_used


@router.get(
    "/providers",
    response_model=ChatProvidersResponse,
    summary="List available chat providers",
    description="Returns configured chat providers with their default models and availability.",
)
async def list_providers(tenant: CurrentTenantDep) -> ChatProvidersResponse:
    """List available chat providers and their status."""
    providers = []

    for name, defaults in PROVIDER_DEFAULTS.items():
        endpoint = os.getenv(defaults.get("endpoint_env", ""), "") or defaults.get("endpoint_fallback", "")
        has_key = bool(resolve_api_key(name)) if "key_env" in defaults else True
        available = bool(endpoint) and (has_key or name == "ollama")

        providers.append({
            "name": name,
            "default_model": defaults.get("model", ""),
            "endpoint": endpoint,
            "available": available,
            "requires_api_key": "key_env" in defaults,
        })

    return ChatProvidersResponse(providers=providers)


@router.get(
    "/models",
    summary="List available models for a provider",
    description="For Ollama, fetches available models. For others, returns default model.",
)
async def list_chat_models(
    tenant: CurrentTenantDep,
    provider: str = "ollama",
) -> dict[str, Any]:
    """List models available for a chat provider."""
    if provider == "ollama":
        endpoint = (
            os.getenv("OLLAMA_CHAT_HOST", "")
            or os.getenv("OLLAMA_ATTACKER_HOST", "")
            or "http://ollama-attacker:11434"
        )
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{endpoint.rstrip('/')}/api/tags")
                resp.raise_for_status()
                data = resp.json()

            models = [
                {
                    "name": m.get("name", ""),
                    "size": f"{m.get('size', 0) / (1024**3):.1f} GB",
                }
                for m in data.get("models", [])
            ]
            return {"provider": "ollama", "models": models}
        except Exception as e:
            logger.warning("Failed to list Ollama models: %s", e)
            return {"provider": "ollama", "models": [], "error": str(e)}

    # For non-Ollama providers, return the default model
    defaults = PROVIDER_DEFAULTS.get(provider, {})
    return {
        "provider": provider,
        "models": [{"name": defaults.get("model", "unknown")}],
    }


@router.get(
    "/config",
    summary="Get current chat and Ollama configuration",
    description="Returns resolved Ollama hosts and provider availability for the settings UI.",
)
async def get_chat_config(tenant: CurrentTenantDep) -> dict[str, Any]:
    """Return current resolved configuration for Ollama and providers."""
    ollama_dest = os.getenv("OLLAMA_HOST", "") or "http://ollama:11434"
    ollama_attacker = os.getenv("OLLAMA_ATTACKER_HOST", "") or "http://ollama-attacker:11434"
    ollama_chat = os.getenv("OLLAMA_CHAT_HOST", "")

    providers = []
    for name, defaults in PROVIDER_DEFAULTS.items():
        has_key = bool(resolve_api_key(name)) if "key_env" in defaults else True
        providers.append({
            "name": name,
            "has_key": has_key,
            "default_model": defaults.get("model", ""),
        })

    return {
        "ollama_destination_host": ollama_dest,
        "ollama_attacker_host": ollama_attacker,
        "ollama_chat_host": ollama_chat or "(using attacker instance)",
        "providers": providers,
    }
