"""LLM-powered code architecture analysis.

Sends selected code files to an LLM (OpenAI, Anthropic, or Ollama) and
parses the structured response to build an ArchitectureMap.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Callable

import httpx

from mass.analyzers.code.file_selector import ScoredFile
from mass.analyzers.code.models import (
    ArchitectureMap,
    DataFlow,
    EntryPoint,
    ModelConnection,
    SafetyMeasure,
    ToolDefinition,
)

logger = logging.getLogger(__name__)

# Provider defaults — mirrors chat.py pattern
PROVIDER_DEFAULTS: dict[str, dict[str, str]] = {
    "ollama": {
        "model": "hermes3:8b",
        "endpoint_env": "OLLAMA_HOST",
        "endpoint_fallback": "http://ollama:11434",
    },
    "openai": {
        "model": "gpt-4o",
        "endpoint_env": "OPENAI_API_BASE",
        "endpoint_fallback": "https://api.openai.com/v1",
        "key_env": "OPENAI_API_KEY",
    },
    "anthropic": {
        "model": "claude-sonnet-4-5-20250929",
        "endpoint_env": "ANTHROPIC_API_BASE",
        "endpoint_fallback": "https://api.anthropic.com",
        "key_env": "ANTHROPIC_API_KEY",
    },
}

# LLM timeout for architecture analysis (generous for large batches / reasoning models)
_TIMEOUT = 300.0

# ── Analysis prompt ─────────────────────────────────────────────────

_ANALYSIS_PROMPT = """\
You are a security architect analyzing an AI application's codebase.
Analyze the following code files and identify the AI architecture components.

{file_sections}

Respond with a JSON object (no markdown, no explanation) containing:
{{
  "entry_points": [
    {{"type": "api_endpoint|cli_command|web_form|websocket", "location": "file:line", "accepts": "what input", "flows_to": ["component name"], "authentication": "auth method or null"}}
  ],
  "model_connections": [
    {{"provider": "openai|anthropic|ollama|langchain|etc", "model_name": "model id or null", "call_location": "file:line", "system_prompt_source": "file path or inline or null", "has_tools": true/false, "has_streaming": true/false}}
  ],
  "tool_definitions": [
    {{"name": "tool name", "purpose": "what it does", "capabilities": ["file_system", "network", "command_execution", "database"], "location": "file:line", "validation": "description or null"}}
  ],
  "data_flows": [
    {{"source": "component", "target": "component", "flow_type": "user_input|model_query|tool_call|tool_response", "data_type": "text|json|file", "sensitive": true/false}}
  ],
  "safety_measures": [
    {{"type": "input_validation|output_filtering|rate_limiting|content_moderation", "location": "file:line", "description": "what it does"}}
  ],
  "pattern": "chatbot|agent|rag_pipeline|workflow|mcp_server|api_wrapper|unknown",
  "summary": "One paragraph describing the overall architecture"
}}

Only include items you find evidence for. If none found for a category, use an empty array.
Focus on security-relevant architecture: how user input reaches models, what tools are exposed, what safety measures exist."""


def _build_file_sections(files: list[ScoredFile]) -> str:
    """Build the file sections for the analysis prompt."""
    sections = []
    for f in files:
        signals = ", ".join(f.signals) if f.signals else "general"
        sections.append(
            f"=== FILE: {f.relative_path} [signals: {signals}] ===\n"
            f"```{f.language}\n{f.content}\n```"
        )
    return "\n\n".join(sections)


# ── Response parsing ────────────────────────────────────────────────

def _parse_llm_response(raw: str) -> dict[str, Any] | None:
    """Parse LLM response using multiple strategies."""
    if not raw or not raw.strip():
        return None

    text = raw.strip()

    # Strategy 1: Direct JSON parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: Extract from markdown code block
    match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Strategy 3: Find JSON object in text (first { to last })
    brace_start = text.find("{")
    brace_end = text.rfind("}")
    if brace_start >= 0 and brace_end > brace_start:
        try:
            return json.loads(text[brace_start : brace_end + 1])
        except json.JSONDecodeError:
            pass

    return None


def _extract_components(data: dict[str, Any]) -> dict[str, Any]:
    """Safely extract architecture components from parsed LLM response."""
    return {
        "entry_points": data.get("entry_points") or [],
        "model_connections": data.get("model_connections") or [],
        "tool_definitions": data.get("tool_definitions") or [],
        "data_flows": data.get("data_flows") or [],
        "safety_measures": data.get("safety_measures") or [],
        "pattern": data.get("pattern", "unknown"),
        "summary": data.get("summary", ""),
    }


# ── Provider-specific LLM calls ────────────────────────────────────

async def _call_ollama(
    prompt: str, model: str, endpoint: str,
) -> str:
    """Call Ollama generate API."""
    url = f"{endpoint.rstrip('/')}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 4000},
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json().get("response", "")


async def _call_openai(
    prompt: str, model: str, endpoint: str, api_key: str,
) -> str:
    """Call OpenAI-compatible chat completions API."""
    url = f"{endpoint.rstrip('/')}/chat/completions"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # Reasoning models (o-series, gpt-5-*) have restricted params:
    #   - max_completion_tokens instead of max_tokens
    #   - temperature must be omitted (only default 1 supported)
    #   - response_format may not be supported
    model_lower = model.lower()
    is_reasoning = any(
        model_lower.startswith(p) for p in ("o1", "o3", "o4", "gpt-5", "gpt5")
    )

    # For reasoning models, wrap JSON instruction in the prompt itself
    messages = [{"role": "user", "content": prompt}]
    if is_reasoning:
        messages[0]["content"] = prompt + "\n\nIMPORTANT: Respond with valid JSON only."

    payload: dict = {
        "model": model,
        "messages": messages,
    }

    if is_reasoning:
        payload["max_completion_tokens"] = 4096
    else:
        payload["temperature"] = 0.3
        payload["max_tokens"] = 4096
        payload["response_format"] = {"type": "json_object"}

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(url, json=payload, headers=headers)

        # Auto-retry on 400: strip the offending parameter and retry
        if resp.status_code == 400:
            body = resp.content
            retried = False
            if b"max_tokens" in body and "max_tokens" in payload:
                del payload["max_tokens"]
                payload["max_completion_tokens"] = 4096
                retried = True
            if b"temperature" in body:
                payload.pop("temperature", None)
                retried = True
            if b"response_format" in body:
                payload.pop("response_format", None)
                retried = True
            if retried:
                resp = await client.post(url, json=payload, headers=headers)

        resp.raise_for_status()
        data = resp.json()
        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        content = message.get("content") or ""

        # Reasoning models may return empty content with a refusal
        if not content and message.get("refusal"):
            logger.warning("OpenAI refusal: %s", message["refusal"])

        # Some reasoning models nest output in 'reasoning_content' or 'output'
        if not content:
            content = data.get("output") or ""

        if not content:
            logger.warning("Empty OpenAI response. Keys: %s", list(data.keys()))

        return content


async def _call_anthropic(
    prompt: str, model: str, endpoint: str, api_key: str,
) -> str:
    """Call Anthropic messages API."""
    url = f"{endpoint.rstrip('/')}/v1/messages"
    headers: dict[str, str] = {
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    if api_key:
        headers["x-api-key"] = api_key
    payload = {
        "model": model,
        "max_tokens": 4096,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        # Anthropic returns content as list of blocks
        blocks = data.get("content", [])
        return blocks[0]["text"] if blocks else ""


# ── Main analyzer ───────────────────────────────────────────────────

class CodeArchitectureAnalyzer:
    """Analyzes code files using an LLM to understand AI architecture."""

    def __init__(
        self,
        provider: str = "ollama",
        model: str | None = None,
        endpoint: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.provider = provider.lower()
        defaults = PROVIDER_DEFAULTS.get(self.provider, PROVIDER_DEFAULTS["ollama"])

        self.model = model or defaults.get("model", "")
        self.endpoint = (
            endpoint
            or os.getenv(defaults.get("endpoint_env", ""), "")
            or defaults.get("endpoint_fallback", "")
        )
        self.api_key = (
            api_key
            or os.getenv(defaults.get("key_env", ""), "")
        )

    async def analyze(
        self,
        files: list[ScoredFile],
        progress_cb: Callable[[str], None] | None = None,
    ) -> ArchitectureMap:
        """Analyze code files and build an architecture map.

        Args:
            files: Scored files from the static selection pass.
            progress_cb: Optional callback for progress messages.

        Returns:
            ArchitectureMap with aggregated results.
        """
        start = time.monotonic()
        arch = ArchitectureMap(
            model_used=self.model,
            provider_used=self.provider,
            total_files=len(files),
        )

        if not files:
            arch.errors.append("No files selected for analysis")
            return arch

        # Chunk files into batches of 3 to stay within context limits
        batches = [files[i : i + 3] for i in range(0, len(files), 3)]

        if progress_cb:
            progress_cb(f"Analyzing {len(files)} files in {len(batches)} batches...")

        for batch_idx, batch in enumerate(batches):
            if progress_cb:
                progress_cb(
                    f"Batch {batch_idx + 1}/{len(batches)}: "
                    f"{', '.join(f.relative_path for f in batch)}"
                )

            try:
                result = await self._analyze_batch(batch)
                self._merge_batch(arch, result)
                arch.analyzed_files += len(batch)
            except httpx.ConnectError as e:
                msg = f"LLM connection failed: {e}"
                logger.warning(msg)
                arch.errors.append(msg)
                break  # No point retrying if connection fails
            except httpx.TimeoutException:
                msg = f"LLM timeout on batch {batch_idx + 1}"
                logger.warning(msg)
                arch.errors.append(msg)
            except httpx.HTTPStatusError as e:
                msg = f"LLM error {e.response.status_code}: {e.response.text[:200]}"
                logger.warning(msg)
                arch.errors.append(msg)
                if e.response.status_code in (401, 403):
                    break  # Auth error — no point retrying
            except Exception as e:
                msg = f"Analysis batch {batch_idx + 1} failed: {e}"
                logger.warning(msg)
                arch.errors.append(msg)

        arch.duration_seconds = round(time.monotonic() - start, 1)
        arch.confidence = self._compute_confidence(arch)

        logger.info(
            "Architecture analysis: %d entry points, %d model connections, "
            "%d tools, %d data flows, %d safety measures — pattern: %s (%.0f%% confidence, %.1fs)",
            len(arch.entry_points), len(arch.model_connections),
            len(arch.tool_definitions), len(arch.data_flows),
            len(arch.safety_measures), arch.pattern,
            arch.confidence * 100, arch.duration_seconds,
        )

        return arch

    async def _analyze_batch(self, batch: list[ScoredFile]) -> dict[str, Any]:
        """Send a batch of files to the LLM and parse the response."""
        file_sections = _build_file_sections(batch)
        prompt = _ANALYSIS_PROMPT.format(file_sections=file_sections)

        # Call the appropriate provider
        if self.provider == "ollama":
            raw = await _call_ollama(prompt, self.model, self.endpoint)
        elif self.provider in ("openai", "grok"):
            raw = await _call_openai(prompt, self.model, self.endpoint, self.api_key)
        elif self.provider == "anthropic":
            raw = await _call_anthropic(prompt, self.model, self.endpoint, self.api_key)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

        parsed = _parse_llm_response(raw)
        if parsed is None:
            logger.warning("Failed to parse LLM response: %s", raw[:200])
            return {"error": "Failed to parse response"}

        return _extract_components(parsed)

    def _merge_batch(self, arch: ArchitectureMap, result: dict[str, Any]) -> None:
        """Merge a batch result into the architecture map."""
        if "error" in result:
            arch.errors.append(result["error"])
            return

        for d in result.get("entry_points", []):
            if isinstance(d, dict):
                arch.entry_points.append(EntryPoint.from_dict(d))

        for d in result.get("model_connections", []):
            if isinstance(d, dict):
                arch.model_connections.append(ModelConnection.from_dict(d))

        for d in result.get("tool_definitions", []):
            if isinstance(d, dict):
                arch.tool_definitions.append(ToolDefinition.from_dict(d))

        for d in result.get("data_flows", []):
            if isinstance(d, dict):
                arch.data_flows.append(DataFlow.from_dict(d))

        for d in result.get("safety_measures", []):
            if isinstance(d, dict):
                arch.safety_measures.append(SafetyMeasure.from_dict(d))

        # Take the most specific pattern (not "unknown")
        pattern = result.get("pattern", "unknown")
        if pattern != "unknown" and arch.pattern == "unknown":
            arch.pattern = pattern

        # Append summaries
        summary = result.get("summary", "")
        if summary:
            if arch.summary:
                arch.summary += " " + summary
            else:
                arch.summary = summary

    def _compute_confidence(self, arch: ArchitectureMap) -> float:
        """Compute confidence score based on analysis completeness."""
        score = 0.0

        if arch.analyzed_files > 0:
            score += 0.3  # Got some LLM results

        if arch.entry_points or arch.model_connections:
            score += 0.3  # Found meaningful architecture

        if arch.tool_definitions:
            score += 0.1  # Found tools

        if arch.data_flows:
            score += 0.1  # Found data flows

        coverage = arch.analyzed_files / max(arch.total_files, 1)
        if coverage > 0.5:
            score += 0.1  # Good coverage

        if not arch.errors:
            score += 0.1  # No errors

        return min(score, 1.0)
