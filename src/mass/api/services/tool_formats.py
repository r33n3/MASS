"""Tool format converters for multi-provider chat tool calling.

Converts canonical TOOL_DEFINITIONS to each provider's expected format,
extracts tool calls from provider responses, and formats tool results
back into provider-specific message structures.

Supported providers:
- OpenAI / Grok (OpenAI-compatible)
- Ollama (OpenAI-compatible for qwen3, llama3.1+, etc.)
- Anthropic (Messages API with tool_use blocks)
- Gemini (function_declarations)
"""

import json
import logging
from typing import Any

from mass.api.services.tool_executor import TOOL_DEFINITIONS

logger = logging.getLogger(__name__)

# Providers that support tool calling
_TOOL_PROVIDERS = {"ollama", "openai", "anthropic", "gemini", "grok"}


def tools_for_provider(provider: str) -> list[dict[str, Any]] | None:
    """Convert TOOL_DEFINITIONS to the provider's expected format.

    Returns None if the provider doesn't support tool calling.
    """
    provider = provider.lower()
    if provider not in _TOOL_PROVIDERS:
        return None

    if provider in ("openai", "grok", "ollama"):
        return _to_openai_format()
    elif provider == "anthropic":
        return _to_anthropic_format()
    elif provider == "gemini":
        return _to_gemini_format()
    return None


def extract_tool_calls(
    provider: str, response_data: dict[str, Any]
) -> list[dict[str, Any]]:
    """Extract tool calls from a provider response.

    Returns list of: {"id": str, "name": str, "arguments": dict}
    """
    provider = provider.lower()
    if provider in ("openai", "grok"):
        return _extract_openai(response_data)
    elif provider == "ollama":
        return _extract_ollama(response_data)
    elif provider == "anthropic":
        return _extract_anthropic(response_data)
    elif provider == "gemini":
        return _extract_gemini(response_data)
    return []


def extract_text_content(
    provider: str, response_data: dict[str, Any]
) -> str:
    """Extract the text content from a provider response."""
    provider = provider.lower()
    if provider in ("openai", "grok"):
        # Standard Chat Completions format
        if "choices" in response_data:
            choice = response_data.get("choices", [{}])[0]
            return choice.get("message", {}).get("content", "") or ""
        # GPT-5 / o-series Responses API format
        if "output" in response_data:
            parts = []
            for item in response_data.get("output", []):
                if item.get("type") == "message":
                    for part in item.get("content", []):
                        if part.get("type") in ("output_text", "text"):
                            parts.append(part.get("text", ""))
            return "".join(parts)
        return ""
    elif provider == "ollama":
        return response_data.get("message", {}).get("content", "") or ""
    elif provider == "anthropic":
        blocks = response_data.get("content", [])
        return "".join(
            b.get("text", "") for b in blocks if b.get("type") == "text"
        )
    elif provider == "gemini":
        candidates = response_data.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            return "".join(p.get("text", "") for p in parts if "text" in p)
    return ""


def extract_token_count(
    provider: str, response_data: dict[str, Any]
) -> int:
    """Extract token usage from a provider response."""
    provider = provider.lower()
    if provider in ("openai", "grok"):
        usage = response_data.get("usage", {})
        return usage.get("total_tokens", 0) or (
            usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
        )
    elif provider == "ollama":
        return (
            response_data.get("prompt_eval_count", 0)
            + response_data.get("eval_count", 0)
        )
    elif provider == "anthropic":
        usage = response_data.get("usage", {})
        return usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
    elif provider == "gemini":
        usage = response_data.get("usageMetadata", {})
        return usage.get("totalTokenCount", 0)
    return 0


def format_assistant_message(
    provider: str, response_data: dict[str, Any]
) -> list[dict[str, Any]]:
    """Format the assistant's response (including tool calls) as
    messages to append to the conversation history.
    """
    provider = provider.lower()
    if provider in ("openai", "grok"):
        # Standard Chat Completions format
        if "choices" in response_data:
            msg = response_data.get("choices", [{}])[0].get("message", {})
            return [msg]
        # GPT-5 / o-series Responses API format — reconstruct as standard message
        if "output" in response_data:
            content_parts = []
            tool_calls = []
            for item in response_data.get("output", []):
                if item.get("type") == "message":
                    for part in item.get("content", []):
                        if part.get("type") in ("output_text", "text"):
                            content_parts.append(part.get("text", ""))
                elif item.get("type") == "function_call":
                    args = item.get("arguments", "{}")
                    tool_calls.append({
                        "id": item.get("call_id", item.get("id", "")),
                        "type": "function",
                        "function": {
                            "name": item.get("name", ""),
                            "arguments": args if isinstance(args, str) else json.dumps(args),
                        },
                    })
            msg: dict[str, Any] = {"role": "assistant", "content": "".join(content_parts) or None}
            if tool_calls:
                msg["tool_calls"] = tool_calls
            return [msg]
        return [{"role": "assistant", "content": ""}]
    elif provider == "ollama":
        msg = response_data.get("message", {})
        return [msg]
    elif provider == "anthropic":
        return [{"role": "assistant", "content": response_data.get("content", [])}]
    elif provider == "gemini":
        candidates = response_data.get("candidates", [])
        if candidates:
            return [{"role": "model", "parts": candidates[0].get("content", {}).get("parts", [])}]
    return []


def format_tool_result_messages(
    provider: str,
    tool_call: dict[str, Any],
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    """Format a tool result as messages to append to the conversation.

    Returns a list of messages (usually 1, but Anthropic needs special
    handling).
    """
    provider = provider.lower()
    result_str = json.dumps(result, default=str)

    if provider in ("openai", "grok"):
        return [{
            "role": "tool",
            "tool_call_id": tool_call.get("id", ""),
            "content": result_str,
        }]
    elif provider == "ollama":
        return [{
            "role": "tool",
            "content": result_str,
        }]
    elif provider == "anthropic":
        return [{
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": tool_call.get("id", ""),
                "content": result_str,
            }],
        }]
    elif provider == "gemini":
        return [{
            "role": "user",
            "parts": [{
                "functionResponse": {
                    "name": tool_call.get("name", ""),
                    "response": result,
                },
            }],
        }]
    return []


# ---------------------------------------------------------------------------
# Provider-specific format converters
# ---------------------------------------------------------------------------

def _to_openai_format() -> list[dict[str, Any]]:
    """Convert to OpenAI/Grok/Ollama tools format."""
    tools = []
    for td in TOOL_DEFINITIONS:
        tools.append({
            "type": "function",
            "function": {
                "name": td["name"],
                "description": td["description"],
                "parameters": td["parameters"],
            },
        })
    return tools


def _to_anthropic_format() -> list[dict[str, Any]]:
    """Convert to Anthropic tools format."""
    tools = []
    for td in TOOL_DEFINITIONS:
        tools.append({
            "name": td["name"],
            "description": td["description"],
            "input_schema": td["parameters"],
        })
    return tools


def _to_gemini_format() -> list[dict[str, Any]]:
    """Convert to Gemini function_declarations format."""
    declarations = []
    for td in TOOL_DEFINITIONS:
        declarations.append({
            "name": td["name"],
            "description": td["description"],
            "parameters": td["parameters"],
        })
    return [{"function_declarations": declarations}]


# ---------------------------------------------------------------------------
# Provider-specific tool call extractors
# ---------------------------------------------------------------------------

def _extract_openai(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract tool calls from OpenAI/Grok response.

    Handles both standard Chat Completions format (choices[].message.tool_calls)
    and GPT-5 / o-series Responses API format (output[].type=function_call).
    """
    result = []

    # Standard Chat Completions format
    if "choices" in data:
        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        tool_calls = message.get("tool_calls", [])

        for tc in tool_calls:
            fn = tc.get("function", {})
            args = fn.get("arguments", "{}")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            result.append({
                "id": tc.get("id", ""),
                "name": fn.get("name", ""),
                "arguments": args,
            })
        return result

    # GPT-5 / o-series Responses API format
    if "output" in data:
        for item in data.get("output", []):
            if item.get("type") == "function_call":
                args = item.get("arguments", "{}")
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                result.append({
                    "id": item.get("call_id", item.get("id", "")),
                    "name": item.get("name", ""),
                    "arguments": args,
                })
        return result

    return result


def _extract_ollama(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract tool calls from Ollama response."""
    message = data.get("message", {})
    tool_calls = message.get("tool_calls", [])

    result = []
    for tc in tool_calls:
        fn = tc.get("function", {})
        args = fn.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        result.append({
            "id": tc.get("id", f"call_{len(result)}"),
            "name": fn.get("name", ""),
            "arguments": args,
        })
    return result


def _extract_anthropic(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract tool calls from Anthropic response."""
    content_blocks = data.get("content", [])

    result = []
    for block in content_blocks:
        if block.get("type") == "tool_use":
            result.append({
                "id": block.get("id", ""),
                "name": block.get("name", ""),
                "arguments": block.get("input", {}),
            })
    return result


def _extract_gemini(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract tool calls from Gemini response."""
    candidates = data.get("candidates", [])
    if not candidates:
        return []

    parts = candidates[0].get("content", {}).get("parts", [])
    result = []
    for part in parts:
        fc = part.get("functionCall")
        if fc:
            result.append({
                "id": f"call_{len(result)}",
                "name": fc.get("name", ""),
                "arguments": fc.get("args", {}),
            })
    return result
