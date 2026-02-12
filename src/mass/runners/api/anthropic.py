"""Anthropic API runner.

Runner for Anthropic's Claude API with tool-calling support.
"""

import os
import time
from typing import Any

from mass.runners.base import BaseRunner, RunnerResult, RunnerStatus, ToolCall, register_runner


@register_runner
class AnthropicRunner(BaseRunner):
    """Anthropic API runner.

    Executes prompts against Anthropic's Claude API.
    Supports tool/function calling via Anthropic's native tools parameter.
    """

    name = "anthropic"
    description = "Anthropic Claude API runner"
    provider = "anthropic"
    supports_async = True

    default_model = "claude-sonnet-4-20250514"

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ):
        """Initialize Anthropic runner.

        Args:
            model: Model identifier.
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var).
            base_url: Optional custom base URL.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            **kwargs: Additional configuration.
        """
        super().__init__(model=model, **kwargs)

        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens

        self._client = None

    def _get_client(self) -> Any:
        """Get or create Anthropic client."""
        if self._client is None:
            try:
                from anthropic import Anthropic

                client_kwargs = {}
                if self.api_key:
                    client_kwargs["api_key"] = self.api_key
                if self.base_url:
                    client_kwargs["base_url"] = self.base_url

                self._client = Anthropic(**client_kwargs)
            except ImportError:
                raise ImportError(
                    "anthropic package not installed. "
                    "Install with: pip install anthropic"
                )

        return self._client

    @staticmethod
    def _convert_tools_to_anthropic(tools: list[dict]) -> list[dict]:
        """Convert OpenAI-format tool definitions to Anthropic format."""
        anthropic_tools = []
        for t in tools:
            fn = t.get("function", t)
            anthropic_tools.append({
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
            })
        return anthropic_tools

    @staticmethod
    def _parse_response_blocks(response: Any) -> tuple[str, list[ToolCall]]:
        """Parse text content and tool_use blocks from Anthropic response."""
        text_parts = []
        tool_calls = []
        for block in response.content:
            if hasattr(block, "text"):
                text_parts.append(block.text)
            elif hasattr(block, "type") and block.type == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.id,
                    name=block.name,
                    arguments=block.input if isinstance(block.input, dict) else {},
                ))
        return "\n".join(text_parts) if text_parts else "", tool_calls

    def run(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt through Anthropic's API.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt.
            **kwargs: Additional parameters (tools, messages).

        Returns:
            RunnerResult with response and metadata.
        """
        start_time = time.time()

        try:
            client = self._get_client()

            # Support full message history override
            messages_override = kwargs.get("messages")
            if messages_override:
                messages = list(messages_override)
            else:
                messages = [{"role": "user", "content": prompt}] if prompt else []

            message_kwargs: dict[str, Any] = {
                "model": kwargs.get("model", self.model),
                "max_tokens": kwargs.get("max_tokens", self.max_tokens),
                "messages": messages,
            }

            if system_prompt:
                message_kwargs["system"] = system_prompt

            if "temperature" in kwargs or self.temperature != 1.0:
                message_kwargs["temperature"] = kwargs.get("temperature", self.temperature)

            tools = kwargs.get("tools")
            if tools:
                message_kwargs["tools"] = self._convert_tools_to_anthropic(tools)

            response = client.messages.create(**message_kwargs)

            latency_ms = (time.time() - start_time) * 1000

            content, tool_calls = self._parse_response_blocks(response)

            tokens_used = (
                response.usage.input_tokens + response.usage.output_tokens
                if response.usage else 0
            )

            return self._create_result(
                response=content,
                status=RunnerStatus.SUCCESS,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
                metadata={
                    "stop_reason": response.stop_reason,
                    "model": response.model,
                },
                tool_calls=tool_calls,
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            error_str = str(e)

            if "rate_limit" in error_str.lower():
                status = RunnerStatus.RATE_LIMITED
            elif "timeout" in error_str.lower():
                status = RunnerStatus.TIMEOUT
            else:
                status = RunnerStatus.ERROR

            return self._create_result(
                response="",
                status=status,
                latency_ms=latency_ms,
                error=error_str,
            )

    async def run_async(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt asynchronously.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt.
            **kwargs: Additional parameters (tools, messages).

        Returns:
            RunnerResult with response and metadata.
        """
        start_time = time.time()

        try:
            from anthropic import AsyncAnthropic

            client_kwargs = {}
            if self.api_key:
                client_kwargs["api_key"] = self.api_key
            if self.base_url:
                client_kwargs["base_url"] = self.base_url

            client = AsyncAnthropic(**client_kwargs)

            messages_override = kwargs.get("messages")
            if messages_override:
                messages = list(messages_override)
            else:
                messages = [{"role": "user", "content": prompt}] if prompt else []

            message_kwargs: dict[str, Any] = {
                "model": kwargs.get("model", self.model),
                "max_tokens": kwargs.get("max_tokens", self.max_tokens),
                "messages": messages,
            }

            if system_prompt:
                message_kwargs["system"] = system_prompt

            if "temperature" in kwargs or self.temperature != 1.0:
                message_kwargs["temperature"] = kwargs.get("temperature", self.temperature)

            tools = kwargs.get("tools")
            if tools:
                message_kwargs["tools"] = self._convert_tools_to_anthropic(tools)

            response = await client.messages.create(**message_kwargs)

            latency_ms = (time.time() - start_time) * 1000

            content, tool_calls = self._parse_response_blocks(response)

            tokens_used = (
                response.usage.input_tokens + response.usage.output_tokens
                if response.usage else 0
            )

            return self._create_result(
                response=content,
                status=RunnerStatus.SUCCESS,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
                metadata={
                    "stop_reason": response.stop_reason,
                    "model": response.model,
                },
                tool_calls=tool_calls,
            )

        except ImportError:
            return self.run(prompt, system_prompt, **kwargs)
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return self._create_result(
                response="",
                status=RunnerStatus.ERROR,
                latency_ms=latency_ms,
                error=str(e),
            )
