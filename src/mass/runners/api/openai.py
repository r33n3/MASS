"""OpenAI API runner.

Runner for OpenAI's chat completion API with tool-calling support.
"""

import json
import os
import time
from typing import Any

from mass.runners.base import BaseRunner, RunnerResult, RunnerStatus, ToolCall, register_runner
from mass.runners.pool import rate_limiter


@register_runner
class OpenAIRunner(BaseRunner):
    """OpenAI API runner.

    Executes prompts against OpenAI's chat completion API.
    Supports tool/function calling via OpenAI's native tools parameter.
    """

    name = "openai"
    description = "OpenAI chat completion API runner"
    provider = "openai"
    supports_async = True

    default_model = "gpt-4o-mini"

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ):
        """Initialize OpenAI runner.

        Args:
            model: Model identifier.
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var).
            base_url: Optional custom base URL.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            **kwargs: Additional configuration.
        """
        super().__init__(model=model, **kwargs)

        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens

        self._client = None
        self._async_client = None

    def _get_client(self) -> Any:
        """Get or create OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI

                client_kwargs = {}
                if self.api_key:
                    client_kwargs["api_key"] = self.api_key
                if self.base_url:
                    client_kwargs["base_url"] = self.base_url

                self._client = OpenAI(**client_kwargs)
            except ImportError:
                raise ImportError(
                    "openai package not installed. "
                    "Install with: pip install openai"
                )

        return self._client

    @staticmethod
    def _parse_tool_calls(message: Any) -> list[ToolCall]:
        """Parse tool_calls from an OpenAI response message."""
        calls = []
        if hasattr(message, "tool_calls") and message.tool_calls:
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except (json.JSONDecodeError, TypeError):
                    args = {}
                calls.append(ToolCall(
                    id=tc.id or "",
                    name=tc.function.name or "",
                    arguments=args,
                ))
        return calls

    def run(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt through OpenAI's API.

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
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                if prompt:
                    messages.append({"role": "user", "content": prompt})

            api_kwargs: dict[str, Any] = {
                "model": kwargs.get("model", self.model),
                "messages": messages,
                "temperature": kwargs.get("temperature", self.temperature),
                "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            }

            tools = kwargs.get("tools")
            if tools:
                api_kwargs["tools"] = tools

            rate_limiter.acquire_sync("openai")
            response = client.chat.completions.create(**api_kwargs)

            latency_ms = (time.time() - start_time) * 1000

            message = response.choices[0].message
            content = message.content or ""
            tool_calls = self._parse_tool_calls(message)
            tokens_used = response.usage.total_tokens if response.usage else 0

            return self._create_result(
                response=content,
                status=RunnerStatus.SUCCESS,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
                metadata={
                    "finish_reason": response.choices[0].finish_reason,
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
            if self._async_client is None:
                from openai import AsyncOpenAI
                client_kwargs = {}
                if self.api_key:
                    client_kwargs["api_key"] = self.api_key
                if self.base_url:
                    client_kwargs["base_url"] = self.base_url
                self._async_client = AsyncOpenAI(**client_kwargs)
            client = self._async_client

            messages_override = kwargs.get("messages")
            if messages_override:
                messages = list(messages_override)
            else:
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                if prompt:
                    messages.append({"role": "user", "content": prompt})

            api_kwargs: dict[str, Any] = {
                "model": kwargs.get("model", self.model),
                "messages": messages,
                "temperature": kwargs.get("temperature", self.temperature),
                "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            }

            tools = kwargs.get("tools")
            if tools:
                api_kwargs["tools"] = tools

            await rate_limiter.acquire("openai")
            response = await client.chat.completions.create(**api_kwargs)

            latency_ms = (time.time() - start_time) * 1000

            message = response.choices[0].message
            content = message.content or ""
            tool_calls = self._parse_tool_calls(message)
            tokens_used = response.usage.total_tokens if response.usage else 0

            return self._create_result(
                response=content,
                status=RunnerStatus.SUCCESS,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
                metadata={
                    "finish_reason": response.choices[0].finish_reason,
                    "model": response.model,
                },
                tool_calls=tool_calls,
            )

        except ImportError:
            # Fall back to sync
            return self.run(prompt, system_prompt, **kwargs)
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return self._create_result(
                response="",
                status=RunnerStatus.ERROR,
                latency_ms=latency_ms,
                error=str(e),
            )
