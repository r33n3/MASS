"""Anthropic API runner.

Runner for Anthropic's Claude API.
"""

import os
import time
from typing import Any

from mass.runners.base import BaseRunner, RunnerResult, RunnerStatus, register_runner


@register_runner
class AnthropicRunner(BaseRunner):
    """Anthropic API runner.

    Executes prompts against Anthropic's Claude API.
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
            **kwargs: Additional parameters.

        Returns:
            RunnerResult with response and metadata.
        """
        start_time = time.time()

        try:
            client = self._get_client()

            message_kwargs: dict[str, Any] = {
                "model": kwargs.get("model", self.model),
                "max_tokens": kwargs.get("max_tokens", self.max_tokens),
                "messages": [{"role": "user", "content": prompt}],
            }

            if system_prompt:
                message_kwargs["system"] = system_prompt

            if "temperature" in kwargs or self.temperature != 1.0:
                message_kwargs["temperature"] = kwargs.get("temperature", self.temperature)

            response = client.messages.create(**message_kwargs)

            latency_ms = (time.time() - start_time) * 1000

            # Extract text from response
            content = ""
            for block in response.content:
                if hasattr(block, "text"):
                    content += block.text

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
            **kwargs: Additional parameters.

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

            message_kwargs: dict[str, Any] = {
                "model": kwargs.get("model", self.model),
                "max_tokens": kwargs.get("max_tokens", self.max_tokens),
                "messages": [{"role": "user", "content": prompt}],
            }

            if system_prompt:
                message_kwargs["system"] = system_prompt

            if "temperature" in kwargs or self.temperature != 1.0:
                message_kwargs["temperature"] = kwargs.get("temperature", self.temperature)

            response = await client.messages.create(**message_kwargs)

            latency_ms = (time.time() - start_time) * 1000

            content = ""
            for block in response.content:
                if hasattr(block, "text"):
                    content += block.text

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
