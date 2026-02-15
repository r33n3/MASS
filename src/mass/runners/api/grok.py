"""Grok (xAI) API runner.

Runner for xAI's Grok API. Uses the OpenAI-compatible endpoint
that xAI provides, so it leverages the OpenAI SDK with a custom base URL.
"""

import os
import time
from typing import Any

from mass.runners.base import BaseRunner, RunnerResult, RunnerStatus, register_runner


XAI_BASE_URL = "https://api.x.ai/v1"


@register_runner
class GrokRunner(BaseRunner):
    """xAI Grok API runner.

    Executes prompts against xAI's Grok models using the
    OpenAI-compatible API endpoint.
    """

    name = "grok"
    description = "xAI Grok API runner (OpenAI-compatible)"
    provider = "xai"
    supports_async = True

    default_model = "grok-3-mini-fast"

    # Model aliases for convenience
    MODEL_ALIASES = {
        "grok-3": "grok-3",
        "grok-3-mini": "grok-3-mini-fast",
        "grok-mini": "grok-3-mini-fast",
        "grok-fast": "grok-3-fast",
    }

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ):
        """Initialize Grok runner.

        Args:
            model: Model identifier or alias.
            api_key: xAI API key (defaults to XAI_API_KEY env var).
            base_url: Custom base URL (defaults to xAI endpoint).
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            **kwargs: Additional configuration.
        """
        resolved_model = self.MODEL_ALIASES.get(model or "", model)
        super().__init__(model=resolved_model, **kwargs)

        self.api_key = api_key or os.getenv("XAI_API_KEY") or os.getenv("GROK_API_KEY")
        self.base_url = base_url or XAI_BASE_URL
        self.temperature = temperature
        self.max_tokens = max_tokens

        self._client = None
        self._async_client = None

    def _get_client(self) -> Any:
        """Get or create xAI client (OpenAI-compatible)."""
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError:
                raise ImportError(
                    "openai package not installed. "
                    "Install with: pip install openai"
                )

            if not self.api_key:
                raise ValueError(
                    "xAI API key required. Set XAI_API_KEY or "
                    "GROK_API_KEY env var, or pass api_key parameter."
                )

            self._client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
            )

        return self._client

    def run(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt through xAI Grok API.

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

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = client.chat.completions.create(
                model=kwargs.get("model", self.model),
                messages=messages,
                temperature=kwargs.get("temperature", self.temperature),
                max_tokens=kwargs.get("max_tokens", self.max_tokens),
            )

            latency_ms = (time.time() - start_time) * 1000

            content = response.choices[0].message.content or ""
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
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            error_str = str(e)

            if "rate_limit" in error_str.lower() or "429" in error_str:
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
        """Run a prompt asynchronously through Grok.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt.
            **kwargs: Additional parameters.

        Returns:
            RunnerResult with response and metadata.
        """
        start_time = time.time()

        try:
            if self._async_client is None:
                from openai import AsyncOpenAI
                self._async_client = AsyncOpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url,
                )
            client = self._async_client

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = await client.chat.completions.create(
                model=kwargs.get("model", self.model),
                messages=messages,
                temperature=kwargs.get("temperature", self.temperature),
                max_tokens=kwargs.get("max_tokens", self.max_tokens),
            )

            latency_ms = (time.time() - start_time) * 1000

            content = response.choices[0].message.content or ""
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
