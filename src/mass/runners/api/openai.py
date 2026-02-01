"""OpenAI API runner.

Runner for OpenAI's chat completion API.
"""

import os
import time
from typing import Any

from mass.runners.base import BaseRunner, RunnerResult, RunnerStatus, register_runner


@register_runner
class OpenAIRunner(BaseRunner):
    """OpenAI API runner.

    Executes prompts against OpenAI's chat completion API.
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
            from openai import AsyncOpenAI

            client_kwargs = {}
            if self.api_key:
                client_kwargs["api_key"] = self.api_key
            if self.base_url:
                client_kwargs["base_url"] = self.base_url

            client = AsyncOpenAI(**client_kwargs)

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
