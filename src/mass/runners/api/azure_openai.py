"""Azure OpenAI API runner.

Runner for Azure OpenAI Service's chat completion API.
Uses the OpenAI SDK with Azure-specific configuration.
"""

import os
import time
from typing import Any

from mass.runners.base import BaseRunner, RunnerResult, RunnerStatus, register_runner


@register_runner
class AzureOpenAIRunner(BaseRunner):
    """Azure OpenAI Service runner.

    Executes prompts against Azure-hosted OpenAI models
    using the OpenAI Python SDK with Azure configuration.
    """

    name = "azure_openai"
    description = "Azure OpenAI Service chat completion runner"
    provider = "azure_openai"
    supports_async = True

    default_model = "gpt-4o-mini"

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        azure_endpoint: str | None = None,
        api_version: str | None = None,
        azure_deployment: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ):
        """Initialize Azure OpenAI runner.

        Args:
            model: Model/deployment name.
            api_key: Azure OpenAI API key (defaults to AZURE_OPENAI_API_KEY env var).
            azure_endpoint: Azure endpoint URL (defaults to AZURE_OPENAI_ENDPOINT env var).
            api_version: API version (defaults to AZURE_OPENAI_API_VERSION or 2024-06-01).
            azure_deployment: Deployment name (defaults to model name).
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            **kwargs: Additional configuration.
        """
        super().__init__(model=model, **kwargs)

        self.api_key = api_key or os.getenv("AZURE_OPENAI_API_KEY")
        self.azure_endpoint = azure_endpoint or os.getenv("AZURE_OPENAI_ENDPOINT")
        self.api_version = api_version or os.getenv(
            "AZURE_OPENAI_API_VERSION", "2024-06-01"
        )
        self.azure_deployment = azure_deployment or self.model
        self.temperature = temperature
        self.max_tokens = max_tokens

        self._client = None
        self._async_client = None

    def _get_client(self) -> Any:
        """Get or create Azure OpenAI client."""
        if self._client is None:
            try:
                from openai import AzureOpenAI
            except ImportError:
                raise ImportError(
                    "openai package not installed. "
                    "Install with: pip install openai"
                )

            if not self.azure_endpoint:
                raise ValueError(
                    "Azure endpoint required. Set AZURE_OPENAI_ENDPOINT env var "
                    "or pass azure_endpoint parameter."
                )

            client_kwargs: dict[str, Any] = {
                "azure_endpoint": self.azure_endpoint,
                "api_version": self.api_version,
            }
            if self.api_key:
                client_kwargs["api_key"] = self.api_key
            else:
                # Fall back to Azure AD / DefaultAzureCredential
                try:
                    from azure.identity import DefaultAzureCredential, get_bearer_token_provider

                    credential = DefaultAzureCredential()
                    token_provider = get_bearer_token_provider(
                        credential, "https://cognitiveservices.azure.com/.default"
                    )
                    client_kwargs["azure_ad_token_provider"] = token_provider
                except ImportError:
                    raise ImportError(
                        "No API key provided and azure-identity not installed. "
                        "Set AZURE_OPENAI_API_KEY or install: pip install azure-identity"
                    )

            self._client = AzureOpenAI(**client_kwargs)

        return self._client

    def run(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt through Azure OpenAI's API.

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
                model=kwargs.get("model", self.azure_deployment),
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
                    "azure_deployment": self.azure_deployment,
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
        """Run a prompt asynchronously through Azure OpenAI.

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
                from openai import AsyncAzureOpenAI
                if not self.azure_endpoint:
                    raise ValueError("Azure endpoint required.")
                client_kwargs: dict[str, Any] = {
                    "azure_endpoint": self.azure_endpoint,
                    "api_version": self.api_version,
                }
                if self.api_key:
                    client_kwargs["api_key"] = self.api_key
                self._async_client = AsyncAzureOpenAI(**client_kwargs)
            client = self._async_client

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = await client.chat.completions.create(
                model=kwargs.get("model", self.azure_deployment),
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
                    "azure_deployment": self.azure_deployment,
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
