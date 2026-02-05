"""AWS Bedrock API runner.

Runner for AWS Bedrock Runtime's Converse API, supporting
Claude, Titan, Llama, and Mistral models on Bedrock.
"""

import json
import os
import time
from typing import Any

from mass.runners.base import BaseRunner, RunnerResult, RunnerStatus, register_runner


@register_runner
class BedrockRunner(BaseRunner):
    """AWS Bedrock Runtime runner.

    Executes prompts against models hosted on AWS Bedrock
    using the Converse API.
    """

    name = "bedrock"
    description = "AWS Bedrock Runtime Converse API runner"
    provider = "bedrock"
    supports_async = False

    default_model = "anthropic.claude-3-haiku-20240307-v1:0"

    # Common Bedrock model IDs
    MODEL_ALIASES = {
        "claude-3-haiku": "anthropic.claude-3-haiku-20240307-v1:0",
        "claude-3-sonnet": "anthropic.claude-3-sonnet-20240229-v1:0",
        "claude-3-opus": "anthropic.claude-3-opus-20240229-v1:0",
        "claude-3.5-sonnet": "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "claude-3.5-haiku": "anthropic.claude-3-5-haiku-20241022-v1:0",
        "titan-text-express": "amazon.titan-text-express-v1",
        "titan-text-lite": "amazon.titan-text-lite-v1",
        "llama3-8b": "meta.llama3-8b-instruct-v1:0",
        "llama3-70b": "meta.llama3-70b-instruct-v1:0",
        "mistral-7b": "mistral.mistral-7b-instruct-v0:2",
        "mixtral-8x7b": "mistral.mixtral-8x7b-instruct-v0:1",
    }

    def __init__(
        self,
        model: str | None = None,
        region_name: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        profile_name: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ):
        """Initialize Bedrock runner.

        Args:
            model: Bedrock model ID or alias.
            region_name: AWS region (defaults to AWS_DEFAULT_REGION env var).
            aws_access_key_id: AWS access key (defaults to env/credentials).
            aws_secret_access_key: AWS secret key (defaults to env/credentials).
            aws_session_token: AWS session token for temporary credentials.
            profile_name: AWS profile name from credentials file.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            **kwargs: Additional configuration.
        """
        # Resolve model alias
        resolved_model = self.MODEL_ALIASES.get(model or "", model)
        super().__init__(model=resolved_model, **kwargs)

        self.region_name = region_name or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_session_token = aws_session_token
        self.profile_name = profile_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._client = None

    def _get_client(self) -> Any:
        """Get or create Bedrock Runtime client."""
        if self._client is None:
            try:
                import boto3
            except ImportError:
                raise ImportError(
                    "boto3 package not installed. "
                    "Install with: pip install boto3"
                )

            session_kwargs: dict[str, Any] = {}
            if self.profile_name:
                session_kwargs["profile_name"] = self.profile_name
            if self.region_name:
                session_kwargs["region_name"] = self.region_name

            session = boto3.Session(**session_kwargs)

            client_kwargs: dict[str, Any] = {}
            if self.aws_access_key_id:
                client_kwargs["aws_access_key_id"] = self.aws_access_key_id
            if self.aws_secret_access_key:
                client_kwargs["aws_secret_access_key"] = self.aws_secret_access_key
            if self.aws_session_token:
                client_kwargs["aws_session_token"] = self.aws_session_token

            self._client = session.client(
                "bedrock-runtime",
                **client_kwargs,
            )

        return self._client

    def run(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt through Bedrock's Converse API.

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

            # Build Converse API request
            converse_kwargs: dict[str, Any] = {
                "modelId": kwargs.get("model", self.model),
                "messages": [
                    {
                        "role": "user",
                        "content": [{"text": prompt}],
                    }
                ],
                "inferenceConfig": {
                    "temperature": kwargs.get("temperature", self.temperature),
                    "maxTokens": kwargs.get("max_tokens", self.max_tokens),
                },
            }

            if system_prompt:
                converse_kwargs["system"] = [{"text": system_prompt}]

            response = client.converse(**converse_kwargs)

            latency_ms = (time.time() - start_time) * 1000

            # Extract response text
            output = response.get("output", {})
            message = output.get("message", {})
            content_blocks = message.get("content", [])
            content = ""
            for block in content_blocks:
                if "text" in block:
                    content += block["text"]

            # Extract token usage
            usage = response.get("usage", {})
            tokens_used = usage.get("totalTokens", 0)

            return self._create_result(
                response=content,
                status=RunnerStatus.SUCCESS,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
                metadata={
                    "stop_reason": response.get("stopReason", ""),
                    "model": self.model,
                    "input_tokens": usage.get("inputTokens", 0),
                    "output_tokens": usage.get("outputTokens", 0),
                },
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            error_str = str(e)

            if "ThrottlingException" in error_str or "rate" in error_str.lower():
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
