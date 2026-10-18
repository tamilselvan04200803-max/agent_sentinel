"""LLM generation error hierarchy for AgentSentinel.

These exceptions extend the root ``AgentSentinelError`` hierarchy specifically
for LLM client failures. Every failure mode is explicitly typed so the
orchestrator can categorize and account for each attempt.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import AgentSentinelError

if TYPE_CHECKING:
    from agentsentinel.llm.pricing import ModelUsage


class LLMError(AgentSentinelError):
    """Root exception for all LLM client failures."""


class LLMGenerationError(LLMError):
    """Raised when the LLM generates a response that cannot be parsed as a PatchProposal.

    Critically, even when parsing fails we carry ``usage`` (a
    :class:`~agentsentinel.llm.pricing.ModelUsage` instance) when the API
    returned token-usage metadata before schema validation failed. This
    guarantees the orchestrator never loses track of spent tokens or attempts:
    a parse failure STILL consumed model tokens and counts as an attempt.
    """

    def __init__(
        self,
        reason: str,
        raw_response: str = "",
        usage: ModelUsage | None = None,
    ) -> None:
        self.reason = reason
        self.raw_response = raw_response
        self.usage = usage
        snippet = raw_response[:200] if raw_response else "(empty)"
        msg = f"LLM generation failed: {reason} | response snippet: {snippet!r}"
        if usage is not None:
            msg += (
                f" [tokens spent: prompt={usage.prompt_tokens}, "
                f"completion={usage.completion_tokens}]"
            )
        super().__init__(msg)


class LLMTimeoutError(LLMError):
    """Raised when an LLM API call exceeds the configured timeout."""

    def __init__(self, timeout_seconds: float, model_id: str) -> None:
        self.timeout_seconds = timeout_seconds
        self.model_id = model_id
        super().__init__(
            f"LLM call to {model_id!r} timed out after {timeout_seconds}s"
        )


class LLMRateLimitError(LLMError):
    """Raised when the LLM provider returns a rate-limit (HTTP 429) response."""

    def __init__(self, model_id: str, retry_after_seconds: float | None = None) -> None:
        self.model_id = model_id
        self.retry_after_seconds = retry_after_seconds
        msg = f"Rate limited by LLM provider for model {model_id!r}"
        if retry_after_seconds is not None:
            msg += f" (retry after {retry_after_seconds}s)"
        super().__init__(msg)


class LLMAuthenticationError(LLMError):
    """Raised when the LLM provider rejects the API key (HTTP 401/403)."""

    def __init__(self, model_id: str) -> None:
        self.model_id = model_id
        super().__init__(
            f"Authentication failed for LLM provider (model: {model_id!r}). "
            "Check AGENTSENTINEL_LLM_API_KEY environment variable."
        )


class LLMServerError(LLMError):
    """Raised when the LLM provider returns an unexpected server error (HTTP 5xx)."""

    def __init__(self, model_id: str, status_code: int, body: str = "") -> None:
        self.model_id = model_id
        self.status_code = status_code
        self.body = body
        super().__init__(
            f"LLM provider server error for {model_id!r}: HTTP {status_code}. "
            f"Body snippet: {body[:200]!r}"
        )
