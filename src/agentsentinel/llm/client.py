"""LLM client interface and concrete OpenAI-compatible REST implementation.

Architecture:
- ``LLMClient`` is a ``Protocol`` (structural typing) for clean dependency injection
  and testing with stub/mock implementations.
- ``OpenAICompatibleClient`` is a concrete implementation using Python's standard
  ``urllib.request`` (no heavy SDK required).  It supports any OpenAI-compatible
  API endpoint including OpenAI, OpenRouter, and any compatible gateway.
- ``GeminiClient`` implements the Google Gemini REST API (generateContent endpoint).
- Both clients enforce strict timeout, parse structured JSON output into a
  ``PatchProposal``, and map all failure modes to typed ``LLMError`` exceptions.

Security:
- API keys are read ONLY from environment variables (``AGENTSENTINEL_LLM_API_KEY``
  or provider-specific equivalents).  Never accept keys from untrusted input.
- No sensitive data (API keys, repo URLs) is logged or included in exceptions.
- All HTTP responses are decoded with ``errors="replace"`` to prevent encoding attacks.

Retry policy:
- Rate limits (429) are retried up to ``max_retries`` times with exponential
  backoff capped at 60 seconds.
- Server errors (5xx) are retried once.
- Client errors (4xx, except 429) and parse failures are NOT retried.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from agentsentinel.domain.models import PatchProposal
from agentsentinel.llm.exceptions import (
    LLMAuthenticationError,
    LLMGenerationError,
    LLMRateLimitError,
    LLMServerError,
    LLMTimeoutError,
)
from agentsentinel.llm.pricing import ModelUsage, PricingRegistry

_DEFAULT_TIMEOUT = 90.0
_DEFAULT_MAX_RETRIES = 2
_BACKOFF_BASE = 2.0
_BACKOFF_CAP = 60.0

_REGISTRY = PricingRegistry()


# ---------------------------------------------------------------------------
# Protocol — structural typing for dependency injection
# ---------------------------------------------------------------------------


@runtime_checkable
class LLMClient(Protocol):
    """Structural protocol for LLM clients.

    Any object implementing ``generate_patch`` satisfies this protocol,
    enabling stub/mock injection in tests without inheritance.
    """

    def generate_patch(
        self,
        case_id: str,
        prompt: str,
        model_id: str,
    ) -> tuple[PatchProposal, ModelUsage]:
        """Generate a patch proposal from the given prompt.

        Parameters
        ----------
        case_id:
            The ``CaseSpec.case_id`` this patch is for.
        prompt:
            The complete repair prompt assembled by ``PromptBuilder``.
        model_id:
            Provider-scoped model identifier.

        Returns
        -------
        tuple[PatchProposal, ModelUsage]
            The parsed patch proposal and the token usage record for cost accounting.

        Raises
        ------
        LLMGenerationError
            If the response cannot be parsed as a valid ``PatchProposal``.
        LLMTimeoutError
            If the API call exceeds the configured timeout.
        LLMRateLimitError
            If the provider returns HTTP 429.
        LLMAuthenticationError
            If the provider returns HTTP 401 or 403.
        LLMServerError
            If the provider returns HTTP 5xx.
        """
        ...


# ---------------------------------------------------------------------------
# Shared response-parsing logic
# ---------------------------------------------------------------------------


def _parse_llm_response(
    raw_response: str,
    case_id: str,
    model_id: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> tuple[PatchProposal, ModelUsage]:
    """Parse a raw JSON LLM response into a ``PatchProposal`` and ``ModelUsage``.

    Parameters
    ----------
    raw_response:
        Raw string returned by the LLM (should be a JSON object).
    case_id:
        Case ID to embed in the ``PatchProposal``.
    model_id:
        Model ID for the ``PatchProposal`` and ``ModelUsage``.
    prompt_tokens:
        Prompt token count from the API response.
    completion_tokens:
        Completion token count from the API response.

    Returns
    -------
    tuple[PatchProposal, ModelUsage]

    Raises
    ------
    LLMGenerationError
        If JSON parsing fails, required keys are missing, or the diff is empty.
    """
    try:
        data = json.loads(raw_response.strip())
    except json.JSONDecodeError as exc:
        raise LLMGenerationError(
            f"Response is not valid JSON: {exc}",
            raw_response=raw_response,
        ) from exc

    if not isinstance(data, dict):
        raise LLMGenerationError(
            "Response JSON must be a top-level object (dict)",
            raw_response=raw_response,
        )

    missing = [k for k in ("root_cause_hypothesis", "unified_diff") if k not in data]
    if missing:
        raise LLMGenerationError(
            f"Response missing required keys: {missing!r}",
            raw_response=raw_response,
        )

    unified_diff = data["unified_diff"]
    if not isinstance(unified_diff, str) or not unified_diff.strip():
        raise LLMGenerationError(
            "unified_diff must be a non-empty string",
            raw_response=raw_response,
        )

    root_cause = data["root_cause_hypothesis"]
    if not isinstance(root_cause, str):
        raise LLMGenerationError(
            "root_cause_hypothesis must be a string",
            raw_response=raw_response,
        )

    try:
        patch = PatchProposal(
            case_id=case_id,
            unified_diff=unified_diff,
            model_id=model_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
    except ValueError as exc:
        raise LLMGenerationError(
            f"PatchProposal construction failed: {exc}",
            raw_response=raw_response,
        ) from exc

    usage = ModelUsage(
        model_id=model_id,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        called_at=datetime.now(tz=UTC),
    )
    return patch, usage


# ---------------------------------------------------------------------------
# OpenAI-compatible client (OpenAI, OpenRouter, any compatible gateway)
# ---------------------------------------------------------------------------


@dataclass
class OpenAICompatibleClient:
    """Concrete LLM client for OpenAI-compatible REST APIs.

    Supports OpenAI, OpenRouter, Groq, and any gateway implementing the
    ``/v1/chat/completions`` endpoint.

    Parameters
    ----------
    base_url:
        API base URL (e.g. ``"https://api.openai.com/v1"``).
    api_key_env:
        Name of the environment variable holding the API key.
    timeout_seconds:
        HTTP request timeout in seconds.
    max_retries:
        Maximum number of retries for rate-limit (429) responses.
    temperature:
        Sampling temperature. Use 0.0 for deterministic output.
    max_completion_tokens:
        Maximum tokens to generate.
    """

    base_url: str = "https://api.openai.com/v1"
    api_key_env: str = "AGENTSENTINEL_LLM_API_KEY"
    timeout_seconds: float = _DEFAULT_TIMEOUT
    max_retries: int = _DEFAULT_MAX_RETRIES
    temperature: float = 0.0
    max_completion_tokens: int = 4096

    def _get_api_key(self) -> str:
        key = os.environ.get(self.api_key_env, "").strip()
        if not key:
            raise LLMAuthenticationError(model_id="(unknown)")
        return key

    def generate_patch(
        self,
        case_id: str,
        prompt: str,
        model_id: str,
    ) -> tuple[PatchProposal, ModelUsage]:
        """Send a repair prompt and parse the response into a ``PatchProposal``."""
        api_key = self._get_api_key()
        url = f"{self.base_url.rstrip('/')}/chat/completions"

        payload = json.dumps({
            "model": model_id,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature,
            "max_completion_tokens": self.max_completion_tokens,
            "response_format": {"type": "json_object"},
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }

        attempt = 0
        while True:
            try:
                req = urllib.request.Request(url, data=payload, headers=headers, method="POST")  # noqa: S310
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:  # noqa: S310
                    raw_body = resp.read().decode("utf-8", errors="replace")
            except TimeoutError as exc:
                raise LLMTimeoutError(self.timeout_seconds, model_id) from exc
            except urllib.error.HTTPError as exc:
                status = exc.code
                body = exc.read().decode("utf-8", errors="replace")[:500]

                if status in (401, 403):
                    raise LLMAuthenticationError(model_id) from exc
                if status == 429:
                    retry_after: float | None = None
                    with contextlib.suppress(TypeError, ValueError):
                        retry_after = float(exc.headers.get("Retry-After", 0))
                    if attempt < self.max_retries:
                        wait = min((_BACKOFF_BASE**attempt) + (retry_after or 0), _BACKOFF_CAP)
                        time.sleep(wait)
                        attempt += 1
                        continue
                    raise LLMRateLimitError(model_id, retry_after) from exc
                if status >= 500:  # noqa: PLR2004
                    if attempt < 1:
                        time.sleep(2.0)
                        attempt += 1
                        continue
                    raise LLMServerError(model_id, status, body) from exc
                # Other 4xx
                raise LLMGenerationError(
                    f"HTTP {status} error from API",
                    raw_response=body,
                ) from exc
            except urllib.error.URLError as exc:
                raise LLMGenerationError(
                    f"Network error reaching LLM API: {exc.reason}",
                    raw_response="",
                ) from exc

            try:
                resp_data = json.loads(raw_body)
            except json.JSONDecodeError as exc:
                raise LLMGenerationError(
                    f"API response is not valid JSON: {exc}",
                    raw_response=raw_body,
                ) from exc

            # Extract text content
            try:
                content = resp_data["choices"][0]["message"]["content"]
                usage = resp_data.get("usage", {})
                prompt_tokens = int(usage.get("prompt_tokens", 0))
                completion_tokens = int(usage.get("completion_tokens", 0))
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise LLMGenerationError(
                    f"Unexpected API response structure: {exc}",
                    raw_response=raw_body,
                ) from exc

            return _parse_llm_response(
                raw_response=content,
                case_id=case_id,
                model_id=model_id,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )


# ---------------------------------------------------------------------------
# Gemini REST client (google.generativeai-style generateContent endpoint)
# ---------------------------------------------------------------------------


@dataclass
class GeminiClient:
    """Concrete LLM client for the Google Gemini REST API (generateContent).

    Parameters
    ----------
    api_key_env:
        Name of the environment variable holding the Gemini API key.
    timeout_seconds:
        HTTP request timeout in seconds.
    max_retries:
        Maximum number of retries for rate-limit (429) responses.
    temperature:
        Sampling temperature.
    max_output_tokens:
        Maximum tokens to generate.
    """

    api_key_env: str = "GEMINI_API_KEY"
    timeout_seconds: float = _DEFAULT_TIMEOUT
    max_retries: int = _DEFAULT_MAX_RETRIES
    temperature: float = 0.0
    max_output_tokens: int = 4096

    _GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

    def _get_api_key(self) -> str:
        key = os.environ.get(self.api_key_env, "").strip()
        if not key:
            raise LLMAuthenticationError(model_id="(gemini)")
        return key

    def generate_patch(
        self,
        case_id: str,
        prompt: str,
        model_id: str,
    ) -> tuple[PatchProposal, ModelUsage]:
        """Send a repair prompt to Gemini and parse the response."""
        api_key = self._get_api_key()
        url = (
            f"{self._GEMINI_BASE}/{model_id}:generateContent?key={api_key}"
        )

        payload = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_output_tokens,
                "responseMimeType": "application/json",
            },
        }).encode("utf-8")

        headers = {"Content-Type": "application/json"}

        attempt = 0
        while True:
            try:
                req = urllib.request.Request(url, data=payload, headers=headers, method="POST")  # noqa: S310
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:  # noqa: S310
                    raw_body = resp.read().decode("utf-8", errors="replace")
            except TimeoutError as exc:
                raise LLMTimeoutError(self.timeout_seconds, model_id) from exc
            except urllib.error.HTTPError as exc:
                status = exc.code
                body = exc.read().decode("utf-8", errors="replace")[:500]

                if status in (401, 403):
                    raise LLMAuthenticationError(model_id) from exc
                if status == 429:  # noqa: PLR2004
                    if attempt < self.max_retries:
                        wait = min(_BACKOFF_BASE**attempt, _BACKOFF_CAP)
                        time.sleep(wait)
                        attempt += 1
                        continue
                    raise LLMRateLimitError(model_id) from exc
                if status >= 500:  # noqa: PLR2004
                    if attempt < 1:
                        time.sleep(2.0)
                        attempt += 1
                        continue
                    raise LLMServerError(model_id, status, body) from exc
                raise LLMGenerationError(
                    f"HTTP {status} error from Gemini API", raw_response=body
                ) from exc
            except urllib.error.URLError as exc:
                raise LLMGenerationError(
                    f"Network error reaching Gemini API: {exc.reason}", raw_response=""
                ) from exc

            try:
                resp_data = json.loads(raw_body)
            except json.JSONDecodeError as exc:
                raise LLMGenerationError(
                    f"Gemini API response not valid JSON: {exc}", raw_response=raw_body
                ) from exc

            try:
                content = resp_data["candidates"][0]["content"]["parts"][0]["text"]
                usage_meta = resp_data.get("usageMetadata", {})
                prompt_tokens = int(usage_meta.get("promptTokenCount", 0))
                completion_tokens = int(usage_meta.get("candidatesTokenCount", 0))
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise LLMGenerationError(
                    f"Unexpected Gemini API response structure: {exc}",
                    raw_response=raw_body,
                ) from exc

            return _parse_llm_response(
                raw_response=content,
                case_id=case_id,
                model_id=model_id,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )
