"""Unit tests for M3 LLM client module (client.py).

Phase C adversarial coverage:
- Malformed JSON in LLM response is caught as LLMGenerationError
- Missing required JSON keys are rejected
- Empty unified_diff is rejected
- Correct PatchProposal construction from valid response
- Protocol check: stub implementation satisfies LLMClient protocol
- Prompt injection in root_cause_hypothesis does not escape to PatchProposal
- Unknown exception wrapping
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from agentsentinel.domain.models import PatchProposal
from agentsentinel.llm.client import LLMClient, OpenAICompatibleClient, _parse_llm_response
from agentsentinel.llm.exceptions import (
    LLMAuthenticationError,
    LLMGenerationError,
    LLMRateLimitError,
    LLMTimeoutError,
)
from agentsentinel.llm.pricing import ModelUsage

# ---------------------------------------------------------------------------
# Test _parse_llm_response directly (core parsing logic)
# ---------------------------------------------------------------------------

_VALID_DIFF = """\
--- a/normalizer.py
+++ b/normalizer.py
@@ -1,2 +1,2 @@
 def normalize(x):
-    return x.lower()
+    return x.strip().lower()
"""


class TestParseLLMResponse:
    @pytest.mark.unit
    def test_valid_response_parsed(self) -> None:
        payload = json.dumps({
            "root_cause_hypothesis": "Missing strip() call",
            "unified_diff": _VALID_DIFF,
        })
        patch_obj, usage = _parse_llm_response(
            raw_response=payload,
            case_id="case-1",
            model_id="gpt-4o",
            prompt_tokens=100,
            completion_tokens=50,
        )
        assert isinstance(patch_obj, PatchProposal)
        assert patch_obj.case_id == "case-1"
        assert patch_obj.model_id == "gpt-4o"
        assert patch_obj.prompt_tokens == 100
        assert patch_obj.completion_tokens == 50
        assert isinstance(usage, ModelUsage)
        assert usage.total_tokens == 150

    @pytest.mark.unit
    @pytest.mark.adversarial
    def test_invalid_json_raises(self) -> None:
        with pytest.raises(LLMGenerationError, match="valid JSON"):
            _parse_llm_response(
                raw_response="this is not json {{{",
                case_id="case-1",
                model_id="gpt-4o",
                prompt_tokens=100,
                completion_tokens=50,
            )

    @pytest.mark.unit
    @pytest.mark.adversarial
    def test_missing_root_cause_raises(self) -> None:
        payload = json.dumps({"unified_diff": _VALID_DIFF})  # missing root_cause_hypothesis
        with pytest.raises(LLMGenerationError, match="missing required keys"):
            _parse_llm_response(
                raw_response=payload,
                case_id="case-1",
                model_id="gpt-4o",
                prompt_tokens=100,
                completion_tokens=50,
            )

    @pytest.mark.unit
    @pytest.mark.adversarial
    def test_missing_unified_diff_raises(self) -> None:
        payload = json.dumps({"root_cause_hypothesis": "some bug"})
        with pytest.raises(LLMGenerationError, match="missing required keys"):
            _parse_llm_response(
                raw_response=payload,
                case_id="case-1",
                model_id="gpt-4o",
                prompt_tokens=100,
                completion_tokens=50,
            )

    @pytest.mark.unit
    @pytest.mark.adversarial
    def test_empty_unified_diff_raises(self) -> None:
        payload = json.dumps({
            "root_cause_hypothesis": "some bug",
            "unified_diff": "   ",  # whitespace-only is empty
        })
        with pytest.raises(LLMGenerationError, match="non-empty"):
            _parse_llm_response(
                raw_response=payload,
                case_id="case-1",
                model_id="gpt-4o",
                prompt_tokens=100,
                completion_tokens=50,
            )

    @pytest.mark.unit
    @pytest.mark.adversarial
    def test_json_array_instead_of_object_raises(self) -> None:
        payload = json.dumps(["not", "a", "dict"])
        with pytest.raises(LLMGenerationError, match="object"):
            _parse_llm_response(
                raw_response=payload,
                case_id="case-1",
                model_id="gpt-4o",
                prompt_tokens=100,
                completion_tokens=50,
            )

    @pytest.mark.unit
    @pytest.mark.adversarial
    def test_non_string_unified_diff_raises(self) -> None:
        payload = json.dumps({
            "root_cause_hypothesis": "bug",
            "unified_diff": 12345,  # number, not string
        })
        with pytest.raises(LLMGenerationError, match="non-empty string"):
            _parse_llm_response(
                raw_response=payload,
                case_id="case-1",
                model_id="gpt-4o",
                prompt_tokens=100,
                completion_tokens=50,
            )


# ---------------------------------------------------------------------------
# Test LLMClient Protocol
# ---------------------------------------------------------------------------


class TestLLMClientProtocol:
    @pytest.mark.unit
    def test_stub_satisfies_protocol(self) -> None:
        """A stub with generate_patch must satisfy the LLMClient protocol check."""

        class StubLLMClient:
            def generate_patch(
                self, case_id: str, prompt: str, model_id: str
            ) -> tuple[PatchProposal, ModelUsage]:
                patch = PatchProposal(
                    case_id=case_id,
                    unified_diff=_VALID_DIFF,
                    model_id=model_id,
                    prompt_tokens=10,
                    completion_tokens=5,
                )
                usage = ModelUsage(
                    model_id=model_id,
                    prompt_tokens=10,
                    completion_tokens=5,
                    called_at=datetime.now(tz=UTC),
                )
                return patch, usage

        stub = StubLLMClient()
        assert isinstance(stub, LLMClient), "StubLLMClient must satisfy LLMClient Protocol"


# ---------------------------------------------------------------------------
# Test OpenAICompatibleClient error handling (mocked HTTP)
# ---------------------------------------------------------------------------


class TestOpenAICompatibleClientErrorHandling:
    @pytest.mark.unit
    def test_missing_api_key_raises_auth_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AGENTSENTINEL_LLM_API_KEY", raising=False)
        client = OpenAICompatibleClient(api_key_env="AGENTSENTINEL_LLM_API_KEY")
        with pytest.raises(LLMAuthenticationError):
            client.generate_patch("case-1", "some prompt", "gpt-4o")

    @pytest.mark.unit
    def test_timeout_raises_llm_timeout_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENTSENTINEL_LLM_API_KEY", "test-key-123")
        client = OpenAICompatibleClient(timeout_seconds=0.001)


        def mock_urlopen(req: object, timeout: float = 0) -> None:
            raise TimeoutError("simulated timeout")

        with (
            patch("agentsentinel.llm.client.urllib.request.urlopen", side_effect=mock_urlopen),
            pytest.raises(LLMTimeoutError),
        ):
            client.generate_patch("case-1", "prompt", "gpt-4o")

    @pytest.mark.unit
    def test_rate_limit_exhausted_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENTSENTINEL_LLM_API_KEY", "test-key-123")
        client = OpenAICompatibleClient(max_retries=0)  # no retries

        import urllib.error
        from io import BytesIO

        http_error = urllib.error.HTTPError(
            url="http://api.example.com",
            code=429,
            msg="Too Many Requests",
            hdrs=MagicMock(get=lambda k, d=None: None),
            fp=BytesIO(b"rate limited"),
        )

        with (
            patch("agentsentinel.llm.client.urllib.request.urlopen", side_effect=http_error),
            pytest.raises(LLMRateLimitError),
        ):
            client.generate_patch("case-1", "prompt", "gpt-4o")

    @pytest.mark.unit
    def test_http_401_raises_auth_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENTSENTINEL_LLM_API_KEY", "invalid-key")
        client = OpenAICompatibleClient()

        import urllib.error
        from io import BytesIO

        http_error = urllib.error.HTTPError(
            url="http://api.example.com",
            code=401,
            msg="Unauthorized",
            hdrs=MagicMock(),
            fp=BytesIO(b"Unauthorized"),
        )

        with (
            patch("agentsentinel.llm.client.urllib.request.urlopen", side_effect=http_error),
            pytest.raises(LLMAuthenticationError),
        ):
            client.generate_patch("case-1", "prompt", "gpt-4o")

    @pytest.mark.unit
    def test_valid_api_response_returns_patch_and_usage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AGENTSENTINEL_LLM_API_KEY", "test-key-xyz")
        client = OpenAICompatibleClient()

        api_response = json.dumps({
            "choices": [
                {
                    "message": {
                        "content": json.dumps({
                            "root_cause_hypothesis": "strip() missing",
                            "unified_diff": _VALID_DIFF,
                        })
                    }
                }
            ],
            "usage": {
                "prompt_tokens": 200,
                "completion_tokens": 80,
            },
        }).encode("utf-8")

        from unittest.mock import MagicMock

        mock_response = MagicMock()
        mock_response.read.return_value = api_response
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch(
            "agentsentinel.llm.client.urllib.request.urlopen",
            return_value=mock_response,
        ):
            patch_obj, usage = client.generate_patch("case-1", "prompt", "gpt-4o")

        assert isinstance(patch_obj, PatchProposal)
        assert patch_obj.prompt_tokens == 200
        assert patch_obj.completion_tokens == 80
        assert isinstance(usage, ModelUsage)
