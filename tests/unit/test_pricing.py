"""Unit tests for M3 LLM pricing module (pricing.py).

Phase C adversarial coverage:
- Unknown model MUST return None costs (never 0.0)
- Negative token counts are rejected
- CostEstimate invariant: all-None or all-set (never partial)
- Cached token count > prompt tokens is rejected
- Correct cost arithmetic for priced models
- Cached-token discount is applied correctly
"""

from __future__ import annotations

import pytest

from agentsentinel.llm.pricing import (
    CostEstimate,
    ModelPrice,
    ModelUsage,
    PricingRegistry,
)


class TestModelUsage:
    @pytest.mark.unit
    def test_valid_construction(self) -> None:
        usage = ModelUsage(
            model_id="gemini-2.5-flash",
            prompt_tokens=1000,
            completion_tokens=500,
        )
        assert usage.total_tokens == 1500

    @pytest.mark.unit
    def test_negative_prompt_tokens_rejected(self) -> None:
        with pytest.raises(ValueError, match="≥ 0"):
            ModelUsage(model_id="gpt-4o", prompt_tokens=-1, completion_tokens=10)

    @pytest.mark.unit
    def test_negative_completion_tokens_rejected(self) -> None:
        with pytest.raises(ValueError, match="≥ 0"):
            ModelUsage(model_id="gpt-4o", prompt_tokens=10, completion_tokens=-1)

    @pytest.mark.unit
    def test_cached_tokens_exceeds_prompt_rejected(self) -> None:
        with pytest.raises(ValueError, match="cached_tokens"):
            ModelUsage(
                model_id="gpt-4o",
                prompt_tokens=100,
                completion_tokens=50,
                cached_tokens=200,  # more than prompt_tokens
            )

    @pytest.mark.unit
    def test_reasoning_tokens_exceeds_completion_rejected(self) -> None:
        with pytest.raises(ValueError, match="reasoning_tokens"):
            ModelUsage(
                model_id="o1",
                prompt_tokens=100,
                completion_tokens=50,
                reasoning_tokens=100,  # more than completion_tokens
            )

    @pytest.mark.unit
    def test_empty_model_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="model_id"):
            ModelUsage(model_id="  ", prompt_tokens=10, completion_tokens=5)

    @pytest.mark.unit
    def test_zero_tokens_are_valid(self) -> None:
        usage = ModelUsage(model_id="gpt-4o-mini", prompt_tokens=0, completion_tokens=0)
        assert usage.total_tokens == 0


class TestCostEstimate:
    @pytest.mark.unit
    def test_all_none_is_valid_unpriced(self) -> None:
        usage = ModelUsage(model_id="unknown-model-x", prompt_tokens=100, completion_tokens=50)
        est = CostEstimate(
            usage=usage,
            prompt_cost_usd=None,
            completion_cost_usd=None,
            total_cost_usd=None,
        )
        assert est.is_unpriced is True

    @pytest.mark.unit
    def test_all_set_is_valid_priced(self) -> None:
        usage = ModelUsage(model_id="gpt-4o", prompt_tokens=1000, completion_tokens=500)
        est = CostEstimate(
            usage=usage,
            prompt_cost_usd=0.0025,
            completion_cost_usd=0.005,
            total_cost_usd=0.0075,
        )
        assert est.is_unpriced is False

    @pytest.mark.unit
    @pytest.mark.adversarial
    def test_partial_none_violates_invariant(self) -> None:
        """CRITICAL: partial None/non-None mix must be rejected."""
        usage = ModelUsage(model_id="gpt-4o", prompt_tokens=1000, completion_tokens=500)
        with pytest.raises(ValueError, match="invariant"):
            CostEstimate(
                usage=usage,
                prompt_cost_usd=0.0025,
                completion_cost_usd=None,   # partial None — FORBIDDEN
                total_cost_usd=0.0075,
            )

    @pytest.mark.unit
    @pytest.mark.adversarial
    def test_total_mismatch_rejected(self) -> None:
        usage = ModelUsage(model_id="gpt-4o", prompt_tokens=1000, completion_tokens=500)
        with pytest.raises(ValueError, match="total_cost_usd"):
            CostEstimate(
                usage=usage,
                prompt_cost_usd=0.0025,
                completion_cost_usd=0.005,
                total_cost_usd=0.999,  # wrong total
            )


class TestPricingRegistry:
    @pytest.mark.unit
    def test_known_model_returns_price(self) -> None:
        registry = PricingRegistry()
        price = registry.get_price("gpt-4o")
        assert price is not None
        assert price.prompt_usd_per_mtok == 2.50
        assert price.completion_usd_per_mtok == 10.00

    @pytest.mark.unit
    def test_unknown_model_returns_none(self) -> None:
        registry = PricingRegistry()
        price = registry.get_price("completely-unknown-model-xyz")
        assert price is None

    @pytest.mark.unit
    @pytest.mark.adversarial
    def test_unknown_model_estimate_is_all_none_not_zero(self) -> None:
        """CRITICAL invariant: unknown model cost must be None, NEVER 0.0."""
        registry = PricingRegistry()
        usage = ModelUsage(
            model_id="some-future-secret-model-v99",
            prompt_tokens=100_000,
            completion_tokens=50_000,
        )
        estimate = registry.estimate_cost(usage)

        # ALL three must be None — never silently zero
        assert estimate.prompt_cost_usd is None, (
            "INVARIANT VIOLATED: prompt_cost_usd must be None for unknown model, not 0.0"
        )
        assert estimate.completion_cost_usd is None, (
            "INVARIANT VIOLATED: completion_cost_usd must be None for unknown model, not 0.0"
        )
        assert estimate.total_cost_usd is None, (
            "INVARIANT VIOLATED: total_cost_usd must be None for unknown model, not 0.0"
        )
        assert estimate.is_unpriced is True

    @pytest.mark.unit
    def test_cost_arithmetic_is_correct(self) -> None:
        """Verify cost calculation: (tokens / 1_000_000) * price."""
        registry = PricingRegistry()
        usage = ModelUsage(
            model_id="gpt-4o",
            prompt_tokens=1_000_000,  # exactly 1M → $2.50
            completion_tokens=1_000_000,  # exactly 1M → $10.00
        )
        estimate = registry.estimate_cost(usage)
        assert estimate.prompt_cost_usd == pytest.approx(2.50, abs=1e-6)
        assert estimate.completion_cost_usd == pytest.approx(10.00, abs=1e-6)
        assert estimate.total_cost_usd == pytest.approx(12.50, abs=1e-6)

    @pytest.mark.unit
    def test_cached_token_discount_applied(self) -> None:
        """Cached tokens are billed at discount rate, non-cached at full rate."""
        registry = PricingRegistry()
        # gpt-4o: prompt=$2.50/MTok, cached=$1.25/MTok
        usage = ModelUsage(
            model_id="gpt-4o",
            prompt_tokens=2_000_000,   # 2M total prompt
            completion_tokens=0,
            cached_tokens=1_000_000,   # 1M from cache, 1M fresh
        )
        estimate = registry.estimate_cost(usage)
        # 1M fresh @ $2.50/MTok = $2.50
        # 1M cached @ $1.25/MTok = $1.25
        expected_prompt = 2.50 + 1.25
        assert estimate.prompt_cost_usd == pytest.approx(expected_prompt, abs=1e-6)

    @pytest.mark.unit
    def test_caller_supplied_price_overrides_builtin(self) -> None:
        """Extra prices supplied at construction override built-in registry entries."""
        custom = ModelPrice(
            model_id="gpt-4o",
            prompt_usd_per_mtok=99.99,
            completion_usd_per_mtok=199.99,
        )
        registry = PricingRegistry(extra_prices=(custom,))
        price = registry.get_price("gpt-4o")
        assert price is not None
        assert price.prompt_usd_per_mtok == 99.99

    @pytest.mark.unit
    def test_gemini_models_are_in_registry(self) -> None:
        registry = PricingRegistry()
        for model in ("gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash",
                      "gemini-1.5-pro", "gemini-1.5-flash"):
            assert registry.get_price(model) is not None, f"Missing: {model}"

    @pytest.mark.unit
    def test_anthropic_models_are_in_registry(self) -> None:
        registry = PricingRegistry()
        for model in ("claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022",
                      "claude-3-opus-20240229"):
            assert registry.get_price(model) is not None, f"Missing: {model}"

    @pytest.mark.unit
    def test_known_models_returns_all_ids(self) -> None:
        registry = PricingRegistry()
        known = registry.known_models()
        assert len(known) > 10  # sanity check
        assert "gpt-4o" in known
        assert "gemini-2.5-pro" in known
