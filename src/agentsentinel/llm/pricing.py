"""Token/cost accounting and model pricing registry for AgentSentinel.

Design invariants:
- ``ModelUsage`` is immutable (``frozen=True``) to prevent silent mutation
  of cost records across retries.
- Unknown usage or unpriced model MUST be recorded as ``None``, NEVER silently
  coerced to ``0.0``.  Callers that need a zero must explicitly check and
  substitute themselves.
- ``PricingRegistry`` uses a dated registry so pricing can be versioned and
  audited; stale entries are surfaced, not suppressed.
- All monetary values are in US dollars per million tokens (USD/MTok),
  consistent with API provider conventions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final

# ---------------------------------------------------------------------------
# ModelUsage — immutable record of a single LLM call's token consumption
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelUsage:
    """Immutable record of token consumption for a single LLM inference call.

    Attributes
    ----------
    model_id:
        Provider-scoped model identifier (e.g. ``"gemini-2.5-flash"``).
    prompt_tokens:
        Number of tokens in the prompt (input context).
    completion_tokens:
        Number of tokens in the completion (output).
    cached_tokens:
        Number of prompt tokens served from the provider's prompt cache
        (counted at a discounted rate).  ``None`` if not reported.
    reasoning_tokens:
        Tokens consumed by internal chain-of-thought reasoning (varies by
        provider).  ``None`` if not applicable.
    called_at:
        UTC timestamp of when this LLM call completed.

    Invariants
    ----------
    - ``prompt_tokens`` and ``completion_tokens`` must be ≥ 0.
    - ``cached_tokens`` must be ≤ ``prompt_tokens`` when set.
    - ``reasoning_tokens`` must be ≤ ``completion_tokens`` when set.
    """

    model_id: str
    prompt_tokens: int
    completion_tokens: int
    cached_tokens: int | None = None
    reasoning_tokens: int | None = None
    called_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))

    def __post_init__(self) -> None:
        if self.prompt_tokens < 0 or self.completion_tokens < 0:
            raise ValueError(
                f"Token counts must be ≥ 0, got prompt={self.prompt_tokens}, "
                f"completion={self.completion_tokens}"
            )
        if self.cached_tokens is not None and (
            self.cached_tokens < 0 or self.cached_tokens > self.prompt_tokens
        ):
            raise ValueError(
                f"cached_tokens ({self.cached_tokens}) must be in "
                f"[0, prompt_tokens={self.prompt_tokens}]"
            )
        if self.reasoning_tokens is not None and (
            self.reasoning_tokens < 0 or self.reasoning_tokens > self.completion_tokens
        ):
            raise ValueError(
                f"reasoning_tokens ({self.reasoning_tokens}) must be in "
                f"[0, completion_tokens={self.completion_tokens}]"
            )
        if not self.model_id.strip():
            raise ValueError("model_id must be a non-empty string")

    @property
    def total_tokens(self) -> int:
        """Total tokens consumed (prompt + completion)."""
        return self.prompt_tokens + self.completion_tokens


# ---------------------------------------------------------------------------
# ModelPrice — a dated pricing entry for a single model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelPrice:
    """USD pricing for a single model at a specific date.

    All prices are in US dollars per **million** tokens (USD/MTok).

    Attributes
    ----------
    model_id:
        Provider-scoped model identifier (must match ``ModelUsage.model_id``).
    prompt_usd_per_mtok:
        Cost per million input (prompt) tokens.
    completion_usd_per_mtok:
        Cost per million output (completion) tokens.
    cached_prompt_usd_per_mtok:
        Cost per million *cached* input tokens.  If ``None``, prompt tokens
        that hit the cache are still billed at ``prompt_usd_per_mtok``.
    effective_date:
        UTC date from which this pricing is valid.  Enables audit trails when
        pricing changes.
    """

    model_id: str
    prompt_usd_per_mtok: float
    completion_usd_per_mtok: float
    cached_prompt_usd_per_mtok: float | None = None
    effective_date: datetime = field(
        default_factory=lambda: datetime(2025, 1, 1, tzinfo=UTC)
    )

    def __post_init__(self) -> None:
        if self.prompt_usd_per_mtok < 0 or self.completion_usd_per_mtok < 0:
            raise ValueError("Pricing values must be ≥ 0")
        if (
            self.cached_prompt_usd_per_mtok is not None
            and self.cached_prompt_usd_per_mtok < 0
        ):
            raise ValueError("cached_prompt_usd_per_mtok must be ≥ 0")


# ---------------------------------------------------------------------------
# CostEstimate — result of pricing a ModelUsage record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CostEstimate:
    """Immutable cost estimate for a single LLM call.

    Attributes
    ----------
    usage:
        The ``ModelUsage`` record this estimate was computed from.
    prompt_cost_usd:
        USD cost for prompt tokens.  ``None`` if model is unpriced.
    completion_cost_usd:
        USD cost for completion tokens.  ``None`` if model is unpriced.
    total_cost_usd:
        Sum of prompt + completion costs.  ``None`` if model is unpriced.
    is_estimated:
        ``True`` if pricing data is approximate or extrapolated.

    Invariants
    ----------
    - If the model is unpriced, ALL three cost fields MUST be ``None``.
      NEVER silently coerce to ``0.0``.
    """

    usage: ModelUsage
    prompt_cost_usd: float | None
    completion_cost_usd: float | None
    total_cost_usd: float | None
    is_estimated: bool = False

    def __post_init__(self) -> None:
        costs = (self.prompt_cost_usd, self.completion_cost_usd, self.total_cost_usd)
        all_none = all(c is None for c in costs)
        all_set = all(c is not None for c in costs)
        if not (all_none or all_set):
            raise ValueError(
                "CostEstimate invariant violated: cost fields must be ALL None "
                "(unpriced model) or ALL set (priced model). "
                f"Got: prompt={self.prompt_cost_usd}, "
                f"completion={self.completion_cost_usd}, total={self.total_cost_usd}"
            )
        if all_set:
            p = self.prompt_cost_usd
            c = self.completion_cost_usd
            t = self.total_cost_usd
            assert p is not None and c is not None and t is not None  # for type narrowing
            if p < 0 or c < 0:
                raise ValueError("Cost values must be ≥ 0")
            # Allow small floating-point rounding tolerance (1 micro-dollar)
            if abs(t - (p + c)) > 1e-6:
                raise ValueError(
                    f"total_cost_usd ({t}) != prompt + completion ({p + c})"
                )

    @property
    def is_unpriced(self) -> bool:
        """True if this model has no pricing data and cost is unknown."""
        return self.total_cost_usd is None


# ---------------------------------------------------------------------------
# PricingRegistry — dated catalog of model prices
# ---------------------------------------------------------------------------

# Pricing as of 2025 Q4 — USD per million tokens.
# Sources: official provider pricing pages (Gemini, OpenAI, Anthropic).
# CRITICAL: Update this registry when provider pricing changes.
_BUILT_IN_PRICES: Final[tuple[ModelPrice, ...]] = (
    # ── Google Gemini ──────────────────────────────────────────────────────
    ModelPrice(
        model_id="gemini-2.5-pro",
        prompt_usd_per_mtok=1.25,
        completion_usd_per_mtok=10.00,
        cached_prompt_usd_per_mtok=0.31,
        effective_date=datetime(2025, 5, 1, tzinfo=UTC),
    ),
    ModelPrice(
        model_id="gemini-2.5-flash",
        prompt_usd_per_mtok=0.30,
        completion_usd_per_mtok=2.50,
        cached_prompt_usd_per_mtok=0.075,
        effective_date=datetime(2025, 5, 1, tzinfo=UTC),
    ),
    ModelPrice(
        model_id="gemini-2.0-flash",
        prompt_usd_per_mtok=0.10,
        completion_usd_per_mtok=0.40,
        cached_prompt_usd_per_mtok=0.025,
        effective_date=datetime(2025, 2, 1, tzinfo=UTC),
    ),
    ModelPrice(
        model_id="gemini-1.5-pro",
        prompt_usd_per_mtok=1.25,
        completion_usd_per_mtok=5.00,
        cached_prompt_usd_per_mtok=0.3125,
        effective_date=datetime(2024, 9, 1, tzinfo=UTC),
    ),
    ModelPrice(
        model_id="gemini-1.5-flash",
        prompt_usd_per_mtok=0.075,
        completion_usd_per_mtok=0.30,
        cached_prompt_usd_per_mtok=0.01875,
        effective_date=datetime(2024, 9, 1, tzinfo=UTC),
    ),
    # ── OpenAI ────────────────────────────────────────────────────────────
    ModelPrice(
        model_id="gpt-4o",
        prompt_usd_per_mtok=2.50,
        completion_usd_per_mtok=10.00,
        cached_prompt_usd_per_mtok=1.25,
        effective_date=datetime(2024, 10, 1, tzinfo=UTC),
    ),
    ModelPrice(
        model_id="gpt-4o-mini",
        prompt_usd_per_mtok=0.15,
        completion_usd_per_mtok=0.60,
        cached_prompt_usd_per_mtok=0.075,
        effective_date=datetime(2024, 7, 1, tzinfo=UTC),
    ),
    ModelPrice(
        model_id="o1",
        prompt_usd_per_mtok=15.00,
        completion_usd_per_mtok=60.00,
        cached_prompt_usd_per_mtok=7.50,
        effective_date=datetime(2024, 12, 1, tzinfo=UTC),
    ),
    ModelPrice(
        model_id="o3-mini",
        prompt_usd_per_mtok=1.10,
        completion_usd_per_mtok=4.40,
        cached_prompt_usd_per_mtok=0.55,
        effective_date=datetime(2025, 1, 1, tzinfo=UTC),
    ),
    ModelPrice(
        model_id="o4-mini",
        prompt_usd_per_mtok=1.10,
        completion_usd_per_mtok=4.40,
        cached_prompt_usd_per_mtok=0.275,
        effective_date=datetime(2025, 4, 1, tzinfo=UTC),
    ),
    # ── Anthropic Claude ─────────────────────────────────────────────────
    ModelPrice(
        model_id="claude-3-5-sonnet-20241022",
        prompt_usd_per_mtok=3.00,
        completion_usd_per_mtok=15.00,
        cached_prompt_usd_per_mtok=0.30,
        effective_date=datetime(2024, 10, 1, tzinfo=UTC),
    ),
    ModelPrice(
        model_id="claude-3-5-haiku-20241022",
        prompt_usd_per_mtok=0.80,
        completion_usd_per_mtok=4.00,
        cached_prompt_usd_per_mtok=0.08,
        effective_date=datetime(2024, 10, 1, tzinfo=UTC),
    ),
    ModelPrice(
        model_id="claude-3-opus-20240229",
        prompt_usd_per_mtok=15.00,
        completion_usd_per_mtok=75.00,
        cached_prompt_usd_per_mtok=1.50,
        effective_date=datetime(2024, 3, 1, tzinfo=UTC),
    ),
    # ── OpenRouter passthrough (OpenRouter markup ~0% for pass-through keys) ──
    ModelPrice(
        model_id="openrouter/google/gemini-2.5-pro",
        prompt_usd_per_mtok=1.25,
        completion_usd_per_mtok=10.00,
        effective_date=datetime(2025, 5, 1, tzinfo=UTC),
    ),
    ModelPrice(
        model_id="openrouter/anthropic/claude-3-5-sonnet",
        prompt_usd_per_mtok=3.00,
        completion_usd_per_mtok=15.00,
        effective_date=datetime(2024, 10, 1, tzinfo=UTC),
    ),
)


class PricingRegistry:
    """Catalog of model prices with lookup and cost-estimation API.

    Thread-safe (read-only after construction).
    """

    def __init__(self, extra_prices: tuple[ModelPrice, ...] = ()) -> None:
        """Initialise with built-in prices plus optional caller-supplied entries.

        Caller-supplied ``extra_prices`` take precedence over built-ins for the
        same ``model_id``.
        """
        # Build lookup: model_id -> most-recently-effective ModelPrice
        # Caller entries supersede built-ins.
        lookup: dict[str, ModelPrice] = {}
        for price in _BUILT_IN_PRICES:
            lookup[price.model_id] = price
        for price in extra_prices:
            lookup[price.model_id] = price
        self._lookup: dict[str, ModelPrice] = lookup

    def get_price(self, model_id: str) -> ModelPrice | None:
        """Return the ``ModelPrice`` for ``model_id``, or ``None`` if unknown.

        Parameters
        ----------
        model_id:
            Provider-scoped model identifier.

        Returns
        -------
        ModelPrice | None
            Pricing entry, or ``None`` if the model is not in the registry.
        """
        return self._lookup.get(model_id)

    def estimate_cost(self, usage: ModelUsage) -> CostEstimate:
        """Compute cost for a ``ModelUsage`` record.

        CRITICAL: If the model has no pricing entry, returns a ``CostEstimate``
        with ALL cost fields set to ``None``.  NEVER returns ``0.0`` for an
        unpriced model — that would silently under-report costs.

        Parameters
        ----------
        usage:
            Token usage record to price.

        Returns
        -------
        CostEstimate
            Priced or explicitly-unpriced cost record.
        """
        price = self.get_price(usage.model_id)
        if price is None:
            # CRITICAL: Unknown model — record as None, NEVER coerce to 0.0
            return CostEstimate(
                usage=usage,
                prompt_cost_usd=None,
                completion_cost_usd=None,
                total_cost_usd=None,
                is_estimated=False,
            )

        # Determine prompt cost: cached tokens at discounted rate if applicable
        if usage.cached_tokens is not None and price.cached_prompt_usd_per_mtok is not None:
            non_cached = usage.prompt_tokens - usage.cached_tokens
            prompt_cost = (
                non_cached * price.prompt_usd_per_mtok / 1_000_000
                + usage.cached_tokens * price.cached_prompt_usd_per_mtok / 1_000_000
            )
        else:
            prompt_cost = usage.prompt_tokens * price.prompt_usd_per_mtok / 1_000_000

        completion_cost = usage.completion_tokens * price.completion_usd_per_mtok / 1_000_000
        total_cost = prompt_cost + completion_cost

        return CostEstimate(
            usage=usage,
            prompt_cost_usd=round(prompt_cost, 8),
            completion_cost_usd=round(completion_cost, 8),
            total_cost_usd=round(total_cost, 8),
            is_estimated=False,
        )

    def known_models(self) -> tuple[str, ...]:
        """Return all model IDs known to this registry."""
        return tuple(sorted(self._lookup.keys()))
