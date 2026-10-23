"""Focused tests for M8b pricing and the external spend boundary."""

import pytest

from benchmark.m8b import SpendLedger, price_deepseek_usage
from evidence_investigation.runtime.model import ModelError
from evidence_investigation.state.contracts import Usage


def test_deepseek_pricer_uses_cache_breakdown_and_selected_tier():
    raw = {
        "prompt_tokens": 1000,
        "completion_tokens": 200,
        "prompt_cache_hit_tokens": 750,
        "prompt_cache_miss_tokens": 250,
    }
    cost, currency = price_deepseek_usage(raw, "offpeak")
    expected = (750 * 0.003 + 250 * 0.15 + 200 * 0.6) / 1_000_000
    assert cost == pytest.approx(expected)
    assert currency == "USD"


def test_deepseek_pricer_prices_inconsistent_cache_counters_as_all_miss():
    cost, currency = price_deepseek_usage({
        "prompt_tokens": 10,
        "completion_tokens": 2,
        "prompt_cache_hit_tokens": 3,
        "prompt_cache_miss_tokens": 6,
    }, "peak")
    assert cost == pytest.approx((10 * 0.3 + 2 * 1.2) / 1_000_000)
    assert currency == "USD"


def test_spend_ledger_records_priced_usage_and_blocks_over_cap():
    ledger = SpendLedger(cap_cny=0.01, fx_cny_per_usd=8)
    ledger.record(Usage(model_cost=0.0005, currency="USD"))
    assert ledger.spent_cny_guard == pytest.approx(0.004)
    assert ledger.priced_calls == 1
    with pytest.raises(ModelError, match="spend cap"):
        ledger.reserve_call([{"role": "user", "content": "x" * 10000}], 5000)


def test_spend_ledger_marks_usage_without_price():
    ledger = SpendLedger(cap_cny=7)
    ledger.record(Usage(input_tokens=10, output_tokens=5))
    assert ledger.unpriced_calls == 1
    assert ledger.spent_usd == 0
