"""Focused tests for M8b pricing and the external spend boundary."""

import pytest

from benchmark.m8b import SpendLedger, _comparison_rows, price_deepseek_usage
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


def _record(case_id, *, calls, inputs, outputs, cost, verdict="Abstain",
            stop="token_budget", complete=True):
    return {
        "case_id": case_id, "method": "proposed", "status": "valid",
        "verdict": verdict, "stop_reason": stop,
        "usage": {"model_calls": calls, "input_tokens": inputs,
                  "output_tokens": outputs, "usage_complete": complete,
                  "model_cost": cost, "currency": "USD" if cost is not None else None},
    }


def test_comparison_rows_use_only_paired_complete_usage():
    before = {
        "C1": _record("C1", calls=5, inputs=1000, outputs=500, cost=0.1,
                      verdict="TP", stop="sufficient"),
        "C2": _record("C2", calls=4, inputs=800, outputs=400, cost=None,
                      complete=False),
    }
    after = {
        "C1": _record("C1", calls=3, inputs=600, outputs=300, cost=0.06,
                     verdict="TP", stop="sufficient"),
        "C2": _record("C2", calls=3, inputs=500, outputs=250, cost=0.05),
    }
    rows, all_totals, totals = _comparison_rows(before, after, {"C1": 1, "C2": 0},
                                                {"C1": 0, "C2": 0})
    assert rows[0]["delta_candidate_minus_baseline"] == {
        "model_calls": -2, "repair_count": -1, "input_tokens": -400,
        "output_tokens": -200, "model_cost_usd": pytest.approx(-0.04),
    }
    assert rows[1]["delta_candidate_minus_baseline"]["input_tokens"] is None
    assert all_totals["model_calls"] == {
        "baseline": 9, "candidate": 6, "delta_candidate_minus_baseline": -3,
    }
    assert totals["complete_usage_case_count"] == 1
    assert totals["priced_case_count"] == 1
    assert totals["input_tokens"] == {
        "baseline": 1000, "candidate": 600, "delta_candidate_minus_baseline": -400,
    }


def test_comparison_rows_reject_different_case_sets():
    row = _record("C1", calls=1, inputs=1, outputs=1, cost=0.0)
    with pytest.raises(ValueError, match="case sets differ"):
        _comparison_rows({"C1": row}, {}, {"C1": 0}, {})
