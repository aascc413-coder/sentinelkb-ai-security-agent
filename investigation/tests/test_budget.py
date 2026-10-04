from dataclasses import replace
import math
from types import SimpleNamespace

import pytest

from evidence_investigation.runtime.budget import BudgetController, BudgetExceeded
from evidence_investigation.state.contracts import Budget, Coverage, ToolResult, Usage
from evidence_investigation.state.codec import decode, encode


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def controller(**changes):
    return BudgetController(replace(Budget(max_tokens=100, finalization_token_reserve=20), **changes), clock=Clock())


def tool_result():
    return ToolResult("call", "siem", "ok", (), Coverage({}, None, "complete", False, ()),
                      "v1", None, False, 2.0, 15, 1)


def test_invalid_cache_retry_and_backend_attempts_all_count():
    ledger = controller(max_tool_calls=4)
    ledger.begin_tool_attempt()
    ledger.record_tool_result(None)  # Invalid query rejected before backend.
    ledger.begin_tool_attempt()
    ledger.record_tool_result(tool_result(), cache_hit=True)
    ledger.begin_tool_attempt()
    ledger.record_tool_result(None, backend_called=True)  # Failed backend call.
    ledger.begin_tool_attempt()
    ledger.record_tool_result(tool_result(), backend_called=True)  # Retry.
    usage = ledger.snapshot()
    assert (usage.tool_attempts, usage.backend_calls, usage.cache_hits) == (4, 2, 1)
    assert (usage.tool_cost_units, usage.simulated_tool_latency_ms) == (2.0, 15)
    assert ledger.stopped_reason == "tool_budget"
    with pytest.raises(BudgetExceeded, match="tool_budget"):
        ledger.reserve_model(1, 1, finalization=True)
    with pytest.raises(RuntimeError):
        ledger.record_tool_result(None)


def test_zero_tool_limit_does_not_prevent_tool_free_models():
    ledger = controller(max_tool_calls=0)
    plan = ledger.reserve_model(2, 3)
    ledger.reconcile_model(plan, Usage(input_tokens=2, output_tokens=1))
    assert ledger.stopped_reason is None
    with pytest.raises(BudgetExceeded, match="tool_budget"):
        ledger.begin_tool_attempt()
    assert ledger.snapshot().tool_attempts == 0


def test_zero_token_budget_cannot_allow_a_nominally_free_model_call():
    ledger = controller(max_tokens=0, finalization_token_reserve=0)
    with pytest.raises(BudgetExceeded, match="token_budget"):
        ledger.reserve_model(0, 0, finalization=True)
    assert ledger.snapshot().model_calls == 0


def test_deadline_covers_late_tool_results_and_latches_reason():
    clock = Clock()
    ledger = BudgetController(Budget(max_time_seconds=2), clock=clock)
    ledger.begin_tool_attempt()
    clock.now += 2
    ledger.record_tool_result(None, backend_called=True)
    assert ledger.remaining_timeout_ms == 0
    assert ledger.stopped_reason == "deadline"
    assert ledger.snapshot().backend_calls == 1
    with pytest.raises(BudgetExceeded, match="deadline"):
        ledger.begin_step()


def test_step_limit_admits_last_step_and_rejects_next():
    ledger = controller(max_investigation_steps=1)
    assert ledger.begin_step() == 1
    plan = ledger.reserve_model(2, 3)
    ledger.reconcile_model(plan, Usage(input_tokens=2, output_tokens=1))
    with pytest.raises(BudgetExceeded, match="step_budget"):
        ledger.begin_step()
    assert ledger.snapshot().steps == 1


def test_reservation_includes_finalization_room_and_releases_known_unused_tokens():
    ledger = controller()
    plan = ledger.reserve_model(30, 40)
    assert plan.finalization_reserve == 20
    result = ledger.reconcile_model(plan, Usage(input_tokens=10, output_tokens=10, model_cost=0.02, currency="USD"))
    assert result.actual_usage.input_tokens == 10
    assert ledger.charged_tokens == 20
    final = ledger.reserve_model(30, 50, finalization=True)
    assert final.finalization_reserve == 0
    ledger.reconcile_model(final, Usage(input_tokens=10, output_tokens=5, model_cost=0.01, currency="USD"))
    assert ledger.snapshot().model_cost == pytest.approx(0.03)


def test_missing_usage_retains_reservation_without_fake_actual_zero():
    ledger = controller()
    plan = ledger.reserve_model(20, 20)
    assert not ledger.snapshot().usage_complete
    result = ledger.reconcile_model(plan, None)
    assert result.actual_usage is None
    assert ledger.charged_tokens == 40
    assert not ledger.snapshot().usage_complete
    with pytest.raises(BudgetExceeded, match="token_budget"):
        ledger.reserve_model(30, 20)  # 40 + 50 + final reserve 20 > 100.


def test_partial_usage_cannot_refund_conservative_reservation():
    ledger = controller()
    plan = ledger.reserve_model(20, 20)
    result = ledger.reconcile_model(plan, Usage(input_tokens=2, output_tokens=0, usage_complete=False))
    assert result.actual_usage.usage_complete is False
    assert ledger.charged_tokens == 40
    assert ledger.snapshot().input_tokens == 2
    assert not ledger.snapshot().usage_complete


def test_actual_overrun_stops_followup_and_records_real_usage():
    ledger = controller()
    plan = ledger.reserve_model(20, 20)
    result = ledger.reconcile_model(plan, Usage(input_tokens=70, output_tokens=40))
    assert result.actual_usage.output_tokens == 40
    assert ledger.charged_tokens == 110
    assert ledger.stopped_reason == "token_budget"
    with pytest.raises(BudgetExceeded, match="token_budget"):
        ledger.begin_tool_attempt()


def test_pending_repeated_and_forged_reservations_cannot_refund():
    ledger = controller()
    plan = ledger.reserve_model(20, 20)
    with pytest.raises(RuntimeError, match="pending"):
        ledger.reserve_model(1, 1)
    with pytest.raises(RuntimeError):
        ledger.reconcile_model(replace(plan), None)
    ledger.reconcile_model(plan, Usage(input_tokens=2, output_tokens=3))
    assert ledger.snapshot().usage_complete
    with pytest.raises(RuntimeError):
        ledger.reconcile_model(plan, Usage())
    assert ledger.charged_tokens == 5
    snapshot = ledger.snapshot()
    snapshot.input_tokens = 999
    assert ledger.snapshot().input_tokens == 2


def test_late_model_usage_is_reconciled_but_does_not_reopen_deadline():
    clock = Clock()
    ledger = BudgetController(Budget(max_time_seconds=1), clock=clock)
    plan = ledger.reserve_model(1, 2)
    clock.now += 2
    reconciled = ledger.reconcile_model(plan, Usage(input_tokens=1, output_tokens=1))
    assert "after deadline" in reconciled.reconciliation
    assert ledger.stopped_reason == "deadline"


@pytest.mark.parametrize("changes", [{"max_tool_calls": True}, {"max_tokens": -1},
    {"max_time_seconds": float("nan")}, {"finalization_token_reserve": 101}])
def test_invalid_budget_rejected(changes):
    with pytest.raises(ValueError):
        controller(**changes)


def test_invalid_reconciliation_preserves_pending_reservation():
    ledger = controller()
    plan = ledger.reserve_model(2, 3)
    with pytest.raises(ValueError):
        ledger.reconcile_model(plan, Usage(input_tokens=-1))
    ledger.reconcile_model(plan, None)
    assert ledger.charged_tokens == 5


def test_tool_aggregate_overflow_rejected_atomically_with_unknown_recovery():
    ledger = controller()
    huge = replace(tool_result(), simulated_cost_units=1e308)
    ledger.begin_tool_attempt()
    ledger.record_tool_result(huge, backend_called=True)
    ledger.begin_tool_attempt()
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="accumulated tool cost"):
        ledger.record_tool_result(huge, backend_called=True)
    assert ledger.snapshot() == before
    ledger.record_tool_result(None, backend_called=True)
    after = ledger.snapshot()
    assert math.isfinite(after.tool_cost_units)
    assert after.backend_calls == 2
    assert not after.usage_complete
    decode(Usage, encode(after))


def test_model_aggregate_overflow_rejected_atomically_with_unknown_recovery():
    ledger = controller()
    huge = Usage(input_tokens=1, output_tokens=1, model_cost=1e308, currency="USD")
    first = ledger.reserve_model(1, 1)
    ledger.reconcile_model(first, huge)
    second = ledger.reserve_model(1, 1)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="accumulated model cost"):
        ledger.reconcile_model(second, huge)
    assert ledger.snapshot() == before
    assert ledger.charged_tokens == 2
    result = ledger.reconcile_model(second, None)
    assert result.actual_usage is None
    assert ledger.charged_tokens == 4
    assert ledger.snapshot().model_cost is None
    decode(Usage, encode(ledger.snapshot()))


@pytest.mark.parametrize("bad", [Usage(model_calls=True), Usage(elapsed_ms=-1),
    Usage(tool_cost_units=float("nan")), Usage(simulated_tool_latency_ms=-1),
    Usage(backend_calls=-1), Usage(tool_cost_units=-1), Usage(cache_hits=1.5),
    Usage(usage_complete="yes"), Usage(currency=4), Usage(model_cost=-1)])
def test_entire_provider_usage_is_validated_before_trace_retention(bad):
    ledger = controller()
    plan = ledger.reserve_model(2, 3)
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.reconcile_model(plan, bad)
    assert ledger.snapshot() == before
    result = ledger.reconcile_model(plan, None)
    assert result.actual_usage is None
    decode(type(result), encode(result))


@pytest.mark.parametrize("bad", [
    SimpleNamespace(simulated_cost_units=1.0, simulated_latency_ms=1),
    replace(tool_result(), actual_duration_ms=-1),
    replace(tool_result(), retryable="yes"),
    replace(tool_result(), status="invented"),
    replace(tool_result(), simulated_latency_ms=True),
])
def test_full_tool_result_validated_before_ledger_changes(bad):
    ledger = controller()
    ledger.begin_tool_attempt()
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.record_tool_result(bad, backend_called=True)
    assert ledger.snapshot() == before
    ledger.record_tool_result(None, backend_called=True)
    assert ledger.snapshot().backend_calls == 1
    assert not ledger.snapshot().usage_complete
