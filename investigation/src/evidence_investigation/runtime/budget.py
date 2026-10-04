"""Sequential budget ledger built on the M1 contracts.

Token estimates are admission controls, not guarantees about provider billing.
Unknown/partial usage retains a conservative reservation; measured token totals
must only enter exact-cost comparisons when ``usage_complete`` is true.

The last admitted investigation step may finish its work. Starting another step
is forbidden. The last tool attempt may finish, then closes tool admission and
model admission; final output must be constructed deterministically by the
caller. A zero tool allowance does not stop tool-free work until a tool is tried.
This controller is sequential: at most one pending tool and one pending model,
and neither may overlap the other. It does not interrupt an active backend.
"""

from __future__ import annotations

from dataclasses import replace
import math
import time
from typing import Callable

from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.contracts import (
    Budget, StopReason, TokenPlan, ToolResult, Usage,
)
from evidence_investigation.state.errors import ProtocolViolation


class BudgetExceeded(RuntimeError):
    """An admission was denied; reason is suitable for deterministic finalization."""

    def __init__(self, reason: StopReason):
        self.reason = reason
        super().__init__(reason)


def _integer(value: int, name: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")


def _finite_nonnegative(value: float, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be finite and nonnegative")
    try:
        finite = math.isfinite(value)
    except OverflowError as exc:
        raise ValueError(f"{name} exceeds finite numeric range") from exc
    if not finite or value < 0:
        raise ValueError(f"{name} must be finite and nonnegative")


def _typed_copy(value: Usage | ToolResult, expected: type):
    if type(value) is not expected:
        raise ValueError(f"expected {expected.__name__}")
    try:
        return decode(expected, encode(value))
    except (ProtocolViolation, OverflowError, TypeError) as exc:
        raise ValueError(f"invalid {expected.__name__}: {exc}") from exc


def _validated_usage(value: Usage) -> Usage:
    actual = _typed_copy(value, Usage)
    for name in ("tool_attempts", "backend_calls", "cache_hits", "steps", "model_calls",
                 "input_tokens", "output_tokens", "elapsed_ms", "simulated_tool_latency_ms"):
        _integer(getattr(actual, name), name)
    _finite_nonnegative(actual.tool_cost_units, "tool_cost_units")
    if actual.model_cost is not None:
        _finite_nonnegative(actual.model_cost, "model_cost")
    if actual.currency is not None and not actual.currency.strip():
        raise ValueError("currency must be a nonempty string or None")
    return actual


class BudgetController:
    """Owns usage, reservation reconciliation and a latched stop reason.

    ``begin_tool_attempt`` must precede validation/cache lookup/retry so each
    admitted attempt counts. Even invalid calls must finish with
    ``record_tool_result(None)``. Unadmitted requests after exhaustion do not
    increase the admitted-attempt count.

    A TokenPlan must be reconciled exactly once, using the same returned object.
    Missing provider usage is represented by None, including failed requests.
    """

    def __init__(self, budget: Budget, *, clock: Callable[[], float] = time.monotonic):
        for name in ("max_tool_calls", "max_tokens", "max_investigation_steps",
                     "finalization_token_reserve"):
            _integer(getattr(budget, name), name)
        _finite_nonnegative(budget.max_time_seconds, "max_time_seconds")
        if budget.finalization_token_reserve > budget.max_tokens:
            raise ValueError("finalization reserve exceeds token budget")
        self.budget = replace(budget)
        self._clock = clock
        self._started = self._last_clock = clock()
        _finite_nonnegative(self._started, "clock")
        self._usage = Usage()
        self._charged_tokens = 0
        self._pending_model: TokenPlan | None = None
        self._pending_tool = False
        self._stopped_reason: StopReason | None = None
        self._cost_complete = True

    def _elapsed(self) -> float:
        now = self._clock()
        _finite_nonnegative(now, "clock")
        if now < self._last_clock:
            raise ValueError("clock must be monotonic")
        self._last_clock = now
        elapsed = now - self._started
        if elapsed >= self.budget.max_time_seconds:
            self._stop("deadline")
        return elapsed

    def _stop(self, reason: StopReason) -> None:
        if self._stopped_reason is None:
            self._stopped_reason = reason

    def _admit(self) -> None:
        self._elapsed()
        if self._stopped_reason is not None:
            raise BudgetExceeded(self._stopped_reason)
        if self._pending_model is not None or self._pending_tool:
            raise RuntimeError("another operation is pending")

    @property
    def stopped_reason(self) -> StopReason | None:
        self._elapsed()
        return self._stopped_reason

    @property
    def charged_tokens(self) -> int:
        """Actual known totals plus reservations for unmeasured calls."""
        return self._charged_tokens

    @property
    def remaining_timeout_ms(self) -> int:
        # Floor rather than round: the caller never receives extra deadline time.
        return max(0, int((self.budget.max_time_seconds - self._elapsed()) * 1000))

    def snapshot(self) -> Usage:
        return replace(
            self._usage, elapsed_ms=int(self._elapsed() * 1000),
            usage_complete=self._usage.usage_complete and self._pending_model is None,
        )

    def begin_step(self) -> int:
        self._admit()
        if self._usage.steps >= self.budget.max_investigation_steps:
            self._stop("step_budget")
            raise BudgetExceeded("step_budget")
        self._usage.steps += 1
        return self._usage.steps

    def begin_tool_attempt(self) -> int:
        self._admit()
        if self._usage.tool_attempts >= self.budget.max_tool_calls:
            self._stop("tool_budget")
            raise BudgetExceeded("tool_budget")
        self._usage.tool_attempts += 1
        self._pending_tool = True
        return self._usage.tool_attempts

    def record_tool_result(
        self, result: ToolResult | None, *, backend_called: bool = False,
        cache_hit: bool = False,
    ) -> None:
        if not self._pending_tool:
            raise RuntimeError("no pending tool attempt")
        if type(backend_called) is not bool or type(cache_hit) is not bool:
            raise ValueError("backend_called and cache_hit must be bool")
        if backend_called and cache_hit:
            raise ValueError("a cache hit cannot also be a backend call")
        if result is not None:
            result = _typed_copy(result, ToolResult)
            _finite_nonnegative(result.simulated_cost_units, "tool cost")
            _integer(result.simulated_latency_ms, "simulated latency")
            _integer(result.actual_duration_ms, "actual duration")
        candidate = replace(self._usage)
        candidate.backend_calls += int(backend_called)
        candidate.cache_hits += int(cache_hit)
        if result is not None and backend_called:
            candidate.tool_cost_units += result.simulated_cost_units
            _finite_nonnegative(candidate.tool_cost_units, "accumulated tool cost")
            candidate.simulated_tool_latency_ms += result.simulated_latency_ms
        if result is None and backend_called:
            # Totals contain known values only; an unmeasured failure is not free.
            candidate.usage_complete = False
        self._elapsed()
        self._usage = candidate
        self._pending_tool = False
        if self._usage.tool_attempts >= self.budget.max_tool_calls:
            self._stop("tool_budget")

    def reserve_model(
        self, estimated_input_tokens: int, max_output_tokens: int, *,
        finalization: bool = False, estimate_note: str = "caller-supplied estimate",
    ) -> TokenPlan:
        _integer(estimated_input_tokens, "estimated_input_tokens")
        _integer(max_output_tokens, "max_output_tokens")
        if type(finalization) is not bool:
            raise ValueError("finalization must be bool")
        if not isinstance(estimate_note, str) or not estimate_note.strip():
            raise ValueError("estimate_note must explain estimation")
        self._admit()
        reserve = 0 if finalization else self.budget.finalization_token_reserve
        if (self._charged_tokens >= self.budget.max_tokens
                or self._charged_tokens + estimated_input_tokens + max_output_tokens + reserve > self.budget.max_tokens):
            self._stop("token_budget")
            raise BudgetExceeded("token_budget")
        plan = TokenPlan(estimated_input_tokens, max_output_tokens, reserve, estimate_note)
        self._pending_model = plan
        self._usage.model_calls += 1
        return plan

    def reconcile_model(self, plan: TokenPlan, actual_usage: Usage | None) -> TokenPlan:
        if self._pending_model is not plan:
            raise RuntimeError("unknown or already reconciled model reservation")
        reserved = plan.estimated_input_tokens + plan.reserved_output_tokens
        actual = None if actual_usage is None else _validated_usage(actual_usage)
        candidate = replace(self._usage)
        cost_complete = self._cost_complete
        if actual is None:
            charge = reserved
            candidate.usage_complete = False
            cost_complete = False
            note = "provider usage unavailable; reservation retained, not measured tokens"
        else:
            measured = actual.input_tokens + actual.output_tokens
            charge = measured if actual.usage_complete else max(reserved, measured)
            candidate.input_tokens += actual.input_tokens
            candidate.output_tokens += actual.output_tokens
            candidate.usage_complete &= actual.usage_complete
            note = "measured usage reconciled" if actual.usage_complete else "partial provider usage; conservative reservation retained"
            if measured > reserved:
                note += "; actual tokens exceeded reservation"
            if actual.model_cost is None or actual.currency is None:
                cost_complete = False
            elif cost_complete:
                if candidate.currency not in (None, actual.currency):
                    cost_complete = False
                else:
                    candidate.currency = actual.currency
                    candidate.model_cost = (candidate.model_cost or 0.0) + actual.model_cost
                    _finite_nonnegative(candidate.model_cost, "accumulated model cost")
        if not cost_complete:
            candidate.model_cost = None
            candidate.currency = None
        # Commit only after full validation and finite aggregate checks succeed.
        self._elapsed()
        self._usage = candidate
        self._cost_complete = cost_complete
        self._charged_tokens += charge
        self._pending_model = None
        if self._charged_tokens >= self.budget.max_tokens:
            self._stop("token_budget")
            note += "; token budget exhausted"
        if self._stopped_reason == "deadline":
            note += "; response arrived after deadline"
        return replace(plan, actual_usage=actual, reconciliation=note)
