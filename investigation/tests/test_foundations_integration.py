"""Budget/tool integration with explicit generic records, no dataset/oracle."""

from datetime import datetime, timedelta, timezone

import pytest

from evidence_investigation.runtime.budget import BudgetController, BudgetExceeded
from evidence_investigation.state.contracts import (
    AssetQuery, Budget, Coverage, Reliability, SIEMQuery, TimeWindow,
    ToolContext, ToolRecord,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.tools.contracts import EnvironmentFixture, FixtureRule
from evidence_investigation.tools.server import MockToolServer, content_hash


def setup():
    as_of = datetime(2026, 9, 1, 2, 20, tzinfo=timezone.utc)
    window = TimeWindow(as_of-timedelta(minutes=10), as_of)
    query = SIEMQuery("process_tree", window, "host-a")
    payload = {"view":"process_tree", "host":"host-a", "occurred_at":window.start.isoformat(),
               "observed_at":as_of.isoformat(), "command_line":"PowerShell -File task.ps1"}
    record = ToolRecord("opaque-record", payload, content_hash(payload), "mock-siem", "sensor-a",
                        Reliability("high", "local test", "test-v1"))
    coverage = Coverage({"host":"host-a", "view":"process_tree"}, window, "complete", False, ())
    rule = FixtureRule("siem", {"host":"host-a"}, (record.record_id,), "ok", coverage, False, None)
    fixture = EnvironmentFixture("opaque-world", as_of, {"siem":(record,)}, (rule,), "test-v1")
    return as_of, query, MockToolServer(fixture, simulate_latency=False)


async def counted_call(ledger, server, query, context):
    ledger.begin_tool_attempt()
    before = server.stats()
    result = None
    try:
        result = await server.siem(query, context)
        return result
    finally:
        after = server.stats()
        ledger.record_tool_result(result, backend_called=after.backend_calls > before.backend_calls,
                                  cache_hit=after.cache_hits > before.cache_hits)


@pytest.mark.asyncio
async def test_cached_attempt_counts_but_does_not_repeat_backend_cost():
    as_of, query, server = setup()
    ledger = BudgetController(Budget(max_tool_calls=3))
    first = await counted_call(ledger, server, query, ToolContext("run", "first", as_of, 1000))
    cached = await counted_call(ledger, server, query, ToolContext("run", "cached", as_of, 1000))
    usage = ledger.snapshot()
    assert first.records == cached.records
    assert (usage.tool_attempts, usage.backend_calls, usage.cache_hits) == (2,1,1)
    assert usage.tool_cost_units == 2 and usage.simulated_tool_latency_ms == 200
    assert usage.model_calls == 0


@pytest.mark.asyncio
async def test_invalid_call_uses_attempt_and_ledger_remains_recoverable():
    as_of, query, server = setup()
    ledger = BudgetController(Budget(max_tool_calls=2))
    with pytest.raises(ProtocolViolation, match="tool_argument_mismatch"):
        await counted_call(ledger, server, AssetQuery("host-a", as_of), ToolContext("run", "bad", as_of, 1000))
    good = await counted_call(ledger, server, query, ToolContext("run", "good", as_of, 1000))
    assert good.status == "ok"
    usage = ledger.snapshot()
    assert usage.tool_attempts == 2 and usage.backend_calls == 1 and usage.tool_cost_units == 2
    with pytest.raises(BudgetExceeded, match="tool_budget"):
        ledger.reserve_model(1, 1)


@pytest.mark.asyncio
async def test_timed_out_backend_is_counted_without_registering_evidence():
    as_of, query, server = setup()
    ledger = BudgetController(Budget(max_tool_calls=1))
    result = await counted_call(ledger, server, query, ToolContext("run", "timeout", as_of, 20))
    usage = ledger.snapshot()
    assert result.status == "timeout" and result.records == ()
    assert usage.tool_attempts == usage.backend_calls == 1
    assert usage.tool_cost_units == 2 and usage.simulated_tool_latency_ms == 20
    assert ledger.stopped_reason == "tool_budget"
