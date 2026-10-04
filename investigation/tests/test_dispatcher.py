"""M4 Dispatcher 测试：准入计费、协议违规、实体授权、重试、迟到、冗余。"""

from datetime import datetime, timedelta, timezone

import pytest

from evidence_investigation.runtime.budget import BudgetController, BudgetExceeded
from evidence_investigation.runtime.dispatcher import Dispatcher
from evidence_investigation.runtime.registry import EvidenceRegistry
from evidence_investigation.state.contracts import (
    AssetQuery, Budget, Coverage, Reliability, SIEMQuery, TimeWindow,
    ToolCall, ToolRecord, ToolResult,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.tools.contracts import EnvironmentFixture, FixtureRule
from evidence_investigation.tools.server import MockToolServer, content_hash

UTC = timezone.utc
AS_OF = datetime(2026, 9, 1, 2, 20, tzinfo=UTC)
WINDOW = TimeWindow(AS_OF - timedelta(minutes=10), AS_OF)


def build_server(*, siem_status="ok", history_status=None):
    payload = {"view": "process_tree", "host": "WS-041", "process_id": "p-101",
               "occurred_at": WINDOW.start.isoformat(),
               "observed_at": AS_OF.isoformat(),
               "command_line": "powershell -enc AAAA",
               "remote_ip": "203.0.113.66"}
    record = ToolRecord("r-1", payload, content_hash(payload), "mock-siem", "sensor-a",
                        Reliability("high", "test", "policy-v1"))
    records_by_tool = {"siem": (record,)}
    rules = [FixtureRule("siem", {"host": "WS-041"}, ("r-1",), siem_status,
                         Coverage({"host": "WS-041", "view": "process_tree"}, WINDOW,
                                  "complete" if siem_status == "ok" else "partial",
                                  False, ()), False, None)]
    if history_status:
        rules.append(FixtureRule(
            "history", {"entity_type": "host", "entity": "WS-041"}, (),
            history_status, Coverage({}, None, "unknown", False, ("history.source",)),
            False, "source_down"))
        records_by_tool["history"] = ()
    fixture = EnvironmentFixture("world-a", AS_OF, records_by_tool, tuple(rules), "test-v1")
    return MockToolServer(fixture, simulate_latency=False)


def make_dispatcher(server, *, max_tool_calls=6, clock=None):
    alert = Alert_with_entities()
    registry = EvidenceRegistry(alert)
    budget = BudgetController(Budget(max_tool_calls=max_tool_calls), clock=clock) \
        if clock else BudgetController(Budget(max_tool_calls=max_tool_calls))
    dispatcher = Dispatcher("run-1", AS_OF, registry, budget, server)
    return dispatcher, registry, budget


def Alert_with_entities(**overrides):
    from test_registry import make_alert
    return make_alert(**overrides)


def siem_call(**overrides):
    base = dict(view="process_tree", window=WINDOW, host="WS-041")
    base.update(overrides)
    return ToolCall("siem", SIEMQuery(**base))


@pytest.mark.asyncio
async def test_happy_path_registers_evidence_and_bills_budget():
    server = build_server()
    dispatcher, registry, budget = make_dispatcher(server)
    outcome = await dispatcher.dispatch(siem_call(), step=1)
    assert outcome.result is not None and outcome.result.status == "ok"
    assert len(outcome.evidence_ids) == 1
    assert outcome.protocol_error_code is None and not outcome.late
    usage = budget.snapshot()
    assert usage.tool_attempts == 1 and usage.backend_calls == 1
    assert usage.tool_cost_units == 2.0
    assert registry.version > 1


@pytest.mark.asyncio
async def test_tool_argument_mismatch_is_a_billed_protocol_error():
    server = build_server()
    dispatcher, registry, budget = make_dispatcher(server)
    outcome = await dispatcher.dispatch(
        ToolCall("siem", AssetQuery(host="WS-041", as_of=AS_OF)))
    assert outcome.protocol_error_code == "tool_argument_mismatch"
    assert outcome.result is None
    usage = budget.snapshot()
    assert usage.tool_attempts == 1 and usage.backend_calls == 0
    # 非法调用不产生任何证据
    assert len(registry.facts()) == 1  # 只有 alert 事实


@pytest.mark.asyncio
async def test_unknown_entity_rejected():
    server = build_server()
    dispatcher, _, _ = make_dispatcher(server)
    outcome = await dispatcher.dispatch(
        ToolCall("asset", AssetQuery(host="never-seen-host", as_of=AS_OF)))
    assert outcome.protocol_error_code == "unknown_entity"


@pytest.mark.asyncio
async def test_indicator_from_records_is_queryable():
    server = build_server()
    dispatcher, registry, _ = make_dispatcher(server)
    await dispatcher.dispatch(siem_call())  # 记录带 remote_ip → 进入台账
    from evidence_investigation.state.contracts import TIQuery
    outcome = await dispatcher.dispatch(
        ToolCall("threat_intel", TIQuery("ip", "203.0.113.66", AS_OF)))
    assert outcome.protocol_error_code is None or outcome.protocol_error_code != "unknown_entity"


@pytest.mark.asyncio
async def test_transient_timeout_retried_once_and_billed():
    """瞬态超时重试一次：两次尝试都计费，第二次成功后登记事实。"""

    class FlakyTools:
        def __init__(self):
            self.calls: list[str] = []

        async def siem(self, query, ctx):
            self.calls.append(ctx.call_id)
            if len(self.calls) == 1:
                return ToolResult(ctx.call_id, "siem", "timeout", (),
                                  Coverage({}, None, "unknown", False, ()),
                                  "test-v1", "tool_timeout", True, 2.0, 200, 3)
            return ToolResult(ctx.call_id, "siem", "ok", (record_ok(),),
                              Coverage({"host": "WS-041", "view": "process_tree"},
                                       WINDOW, "complete", False, ()),
                              "test-v1", None, False, 2.0, 200, 3)

    def record_ok():
        payload = {"view": "process_tree", "host": "WS-041",
                   "occurred_at": WINDOW.start.isoformat(),
                   "observed_at": AS_OF.isoformat()}
        return ToolRecord("r-ok", payload, content_hash(payload), "mock-siem",
                          "sensor-a", Reliability("high", "test", "policy-v1"))

    flaky = FlakyTools()
    dispatcher, registry, budget = make_dispatcher(flaky, max_tool_calls=5)
    outcome = await dispatcher.dispatch(siem_call())
    assert len(flaky.calls) == 2                       # 恰好重试一次
    assert outcome.result is not None and outcome.result.status == "ok"
    assert outcome.retry_of is not None
    assert len(outcome.evidence_ids) == 1              # 成功结果登记事实
    usage = budget.snapshot()
    assert usage.tool_attempts == 2 and usage.backend_calls == 2
    assert usage.tool_cost_units == 4.0                # 两次尝试都计费
    operational = [f for f in registry.operational_facts()
                   if f.evidence_type == "source_unavailable"]
    assert len(operational) == 1                       # 首次超时的操作事实


@pytest.mark.asyncio
async def test_permanent_unavailable_short_circuits_later_calls():
    server = build_server(history_status="unavailable")
    dispatcher, registry, budget = make_dispatcher(server, max_tool_calls=6)
    from evidence_investigation.state.contracts import HistoryQuery
    call = ToolCall("history", HistoryQuery("host", "WS-041",
                                            TimeWindow(AS_OF - timedelta(days=1), AS_OF)))
    first = await dispatcher.dispatch(call)
    assert first.result is not None and first.result.status == "unavailable"
    assert first.backend_called and not first.cache_hit
    second = await dispatcher.dispatch(call)
    assert second.redundant and second.cache_hit and not second.backend_called
    usage = budget.snapshot()
    assert usage.tool_attempts == 2 and usage.backend_calls == 1 and usage.cache_hits == 1
    # 永久不可用的操作事实只登记一次
    operational = registry.operational_facts()
    assert sum(1 for f in operational if f.evidence_type == "source_unavailable") == 1


@pytest.mark.asyncio
async def test_redundant_repeat_is_cache_hit_with_zero_cost():
    server = build_server()
    dispatcher, registry, budget = make_dispatcher(server)
    await dispatcher.dispatch(siem_call())
    second = await dispatcher.dispatch(siem_call())
    assert second.redundant and second.cache_hit
    assert second.result.simulated_cost_units == 0.0
    usage = budget.snapshot()
    assert usage.tool_attempts == 2 and usage.backend_calls == 1 and usage.cache_hits == 1
    assert usage.tool_cost_units == 2.0  # 缓存命中不加后端成本
    # 重复调用不产生新事实
    assert len(registry.facts()) == 2  # alert + 1


@pytest.mark.asyncio
async def test_late_response_recorded_but_not_registered():
    server = build_server()
    ticks = iter([0.0, 0.1, 0.2, 100.0])
    clock = lambda: next(ticks, 100.0)
    dispatcher, registry, budget = make_dispatcher(server, clock=clock)
    outcome = await dispatcher.dispatch(siem_call())
    assert outcome.late is True
    assert outcome.evidence_ids == ()          # 迟到响应不写 Evidence
    usage = budget.snapshot()
    assert usage.tool_attempts == 1 and usage.backend_calls == 1  # 费用照记
    assert budget.stopped_reason == "deadline"
    assert len(registry.facts()) == 1          # 只有 alert 事实


@pytest.mark.asyncio
async def test_budget_exhaustion_raises_for_caller_finalization():
    server = build_server()
    dispatcher, _, budget = make_dispatcher(server, max_tool_calls=1)
    await dispatcher.dispatch(siem_call())
    with pytest.raises(BudgetExceeded, match="tool_budget"):
        await dispatcher.dispatch(siem_call())
