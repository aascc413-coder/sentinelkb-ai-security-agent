"""M4 运行时集成测试：Registry+Dispatcher+Trace+Budget+Model 全链路与 A4 正控。"""

from datetime import datetime, timedelta, timezone

import pytest

from evidence_investigation.runtime.budget import BudgetController, BudgetExceeded
from evidence_investigation.runtime.dispatcher import Dispatcher
from evidence_investigation.runtime.model import FakeScriptedModel, run_model_call
from evidence_investigation.runtime.registry import EvidenceRegistry
from evidence_investigation.runtime.trace import TraceRecorder, read_trace
from evidence_investigation.state.contracts import (
    Alert, Budget, Coverage, EventType, FinalAssessment, RawReference, Reliability,
    RunManifest, SIEMQuery, TimeWindow, ToolCall, ToolRecord, ToolResult, Claim,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.codec import encode, decode
from evidence_investigation.state.validation import validate_final_assessment
from evidence_investigation.state.adapters import final_assessment_from_output
from evidence_investigation.tools.contracts import EnvironmentFixture, FixtureRule
from evidence_investigation.tools.server import MockToolServer, content_hash

UTC = timezone.utc
AS_OF = datetime(2026, 9, 1, 2, 20, tzinfo=UTC)
WINDOW = TimeWindow(AS_OF - timedelta(minutes=10), AS_OF)


def make_alert():
    return Alert(
        alert_id="a-1", alert_type="powershell_encoded", occurred_at=WINDOW.start,
        as_of=AS_OF, host="WS-041", user="analyst-a", process_id="p-101",
        command_line="powershell -enc AAAA", raw={"rule": "suspicious"},
        raw_reference=RawReference("rec-alert", "/alerts/0", "ab" * 32),
    )


def make_fixture():
    payload = {"view": "process_tree", "host": "WS-041", "process_id": "p-101",
               "occurred_at": WINDOW.start.isoformat(),
               "observed_at": AS_OF.isoformat(),
               "command_line": "powershell -enc AAAA",
               "remote_ip": "203.0.113.66"}
    record = ToolRecord("r-1", payload, content_hash(payload), "mock-siem", "sensor-a",
                        Reliability("high", "test", "policy-v1"))
    rule = FixtureRule("siem", {"host": "WS-041"}, ("r-1",), "ok",
                       Coverage({"host": "WS-041", "view": "process_tree"}, WINDOW,
                                "complete", False, ()), False, None)
    return EnvironmentFixture("world-m4", AS_OF, {"siem": (record,)}, (rule,), "test-v1")


def make_manifest(run_id):
    return RunManifest(
        run_id=run_id, method="direct", model_snapshot="fake-1", model_parameters={},
        prompt_hashes={}, dataset_version="test", tool_snapshot="test-v1",
        rubric_version="none", code_revision="test", seed=None, seed_supported=False,
        budget=Budget(), price_snapshot={},
    )


@pytest.mark.asyncio
async def test_full_chain_dispatch_trace_model(tmp_path):
    run_id = "run-int-1"
    alert = make_alert()
    registry = EvidenceRegistry(alert)
    budget = BudgetController(Budget(max_tool_calls=6))
    server = MockToolServer(make_fixture(), simulate_latency=False)
    trace = TraceRecorder(run_id, make_manifest(run_id), tmp_path,
                          usage_provider=budget.snapshot)
    dispatcher = Dispatcher(run_id, AS_OF, registry, budget, server, trace=trace)
    trace.emit("alert_received", {"alert": encode(alert)}, step=0,
               state_version_after=registry.version)

    outcome = await dispatcher.dispatch(
        ToolCall("siem", SIEMQuery("process_tree", WINDOW, "WS-041")), step=1)
    assert outcome.evidence_ids

    final = FinalAssessment(
        verdict="Suspicious", disposition="human_review", stop_reason="no_useful_action",
        p_attack=None, claims=(), final_evidence_ids=tuple(outcome.evidence_ids),
        unresolved_questions=(), risk_flags=("encoded",), abstain_reason=None,
        confidence_status="uncalibrated",
    )
    model = FakeScriptedModel([encode(final)])
    response = await run_model_call(
        budget, model, run_id=run_id, phase="final",
        messages=({"role": "user", "content": "Investigate the supplied records."},),
        schema_name="final_assessment.schema.json", max_output_tokens=800,
        trace=trace, output_validator=lambda output: validate_final_assessment(
            final_assessment_from_output(output), [e.evidence_id for e in registry.facts()]),
    )
    trace.finalize(final_assessment_from_output(response.output))

    bundle = read_trace(tmp_path, run_id)
    kinds = [e.event_type for e in bundle.events]
    assert kinds[0] == "alert_received"
    assert "tool_requested" in kinds and "tool_returned" in kinds
    assert "evidence_registered" in kinds
    # 事件类型全部合法、sequence 连续
    assert all(e.event_type in EventType.ALL for e in bundle.events)
    assert [e.sequence for e in bundle.events] == list(range(1, len(bundle.events) + 1))
    # usage 快照随事件演化（非全零）
    assert bundle.events[-1].usage_snapshot.tool_attempts == 1
    assert model.calls == 1
    # Reconstruct facts using only persisted alert + raw tool results, no backend.
    replay = EvidenceRegistry(decode(Alert, bundle.events[0].payload["alert"]))
    for event in bundle.events:
        if event.event_type == "tool_returned" and not event.payload["late"]:
            replay.register_tool_result(decode(ToolResult, event.payload["result"]))
    assert encode(replay.facts()) == encode(registry.facts())
    validate_final_assessment(bundle.final, [e.evidence_id for e in replay.facts()])


@pytest.mark.asyncio
async def test_zero_tool_budget_still_allows_model_work_a4():
    """A4 正控：max_tool_calls=0 不禁止无工具工作；只有真正调用工具才被拒。"""
    budget = BudgetController(Budget(max_tool_calls=0, max_tokens=16000))
    # Synthetic positive control with a declared, narrow test policy: a signed
    # canary execution receipt is sufficient for this canary alert only.
    from dataclasses import replace
    alert = replace(make_alert(), alert_type="canary_execution_confirmed",
                    raw={"receipt_verified": True, "executed": True,
                         "canary_id": "attack-simulation-001"})
    registry = EvidenceRegistry(alert)
    eid = registry.facts()[0].evidence_id
    output = {
        "verdict": "TP", "disposition": "escalate", "stop_reason": "sufficient",
        "claims": [encode(Claim("claim-1", alert.host, "canary_executed", True,
                                (eid,), "Verified canary execution receipt", "observation"))],
        "final_evidence_ids": [eid],
    }
    def check_canary(value):
        validate_final_assessment(final_assessment_from_output(value), [eid])
        evidence = registry.get(eid).value["raw"]
        if not (evidence.get("receipt_verified") and evidence.get("executed")):
            raise ProtocolViolation("insufficient_evidence", "canary receipt absent")
        assert value["claims"][0]["evidence_ids"] == [eid]
    model = FakeScriptedModel([output])
    result = await run_model_call(
        budget, model, run_id="run-a4", phase="final",
        messages=({"role": "user", "content": "Evaluate the supplied canary receipt."},),
        schema_name="final_assessment.schema.json", max_output_tokens=800,
        estimated_input_tokens=100, output_validator=check_canary,
    )
    assert result.output["verdict"] == "TP"
    assert result.output["final_evidence_ids"] == [eid]
    assert budget.snapshot().tool_attempts == 0
    # Paired negative control: same model verdict must fail with a missing receipt.
    registry = EvidenceRegistry(replace(alert, raw={"executed": True}))
    with pytest.raises(ProtocolViolation, match="model_output_invalid"):
        await run_model_call(
            BudgetController(Budget(max_tool_calls=0)), FakeScriptedModel([output, output]),
            run_id="run-a4-negative", phase="final",
            messages=({"role": "user", "content": "Evaluate the supplied receipt."},),
            schema_name="final_assessment.schema.json", max_output_tokens=800,
            output_validator=check_canary,
        )

    registry2 = EvidenceRegistry(make_alert())
    budget2 = BudgetController(Budget(max_tool_calls=0))
    dispatcher = Dispatcher("run-a4-2", AS_OF, registry2, budget2,
                            MockToolServer(make_fixture(), simulate_latency=False))
    with pytest.raises(BudgetExceeded, match="tool_budget"):
        await dispatcher.dispatch(
            ToolCall("siem", SIEMQuery("process_tree", WINDOW, "WS-041")))
    # tool_budget 锁存后模型准入同步关闭（M3 预算语义）：最终输出必须由
    # 调用方从最后已验证状态确定性构造 Abstain，禁止额外模型总结（设计稿 §8）。
    model2 = FakeScriptedModel([{
        "verdict": "Abstain", "disposition": "human_review",
        "stop_reason": "tool_budget", "claims": [], "final_evidence_ids": [],
    }])
    with pytest.raises(BudgetExceeded, match="tool_budget"):
        await run_model_call(
            budget2, model2, run_id="run-a4-2", phase="final",
            messages=({"role": "user", "content": "工具预算已尽"},),
            schema_name="final_assessment.schema.json", max_output_tokens=800,
            estimated_input_tokens=100,
        )
    assert budget2.snapshot().tool_attempts == 0  # 未获准的请求不计数
