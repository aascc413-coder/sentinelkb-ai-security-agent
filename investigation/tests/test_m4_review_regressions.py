"""Regression gates for independent M4 review R1–R8, using no paid services."""

import asyncio
import json
from dataclasses import replace
from datetime import timedelta

import httpx
import pytest

from evidence_investigation.runtime.budget import BudgetController, BudgetExceeded
from evidence_investigation.runtime.model import (
    FakeScriptedModel, ModelError, OpenAICompatAdapter, run_model_call,
)
from evidence_investigation.runtime.registry import EvidenceRegistry, canonical_hash
from evidence_investigation.runtime.trace import TraceRecorder, read_trace
from evidence_investigation.state.contracts import Budget, Coverage, TimeWindow, Usage
from evidence_investigation.state.errors import ProtocolViolation
from test_dispatcher import make_dispatcher, siem_call
from test_model_adapter import VALID_FINAL, INVALID_FINAL
from test_registry import make_alert, make_result, siem_record, WINDOW
from test_trace import make_manifest, make_final


async def invoke(budget, model, trace=None, **kwargs):
    return await run_model_call(
        budget, model, run_id="review", phase="investigate",
        messages=({"role": "user", "content": "Use only the supplied evidence."},),
        schema_name=kwargs.pop("schema_name", "final_assessment.schema.json"),
        max_output_tokens=800, estimated_input_tokens=100, trace=trace, **kwargs,
    )


def recorder(tmp_path, budget):
    return TraceRecorder("review", make_manifest("review"), tmp_path,
                         usage_provider=budget.snapshot)


@pytest.mark.parametrize("change", ["window", "completeness", "missing_sources", "snapshot"])
def test_absence_identity_includes_full_scope_and_coverage(change):
    registry = EvidenceRegistry(make_alert())
    result = make_result([], status="empty")
    first = registry.register_tool_result(result).operational_ids[0]
    other = replace(result, call_id="other")
    if change == "window":
        other = replace(other, coverage=replace(
            other.coverage, window=TimeWindow(WINDOW.start-timedelta(days=1),
                                             WINDOW.end-timedelta(days=1))))
    elif change == "completeness":
        other = replace(other, coverage=replace(other.coverage, completeness="partial"))
    elif change == "missing_sources":
        other = replace(other, coverage=replace(other.coverage, missing_sources=("EDR",)))
    else:
        other = replace(other, snapshot_version="next")
    second = registry.register_tool_result(other).operational_ids[0]
    assert second != first
    if change in {"completeness", "missing_sources"}:
        assert registry.get(second).value["absence_provable"] is False
    assert registry.get(first).value["absence_provable"] is True
    equivalent = registry.register_tool_result(replace(result, call_id="third"))
    assert equivalent.operational_ids == (first,)


def test_registry_isolates_input_and_output_and_rejects_wrong_hash():
    registry = EvidenceRegistry(make_alert())
    initial = registry.facts()[0]
    registry.alert.raw["rule"] = "external mutation"
    assert registry.facts()[0].value == initial.value
    original = siem_record()
    evidence_id = registry.register_tool_result(make_result([original])).evidence_ids[0]
    original.payload["remote_ip"] = "198.51.100.99"
    registry.get(evidence_id).value["remote_ip"] = "198.51.100.100"
    for evidence in registry.facts():
        if evidence.evidence_id == evidence_id:
            evidence.value["remote_ip"] = "198.51.100.101"
    saved = registry.get(evidence_id)
    assert saved.value["remote_ip"] == "203.0.113.66"
    assert canonical_hash(saved.value) == saved.raw_reference.content_sha256
    with pytest.raises(ProtocolViolation, match="content_hash_mismatch"):
        registry.register_tool_result(make_result([original], call_id="bad-hash"))


@pytest.mark.asyncio
async def test_schema_error_never_reserves_budget():
    budget = BudgetController(Budget())
    model = FakeScriptedModel([VALID_FINAL])
    with pytest.raises(ProtocolViolation, match="unknown_schema"):
        await invoke(budget, model, schema_name="absent.schema.json")
    assert budget.snapshot().model_calls == 0
    assert model.calls == 0
    assert (await invoke(budget, model)).output == VALID_FINAL


@pytest.mark.asyncio
async def test_repair_service_error_reconciles_and_retains_first_error(tmp_path):
    budget = BudgetController(Budget())
    trace = recorder(tmp_path, budget)
    with pytest.raises(ModelError, match="repair down"):
        await invoke(budget, FakeScriptedModel([INVALID_FINAL, ModelError("repair down")]), trace)
    records = [e.payload for e in trace.events if e.event_type == "model_output_recorded"]
    assert records[0]["raw_output"] == INVALID_FINAL
    assert all(r["accepted_output"] is None for r in records)
    assert len([e for e in trace.events if e.event_type == "budget_reconciled"]) == 2
    assert budget.charged_tokens >= 1050
    assert not budget.snapshot().usage_complete
    assert (await invoke(budget, FakeScriptedModel([VALID_FINAL]))).output == VALID_FINAL


@pytest.mark.asyncio
async def test_repair_budget_denial_preserves_original_failure(tmp_path):
    budget = BudgetController(Budget())
    trace = recorder(tmp_path, budget)
    model = FakeScriptedModel([{**INVALID_FINAL, "__usage__": (8000, 5000)}])
    with pytest.raises(BudgetExceeded, match="token_budget"):
        await invoke(budget, model, trace)
    assert model.calls == 1
    records = [e.payload for e in trace.events if e.event_type == "model_output_recorded"]
    assert records[0]["raw_output"] == INVALID_FINAL
    assert records[0]["validation_error"]
    assert records[0]["accepted_output"] is None
    assert budget.charged_tokens == 13000


@pytest.mark.asyncio
async def test_nonjson_response_preserves_text_and_known_usage_then_repairs(tmp_path):
    calls = []
    def handler(request):
        calls.append(request)
        content = "not JSON" if len(calls) == 1 else json.dumps(VALID_FINAL)
        return httpx.Response(200, json={
            "choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 34},
        })
    adapter = OpenAICompatAdapter(api_key="fake", base_url="https://mock.test/v1",
                                  model="fake", transport=httpx.MockTransport(handler))
    budget = BudgetController(Budget())
    trace = recorder(tmp_path, budget)
    try:
        result = await invoke(budget, adapter, trace)
    finally:
        await adapter.aclose()
    assert result.record.raw_output == "not JSON"
    assert result.record.validation_error
    assert result.record.accepted_output == VALID_FINAL
    assert budget.charged_tokens == 92 and budget.snapshot().usage_complete
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_late_model_is_charged_but_not_accepted(tmp_path):
    now = [0.0]
    budget = BudgetController(Budget(max_time_seconds=0.5), clock=lambda: now[0])
    trace = recorder(tmp_path, budget)
    def late(messages, schema, max_output, timeout):
        assert 0 < timeout <= 0.5
        now[0] = 2
        return VALID_FINAL, Usage(input_tokens=12, output_tokens=34)
    with pytest.raises(BudgetExceeded, match="deadline"):
        await invoke(budget, FakeScriptedModel([late]), trace)
    assert budget.charged_tokens == 46
    records = [e.payload for e in trace.events if e.event_type == "model_output_recorded"]
    assert records[-1]["raw_output"] == VALID_FINAL
    assert records[-1]["accepted_output"] is None


@pytest.mark.asyncio
async def test_model_task_cancellation_releases_reservation(tmp_path):
    started = asyncio.Event()
    class WaitingModel:
        async def complete(self, *args, **kwargs):
            started.set()
            await asyncio.Event().wait()
    budget = BudgetController(Budget())
    trace = recorder(tmp_path, budget)
    task = asyncio.create_task(invoke(budget, WaitingModel(), trace))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert budget.charged_tokens == 900
    assert not budget.snapshot().usage_complete
    assert (await invoke(budget, FakeScriptedModel([VALID_FINAL]))).output == VALID_FINAL


@pytest.mark.asyncio
async def test_each_retry_has_one_complete_return_event(tmp_path):
    class FlakyTools:
        calls = 0
        async def siem(self, query, ctx):
            self.calls += 1
            if self.calls == 1:
                return make_result([], call_id=ctx.call_id, status="timeout",
                                   coverage=Coverage({}, None, "unknown", False, ()),
                                   error_code="tool_timeout", retryable=True)
            return make_result([siem_record()], call_id=ctx.call_id)
    dispatcher, registry, budget = make_dispatcher(FlakyTools())
    trace = recorder(tmp_path, budget)
    dispatcher.trace = trace
    await dispatcher.dispatch(siem_call())
    requested = [e.payload["call_id"] for e in trace.events if e.event_type == "tool_requested"]
    returned = [e.payload["call_id"] for e in trace.events if e.event_type == "tool_returned"]
    assert requested == returned and len(returned) == 2
    first = next(e.payload for e in trace.events if e.event_type == "tool_returned")
    assert first["result"]["error_code"] == "tool_timeout"
    assert budget.snapshot().tool_attempts == 2


def test_reusing_trace_id_is_rejected_without_changing_old_files(tmp_path):
    budget = BudgetController(Budget())
    first = recorder(tmp_path, budget)
    first.emit("alert_received", {"alert": "old"})
    first.finalize(make_final())
    previous = {p.name: p.read_bytes() for p in first.dir.iterdir()}
    with pytest.raises(ProtocolViolation, match="run_exists"):
        recorder(tmp_path, budget)
    assert previous == {p.name: p.read_bytes() for p in first.dir.iterdir()}
    assert [e.sequence for e in read_trace(tmp_path, "review").events] == [1]


@pytest.mark.asyncio
async def test_grounding_error_is_preserved_and_repaired_with_registered_evidence(tmp_path):
    registry = EvidenceRegistry(make_alert())
    known = registry.facts()[0].evidence_id
    wrong = {**VALID_FINAL, "final_evidence_ids": ["invented-evidence"]}
    corrected = {**VALID_FINAL, "final_evidence_ids": [known]}
    def check(output):
        registry.require_known(output["final_evidence_ids"])
    budget = BudgetController(Budget())
    trace = recorder(tmp_path, budget)
    result = await invoke(budget, FakeScriptedModel([wrong, corrected]), trace,
                          output_validator=check)
    assert result.record.raw_output == wrong
    assert "dangling_reference" in result.record.validation_error
    assert result.record.repaired_output == corrected == result.record.accepted_output
    assert len(registry.facts()) == 1  # Model output never becomes evidence.


@pytest.mark.asyncio
async def test_backend_exception_releases_budget_and_has_return_event(tmp_path):
    class BrokenTools:
        async def siem(self, query, ctx):
            raise TimeoutError("backend failed")
    dispatcher, registry, budget = make_dispatcher(BrokenTools())
    trace = recorder(tmp_path, budget)
    dispatcher.trace = trace
    outcome = await dispatcher.dispatch(siem_call())
    assert outcome.protocol_error_code == "tool_exception"
    assert not budget.snapshot().usage_complete
    assert budget.snapshot().backend_calls == 1
    assert len(registry.facts()) == 1
    assert [e.event_type for e in trace.events] == ["tool_requested", "tool_returned"]
    assert (await invoke(budget, FakeScriptedModel([VALID_FINAL]))).output == VALID_FINAL


@pytest.mark.asyncio
async def test_invalid_and_permanent_cached_calls_have_paired_events(tmp_path):
    from test_dispatcher import build_server
    from evidence_investigation.state.contracts import HistoryQuery, ToolCall
    dispatcher, _, budget = make_dispatcher(build_server(history_status="unavailable"))
    trace = recorder(tmp_path, budget)
    dispatcher.trace = trace
    await dispatcher.dispatch(siem_call(host="unknown-host"))
    call = ToolCall("history", HistoryQuery("host", "WS-041", WINDOW))
    await dispatcher.dispatch(call)
    outcome = await dispatcher.dispatch(call)
    assert outcome.cache_hit and outcome.result.simulated_cost_units == 0
    requested = [e.payload["call_id"] for e in trace.events if e.event_type == "tool_requested"]
    returned = [e.payload["call_id"] for e in trace.events if e.event_type == "tool_returned"]
    assert requested == returned and len(returned) == 3


@pytest.mark.asyncio
async def test_final_call_can_use_reserved_finalization_tokens():
    budget = BudgetController(Budget(max_tokens=3000, finalization_token_reserve=2500))
    result = await run_model_call(
        budget, FakeScriptedModel([VALID_FINAL]), run_id="final", phase="final",
        messages=({"role": "user", "content": "Finalize."},),
        schema_name="final_assessment.schema.json", max_output_tokens=800,
        estimated_input_tokens=100,
    )
    assert result.token_plans[0].finalization_reserve == 0
    assert budget.charged_tokens == 150


@pytest.mark.asyncio
async def test_unencodable_invalid_arguments_do_not_leak_budget(tmp_path):
    from evidence_investigation.state.contracts import ToolCall
    from test_dispatcher import build_server
    dispatcher, _, budget = make_dispatcher(build_server())
    trace = recorder(tmp_path, budget)
    dispatcher.trace = trace
    outcome = await dispatcher.dispatch(ToolCall("siem", object()))
    assert outcome.protocol_error_code == "tool_argument_mismatch"
    assert [e.event_type for e in trace.events] == ["tool_requested", "tool_returned"]
    assert budget.snapshot().backend_calls == 0
    assert (await invoke(budget, FakeScriptedModel([VALID_FINAL]))).output == VALID_FINAL


@pytest.mark.asyncio
async def test_bad_tool_hash_is_logged_charged_and_not_registered(tmp_path):
    class BadTools:
        async def siem(self, query, ctx):
            return make_result([replace(siem_record(), content_sha256="00"*32)],
                               call_id=ctx.call_id)
    dispatcher, registry, budget = make_dispatcher(BadTools())
    trace = recorder(tmp_path, budget)
    dispatcher.trace = trace
    outcome = await dispatcher.dispatch(siem_call())
    assert outcome.protocol_error_code == "content_hash_mismatch"
    assert outcome.evidence_ids == () and len(registry.facts()) == 1
    assert budget.snapshot().backend_calls == 1
    assert [e.event_type for e in trace.events] == ["tool_requested", "tool_returned"]
    assert trace.events[-1].payload["result"]["records"][0]["content_sha256"] == "00"*32


def test_registry_rejection_does_not_partially_register_batch():
    registry = EvidenceRegistry(make_alert())
    first = siem_record()
    second = siem_record({"observed_at": None}, record_id="bad")
    with pytest.raises(ProtocolViolation, match="unregistrable_record"):
        registry.register_tool_result(make_result([first, second]))
    assert len(registry.facts()) == 1
    registration = registry.register_tool_result(make_result([first]))
    assert registration.evidence_ids == ("ev-0002",)
