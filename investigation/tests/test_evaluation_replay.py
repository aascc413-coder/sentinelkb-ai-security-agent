"""Offline replay accepts complete traces and rejects corrupt acquisition logs."""

import json
from dataclasses import replace

import pytest

from evaluation.replay import replay_run
from evidence_investigation.runtime.trace import TraceRecorder
from evidence_investigation.state.codec import encode
from evidence_investigation.state.content import content_hash
from evidence_investigation.state.contracts import Coverage
from evidence_investigation.state.errors import ProtocolViolation
from test_dispatcher import make_dispatcher, build_server, siem_call
from test_registry import make_result, siem_record
from test_trace import make_manifest, make_final


async def make_trace(tmp_path, *, retry=False, repeat=False, invalid=False):
    class RetryTools:
        calls = 0
        async def siem(self, query, ctx):
            self.calls += 1
            if self.calls == 1:
                return make_result([], status="timeout", call_id=ctx.call_id,
                                   error_code="tool_timeout", retryable=True,
                                   coverage=Coverage({}, None, "unknown", False, ()))
            return make_result([siem_record()], call_id=ctx.call_id)
    dispatcher, registry, budget = make_dispatcher(RetryTools() if retry else build_server())
    trace = TraceRecorder("run-1", make_manifest(), tmp_path, usage_provider=budget.snapshot)
    dispatcher.trace = trace
    trace.emit("alert_received", {"alert": encode(registry.alert)}, state_version_after=1)
    if invalid:
        await dispatcher.dispatch(siem_call(host="unseen"))
    result = await dispatcher.dispatch(siem_call())
    if repeat:
        await dispatcher.dispatch(siem_call())
    trace.finalize(replace(make_final(), final_evidence_ids=result.evidence_ids))
    return trace.dir, registry, budget


@pytest.mark.asyncio
@pytest.mark.parametrize("options", [{}, {"retry": True}, {"repeat": True}, {"invalid": True}])
async def test_replay_recovers_facts_from_raw_responses_without_runtime_calls(tmp_path, options):
    folder, registry, budget = await make_trace(tmp_path, **options)
    replay = replay_run(folder)
    expected = {e.evidence_id: e for e in registry.facts() + registry.operational_facts()}
    assert set(replay.facts) == set(expected)
    for eid, fact in replay.facts.items():
        assert fact.fact_key == expected[eid].fact_key
        assert fact.value == expected[eid].value
    assert replay.usage.tool_attempts == budget.snapshot().tool_attempts
    assert replay.final.final_evidence_ids


@pytest.mark.asyncio
@pytest.mark.parametrize("corruption", ["sequence", "run_id", "hash", "registration_id",
                                        "return_missing", "duplicate_return", "call_id",
                                        "elapsed", "version", "final_reference", "attempt_count",
                                        "missing_observation", "future_observation", "snapshot",
                                        "late_registration", "missing_result"])
async def test_replay_rejects_corruption(tmp_path, corruption):
    folder, _, _ = await make_trace(tmp_path)
    events_path = folder / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    final_path = folder / "final.json"
    final = json.loads(final_path.read_text(encoding="utf-8"))
    returned = next(e for e in events if e["event_type"] == "tool_returned")
    registered = next(e for e in events if e["event_type"] == "evidence_registered")
    if corruption == "sequence":
        events[-1]["sequence"] = 99
    elif corruption == "run_id":
        events[-1]["run_id"] = "other"
    elif corruption == "hash":
        returned["payload"]["result"]["records"][0]["payload"]["remote_ip"] = "198.51.100.99"
    elif corruption == "registration_id":
        registered["payload"]["evidence_ids"] = ["invented"]
    elif corruption == "return_missing":
        events.remove(returned)
        final["event_count"] -= 1
    elif corruption == "duplicate_return":
        events.append({**returned, "sequence": len(events)+1})
        final["event_count"] += 1
    elif corruption == "call_id":
        returned["payload"]["result"]["call_id"] = "different"
    elif corruption == "elapsed":
        events[-1]["elapsed_ms"] = -1
    elif corruption == "version":
        registered["state_version_after"] = 999
    elif corruption == "final_reference":
        final["final"]["final_evidence_ids"] = ["never-acquired"]
    elif corruption == "attempt_count":
        final["usage"]["tool_attempts"] = 0
    elif corruption in {"missing_observation", "future_observation"}:
        record = returned["payload"]["result"]["records"][0]
        if corruption == "missing_observation":
            del record["payload"]["observed_at"]
        else:
            record["payload"]["observed_at"] = "2030-01-01T00:00:00+00:00"
        record["content_sha256"] = content_hash(record["payload"])
    elif corruption == "snapshot":
        returned["payload"]["result"]["snapshot_version"] = "unrecorded-world"
    elif corruption == "late_registration":
        registered["elapsed_ms"] = registered["usage_snapshot"]["elapsed_ms"] = 1000000
        returned["elapsed_ms"] = returned["usage_snapshot"]["elapsed_ms"] = 1000001
        final["usage"]["elapsed_ms"] = 1000002
    elif corruption == "missing_result":
        del returned["payload"]["result"]
    events_path.write_text("\n".join(json.dumps(e) for e in events)+"\n", encoding="utf-8")
    final_path.write_text(json.dumps(final), encoding="utf-8")
    with pytest.raises(ProtocolViolation):
        replay_run(folder)


@pytest.mark.asyncio
async def test_replay_missing_full_alert_is_rejected(tmp_path):
    folder, _, _ = await make_trace(tmp_path)
    path = folder / "events.jsonl"
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    events[0]["payload"] = {"alert_id": "a-1"}
    path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    with pytest.raises(ProtocolViolation, match="full original alert"):
        replay_run(folder)


@pytest.mark.asyncio
async def test_final_usage_must_include_budget_clock_even_when_trace_started_later(tmp_path):
    folder, _, _ = await make_trace(tmp_path)
    path = folder / "events.jsonl"
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    for event in events:
        event["elapsed_ms"] = 0
        event["usage_snapshot"]["elapsed_ms"] = 100
    path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    final_path = folder / "final.json"
    final = json.loads(final_path.read_text(encoding="utf-8"))
    final["usage"]["elapsed_ms"] = 1
    final_path.write_text(json.dumps(final), encoding="utf-8")
    with pytest.raises(ProtocolViolation, match="final usage precedes"):
        replay_run(folder)


async def make_model_trace(tmp_path, mode="known"):
    from evidence_investigation.runtime.model import FakeScriptedModel, run_model_call
    from evidence_investigation.state.contracts import Usage
    from test_model_adapter import VALID_FINAL, INVALID_FINAL

    class FailingTools:
        async def siem(self, query, context):
            raise RuntimeError("unmeasured backend failure")

    dispatcher, registry, budget = make_dispatcher(FailingTools() if mode == "tool_unknown" else build_server())
    trace = TraceRecorder("run-1", make_manifest(), tmp_path, usage_provider=budget.snapshot)
    trace.emit("alert_received", {"alert": encode(registry.alert)}, state_version_after=1)
    if mode == "tool_unknown":
        dispatcher.trace = trace
        await dispatcher.dispatch(siem_call())
    script = [VALID_FINAL]
    if mode == "repair":
        script = [INVALID_FINAL, VALID_FINAL]
    elif mode == "unknown":
        script = [lambda *args: (VALID_FINAL, None)]
    elif mode == "partial":
        script = [lambda *args: (VALID_FINAL, Usage(input_tokens=7, usage_complete=False))]
    await run_model_call(
        budget, FakeScriptedModel(script), run_id="run-1", phase="final",
        messages=({"role": "user", "content": "investigate"},),
        schema_name="final_assessment.schema.json", max_output_tokens=800,
        estimated_input_tokens=100, trace=trace,
    )
    trace.finalize(make_final())
    return trace.dir


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,counts,complete", [
    ("known", (1, 100, 50), True), ("repair", (2, 200, 100), True),
    ("unknown", (1, 0, 0), False), ("partial", (1, 7, 0), False),
    ("tool_unknown", (1, 100, 50), False),
])
async def test_model_ledger_accepts_measured_repair_and_preserves_unknown(tmp_path, mode, counts, complete):
    replay = replay_run(await make_model_trace(tmp_path, mode))
    assert (replay.usage.model_calls, replay.usage.input_tokens, replay.usage.output_tokens) == counts
    assert replay.usage.usage_complete is complete
    settlements = [e for e in replay.events if e.event_type == "budget_reconciled"]
    if mode == "unknown":
        assert settlements[0].payload["actual_usage"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("corruption", [
    "zero_tokens", "calls", "completeness", "missing_settlement", "duplicate_settlement",
    "missing_reservation", "duplicate_reservation", "settlement_estimate",
    "settlement_phase", "snapshot_tokens", "actual_negative", "actual_boolean",
    "duplicate_output", "output_identity", "unknown_marked_complete", "invented_cost",
])
async def test_model_ledger_rejects_corrupt_usage_and_lifecycle(tmp_path, corruption):
    folder = await make_model_trace(tmp_path, "unknown" if corruption == "unknown_marked_complete" else "known")
    path = folder / "events.jsonl"
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    final_path = folder / "final.json"
    final = json.loads(final_path.read_text(encoding="utf-8"))
    settlement = next(e for e in events if e["event_type"] == "budget_reconciled")
    reservation = next(e for e in events if e["event_type"] == "budget_checked")
    output = next(e for e in events if e["event_type"] == "model_output_recorded")
    if corruption == "zero_tokens":
        final["usage"]["input_tokens"] = final["usage"]["output_tokens"] = 0
    elif corruption == "calls":
        final["usage"]["model_calls"] = 0
    elif corruption in {"completeness", "unknown_marked_complete"}:
        final["usage"]["usage_complete"] = not final["usage"]["usage_complete"]
    elif corruption == "invented_cost":
        final["usage"]["model_cost"], final["usage"]["currency"] = 0.0, "USD"
    elif corruption.startswith("missing_"):
        events.remove(settlement if corruption == "missing_settlement" else reservation)
    elif corruption.startswith("duplicate_"):
        target = {"duplicate_settlement": settlement, "duplicate_reservation": reservation,
                  "duplicate_output": output}[corruption]
        events.insert(events.index(target), json.loads(json.dumps(target)))
    elif corruption == "settlement_estimate":
        settlement["payload"]["estimated_input_tokens"] += 1
    elif corruption == "settlement_phase":
        settlement["payload"]["phase"] = "plan"
    elif corruption == "snapshot_tokens":
        settlement["usage_snapshot"]["output_tokens"] = 0
    elif corruption == "actual_negative":
        settlement["payload"]["actual_usage"]["input_tokens"] = -1
    elif corruption == "actual_boolean":
        settlement["payload"]["actual_usage"]["input_tokens"] = True
    elif corruption == "output_identity":
        output["payload"]["call_id"] = "invented"
    for index, event in enumerate(events, 1):
        event["sequence"] = index
    final["event_count"] = len(events)
    path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    final_path.write_text(json.dumps(final), encoding="utf-8")
    with pytest.raises(ProtocolViolation):
        replay_run(folder)
