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
