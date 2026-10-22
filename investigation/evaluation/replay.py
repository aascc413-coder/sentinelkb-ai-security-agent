"""Offline provenance replay for the M4 registry-v1 trace format.

Consumes files only; never imports the runtime, agent, tools or oracle. This
checks acquisition integrity, not semantic grounding or evidence sufficiency.
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import json

from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.content import content_hash, load_json
from evidence_investigation.state.contracts import (
    Alert, EventType, FinalAssessment, RunManifest, ToolResult, TraceEvent, Usage,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.validation import validate_final_assessment, require_utc


@dataclass
class ReplayFact:
    evidence_id: str
    fact_key: str
    value: dict
    record_ids: list[str] = field(default_factory=list)
    call_ids: list[str] = field(default_factory=list)
    independence_groups: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ReplayResult:
    manifest: RunManifest
    alert: Alert
    facts: dict[str, ReplayFact]
    final: FinalAssessment
    usage: Usage
    tool_results: tuple[ToolResult, ...]
    model_output_revisions: tuple[dict, ...]
    events: tuple[TraceEvent, ...] = ()


def _require(condition, detail):
    if not condition:
        raise ProtocolViolation("invalid_trace", detail)


def _unique_append(items, value):
    if value not in items:
        items.append(value)


def _strict_line(text):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ProtocolViolation("invalid_trace", f"non-finite JSON: {value}")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)


def _verify_model_ledger(events, final_usage):
    """Verify registry-v1's sequential reservation/settlement protocol offline.

    The request is budget_checked(kind=model_reserve), not model_requested.
    Settlements lack call IDs: pairing therefore relies on exactly one pending
    reservation and matching phase/estimates. This checks trace consistency,
    not provider truth. Unknown actual_usage stays None in the returned events;
    aggregate tokens represent only known measurements, never estimated cost.
    """
    pending = None
    attempts = {}
    calls = inputs = outputs = 0
    complete = cost_complete = True
    cost = currency = None

    def integer(value):
        _require(type(value) is int and value >= 0, "invalid model ledger integer")

    def check_snapshot(usage, *, reserved=False):
        for value in (usage.model_calls, usage.input_tokens, usage.output_tokens):
            integer(value)
        _require((usage.model_calls, usage.input_tokens, usage.output_tokens)
                 == (calls, inputs, outputs), "model ledger token/count mismatch")
        _require(type(usage.usage_complete) is bool
                 and usage.usage_complete == (complete and not reserved),
                 "model ledger completeness mismatch")
        _require(usage.model_cost == cost and usage.currency == currency,
                 "model ledger monetary cost mismatch")

    for event in events:
        body = event.payload
        if event.event_type == "tool_returned":
            if body.get("backend_called") and body.get("result") is None:
                complete = False
        elif event.event_type == "budget_checked" and body.get("kind") == "model_reserve":
            _require(pending is None, "overlapping model reservations")
            call_id, attempt = body["call_id"], body["attempt"]
            _require(isinstance(call_id, str) and bool(call_id), "missing model call identity")
            integer(attempt)
            _require(attempt == attempts.get(call_id, 0) + 1 and attempt <= 2,
                     "duplicate/noncontiguous model attempt")
            integer(body["estimated_input_tokens"])
            integer(body["max_output_tokens"])
            attempts[call_id] = attempt
            pending = (body, False)
            calls += 1
            check_snapshot(event.usage_snapshot, reserved=True)
        elif event.event_type == "model_output_recorded":
            _require(pending is not None and not pending[1], "orphan/duplicate model output")
            request = pending[0]
            _require(body["call_id"] == request["call_id"] and body["phase"] == request["phase"],
                     "model output identity mismatch")
            pending = (request, True)
        elif event.event_type == "budget_reconciled":
            _require(pending is not None and pending[1], "orphan/duplicate model settlement")
            request = pending[0]
            _require(body["phase"] == request["phase"]
                     and body["estimated_input_tokens"] == request["estimated_input_tokens"]
                     and body["reserved_output_tokens"] == request["max_output_tokens"],
                     "model settlement reservation mismatch")
            actual = body["actual_usage"]
            if actual is None:
                complete = cost_complete = False
            else:
                actual = decode(Usage, actual)
                integer(actual.input_tokens)
                integer(actual.output_tokens)
                _require(type(actual.usage_complete) is bool, "invalid actual completeness")
                inputs += actual.input_tokens
                outputs += actual.output_tokens
                complete = complete and actual.usage_complete
                if actual.model_cost is None or actual.currency is None:
                    cost_complete = False
                elif cost_complete:
                    _require(type(actual.model_cost) in (int, float)
                             and actual.model_cost >= 0, "invalid measured model cost")
                    if currency not in (None, actual.currency):
                        cost_complete = False
                    else:
                        currency = actual.currency
                        cost = (cost or 0.0) + actual.model_cost
            if not cost_complete:
                cost = currency = None
            pending = None
            check_snapshot(event.usage_snapshot)
    _require(pending is None, "missing model settlement")
    check_snapshot(final_usage)


def replay_run(run_dir: str | Path) -> ReplayResult:
    """Read a complete trace; malformed input is a protocol failure, not a crash."""
    try:
        return _replay_run(run_dir)
    except (KeyError, TypeError, IndexError, ValueError, OSError) as exc:
        raise ProtocolViolation("invalid_trace", f"malformed trace: {exc}") from exc


def _replay_run(run_dir: str | Path) -> ReplayResult:
    """Require a complete run, preserving failures rather than filling gaps.

    Evidence IDs follow M4's deterministic ev-NNNN registry-v1 allocation.
    Registration notices precede tool_returned in this format. All notices are
    independently checked against the raw response before a fact is accepted.
    """
    folder = Path(run_dir)
    manifest = decode(RunManifest, load_json(folder / "manifest.json"))
    final_payload = load_json(folder / "final.json")
    final = decode(FinalAssessment, final_payload["final"])
    usage = decode(Usage, final_payload["usage"])
    try:
        events = tuple(decode(TraceEvent, _strict_line(line)) for line in
                       (folder / "events.jsonl").read_text(encoding="utf-8").splitlines()
                       if line.strip())
    except (ValueError, OSError) as exc:
        raise ProtocolViolation("invalid_trace", str(exc)) from exc
    _require(final_payload["event_count"] == len(events), "final event_count mismatch")
    _require(events and events[0].event_type == "alert_received", "missing initial alert")
    _require("alert" in events[0].payload, "full original alert is required")
    alert = decode(Alert, events[0].payload["alert"])
    payload = {"alert_id": alert.alert_id, "alert_type": alert.alert_type,
               "host": alert.host, "user": alert.user, "process_id": alert.process_id,
               "command_line": alert.command_line, "occurred_at": alert.occurred_at.isoformat(),
               "raw": alert.raw}
    facts = {"ev-0001": ReplayFact("ev-0001", "alert:" + content_hash(payload), payload,
                                   [alert.raw_reference.record_id], [], ["alert"])}
    by_key = {facts["ev-0001"].fact_key: "ev-0001"}
    requests, registrations, returned = {}, {}, set()
    results, model_revisions = [], []
    elapsed, version, usage_elapsed = 0, 1, 0

    def register(key, value, record_id, call_id, group):
        existing = by_key.get(key)
        if existing is None:
            existing = f"ev-{len(facts)+1:04d}"
            facts[existing] = ReplayFact(existing, key, value)
            by_key[key] = existing
        fact = facts[existing]
        _unique_append(fact.record_ids, record_id)
        _unique_append(fact.call_ids, call_id)
        _unique_append(fact.independence_groups, group)
        return existing

    for index, event in enumerate(events, 1):
        _require(event.sequence == index, "event sequence is not contiguous")
        _require(event.run_id == manifest.run_id, "event run_id mismatch")
        _require(event.event_type in EventType.ALL, "unknown event type")
        require_utc(event.timestamp, "trace timestamp")
        _require(event.elapsed_ms >= elapsed and event.step >= 0, "nonmonotonic elapsed/negative step")
        _require(event.usage_snapshot.elapsed_ms >= usage_elapsed, "nonmonotonic budget time")
        usage_elapsed = event.usage_snapshot.elapsed_ms
        elapsed = event.elapsed_ms
        body = event.payload
        if event.event_type == "alert_received":
            _require(index == 1, "duplicate alert")
        elif event.event_type == "tool_requested":
            call_id = body["call_id"]
            _require(call_id not in requests, "duplicate tool request")
            requests[call_id] = body
        elif event.event_type == "evidence_registered":
            call_id = body["call_id"]
            _require(call_id in requests and call_id not in returned, "registration outside active call")
            _require(call_id not in registrations, "duplicate registration notice")
            _require(event.state_version_before == version, "registration version does not follow state")
            _require(event.elapsed_ms < manifest.budget.max_time_seconds * 1000
                     and event.usage_snapshot.elapsed_ms < manifest.budget.max_time_seconds * 1000,
                     "evidence registered after deadline")
            registrations[call_id] = event
        elif event.event_type == "tool_returned":
            call_id = body["call_id"]
            _require(call_id in requests and call_id not in returned, "orphan/duplicate tool return")
            returned.add(call_id)
            _require(body["tool"] == requests[call_id]["tool"], "tool identity mismatch")
            notice = registrations.pop(call_id, None)
            result = None if body["result"] is None else decode(ToolResult, body["result"])
            if result is not None:
                _require(result.call_id == call_id and result.tool == body["tool"], "response identity mismatch")
                results.append(result)
            if notice is None:
                _require(not body.get("evidence_ids") and not body.get("operational_ids"),
                         "unregistered response exposes evidence")
                _require(result is None or body.get("late") or body.get("protocol_error_code")
                         or (body.get("cache_hit") and result.status == "unavailable"),
                         "successful response missing registration")
                continue
            _require(result is not None and not body.get("late") and not body.get("protocol_error_code"),
                     "failed or late response registered as evidence")
            _require(result.snapshot_version == manifest.tool_snapshot, "tool snapshot mismatch")
            new_ids, merged_keys = [], []
            for record in result.records:
                _require(content_hash(record.payload) == record.content_sha256, "record hash mismatch")
                observed = record.payload.get("observed_at") or record.payload.get("published_at")
                _require(isinstance(observed, str), "record missing observation time")
                stamp = datetime.fromisoformat(observed)
                require_utc(stamp, "record observation time")
                _require(stamp <= alert.as_of, "record observed after frozen as_of")
                key = f"{result.tool}:{content_hash(record.payload)}"
                existed = key in by_key
                eid = register(key, record.payload, record.record_id, call_id, record.independence_group)
                if existed:
                    merged_keys.append(key)
                else:
                    new_ids.append(eid)
            envelope = {"tool": result.tool, "status": result.status,
                        "error_code": result.error_code, "retryable": result.retryable,
                        "coverage": encode(result.coverage), "snapshot_version": result.snapshot_version}
            key, value = None, envelope
            if result.status in {"unavailable", "timeout", "error"}:
                key = f"source:{result.tool}:{content_hash(envelope)}"
            elif result.status == "empty":
                key = f"absence:{result.tool}:{content_hash(envelope)}"
                value = {**envelope, "absence_provable": result.coverage.completeness == "complete"
                         and not result.coverage.truncated and not result.coverage.missing_sources}
            elif result.status == "partial":
                key = f"source:{result.tool}:partial:{content_hash(envelope)}"
            operational_ids = []
            if key is not None:
                if key not in by_key:
                    version += 1
                operational_ids.append(register(key, value, f"call:{call_id}", call_id,
                                                f"{result.tool}-availability"))
            version += 1
            _require(new_ids == notice.payload["evidence_ids"] == body["evidence_ids"], "evidence IDs mismatch")
            _require(merged_keys == notice.payload["merged_fact_keys"], "deduplication mismatch")
            _require(operational_ids == notice.payload["operational_ids"] == body["operational_ids"],
                     "operational IDs mismatch")
            _require(notice.state_version_after == version, "registration version mismatch")
        elif event.event_type == "model_output_recorded":
            model_revisions.append({**body, "available_evidence_ids": list(facts),
                                    "trace_sequence": event.sequence})
    _require(set(requests) == returned and not registrations, "incomplete tool lifecycle")
    _require(usage.tool_attempts == len(requests), "final tool attempt count mismatch")
    _require(usage.elapsed_ms >= max(elapsed, usage_elapsed), "final usage precedes trace events")
    _verify_model_ledger(events, usage)
    validate_final_assessment(final, facts)
    return ReplayResult(manifest, alert, facts, final, usage, tuple(results), tuple(model_revisions), events)
