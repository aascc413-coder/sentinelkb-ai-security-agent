from copy import deepcopy

import pytest

from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.normalization import compare_static, normalize_visible


def documents():
    public = {"alert": {"alert_id": "opaque-a", "raw_reference": {"record_id": "opaque-r", "content_sha256": "unchanged"},
                        "host": "host", "user": "user", "occurred_at": "fixed", "as_of": "fixed", "raw": {"detector_claim": "trigger"}}}
    env = {"environment_id": "opaque-e", "fixture_version": "v1", "records_by_tool": {
        "siem": [{"record_id": "fixed-record", "payload": {"host": "host", "process_id": "p", "call_id": "business-call-id"},
                  "content_sha256": "fixed-hash", "reliability": {"level": "high"}, "independence_group": "source"}]},
        "query_rules": [{"status": "partial", "coverage": {"scope": {"host": "host"}, "missing_sources": ["script"]}}]}
    return public, env


def test_dynamic_envelopes_equal_and_no_mutation():
    public, env = documents()
    before = deepcopy((public, env))
    other_public, other_env = deepcopy((public, env))
    other_public["alert"]["alert_id"] = "other-alert"
    other_public["alert"]["raw_reference"]["record_id"] = "other-record"
    other_env["environment_id"] = "other-environment"
    report = compare_static(public, env, other_public, other_env)
    assert report.equal
    assert len(report.normalized_paths) == 6
    assert len(report.normalization_sha256) == 64
    assert (public, env) == before


@pytest.mark.parametrize("path", [
    ("public", "alert", "host"), ("public", "alert", "user"),
    ("public", "alert", "occurred_at"), ("public", "alert", "as_of"),
    ("public", "alert", "raw_reference", "content_sha256"),
    ("public", "alert", "raw", "detector_claim"),
    ("environment", "fixture_version"),
    ("environment", "records_by_tool", "siem", 0, "record_id"),
    ("environment", "records_by_tool", "siem", 0, "payload", "process_id"),
    ("environment", "records_by_tool", "siem", 0, "payload", "call_id"),
    ("environment", "records_by_tool", "siem", 0, "content_sha256"),
    ("environment", "records_by_tool", "siem", 0, "independence_group"),
    ("environment", "records_by_tool", "siem", 0, "reliability", "level"),
    ("environment", "query_rules", 0, "status"),
    ("environment", "query_rules", 0, "coverage", "scope", "host"),
])
def test_business_field_changes_always_visible(path):
    public, env = documents()
    other_public, other_env = deepcopy((public, env))
    target = other_public if path[0] == "public" else other_env
    for key in path[1:-1]:
        target = target[key]
    target[path[-1]] = "different"
    assert not compare_static(public, env, other_public, other_env).equal


def test_identity_bijection_retains_same_vs_different_id():
    public, env = documents()
    public["alert"]["raw_reference"]["record_id"] = public["alert"]["alert_id"]
    other_public = deepcopy(public)
    other_public["alert"]["raw_reference"]["record_id"] = "separate"
    assert not compare_static(public, env, other_public, env).equal


def test_cross_document_reference_is_not_hidden():
    public, env = documents()
    env["records_by_tool"]["siem"][0]["record_id"] = public["alert"]["raw_reference"]["record_id"]
    other_public = deepcopy(public)
    other_public["alert"]["raw_reference"]["record_id"] = "broken-link"
    assert not compare_static(public, env, other_public, env).equal


def test_cross_document_dictionary_key_reference_is_not_hidden():
    public, env = documents()
    env["records_by_tool"]["siem"][0]["payload"]["by_alert"] = {public["alert"]["alert_id"]: "linked-event"}
    other_public = deepcopy(public)
    other_public["alert"]["alert_id"] = "broken-key-link"
    assert not compare_static(public, env, other_public, env).equal


def test_object_key_order_and_array_order_preserved():
    public, env = documents()
    reordered = dict(reversed(list(public["alert"].items())))
    assert not compare_static(public, env, {"alert": reordered}, env).equal
    env["query_rules"].append(deepcopy(env["query_rules"][0]))
    other = deepcopy(env)
    other["query_rules"][1]["status"] = "unavailable"
    reversed_env = deepcopy(other)
    reversed_env["query_rules"].reverse()
    assert not compare_static(public, other, public, reversed_env).equal


def test_measured_runtime_only_normalized_cost_latency_preserved():
    result = {"call_id": "call-a", "actual_duration_ms": 10, "simulated_cost_units": 2.0,
              "simulated_latency_ms": 200, "records": [{"payload": {"call_id": "business", "actual_duration_ms": 9}}]}
    other = deepcopy(result)
    other.update(call_id="call-b", actual_duration_ms=50)
    assert normalize_visible(result, surface="tool_result").value == normalize_visible(other, surface="tool_result").value
    for field in ("simulated_cost_units", "simulated_latency_ms"):
        changed = deepcopy(other)
        changed[field] = 999
        assert normalize_visible(result, surface="tool_result").value != normalize_visible(changed, surface="tool_result").value


@pytest.mark.parametrize("value", [True, -1, 1.5, "3"])
def test_invalid_actual_duration_cannot_be_hidden(value):
    with pytest.raises(ProtocolViolation):
        normalize_visible({"actual_duration_ms": value}, surface="tool_result")


def test_unknown_surface_rejected():
    with pytest.raises(ProtocolViolation):
        normalize_visible({}, surface="oracle")


@pytest.mark.parametrize("key", [1, True, None, 1.5, ("key",)])
def test_nonstring_keys_rejected_before_codec_coercion(key):
    with pytest.raises(ProtocolViolation, match="keys must be strings"):
        normalize_visible({"payload": {key: "value"}}, surface="message")
    public, env = documents()
    bad = deepcopy(public)
    bad["alert"]["raw"] = {key: "value"}
    with pytest.raises(ProtocolViolation, match="keys must be strings"):
        compare_static(bad, env, public, env)


def test_typed_datetime_contracts_and_shared_values_remain_valid():
    from dataclasses import dataclass
    from datetime import datetime, timezone
    @dataclass(frozen=True)
    class Message:
        occurred_at: datetime
        nested: tuple[dict, ...]
    shared = {"value": "one"}
    message = Message(datetime(2026, 9, 1, tzinfo=timezone.utc), (shared, shared))
    result = normalize_visible(message, surface="message")
    assert result.value["occurred_at"] == "2026-09-01T00:00:00+00:00"
    assert result.value["nested"] == [shared, shared]


def test_cyclic_mapping_rejected_with_protocol_error():
    cycle = {}
    cycle["cycle"] = cycle
    with pytest.raises(ProtocolViolation, match="cyclic"):
        normalize_visible(cycle, surface="message")
