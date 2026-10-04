"""Whitelist normalization must never conceal observable business differences."""

from copy import deepcopy
from dataclasses import replace

import pytest

from evidence_investigation.state.contracts import Coverage, Reliability, ToolRecord, ToolResult
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.tools.diff_report import compare_responses, normalization_policy


def response():
    record = ToolRecord("opaque-record-1", {"host": "WS-088", "occurred_at": "2026-09-01T02:14:00+00:00",
                        "call_id": "payload-identity", "actual_duration_ms": 123},
                        "a" * 64, "sensor-a", "group-a", Reliability("high", "sensor policy", "v1"))
    return ToolResult("call-1", "siem", "partial", (record,),
                      Coverage({"host": "WS-088", "as_of": "2026-09-01T02:20:00+00:00"},
                               None, "partial", False, ("process_parent",)),
                      "snapshot-v1", None, False, 2.0, 200, 1)


def paths(report):
    return {item["path"] for item in report["differences"]}


def test_only_dynamic_envelope_metadata_is_normalized():
    first = response()
    report = compare_responses(first, replace(first, call_id="other-call", actual_duration_ms=984))
    assert report["equal"] and report["difference_count"] == 0
    assert {item["path"] for item in report["normalized_fields"]} == {"/call_id", "/actual_duration_ms"}
    assert all(item["reason"] and item["changed"] for item in report["normalized_fields"])
    assert first.call_id == "call-1" and first.actual_duration_ms == 1


@pytest.mark.parametrize("field,value", [
    ("tool", "history"), ("status", "unavailable"), ("snapshot_version", "other-snapshot"),
    ("error_code", "missing_source"), ("retryable", True),
    ("simulated_cost_units", 3.0), ("simulated_latency_ms", 201),
])
def test_envelope_business_fields_remain_visible(field, value):
    first = response()
    report = compare_responses(first, replace(first, **{field: value}))
    assert not report["equal"] and f"/{field}" in paths(report)


@pytest.mark.parametrize("field,value", [
    ("record_id", "different-record"), ("content_sha256", "b" * 64),
    ("source_system", "sensor-b"), ("independence_group", "group-b"),
    ("reliability", Reliability("low", "unknown provenance", "v2")),
])
def test_record_identity_hash_source_quality_are_not_normalized(field, value):
    first = response()
    other = replace(first, records=(replace(first.records[0], **{field: value}),))
    report = compare_responses(first, other)
    assert not report["equal"]
    assert any(path.startswith(f"/records/0/{field}") for path in paths(report))


@pytest.mark.parametrize("field,value", [
    ("host", "WS-089"), ("occurred_at", "2026-09-01T02:15:00+00:00"),
    ("call_id", "changed-business-call"), ("actual_duration_ms", 124),
    ("new/field~name", "extra"),
])
def test_arbitrary_payload_keys_including_names_of_dynamic_fields_are_compared(field, value):
    first = response()
    payload = {**first.records[0].payload, field: value}
    other = replace(first, records=(replace(first.records[0], payload=payload),))
    report = compare_responses(first, other)
    escaped = field.replace("~", "~0").replace("/", "~1")
    assert not report["equal"] and f"/records/0/payload/{escaped}" in paths(report)


@pytest.mark.parametrize("changes,expected", [
    ({"completeness": "complete"}, "/coverage/completeness"),
    ({"truncated": True}, "/coverage/truncated"),
    ({"missing_sources": ()}, "/coverage/missing_sources/0"),
    ({"scope": {"host": "WS-089"}}, "/coverage/scope/host"),
    ({"scope": {"host": "WS-088", "as_of": "2026-09-01T02:21:00+00:00"}}, "/coverage/scope/as_of"),
])
def test_coverage_and_frozen_query_time_are_not_normalized(changes, expected):
    first = response()
    report = compare_responses(first, replace(first, coverage=replace(first.coverage, **changes)))
    assert not report["equal"] and expected in paths(report)


def test_record_order_is_observable_and_preserved():
    first = response()
    second_record = replace(first.records[0], record_id="opaque-record-2")
    first = replace(first, records=(*first.records, second_record))
    assert not compare_responses(first, replace(first, records=tuple(reversed(first.records))))["equal"]


def test_dictionary_key_order_is_visible_despite_equal_canonical_hash():
    first = response()
    reordered = dict(reversed(list(first.records[0].payload.items())))
    other = replace(first, records=(replace(first.records[0], payload=reordered),))
    report = compare_responses(first, other)
    assert first.records[0].content_sha256 == other.records[0].content_sha256
    assert not report["equal"]
    assert any(item["kind"] == "object_key_order" and item["path"] == "/records/0/payload"
               for item in report["differences"])


@pytest.mark.parametrize("referenced", ["call-1", "call-2"])
def test_identifier_referenced_in_any_business_value_cannot_be_normalized(referenced):
    first = response()
    payload = {**first.records[0].payload, "unfamiliar_reference": [{"link": referenced}]}
    first = replace(first, records=(replace(first.records[0], payload=payload),))
    other = replace(first, call_id="call-2")
    report = compare_responses(first, other)
    assert not report["equal"] and "/call_id" in paths(report)
    assert {item["path"] for item in report["normalized_fields"]} == {"/actual_duration_ms"}
    assert report["normalization_exclusions"][0]["reference_paths"]["left"]


def test_identifier_referenced_as_business_key_or_scope_value_cannot_be_normalized():
    first = response()
    first = replace(first, coverage=replace(first.coverage, scope={"call-1": "key reference"}))
    assert not compare_responses(first, replace(first, call_id="call-2"))["equal"]
    first = replace(first, coverage=replace(first.coverage, scope={"link": "call-2"}))
    assert not compare_responses(first, replace(first, call_id="call-2"))["equal"]


def test_missing_value_is_distinct_from_explicit_null_and_json_number_type():
    first = response()
    left_payload = {**first.records[0].payload, "maybe": None, "number": 1}
    right_payload = {**first.records[0].payload, "number": 1.0}
    left = replace(first, records=(replace(first.records[0], payload=left_payload),))
    right = replace(first, records=(replace(first.records[0], payload=right_payload),))
    report = compare_responses(left, right)
    missing = next(item for item in report["differences"] if item["path"].endswith("/maybe"))
    assert missing["left_present"] and not missing["right_present"]
    assert "/records/0/payload/number" in paths(report)


def test_policy_is_fixed_and_its_returned_copy_cannot_change_comparison():
    policy = normalization_policy()
    original = deepcopy(policy)
    policy["rules"].append({"path": "/simulated_cost_units", "reason": "not allowed"})
    assert normalization_policy() == original
    report = compare_responses(response(), replace(response(), simulated_cost_units=999.0))
    assert not report["equal"] and report["normalization_sha256"] == original["sha256"]


@pytest.mark.parametrize("change", [
    {"actual_duration_ms": True}, {"simulated_latency_ms": -1},
    {"simulated_cost_units": float("nan")}, {"simulated_cost_units": -1.0},
])
def test_invalid_usage_is_rejected_before_normalization(change):
    with pytest.raises(ProtocolViolation):
        compare_responses(response(), replace(response(), **change))


def test_unknown_envelope_fields_and_non_string_payload_keys_do_not_disappear():
    with pytest.raises(ProtocolViolation):
        compare_responses(response(), {"unknown": "field"})
    first = response()
    other = replace(first, records=(replace(first.records[0], payload={1: "bad-key"}),))
    with pytest.raises(ProtocolViolation):
        compare_responses(first, other)


@pytest.mark.parametrize("changes", [{"coverage": None}, {"records": None}, {"records": ({},)}])
def test_invalid_nested_structures_raise_protocol_errors(changes):
    with pytest.raises(ProtocolViolation):
        compare_responses(response(), replace(response(), **changes))
