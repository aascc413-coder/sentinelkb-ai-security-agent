"""Selection tests use an independent generic fixture, never M2 case data."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from evidence_investigation.state.contracts import (
    AssetQuery, AttackQuery, HistoryQuery, Reliability, SIEMQuery, TIQuery,
    TimeWindow, ToolRecord,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.tools.selection import (
    filter_records, matches_constraints, select_records,
)


START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = START + timedelta(hours=1)
AS_OF = END + timedelta(minutes=5)
WINDOW = TimeWindow(START, END)
QUERY = SIEMQuery("process_tree", WINDOW, host="host-a", process_id="process-a")


def record(record_id="record-a", **changes):
    payload = {
        "host": "host-a", "process_id": "process-a", "view": "process_tree",
        "occurred_at": START.isoformat(), "observed_at": END.isoformat(),
        "parent_process": None, "command_line": None,
    }
    payload.update(changes)
    return ToolRecord(record_id, payload, "unchanged-original-hash", "siem-a", "sensor-a",
                      Reliability("high", "fixture provenance", "test-v1"))


def test_records_returned_unchanged_and_in_fixture_order_without_limit():
    first, second = record("first"), record("second")
    records = (second, first)
    result = select_records(replace(QUERY, limit=1), records, AS_OF)
    assert result.records == records
    assert result.records[0] is second
    assert result.records[0].content_sha256 == "unchanged-original-hash"
    assert not result.incomplete  # Missing process facts are not selection metadata.


@pytest.mark.parametrize("changes", [
    {"host": "other"}, {"view": "network_events"}, {"process_id": "other"},
    {"occurred_at": (START - timedelta(microseconds=1)).isoformat()},
    {"occurred_at": END.isoformat()},
    {"observed_at": (AS_OF + timedelta(microseconds=1)).isoformat()},
])
def test_definite_scope_or_time_mismatch_is_excluded_without_unknown(changes):
    selected = select_records(QUERY, (record(**changes),), AS_OF)
    assert selected.records == ()
    assert selected.incomplete is False


@pytest.mark.parametrize("field,bad_value", [
    ("occurred_at", None), ("occurred_at", "bad-time"),
    ("occurred_at", "2026-01-01T00:10:00"),
    ("observed_at", "2026-01-01T09:00:00+08:00"),
    ("observed_at", None), ("host", None), ("process_id", []), ("view", None),
])
def test_potential_match_with_bad_metadata_is_partial_not_complete_empty(field, bad_value):
    selected = select_records(QUERY, (record(**{field: bad_value}),), AS_OF)
    assert selected.records == ()
    assert selected.incomplete
    assert field in selected.missing_fields


def test_known_other_host_wins_over_missing_timestamp_regardless_payload_order():
    selected = select_records(QUERY, (record(host="other", occurred_at=None, observed_at=None),), AS_OF)
    assert not selected.incomplete
    assert selected.records == ()


def test_observed_at_precedence_cannot_fall_back_from_future_or_invalid_observation():
    for observation in (None, (AS_OF + timedelta(seconds=1)).isoformat()):
        value = record(observed_at=observation, published_at=START.isoformat())
        assert filter_records(QUERY, (value,), AS_OF) == ()


def test_missing_observed_at_uses_publication_and_boundary_is_available():
    value = record(published_at=AS_OF.isoformat())
    del value.payload["observed_at"]
    assert filter_records(QUERY, (value,), AS_OF) == (value,)


def test_impossible_observation_before_occurrence_is_unknown():
    value = record(occurred_at=(START + timedelta(minutes=10)).isoformat(), observed_at=START.isoformat())
    result = select_records(QUERY, (value,), AS_OF)
    assert result.records == ()
    assert result.missing_fields == ("publication_before_occurrence",)


def test_partial_selection_can_keep_valid_records_and_collect_unknown_fields():
    good = record("good")
    result = select_records(QUERY, (record("bad-a", observed_at=None), good,
                                    record("bad-b", occurred_at=None)), AS_OF)
    assert result.records == (good,)
    assert result.missing_fields == ("observed_at", "occurred_at")
    assert result.incomplete


def test_occurrence_after_context_as_of_cannot_be_selected_even_if_in_query_window():
    value = record(occurred_at=(START + timedelta(minutes=30)).isoformat(), observed_at=START.isoformat())
    assert filter_records(QUERY, (value,), START + timedelta(minutes=10)) == ()


def test_history_combines_entity_optional_selectors_and_event_window():
    query = HistoryQuery("command", "backup -verify", WINDOW, host="host-a", user="svc-a",
                         command_line="backup -verify")
    value = record(entity_type="command", entity="backup -verify", user="svc-a", command_line="backup -verify")
    assert filter_records(query, (value,), AS_OF) == (value,)
    assert filter_records(replace(query, user="svc-other"), (value,), AS_OF) == ()
    del value.payload["command_line"]
    assert select_records(query, (value,), AS_OF).incomplete


def test_siem_user_view_requires_user_and_honors_optional_host():
    query = SIEMQuery("user_events", WINDOW, user="svc-a", host="host-a")
    values = (record(view="user_events", user="svc-a"), record(view="user_events", user="svc-a", host="other"))
    assert filter_records(query, values, AS_OF) == values[:1]


@pytest.mark.parametrize("indicator_type,query_value,record_value", [
    ("domain", "BÜCHER.Example.", "xn--bcher-kva.example"),
    ("ip", "2001:0db8:0:0::1", "2001:db8::1"),
    ("hash", "A" * 64, "a" * 64),
])
def test_ti_normalization_matches_signature_semantics(indicator_type, query_value, record_value):
    query = TIQuery(indicator_type, query_value, AS_OF)
    value = record(indicator_type=indicator_type, value=record_value, published_at=AS_OF.isoformat())
    assert filter_records(query, (value,), AS_OF) == (value,)
    assert matches_constraints(query, {"value": record_value})


@pytest.mark.parametrize("query", [TIQuery("ip", "192.0.2.1", END), AssetQuery("host-a", END)])
def test_publication_uses_both_query_and_context_as_of(query):
    value = record(indicator_type="ip", value="192.0.2.1", published_at=AS_OF.isoformat())
    assert filter_records(query, (value,), AS_OF) == ()
    value.payload["published_at"] = END.isoformat()
    assert filter_records(query, (value,), END - timedelta(seconds=1)) == ()
    assert filter_records(query, (value,), END) == (value,)


def test_ti_missing_publication_or_entity_is_unknown_and_wrong_indicator_is_definite():
    query = TIQuery("ip", "192.0.2.1", AS_OF)
    value = record(indicator_type="ip", value="192.0.2.1")
    assert select_records(query, (value,), AS_OF).missing_fields == ("published_at",)
    value.payload["indicator_type"] = "hash"
    assert not select_records(query, (value,), AS_OF).incomplete


def test_asset_selector_and_missing_publication():
    query = AssetQuery("host-a", AS_OF)
    value = record(published_at=END.isoformat())
    assert filter_records(query, (value,), AS_OF) == (value,)
    assert filter_records(AssetQuery("other", AS_OF), (value,), AS_OF) == ()
    del value.payload["published_at"]
    assert select_records(query, (value,), AS_OF).incomplete


def test_attack_snapshot_and_union_of_exact_ids_and_terms():
    query = AttackQuery("snapshot-a", ("PowerShell", "PowerShell"), ("T1059.001",))
    by_id = record("id", snapshot_version="snapshot-a", technique_id="T1059.001", published_at=END.isoformat())
    by_term = record("term", snapshot_version="snapshot-a", behavior_terms=["PowerShell"], published_at=END.isoformat())
    assert filter_records(query, (by_id, by_term), AS_OF) == (by_id, by_term)
    assert matches_constraints(query, {"behavior_terms": ["PowerShell"], "technique_ids": ["T1059.001"]})
    assert filter_records(replace(query, snapshot_version="other"), (by_id, by_term), AS_OF) == ()


def test_attack_empty_terms_means_snapshot_lookup_and_never_reads_verdict_fields():
    query = AttackQuery("snapshot-a")
    value = record(snapshot_version="snapshot-a", published_at=END.isoformat(), verdict="TP", malicious=True)
    assert filter_records(query, (value,), AS_OF) == (value,)


def test_attack_known_nonmatch_is_not_unknown_even_with_missing_publication():
    query = AttackQuery("snapshot-a", ("PowerShell",), ("T1059.001",))
    value = record(snapshot_version="snapshot-a", technique_ids=["T1003"], behavior_terms=["powershell"])
    result = select_records(query, (value,), AS_OF)
    assert result.records == () and not result.incomplete


def test_attack_missing_matching_metadata_is_unknown():
    value = record(snapshot_version="snapshot-a", published_at=END.isoformat())
    result = select_records(AttackQuery("snapshot-a", technique_ids=("T1059.001",)), (value,), AS_OF)
    assert result.missing_fields == ("technique_ids",)


def test_rule_window_must_contain_whole_query_and_utc_instants_match():
    assert matches_constraints(QUERY, {"window": {"start": START.isoformat(), "end": END.isoformat()}})
    assert matches_constraints(QUERY, {"window": {"start": "2025-12-31T23:00:00Z", "end": END.isoformat()}})
    assert not matches_constraints(QUERY, {"window": {"start": (START + timedelta(seconds=1)).isoformat(), "end": END.isoformat()}})
    assert matches_constraints(AssetQuery("host-a", AS_OF), {"as_of": AS_OF.isoformat().replace("+00:00", "Z")})


@pytest.mark.parametrize("constraints", [
    {"host": "different", "unknown": "typo"},
    {"window": {"start": START.isoformat(), "end": END.isoformat(), "extra": 1}},
    {"window": {"start": None, "end": END.isoformat()}},
    {"window": {"start": END.isoformat(), "end": START.isoformat()}},
    {"limit": True}, {"limit": 0}, {"view": "unknown_view"},
])
def test_bad_constraints_are_rejected_even_after_an_ordinary_nonmatch(constraints):
    with pytest.raises(ProtocolViolation):
        matches_constraints(QUERY, constraints)


@pytest.mark.parametrize("constraints", [[], {1: "bad-key"}, {"host": "other", 1: "bad-key"}])
def test_non_object_or_non_string_constraint_keys_are_protocol_errors(constraints):
    with pytest.raises(ProtocolViolation):
        matches_constraints(QUERY, constraints)


def test_constraint_matching_and_selection_are_stateless_across_call_order():
    value = record()
    assert filter_records(QUERY, (value,), AS_OF) == (value,)
    assert filter_records(replace(QUERY, host="other"), (value,), AS_OF) == ()
    assert filter_records(QUERY, (value,), AS_OF) == (value,)
    assert matches_constraints(QUERY, {})
    assert not matches_constraints(QUERY, {"host": "other"})
    assert matches_constraints(QUERY, {"host": "host-a"})


def test_non_utc_context_and_invalid_query_are_rejected():
    with pytest.raises(ProtocolViolation):
        filter_records(QUERY, (), AS_OF.replace(tzinfo=None))
    with pytest.raises(ProtocolViolation):
        filter_records(replace(QUERY, limit=0), (), AS_OF)
