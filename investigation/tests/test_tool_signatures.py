"""Query identity must reflect lookup semantics, never caller metadata."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from evidence_investigation.state.contracts import (
    AssetQuery, AttackQuery, Coverage, HistoryQuery, Reliability, SIEMQuery,
    TIQuery, TimeWindow, ToolRecord, ToolResult,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.tools.signatures import (
    QueryCache, canonical_query, request_signature, validate_call,
)

NOW = datetime(2026, 9, 1, 2, 20, tzinfo=timezone.utc)
WINDOW = TimeWindow(NOW - timedelta(minutes=10), NOW)
QUERIES = {
    "siem": SIEMQuery("process_tree", WINDOW, host="WS-041", process_id="p-101"),
    "threat_intel": TIQuery("ip", "203.0.113.66", NOW),
    "asset": AssetQuery("WS-041", NOW),
    "history": HistoryQuery("command", "PowerShell -X", WINDOW, command_line="PowerShell -X"),
    "attack": AttackQuery("attack-v1", ("encoded",), ("T1059.001",)),
}


@pytest.mark.parametrize("tool", QUERIES)
@pytest.mark.parametrize("argument_tool", QUERIES)
def test_every_tool_argument_combination(tool, argument_tool):
    if tool == argument_tool:
        validate_call(tool, QUERIES[argument_tool])
    else:
        with pytest.raises(ProtocolViolation, match="requires"):
            validate_call(tool, QUERIES[argument_tool])


@pytest.mark.parametrize("query", [
    SIEMQuery("process_tree", WINDOW, host="WS-041", limit=True),
    SIEMQuery("bogus", WINDOW, host="WS-041"),
    SIEMQuery("process_tree", WINDOW, host=4),
    SIEMQuery("process_tree", TimeWindow(WINDOW.start, NOW.isoformat()), host="WS-041"),
    SIEMQuery("process_tree", WINDOW, host="WS-041", limit=float("nan")),
    SIEMQuery("process_tree", WINDOW, host="WS-041", limit=51),
    AttackQuery("attack-v1", ["encoded"], ()),
    AssetQuery("WS-041", NOW.replace(tzinfo=None)),
])
def test_invalid_constructed_dataclasses_rejected(query):
    with pytest.raises(ProtocolViolation):
        canonical_query(query)


def _signature(tool, query):
    return request_signature(tool, query, NOW, "fixture-v1")


def test_query_cache_key_preserves_meaningful_scope():
    query = QUERIES["siem"]
    original = _signature("siem", query)
    assert len(original) == 64
    for change in [
        {"host": "ws-041"}, {"process_id": "p-102"}, {"limit": 49},
        {"window": TimeWindow(WINDOW.start - timedelta(seconds=1), NOW)},
    ]:
        assert original != _signature("siem", replace(query, **change))
    assert original != request_signature("siem", query, NOW + timedelta(seconds=1), "fixture-v1")
    assert original != request_signature("siem", query, NOW, "fixture-v2")
    assert original == _signature("siem", query)
    assert _signature("history", QUERIES["history"]) != _signature(
        "history", replace(QUERIES["history"], command_line="powershell -X")
    )


@pytest.mark.parametrize("kind,a,b", [
    ("ip", "2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ("domain", "EXAMPLE.COM.", "example.com"),
    ("domain", "BÜCHER.example", "xn--bcher-kva.example"),
    ("hash", "AB" * 32, "ab" * 32),
])
def test_equivalent_indicators_share_signature(kind, a, b):
    assert _signature("threat_intel", TIQuery(kind, a, NOW)) == _signature(
        "threat_intel", TIQuery(kind, b, NOW)
    )


def test_opaque_hash_labels_and_attack_terms_keep_case():
    assert canonical_query(TIQuery("hash", "h7", NOW)).value == "h7"
    assert _signature("threat_intel", TIQuery("hash", "h7", NOW)) != _signature(
        "threat_intel", TIQuery("hash", "H7", NOW)
    )
    query = AttackQuery("attack-v1", ("encoded", "PowerShell", "encoded"), ("T1059.001", "T1003"))
    permuted = replace(query, behavior_terms=("PowerShell", "encoded"), technique_ids=("T1003", "T1059.001", "T1003"))
    assert _signature("attack", query) == _signature("attack", permuted)
    assert _signature("attack", query) != _signature("attack", replace(query, behavior_terms=("powershell", "encoded")))


@pytest.mark.parametrize("kind,value", [
    ("ip", "999.1.1.1"), ("ip", "fe80::1%eth0"),
    ("domain", "https://example.com"), ("domain", "example.com.."),
    ("domain", "bad domain"), ("domain", "-bad.example"),
    ("hash", " "), ("hash", "h 7"), ("hash", "h\x007"),
])
def test_invalid_indicators_rejected(kind, value):
    with pytest.raises(ProtocolViolation):
        canonical_query(TIQuery(kind, value, NOW))


@pytest.mark.parametrize("as_of,snapshot", [
    (NOW.replace(tzinfo=None), "v1"),
    (NOW.astimezone(timezone(timedelta(hours=8))), "v1"),
    (NOW, ""), (NOW, True),
])
def test_invalid_signature_context_rejected(as_of, snapshot):
    with pytest.raises(ProtocolViolation):
        request_signature("asset", QUERIES["asset"], as_of, snapshot)


def _result(**changes):
    base = ToolResult(
        "call-1", "asset", "ok",
        (ToolRecord("r-1", {"nested": {"role": "workstation"}}, "a" * 64, "cmdb", "asset", Reliability("high", "snapshot", "v1")),),
        Coverage({"hosts": ["WS-041"]}, None, "complete", False, ()),
        "fixture-v1", None, False, 1.0, 20, 1,
    )
    return replace(base, **changes)


def test_cache_copies_on_both_write_and_read():
    cache = QueryCache()
    result = _result()
    cache.put("key", result)
    result.records[0].payload["nested"]["role"] = "modified"
    result.coverage.scope["hosts"].append("attacker")
    first = cache.get("key")
    assert first.records[0].payload["nested"]["role"] == "workstation"
    assert first.coverage.scope["hosts"] == ["WS-041"]
    first.records[0].payload["nested"]["role"] = "again"
    assert cache.get("key").records[0].payload["nested"]["role"] == "workstation"
    assert cache.get("missing") is None
    assert len(cache) == 1


@pytest.mark.parametrize("status", ["ok", "empty", "partial", "unavailable", "timeout", "error"])
@pytest.mark.parametrize("retryable", [False, True])
def test_only_stable_responses_are_cached(status, retryable):
    cache = QueryCache()
    cache.put("key", _result(status=status, retryable=retryable))
    expected = not retryable and status in {"ok", "empty", "partial", "unavailable"}
    assert (cache.get("key") is not None) is expected
    assert len(cache) == int(expected)


@pytest.mark.parametrize("changes", [
    {"simulated_cost_units": float("nan")}, {"simulated_cost_units": -1},
    {"actual_duration_ms": True}, {"simulated_latency_ms": -1},
    {"retryable": "false"}, {"status": "invented"},
])
def test_cache_rejects_invalid_result_types_and_costs(changes):
    with pytest.raises(ProtocolViolation):
        QueryCache().put("key", _result(**changes))
