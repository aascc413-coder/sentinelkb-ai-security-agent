"""Generic contract fixtures; these are not the five accepted M2 cases."""

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import (
    AssetQuery, AttackQuery, Coverage, HistoryQuery, Reliability, SIEMQuery,
    TIQuery, TimeWindow, ToolContext, ToolRecord,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.tools.contracts import EnvironmentFixture, FixtureRule
from evidence_investigation.tools.server import MockToolServer, content_hash

AS_OF = datetime(2026, 9, 1, 2, 20, tzinfo=timezone.utc)
WINDOW = TimeWindow(AS_OF - timedelta(minutes=10), AS_OF)


def context(call="call-1", timeout=1000):
    return ToolContext("run-opaque", call, AS_OF, timeout)


def record(payload, rid="record-1", group="sensor-1"):
    return ToolRecord(rid, payload, content_hash(payload), "local-test", group,
                      Reliability("high", "frozen test record", "test-v1"))


def fixture(tool, query, payload=None, *, records=None, status="ok", completeness="complete",
            constraints=None, error=None, retryable=False, coverage_window=None):
    if records is None:
        records = (record(payload),) if payload is not None else ()
    args = encode(query)
    scope = {k: v for k, v in args.items() if k not in {"window", "limit"}}
    coverage = Coverage(scope, coverage_window or getattr(query, "window", None),
                        completeness, False, ())
    rule = FixtureRule(tool, constraints or {}, tuple(r.record_id for r in records),
                       status, coverage, retryable, error)
    return EnvironmentFixture("opaque-environment", AS_OF, {tool: records}, (rule,), "test-v1")


def process_payload(**changes):
    base = {"view": "process_tree", "host": "host-a", "user": "operator-a",
            "process_id": "process-a", "occurred_at": (AS_OF-timedelta(minutes=2)).isoformat(),
            "observed_at": (AS_OF-timedelta(minutes=1)).isoformat(),
            "process_guid": "guid-a", "command_line": "PowerShell -File task.ps1"}
    return {**base, **changes}


def process_query(limit=50):
    return SIEMQuery("process_tree", WINDOW, "host-a", process_id="process-a", limit=limit)


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,query,payload", [
    ("siem", process_query(), process_payload()),
    ("asset", AssetQuery("host-a", AS_OF), {"host":"host-a", "published_at":AS_OF.isoformat(), "purpose":"test"}),
    ("threat_intel", TIQuery("domain", "example.test", AS_OF),
     {"indicator_type":"domain", "value":"EXAMPLE.TEST.", "published_at":AS_OF.isoformat(), "verdict":"unknown"}),
    ("history", HistoryQuery("user", "operator-a", WINDOW),
     {"entity_type":"user", "entity":"operator-a", "occurred_at":WINDOW.start.isoformat(), "observed_at":AS_OF.isoformat()}),
    ("attack", AttackQuery("attack-v1", technique_ids=("T1059.001",)),
     {"snapshot_version":"attack-v1", "technique_id":"T1059.001", "published_at":AS_OF.isoformat(), "description":"behavior context"}),
])
async def test_all_five_protocol_operations(tool, query, payload):
    env = fixture(tool, query, payload)
    server = MockToolServer(env, simulate_latency=False)
    result = await getattr(server, tool)(query, context())
    assert result.status == "ok" and result.coverage.completeness == "complete"
    assert result.records == env.records_by_tool[tool]
    assert result.call_id == "call-1" and result.simulated_cost_units > 0
    assert server.stats().backend_calls == 1


@pytest.mark.asyncio
async def test_cache_isolated_updates_context_and_keeps_original_facts():
    query = process_query()
    env = fixture("siem", query, process_payload())
    server = MockToolServer(env, simulate_latency=False)
    env.records_by_tool["siem"][0].payload["command_line"] = "changed outside server"
    first = await server.siem(query, context())
    first.records[0].payload["command_line"] = "changed by client"
    second = await server.siem(query, context("call-2"))
    assert second.records[0].payload["command_line"] == "PowerShell -File task.ps1"
    assert second.call_id == "call-2"
    assert second.simulated_cost_units == second.simulated_latency_ms == 0
    assert (server.stats().attempts, server.stats().backend_calls, server.stats().cache_hits) == (2,1,1)
    assert second.records[0].content_sha256 == content_hash(second.records[0].payload)


@pytest.mark.asyncio
async def test_concurrent_duplicates_execute_backend_once():
    query = process_query()
    server = MockToolServer(fixture("siem", query, process_payload()), simulate_latency=False)
    results = await asyncio.gather(server.siem(query, context("a")), server.siem(query, context("b")))
    assert {r.call_id for r in results} == {"a", "b"}
    assert results[0].records == results[1].records
    assert server.stats().backend_calls == server.stats().cache_hits == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status,completeness,error", [
    ("empty", "complete", None), ("partial", "partial", None),
    ("unavailable", "unknown", "missing_source"),
])
async def test_empty_partial_unavailable_remain_distinct(status, completeness, error):
    query = process_query()
    server = MockToolServer(fixture("siem", query, status=status, completeness=completeness,
                                   error=error), simulate_latency=False)
    result = await server.siem(query, context())
    assert result.status == status and result.coverage.completeness == completeness
    assert result.records == ()


@pytest.mark.asyncio
async def test_unknown_entity_without_coverage_is_unavailable():
    query = process_query()
    server = MockToolServer(fixture("siem", query, process_payload(), constraints={"host":"host-a"}),
                            simulate_latency=False)
    result = await server.siem(replace(query, host="other-host"), context())
    assert result.status == "unavailable" and result.error_code == "no_matching_rule"
    assert result.coverage.completeness == "unknown" and not result.retryable


@pytest.mark.asyncio
async def test_missing_filter_metadata_cannot_be_complete_empty():
    query = process_query()
    payload = process_payload()
    del payload["observed_at"]
    server = MockToolServer(fixture("siem", query, payload), simulate_latency=False)
    result = await server.siem(query, context())
    assert result.status == "partial" and not result.records
    assert result.coverage.completeness == "partial"
    assert "published_at" in result.coverage.missing_sources


@pytest.mark.asyncio
async def test_known_future_record_does_not_leak_into_past():
    query = process_query()
    server = MockToolServer(fixture("siem", query, process_payload(observed_at=(AS_OF+timedelta(seconds=1)).isoformat())),
                            simulate_latency=False)
    result = await server.siem(query, context())
    assert result.status == "empty" and not result.records


@pytest.mark.asyncio
async def test_limit_reports_truncation_and_preserves_mirror_identity():
    query = process_query(limit=1)
    records = (record(process_payload(), "primary", "same-sensor"),
               record(process_payload(), "mirror", "same-sensor"))
    server = MockToolServer(fixture("siem", query, records=records), simulate_latency=False)
    result = await server.siem(query, context())
    assert len(result.records) == 1 and result.coverage.truncated
    assert result.status == "partial" and result.coverage.completeness == "partial"
    full = await server.siem(replace(query, limit=50), context("call-2"))
    assert full.records[0].independence_group == full.records[1].independence_group
    assert full.records[0].content_sha256 == full.records[1].content_sha256


@pytest.mark.asyncio
async def test_narrow_coverage_cannot_support_wider_absence():
    query = process_query()
    narrow = TimeWindow(WINDOW.start+timedelta(minutes=1), WINDOW.end)
    server = MockToolServer(fixture("siem", query, status="empty", coverage_window=narrow),
                            simulate_latency=False)
    result = await server.siem(query, context())
    assert result.status == "partial" and result.coverage.completeness == "partial"


@pytest.mark.asyncio
@pytest.mark.parametrize("query_change,scope_change", [
    ({"process_id":"other-process"}, {"process_id":"process-a"}),
    ({"process_id":None}, {"process_id":"process-a"}),
    ({"user":"other-user"}, {"user":"operator-a"}),
    ({"user":None}, {"user":"operator-a"}),
])
async def test_narrow_selector_scope_cannot_be_complete_empty(query_change, scope_change):
    query = process_query()
    env = fixture("siem", query, process_payload())
    rule = env.query_rules[0]
    coverage = replace(rule.coverage, scope={**rule.coverage.scope, **scope_change})
    env = replace(env, query_rules=(replace(rule, coverage=coverage),))
    server = MockToolServer(env, simulate_latency=False)
    result = await server.siem(replace(query, **query_change), context())
    assert result.status == "partial" and result.coverage.completeness == "partial"
    assert result.coverage.scope["source_scope"] == coverage.scope


@pytest.mark.asyncio
async def test_asset_old_scope_cannot_support_current_complete_absence():
    query = AssetQuery("host-a", AS_OF)
    env = fixture("asset", query, status="empty")
    rule = env.query_rules[0]
    coverage = replace(rule.coverage, scope={"host":"host-a", "as_of":(AS_OF-timedelta(minutes=1)).isoformat()})
    server = MockToolServer(replace(env, query_rules=(replace(rule, coverage=coverage),)), simulate_latency=False)
    result = await server.asset(query, context())
    assert result.status == "partial" and result.coverage.completeness == "partial"


@pytest.mark.asyncio
async def test_request_deadline_applies_while_waiting_for_another_call():
    started, release = asyncio.Event(), asyncio.Event()
    async def sleeper(seconds):
        started.set()
        await release.wait()
    query = process_query()
    server = MockToolServer(fixture("siem", query, process_payload()), sleeper=sleeper)
    first = asyncio.create_task(server.siem(query, context("first", timeout=5000)))
    await started.wait()
    try:
        waiting = await asyncio.wait_for(server.siem(query, context("waiting", timeout=20)), timeout=0.5)
        assert waiting.status == "timeout" and waiting.error_code == "deadline_exhausted"
        assert waiting.simulated_cost_units == 0 and server.stats().backend_calls == 1
    finally:
        release.set()
        await first


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["error", "timeout"])
async def test_retryable_failures_are_not_cached(status):
    query = process_query()
    server = MockToolServer(fixture("siem", query, status=status, completeness="unknown",
                                   error="temporary", retryable=True), simulate_latency=False)
    for call in ("a", "b"):
        result = await server.siem(query, context(call))
        assert result.status == status and result.retryable
    assert server.stats().backend_calls == 2 and server.stats().cache_hits == 0


@pytest.mark.asyncio
async def test_permanent_unavailable_is_cached_but_not_turned_into_absence():
    query = process_query()
    server = MockToolServer(fixture("siem", query, status="unavailable", completeness="unknown",
                                   error="missing"), simulate_latency=False)
    await server.siem(query, context())
    result = await server.siem(query, context("b"))
    assert result.status == "unavailable" and not result.retryable
    assert server.stats().cache_hits == 1


@pytest.mark.asyncio
async def test_declared_latency_timeout_is_counted_without_evidence():
    query = process_query()
    server = MockToolServer(fixture("siem", query, process_payload()), simulate_latency=False)
    result = await server.siem(query, context(timeout=50))
    assert result.status == "timeout" and not result.records and result.retryable
    assert result.simulated_latency_ms == 50 and result.simulated_cost_units == 2
    assert server.stats().backend_calls == 1
    retry = await server.siem(query, context("retry"))
    assert retry.status == "ok" and server.stats().backend_calls == 2


@pytest.mark.asyncio
async def test_deadline_blocks_cached_response_and_no_backend_is_started():
    query = process_query()
    server = MockToolServer(fixture("siem", query, process_payload()), simulate_latency=False)
    await server.siem(query, context())
    result = await server.siem(query, context("late", timeout=0))
    assert result.status == "timeout" and not result.records and result.simulated_cost_units == 0
    assert server.stats().backend_calls == 1 and server.stats().cache_hits == 0


@pytest.mark.asyncio
async def test_future_query_and_wrong_argument_types_rejected():
    query = process_query()
    server = MockToolServer(fixture("siem", query, process_payload()), simulate_latency=False)
    with pytest.raises(ProtocolViolation, match="future_query"):
        await server.siem(replace(query, window=TimeWindow(WINDOW.start, AS_OF+timedelta(seconds=1))), context())
    with pytest.raises(ProtocolViolation, match="tool_argument_mismatch"):
        await server.siem(AssetQuery("host-a", AS_OF), context())
    assert server.stats().attempts == 2 and server.stats().backend_calls == 0


@pytest.mark.asyncio
async def test_ambiguous_rules_are_rejected_instead_of_guessing():
    query = process_query()
    env = fixture("siem", query, process_payload())
    server = MockToolServer(replace(env, query_rules=env.query_rules*2), simulate_latency=False)
    with pytest.raises(ProtocolViolation, match="ambiguous_fixture_rule"):
        await server.siem(query, context())


@pytest.mark.parametrize("change", ["hash", "unknown_status", "dangling", "complete_failure"])
def test_invalid_fixture_cannot_be_used(change):
    query = process_query()
    env = fixture("siem", query, process_payload())
    if change == "hash":
        env = replace(env, records_by_tool={"siem":(replace(env.records_by_tool["siem"][0], content_sha256="wrong"),)})
    else:
        rule = env.query_rules[0]
        if change == "unknown_status":
            rule = replace(rule, status="failed")
        elif change == "dangling":
            rule = replace(rule, record_ids=("not-found",))
        else:
            rule = replace(rule, status="unavailable", error_code="missing", record_ids=())
        env = replace(env, query_rules=(rule,))
    with pytest.raises(ProtocolViolation):
        MockToolServer(env)
