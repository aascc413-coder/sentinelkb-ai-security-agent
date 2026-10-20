from datetime import timedelta
import importlib.util
from pathlib import Path

import pytest

from evidence_investigation.state.contracts import AssetQuery, HistoryQuery, SIEMQuery, TimeWindow, ToolContext
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.tools.diff_report import compare_responses
from evidence_investigation.tools.fixture_loader import load_environment
from evidence_investigation.tools.server import MockToolServer

LAB = Path(__file__).resolve().parents[1]


def world(index):
    alert = load_public(LAB / f"datasets/public/c{index}.json").alert
    file = "shared-pair" if index >= 4 else f"world-{index}"
    server = MockToolServer(load_environment(LAB / f"datasets/environment/{file}.json"), simulate_latency=False)
    return alert, server


async def call(server, alert, tool, query, call_id="test-call"):
    return await getattr(server, tool)(query, ToolContext("test-run", call_id, alert.as_of, 5000))


def window(alert):
    return TimeWindow(alert.as_of - timedelta(minutes=10), alert.as_of)


@pytest.mark.asyncio
@pytest.mark.parametrize("index,expected", [(1,("ok","ok","ok")), (2,("ok","ok","ok")),
    (3,("partial","ok","ok")), (4,("partial","unavailable","partial")), (5,("partial","unavailable","partial"))])
async def test_each_case_observability(index, expected):
    alert, server = world(index)
    responses = []
    for view in ("process_tree", "network_events"):
        responses.append(await call(server, alert, "siem", SIEMQuery(view, window(alert), alert.host, alert.user, alert.process_id)))
    responses.append(await call(server, alert, "asset", AssetQuery(alert.host, alert.as_of)))
    assert tuple(r.status for r in responses) == expected
    if index in (1,2):
        assert responses[0].records[0].payload["process_guid"] == responses[1].records[0].payload["process_guid"]
        assert responses[0].records[0].independence_group != responses[1].records[0].independence_group
    if index >= 4:
        assert responses[1].records == () and not responses[1].retryable
        assert responses[2].coverage.completeness == "partial"


@pytest.mark.asyncio
async def test_alternative_approval_same_source_not_extra_independence():
    alert, server = world(1)
    asset = await call(server, alert, "asset", AssetQuery(alert.host, alert.as_of))
    history = await call(server, alert, "history", HistoryQuery("user", alert.user, window(alert), alert.host, alert.user))
    assert history.status == "ok" and len(history.records) == 1
    assert history.records[0].payload["approved_jobs"] == asset.records[0].payload["approved_jobs"] == []
    assert history.records[0].payload["register_window"] == asset.records[0].payload["approval_register_window"]
    assert history.records[0].independence_group == asset.records[0].independence_group


@pytest.mark.asyncio
async def test_authorization_matching_and_c3_counterevidence_visible():
    for index in (2,3):
        alert, server = world(index)
        process = await call(server, alert, "siem", SIEMQuery("process_tree", window(alert), alert.host, alert.user, alert.process_id))
        asset = await call(server, alert, "asset", AssetQuery(alert.host, alert.as_of))
        observed, approved = process.records[0].payload, asset.records[0].payload["approved_jobs"][0]
        matches = all(observed[k] == approved[k] for k in ("host", "user", "job_id", "script_hash", "parameters"))
        assert matches == (index == 2)
        if index == 3:
            history = await call(server, alert, "history", HistoryQuery("user", alert.user, window(alert), alert.host, alert.user))
            assert history.status == "unavailable" and not history.retryable and history.error_code


@pytest.mark.asyncio
async def test_empty_missing_truncated_and_cache_are_distinct():
    alert, server = world(1)
    before = TimeWindow(window(alert).start, alert.occurred_at)
    empty = await call(server, alert, "siem", SIEMQuery("process_tree", before, alert.host, alert.user, alert.process_id))
    assert empty.status == "empty" and empty.coverage.completeness == "complete"
    unknown = await call(server, alert, "siem", SIEMQuery("process_tree", window(alert), "unobserved-host", alert.user, alert.process_id))
    assert unknown.status == "unavailable" and unknown.coverage.completeness != "complete"
    truncated = await call(server, alert, "siem", SIEMQuery("process_tree", window(alert), alert.host, alert.user, alert.process_id, 1))
    assert truncated.status == "partial" and truncated.coverage.truncated and len(truncated.records) == 1
    query = SIEMQuery("process_tree", window(alert), alert.host, alert.user, alert.process_id)
    first = await call(server, alert, "siem", query, "first")
    second = await call(server, alert, "siem", query, "second")
    assert first.records == second.records and second.simulated_cost_units == 0 and second.call_id == "second"
    outside = TimeWindow(alert.as_of - timedelta(hours=1), alert.as_of)
    partial = await call(server, alert, "siem", SIEMQuery("process_tree", outside, alert.host, alert.user, alert.process_id))
    assert partial.status == "partial" and "coverage_scope" in partial.coverage.missing_sources


def replay_module():
    spec = importlib.util.spec_from_file_location("replay_seed_tools", LAB / "scripts/replay_seed_tools.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_paired_responses_in_both_orders_and_cached_replay():
    alert, left = world(4)
    _, right = world(5)
    queries = replay_module().representative_queries(alert)
    for indices in (range(len(queries)), reversed(range(len(queries)))):
        for index in indices:
            tool, query = queries[index]
            a = await call(left, alert, tool, query, f"left-{index}")
            b = await call(right, alert, tool, query, f"right-{index}")
            report = compare_responses(a,b)
            assert report["equal"], report


@pytest.mark.asyncio
async def test_five_case_replay_report_no_model_oracle_verdict_claim():
    report = await replay_module().replay()
    assert report["paired_equal"] and report["paired_queries"] == 27
    assert set(report["cases"]) == {"C1", "C2", "C3", "C4", "C5"}
    assert all(result["stats"]["cache_hits"] >= 1 for result in report["cases"].values())


@pytest.mark.asyncio
async def test_ti_mixed_indicator_rules_do_not_coerce_hash_to_ip():
    from evidence_investigation.state.contracts import TIQuery
    alert, server = world(3)
    for kind, value in (("ip", "198.51.100.27"), ("hash", "h-9")):
        result = await call(server, alert, "threat_intel", TIQuery(kind, value, alert.as_of))
        assert result.status == "ok" and len(result.records) == 1
        assert result.records[0].payload["indicator_type"] == kind
        assert result.records[0].payload["reputation"] == "unknown"


def test_ti_partial_type_and_value_rules_do_not_reclassify_request():
    from evidence_investigation.state.contracts import TIQuery
    from evidence_investigation.tools.selection import matches_constraints
    from evidence_investigation.state.errors import ProtocolViolation
    alert, _ = world(3)
    query = TIQuery("hash", "h-9", alert.as_of)
    assert not matches_constraints(query, {"indicator_type": "ip"})
    assert matches_constraints(query, {"indicator_type": "hash"})
    assert not matches_constraints(TIQuery("ip", "198.51.100.27", alert.as_of), {"value": "h-9"})
    with pytest.raises(ProtocolViolation):
        matches_constraints(query, {"indicator_type": "ip", "as_of": "not-a-time"})
