"""Behavior scores use the evidence available before the action, not hindsight."""

from datetime import timedelta
from pathlib import Path

import pytest

from evaluation.behavior import score_behavior
from evaluation.oracle_loader import load_oracle
from evaluation.replay import replay_run
from evidence_investigation.runtime.budget import BudgetController
from evidence_investigation.runtime.dispatcher import Dispatcher
from evidence_investigation.runtime.registry import EvidenceRegistry
from evidence_investigation.runtime.trace import TraceRecorder
from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import (
    AssetQuery, Budget, FinalAssessment, RunManifest, SIEMQuery, TimeWindow, ToolCall,
)
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.tools.fixture_loader import load_environment
from evidence_investigation.tools.server import MockToolServer

DATA = Path(__file__).resolve().parents[1] / "datasets"


@pytest.mark.asyncio
async def test_action_parameters_state_coverage_and_duplicate_cost(tmp_path):
    alert = load_public(DATA / "public/c1.json").alert
    environment = load_environment(DATA / "environment/world-1.json")
    budget = BudgetController(Budget(max_tool_calls=10))
    registry = EvidenceRegistry(alert)
    manifest = RunManifest("behavior", "fixed_all", "fake", {}, {}, "synthetic-v1",
                           environment.fixture_version, "powershell-v1", "test", None,
                           False, budget.budget, {})
    trace = TraceRecorder("behavior", manifest, tmp_path, usage_provider=budget.snapshot)
    trace.emit("alert_received", {"alert": encode(alert)}, state_version_after=1)
    dispatcher = Dispatcher("behavior", alert.as_of, registry, budget,
                            MockToolServer(environment, simulate_latency=False), trace=trace)
    query = ToolCall("siem", SIEMQuery("process_tree", TimeWindow(
        alert.as_of-timedelta(minutes=10), alert.as_of), alert.host, alert.user, alert.process_id))
    await dispatcher.dispatch(query)
    await dispatcher.dispatch(query)
    await dispatcher.dispatch(ToolCall("asset", AssetQuery(alert.host, alert.as_of)))
    trace.finalize(FinalAssessment("Abstain", "human_review", "no_useful_action"))
    report = score_behavior(replay_run(trace.dir), load_oracle(DATA / "oracle/c1.json"))
    assert report.metrics["tool_selection_accuracy"].value == pytest.approx(2/3)
    assert report.metrics["action_annotation_coverage"].value == 1
    assert report.metrics["known_unnecessary_tool_call_rate"].value == pytest.approx(1/3)
    assert report.metrics["tool_call_success_rate"].value == 1
    assert "E1" not in report.actions[0]["observed_before"]
    assert "E1" in report.actions[1]["observed_before"]
    assert report.actions[1]["acceptable"] is False
    assert report.measurement["tool_attempts"] == 3
    assert report.measurement["backend_calls"] == 2
    assert report.measurement["cache_hits"] == 1
    assert report.measurement["model_calls"] == 0
    assert report.measurement["cost_comparison_eligible"] is True


@pytest.mark.asyncio
async def test_unannotated_action_is_na_not_automatically_wrong(tmp_path):
    from dataclasses import replace
    from test_evaluation_replay import make_trace
    folder, _, _ = await make_trace(tmp_path)
    oracle = replace(load_oracle(DATA / "oracle/c1.json"), expected_actions=())
    report = score_behavior(replay_run(folder), oracle)
    assert report.metrics["tool_selection_accuracy"].value is None
    assert report.metrics["action_annotation_coverage"].value == 0


@pytest.mark.asyncio
async def test_manual_repeat_after_transient_failure_is_not_unnecessary(tmp_path):
    from test_dispatcher import make_dispatcher, siem_call
    from test_registry import make_result, siem_record
    from test_trace import make_final, make_manifest

    class TransientSource:
        calls = 0

        async def siem(self, query, context):
            self.calls += 1
            if self.calls == 1:
                return make_result([], status="error", retryable=True,
                                   error_code="temporary_source_error", call_id=context.call_id)
            return make_result([siem_record()], call_id=context.call_id)

    dispatcher, registry, budget = make_dispatcher(TransientSource())
    trace = TraceRecorder("run-1", make_manifest(), tmp_path, usage_provider=budget.snapshot)
    dispatcher.trace = trace
    trace.emit("alert_received", {"alert": encode(registry.alert)}, state_version_after=1)
    await dispatcher.dispatch(siem_call())
    await dispatcher.dispatch(siem_call())
    await dispatcher.dispatch(siem_call())
    trace.finalize(make_final())

    report = score_behavior(replay_run(trace.dir), load_oracle(DATA / "oracle/c1.json"))
    assert [action["automatic_retry"] for action in report.actions] == [False] * 3
    assert [action["known_redundant"] for action in report.actions] == [False, False, True]
    assert report.metrics["known_unnecessary_tool_call_rate"].value == pytest.approx(1/3)
    assert report.measurement["backend_calls"] == 3
