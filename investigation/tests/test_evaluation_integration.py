"""Five scripted engineering cases: tests evaluator wiring, not Agent accuracy."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evaluation.leakage import CapturingModelAdapter, LeakagePolicy
from evaluation.oracle_loader import load_oracle
from evaluation.report import aggregate_report, evaluate_run
from evidence_investigation.runtime.budget import BudgetController
from evidence_investigation.runtime.dispatcher import Dispatcher
from evidence_investigation.runtime.model import FakeScriptedModel, run_model_call
from evidence_investigation.runtime.registry import EvidenceRegistry
from evidence_investigation.runtime.trace import TraceRecorder
from evidence_investigation.state.adapters import final_assessment_from_output
from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import (
    AssetQuery, Budget, Claim, HistoryQuery, RunManifest, SIEMQuery, TimeWindow, ToolCall,
)
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.tools.fixture_loader import load_environment
from evidence_investigation.tools.server import MockToolServer

DATA = Path(__file__).resolve().parents[1] / "datasets"


async def seed_trace(tmp_path, case_number, verdict, *, leaked=False):
    # Oracle remains exclusively in the test's post-run evaluation call.
    alert = load_public(DATA / f"public/c{case_number}.json").alert
    world = f"world-{case_number}" if case_number < 4 else "shared-pair"
    environment = load_environment(DATA / f"environment/{world}.json")
    budget = BudgetController(Budget(max_tool_calls=12))
    registry = EvidenceRegistry(alert)
    run_id = f"engineering-{case_number}"
    manifest = RunManifest(run_id, "fixed_all", "fake", {}, {}, "synthetic-v1",
                           environment.fixture_version, "powershell-v1", "test", None,
                           False, budget.budget, {})
    trace = TraceRecorder(run_id, manifest, tmp_path, usage_provider=budget.snapshot)
    trace.emit("alert_received", {"alert": encode(alert)}, state_version_after=1)
    dispatcher = Dispatcher(run_id, alert.as_of, registry, budget,
                            MockToolServer(environment, simulate_latency=False), trace=trace)
    window = TimeWindow(alert.as_of-timedelta(minutes=10), alert.as_of)
    for view in ("process_tree", "network_events"):
        await dispatcher.dispatch(ToolCall("siem", SIEMQuery(view, window, alert.host,
                                                             alert.user, alert.process_id)))
    await dispatcher.dispatch(ToolCall("asset", AssetQuery(alert.host, alert.as_of)))
    await dispatcher.dispatch(ToolCall("history", HistoryQuery("user", alert.user,
        TimeWindow(alert.as_of-timedelta(days=1), alert.as_of), alert.host, alert.user)))
    facts = registry.facts() + registry.operational_facts()
    first = registry.facts()[0]
    claims = [encode(Claim("obs-1", alert.host, "/alert_type", alert.alert_type,
                           (first.evidence_id,), "Detector type", "observation"))]
    output = {"verdict": verdict, "disposition": "escalate" if verdict == "TP" else
              "close_recommended" if verdict == "FP" else "human_review",
              "stop_reason": "sufficient" if verdict in {"TP", "FP"} else "no_useful_action",
              "claims": claims, "final_evidence_ids": [f.evidence_id for f in facts]}
    policy = LeakagePolicy(canary_tokens=("ORACLE_CANARY_7d31",), semantic_case_ids=(f"C{case_number}",))
    model = CapturingModelAdapter(FakeScriptedModel([output]), policy=policy)
    message = json.dumps(encode(facts), ensure_ascii=False)
    if leaked:
        message += " ORACLE_CANARY_7d31"
    result = await run_model_call(budget, model, run_id=run_id, phase="final",
        messages=({"role": "user", "content": message},),
        schema_name="final_assessment.schema.json", max_output_tokens=800, trace=trace)
    trace.finalize(final_assessment_from_output(result.output))
    return trace.dir, manifest, model.captures, policy


@pytest.mark.asyncio
async def test_five_scripted_cases_have_independent_scores_and_real_request_captures(tmp_path):
    rows, manifests = [], {}
    for number, verdict in enumerate(("TP", "FP", "Suspicious", "Abstain", "Abstain"), 1):
        folder, manifest, captures, policy = await seed_trace(tmp_path, number, verdict)
        oracle = load_oracle(DATA / f"oracle/c{number}.json")
        result = evaluate_run(folder, oracle, manifest, captured_requests=captures, leakage_policy=policy)
        assert result.score.run_status == "valid", result.score.annotation_notes
        assert result.input_request_count == 1 and result.leakage_finding_count == 0
        assert result.score.metrics["evidence_grounding_rate"].value == 1
        if number < 3:
            assert result.score.evidence_sufficient is True, result.score.annotation_notes
        else:
            assert result.score.evidence_sufficient is None
        rows.append(result)
        manifests[manifest.run_id] = manifest
    report = aggregate_report(rows, method="fixed_all", dataset_version="synthetic-v1", manifests=manifests)
    assert report.verdicts.aggregate.attempted_runs == 5
    assert report.verdicts.aggregate.failed_runs == 0
    assert report.verdicts.aggregate.metrics["decision_coverage"].value == 2/5
    assert report.verdicts.aggregate.metrics["false_close_rate"].value == 0
    # These verdicts are scripted test vectors, not an experiment result.


@pytest.mark.asyncio
async def test_missing_capture_and_detected_leak_are_failed_attempts(tmp_path):
    folder, manifest, captures, policy = await seed_trace(tmp_path, 1, "TP", leaked=True)
    oracle = load_oracle(DATA / "oracle/c1.json")
    missing = evaluate_run(folder, oracle, manifest, leakage_policy=policy)
    assert missing.score.run_status == "protocol_failure"
    assert "missing_request_capture" in missing.score.annotation_notes[0]
    leaked = evaluate_run(folder, oracle, manifest, captured_requests=captures, leakage_policy=policy)
    assert leaked.score.run_status == "protocol_failure" and leaked.leakage_finding_count > 0
    default_policy = evaluate_run(folder, oracle, manifest, captured_requests=captures)
    assert default_policy.score.run_status == "protocol_failure"
    assert default_policy.leakage_finding_count == leaked.leakage_finding_count
    blocked = evaluate_run(folder, oracle, manifest,
                           captured_requests=(replace(captures[0], forwarded=False),))
    assert blocked.score.run_status == "protocol_failure"
    assert "request_not_forwarded" in blocked.score.annotation_notes[0]
    report = aggregate_report([leaked], method="fixed_all", dataset_version="synthetic-v1",
                               manifests={manifest.run_id: manifest})
    assert report.verdicts.aggregate.attempted_runs == report.verdicts.aggregate.failed_runs == 1
    assert report.verdicts.aggregate.metrics["false_close_rate"].value is None


@pytest.mark.asyncio
async def test_missing_trace_retained_as_protocol_failure(tmp_path):
    _, manifest, _, _ = await seed_trace(tmp_path, 4, "Abstain")
    result = evaluate_run(tmp_path / "absent", load_oracle(DATA / "oracle/c4.json"), manifest)
    assert result.score.run_status == "protocol_failure"
    assert result.score.verdict is None
    assert not result.score.usage.usage_complete

@pytest.mark.asyncio
async def test_twin_cases_actual_adapter_requests_equal_except_transport_call_ids(tmp_path):
    from copy import deepcopy

    def normalize(captures):
        requests = deepcopy([capture.request for capture in captures])
        call_ids = {}
        for request in requests:
            for message in request['messages']:
                facts = json.loads(message['content'])
                for fact in facts:
                    cid = fact['source']['call_id']
                    if cid is not None:
                        canonical = call_ids.setdefault(cid, f'call-{len(call_ids)+1}')
                        fact['source']['call_id'] = canonical
                        ref = fact['raw_reference']
                        if ref['json_pointer'] == '/envelope':
                            assert ref['record_id'] == f'call:{cid}'
                            ref['record_id'] = f'call:{canonical}'
                message['content'] = json.dumps(facts, sort_keys=True)
            # This is an actual per-call deadline, not business evidence.
            assert request['timeout_seconds'] > 0
            request['timeout_seconds'] = '<remaining-runtime-deadline>'
        return requests

    _, _, left, _ = await seed_trace(tmp_path, 4, 'Abstain')
    _, _, right, _ = await seed_trace(tmp_path, 5, 'Abstain')
    assert normalize(left) == normalize(right)
    # Do not hide business identifiers while normalizing transport metadata.
    changed = deepcopy(right)
    facts = json.loads(changed[0].request['messages'][0]['content'])
    facts[0]['value']['host'] = 'DIFFERENT-HOST'
    changed[0].request['messages'][0]['content'] = json.dumps(facts)
    assert normalize(left) != normalize(changed)
