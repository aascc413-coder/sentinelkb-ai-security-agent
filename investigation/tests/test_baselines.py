"""M6 acceptance tests for shared baseline behavior and auditable differences."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from evidence_investigation.baselines import (
    DirectBaseline, FixedWorkflowBaseline, ReActBaseline,
)
from evidence_investigation.baselines.common import required_prompt_hashes
from evidence_investigation.runtime.prompts import prompt_sha256
from evaluation.replay import replay_run
from evidence_investigation.runtime.model import FakeScriptedModel, ModelError
from evidence_investigation.runtime.trace import read_trace
from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import (
    Budget, RunManifest, SIEMQuery, TimeWindow,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.tools.fixture_loader import load_environment
from evidence_investigation.tools.server import MockToolServer


LAB = Path(__file__).resolve().parents[1]
DATA = LAB / "datasets"
BUDGET = Budget()


def c1():
    case = load_public(DATA / "public/c1.json")
    tools = MockToolServer(
        load_environment(DATA / "environment/world-1.json"), simulate_latency=False
    )
    return case, tools


def manifest(run_id, method, *, prompt_hashes=None, budget=BUDGET):
    return RunManifest(
        run_id=run_id,
        method=method,
        model_snapshot="fake-m6-v1",
        model_parameters={"temperature": 0},
        prompt_hashes=(required_prompt_hashes(method)
                       if prompt_hashes is None else prompt_hashes),
        dataset_version="synthetic-v1",
        tool_snapshot="synthetic-v1",
        rubric_version="powershell-v1",
        code_revision="test",
        seed=7,
        seed_supported=True,
        budget=budget,
        price_snapshot={},
    )


def suspicious_final(*, evidence=("ev-0001",)):
    return {
        "verdict": "Suspicious",
        "disposition": "human_review",
        "stop_reason": "no_useful_action",
        "claims": [],
        "final_evidence_ids": list(evidence),
        "unresolved_questions": ["Benign authorization remains unresolved."],
        "risk_flags": ["encoded_powershell"],
    }


def tool_names(bundle):
    return [
        event.payload["tool"] for event in bundle.events
        if event.event_type == "tool_requested"
    ]


@pytest.mark.asyncio
async def test_c1_direct_has_no_tool_calls_and_complete_replayable_trace(tmp_path):
    case, tools = c1()
    run_id = "m6-direct-c1"
    final = await DirectBaseline(
        FakeScriptedModel([suspicious_final()]), manifest(run_id, "direct"), tmp_path
    ).run(case, tools, BUDGET)

    bundle = read_trace(tmp_path, run_id)
    assert final.verdict == "Suspicious"
    assert tool_names(bundle) == []
    assert bundle.final == final
    assert bundle.final_payload["usage"]["model_calls"] == 1
    assert replay_run(tmp_path / run_id).final == final


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "include_all,method,expected",
    [
        (False, "fixed", ["siem", "threat_intel", "attack"]),
        (True, "fixed_all", ["siem", "threat_intel", "asset", "history", "attack"]),
    ],
)
async def test_c1_fixed_sequences_are_frozen_and_model_cannot_choose_tools(
    tmp_path, include_all, method, expected
):
    case, tools = c1()
    run_id = "m6-" + method + "-c1"
    model = FakeScriptedModel([suspicious_final()])
    final = await FixedWorkflowBaseline(
        model, manifest(run_id, method), tmp_path, include_all_tools=include_all
    ).run(case, tools, BUDGET)

    bundle = read_trace(tmp_path, run_id)
    assert final.verdict == "Suspicious"
    assert tool_names(bundle) == expected
    assert model.calls == 1
    assert replay_run(tmp_path / run_id).final == final
    planned = [event.payload for event in bundle.events
               if event.event_type == "plan_selected"]
    assert [item["stage"] for item in planned] == (
        list(("siem", "threat_intel", "asset", "history", "attack"))
        if include_all else list(("siem", "threat_intel", "attack"))
    )


class RecordingAdapter:
    def __init__(self, script):
        self.inner = FakeScriptedModel(script)
        self.messages = []

    async def complete(self, messages, output_schema, max_output_tokens, timeout_seconds):
        self.messages.append(messages)
        return await self.inner.complete(
            messages, output_schema, max_output_tokens, timeout_seconds
        )


@pytest.mark.asyncio
async def test_c1_react_selects_tool_then_finish_without_proposed_fields(tmp_path):
    case, tools = c1()
    window = TimeWindow(case.alert.as_of - timedelta(minutes=10), case.alert.as_of)
    action = {
        "action": "tool",
        "tool": "siem",
        "arguments": encode(SIEMQuery(
            "process_tree", window, case.alert.host, case.alert.user,
            case.alert.process_id, 50,
        )),
    }
    finish = {"action": "finish", "final": suspicious_final()}
    model = RecordingAdapter([action, finish])
    run_id = "m6-react-c1"

    final = await ReActBaseline(
        model, manifest(run_id, "react"), tmp_path
    ).run(case, tools, BUDGET)

    bundle = read_trace(tmp_path, run_id)
    assert final.verdict == "Suspicious"
    assert tool_names(bundle) == ["siem"]
    assert len(model.messages) == 2
    assert replay_run(tmp_path / run_id).final == final
    visible = "\n".join(
        str(message["content"])
        for request in model.messages for message in request
    )
    for proposed_field in (
        "hypotheses_to_distinguish", "critical_gap", "discrimination_score",
        "missing_gap_ids", "sufficiency_checked",
    ):
        assert proposed_field not in visible


@pytest.mark.asyncio
async def test_all_methods_persist_same_final_schema_shape(tmp_path):
    case, tools = c1()
    outputs = []
    methods = [
        DirectBaseline(FakeScriptedModel([suspicious_final()]),
                       manifest("shape-direct", "direct"), tmp_path),
        FixedWorkflowBaseline(FakeScriptedModel([suspicious_final()]),
                              manifest("shape-fixed", "fixed"), tmp_path),
        ReActBaseline(FakeScriptedModel([
            {"action": "finish", "final": suspicious_final()}
        ]), manifest("shape-react", "react"), tmp_path),
    ]
    for runner in methods:
        # Each server owns mutable cache state, so each run gets an isolated fixture server.
        _, isolated_tools = c1()
        outputs.append(encode(await runner.run(case, isolated_tools, BUDGET)))
    assert len({tuple(sorted(item)) for item in outputs}) == 1


@pytest.mark.asyncio
async def test_fixed_zero_tool_budget_abstains_and_keeps_complete_trace(tmp_path):
    case, tools = c1()
    budget = Budget(max_tool_calls=0)
    run_id = "fixed-no-tools"
    runner = FixedWorkflowBaseline(
        FakeScriptedModel([]), manifest(run_id, "fixed", budget=budget), tmp_path
    )
    final = await runner.run(case, tools, budget)
    bundle = read_trace(tmp_path, run_id)
    assert final.verdict == "Abstain"
    assert final.stop_reason == "tool_budget"
    assert bundle.final == final
    assert tool_names(bundle) == []


@pytest.mark.asyncio
async def test_fixed_records_ti_stage_skipped_when_siem_reveals_no_indicator(tmp_path):
    case = load_public(DATA / "public/c4.json")
    tools = MockToolServer(
        load_environment(DATA / "environment/shared-pair.json"), simulate_latency=False
    )
    run_id = "fixed-c4-no-indicator"
    await FixedWorkflowBaseline(
        FakeScriptedModel([suspicious_final()]), manifest(run_id, "fixed"), tmp_path
    ).run(case, tools, BUDGET)
    bundle = read_trace(tmp_path, run_id)
    assert tool_names(bundle) == ["siem", "attack"]
    skipped = [event.payload for event in bundle.events
               if event.event_type == "plan_selected"
               and event.payload.get("decision") == "stage_skipped"]
    assert skipped == [{
        "method": "fixed", "stage": "threat_intel",
        "decision": "stage_skipped", "reason": "no alert-or-tool-derived indicator",
    }]


@pytest.mark.asyncio
async def test_manifest_must_bind_exact_prompt_bytes_before_trace_creation(tmp_path):
    case, tools = c1()
    runner = DirectBaseline(
        FakeScriptedModel([suspicious_final()]),
        manifest("bad-prompt", "direct", prompt_hashes={"direct-v1.txt": "0" * 64}),
        tmp_path,
    )
    with pytest.raises(ProtocolViolation, match="prompt"):
        await runner.run(case, tools, BUDGET)
    assert not (tmp_path / "bad-prompt").exists()


@pytest.mark.asyncio
async def test_direct_repairs_dangling_evidence_reference_and_replays(tmp_path):
    case, tools = c1()
    invalid = suspicious_final(evidence=("ev-not-acquired",))
    run_id = "direct-grounding-repair"
    model = FakeScriptedModel([invalid, suspicious_final()])
    final = await DirectBaseline(
        model, manifest(run_id, "direct"), tmp_path
    ).run(case, tools, BUDGET)
    replay = replay_run(tmp_path / run_id)
    assert final.final_evidence_ids == ("ev-0001",)
    assert model.calls == replay.usage.model_calls == 2
    assert len(replay.model_output_revisions) == 2
    assert replay.model_output_revisions[0]["validation_error"]
    assert replay.model_output_revisions[-1]["accepted_output"] is not None


@pytest.mark.asyncio
async def test_model_failure_becomes_explicit_replayable_abstention(tmp_path):
    case, tools = c1()
    run_id = "direct-model-error"
    final = await DirectBaseline(
        FakeScriptedModel([ModelError("offline")]), manifest(run_id, "direct"), tmp_path
    ).run(case, tools, BUDGET)
    replay = replay_run(tmp_path / run_id)
    assert final.verdict == "Abstain"
    assert final.stop_reason == "model_error"
    assert replay.final == final
    assert not replay.usage.usage_complete


@pytest.mark.asyncio
async def test_native_model_timeout_becomes_replayable_model_error(tmp_path):
    case, tools = c1()
    run_id = "direct-native-timeout"
    final = await DirectBaseline(
        FakeScriptedModel([TimeoutError("provider stalled")]),
        manifest(run_id, "direct"), tmp_path,
    ).run(case, tools, BUDGET)
    assert final.verdict == "Abstain" and final.stop_reason == "model_error"
    assert replay_run(tmp_path / run_id).final == final


@pytest.mark.asyncio
async def test_react_protocol_rejection_cannot_be_followed_by_false_close(tmp_path):
    case, tools = c1()
    invalid_tool = {
        "action": "tool", "tool": "asset",
        "arguments": {"host": "UNKNOWN-HOST", "as_of": case.alert.as_of.isoformat()},
    }
    unsafe_finish = {
        "action": "finish",
        "final": {
            "verdict": "FP", "disposition": "close_recommended",
            "stop_reason": "sufficient", "claims": [],
            "final_evidence_ids": ["ev-0001"],
        },
    }
    run_id = "react-protocol-rejection"
    model = FakeScriptedModel([invalid_tool, unsafe_finish])
    final = await ReActBaseline(
        model, manifest(run_id, "react"), tmp_path
    ).run(case, tools, BUDGET)
    assert final.verdict == "Abstain" and final.stop_reason == "protocol_error"
    assert model.calls == 1
    assert replay_run(tmp_path / run_id).final == final


@pytest.mark.asyncio
async def test_react_last_tool_attempt_stops_without_unbudgeted_model_call(tmp_path):
    case, tools = c1()
    budget = Budget(max_tool_calls=1)
    window = TimeWindow(case.alert.as_of - timedelta(minutes=10), case.alert.as_of)
    action = {
        "action": "tool", "tool": "siem",
        "arguments": encode(SIEMQuery(
            "process_tree", window, case.alert.host, case.alert.user,
            case.alert.process_id, 50,
        )),
    }
    run_id = "react-tool-limit"
    model = FakeScriptedModel([action])
    final = await ReActBaseline(
        model, manifest(run_id, "react", budget=budget), tmp_path
    ).run(case, tools, budget)
    replay = replay_run(tmp_path / run_id)
    assert final.verdict == "Abstain" and final.stop_reason == "tool_budget"
    assert model.calls == replay.usage.model_calls == 1
    assert replay.usage.tool_attempts == 1


def test_prompt_hash_binds_exact_packaged_bytes():
    prompt = LAB / "src/evidence_investigation/prompts/direct-v1.txt"
    from hashlib import sha256
    assert prompt_sha256("direct-v1.txt") == sha256(prompt.read_bytes()).hexdigest()


def test_baseline_source_has_no_oracle_or_evaluation_dependency():
    root = LAB / "src/evidence_investigation/baselines"
    source = "\n".join(path.read_text(encoding="utf-8") for path in root.glob("*.py"))
    assert "evidence_investigation.evaluation" not in source
    assert "datasets.oracle" not in source
