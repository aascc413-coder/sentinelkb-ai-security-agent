"""M7 Proposed-method unit and five-case acceptance tests."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidence_investigation.agents.hypothesis import validate_hypothesis_output
from evidence_investigation.agents.investigator import (
    EvidenceAwareInvestigator, required_prompt_hashes,
)
from evidence_investigation.agents.planner import DeterministicPlanner
from evidence_investigation.agents.sufficiency import (
    AcquiredResult, SufficiencyEvaluation, evaluate_sufficiency,
)
from evidence_investigation.agents.sufficiency import _approval
from evidence_investigation.runtime.trace import read_trace
from evidence_investigation.runtime.registry import EvidenceRegistry
from evidence_investigation.state.contracts import (
    Budget, CriterionCheck, RunManifest, SIEMQuery, SufficiencyResult,
    TimeWindow, ToolCall, ToolContext, Usage,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.state.rubric import load_rubric
from evidence_investigation.tools.fixture_loader import load_environment
from evidence_investigation.tools.server import MockToolServer, content_hash


LAB = Path(__file__).resolve().parents[1]
DATA = LAB / "datasets"
RUBRIC = load_rubric(LAB / "rubrics/powershell-v1.json")
BUDGET = Budget()


class SchemaAwareModel:
    def __init__(self, *, corrupt_sufficiency=False):
        self.calls = 0
        self.corrupt_sufficiency = corrupt_sufficiency

    async def complete(self, messages, output_schema, max_output_tokens, timeout_seconds):
        self.calls += 1
        title = output_schema.get("title", "")
        if "假设" in title:
            hypothesis_context = json.loads(messages[-1]["content"])
            previous = {item["hypothesis_id"]: item
                        for item in hypothesis_context["previous_hypotheses"]}
            assert all("supporting_evidence" not in item
                       and "disconfirming_evidence" not in item
                       for item in previous.values())
            revision = max((item["version"] for item in previous.values()), default=0) + 1
            output = {
                "hypotheses": [
                    {"hypothesis_id": "malicious", "version": revision,
                     "explanation": "Unauthorized PowerShell activity.", "kind": "malicious",
                     "status": "open", "expected_observations": ["unauthorized behavior"],
                     "falsifying_observations": ["matching approved operation"],
                     "supersedes": "malicious" if previous else None},
                    {"hypothesis_id": "benign", "version": revision,
                     "explanation": "Authorized administrative activity.", "kind": "benign",
                     "status": "open", "expected_observations": ["matching approval"],
                     "falsifying_observations": ["unauthorized effects"],
                     "supersedes": "benign" if previous else None},
                ],
                "links": [],
            }
        elif "充分性" in title:
            supplied = None
            for message in reversed(messages):
                try:
                    parsed = json.loads(message.get("content", ""))
                except (TypeError, json.JSONDecodeError):
                    continue
                if isinstance(parsed, dict) and "program_result" in parsed:
                    supplied = parsed["program_result"]
                    break
            assert supplied is not None
            criteria = supplied["tp_checks"] + [
                item for item in supplied["fp_checks"]
                if item["criterion_id"] not in {x["criterion_id"] for x in supplied["tp_checks"]}
            ]
            if self.corrupt_sufficiency:
                criteria[0] = {**criteria[0], "outcome": "met",
                               "evidence_ids": ["invented-evidence"]}
            output = {"rubric_version": supplied["rubric_version"],
                      "criteria": criteria,
                      "unresolved_alternatives": supplied["unresolved_alternatives"]}
        else:  # pragma: no cover - protects against adding an unreviewed model phase
            raise AssertionError(title)
        return output, Usage(input_tokens=100, output_tokens=50, usage_complete=True)


def manifest(run_id, budget=BUDGET):
    return RunManifest(
        run_id, "proposed", "fake-m7-v1", {"temperature": 0},
        required_prompt_hashes(), "synthetic-v1", "synthetic-v1",
        "powershell-v1", "test", 7, True, budget, {},
    )


def case_tools(index):
    case = load_public(DATA / f"public/c{index}.json")
    environment = "shared-pair" if index >= 4 else f"world-{index}"
    tools = MockToolServer(load_environment(DATA / f"environment/{environment}.json"),
                           simulate_latency=False)
    return case, tools


def tool_views(bundle):
    return [event.payload["arguments"].get("view", event.payload["tool"])
            for event in bundle.events if event.event_type == "tool_requested"]


def test_hypothesis_semantics_reject_single_kind_and_dangling_links():
    one = {"hypotheses": [{
        "hypothesis_id": "h1", "version": 1, "explanation": "only one",
        "kind": "malicious", "status": "open", "expected_observations": [],
        "falsifying_observations": [], "supersedes": None,
    }], "links": []}
    with pytest.raises(ProtocolViolation, match="competing"):
        validate_hypothesis_output(one, ("ev-1",))
    two = {"hypotheses": one["hypotheses"] + [{
        "hypothesis_id": "h2", "version": 1, "explanation": "benign",
        "kind": "benign", "status": "open", "expected_observations": [],
        "falsifying_observations": [], "supersedes": None,
    }], "links": [{"evidence_id": "ev-x", "hypothesis_id": "h2",
                    "stance": "support", "interpretation": "invented"}]}
    with pytest.raises(ProtocolViolation, match="grounded"):
        validate_hypothesis_output(two, ("ev-1",))


def test_hypothesis_links_are_projected_once_and_conflicts_are_rejected():
    payload = {"hypotheses": [
        {"hypothesis_id": "malicious", "version": 1, "explanation": "malicious",
         "kind": "malicious", "status": "open", "expected_observations": [],
         "falsifying_observations": [], "supersedes": None},
        {"hypothesis_id": "benign", "version": 1, "explanation": "benign",
         "kind": "benign", "status": "open", "expected_observations": [],
         "falsifying_observations": [], "supersedes": None},
    ], "links": [
        {"evidence_id": "ev-1", "hypothesis_id": "malicious",
         "stance": "support", "interpretation": "supports",
         "related_evidence_ids": []},
        {"evidence_id": "ev-1", "hypothesis_id": "benign",
         "stance": "contradict", "interpretation": "contradicts",
         "related_evidence_ids": []},
    ]}
    hypotheses, _ = validate_hypothesis_output(payload, ("ev-1",))
    by_id = {item.hypothesis_id: item for item in hypotheses}
    assert by_id["malicious"].supporting_evidence == ("ev-1",)
    assert by_id["benign"].disconfirming_evidence == ("ev-1",)

    payload["links"].append({
        "evidence_id": "ev-1", "hypothesis_id": "malicious",
        "stance": "contradict", "interpretation": "conflicts",
        "related_evidence_ids": [],
    })
    with pytest.raises(ProtocolViolation, match="both support and contradict"):
        validate_hypothesis_output(payload, ("ev-1",))


def test_hypothesis_revision_preserves_ids_and_kinds():
    initial_payload = {"hypotheses": [
        {"hypothesis_id": "malicious", "version": 1, "explanation": "malicious",
         "kind": "malicious", "status": "open", "expected_observations": [],
         "falsifying_observations": [], "supersedes": None},
        {"hypothesis_id": "benign", "version": 1, "explanation": "benign",
         "kind": "benign", "status": "open", "expected_observations": [],
         "falsifying_observations": [], "supersedes": None},
    ], "links": []}
    previous, _ = validate_hypothesis_output(initial_payload, ())
    revised = {"hypotheses": [dict(item) for item in initial_payload["hypotheses"]],
               "links": []}
    for item in revised["hypotheses"]:
        item["version"] = 2
        item["supersedes"] = item["hypothesis_id"]
    revised["hypotheses"][0]["kind"] = "benign"
    revised["hypotheses"][1]["kind"] = "malicious"
    with pytest.raises(ProtocolViolation, match="supersede"):
        validate_hypothesis_output(revised, (), previous)


def test_planner_initial_action_is_process_and_window_is_frozen():
    case, _ = case_tools(1)
    checks = tuple(CriterionCheck(cid, "unknown", (), "missing")
                   for cid in ("G0", "G1", "G2", "G3", "G4"))
    fp = (checks[0], checks[1]) + tuple(CriterionCheck(cid, "unknown", (), "missing")
                                        for cid in ("B1", "B2", "B3"))
    evaluation = SufficiencyEvaluation(
        SufficiencyResult("powershell-v1", checks, fp, None, ("open",), (),
                          ("current_process_behavior",), True), (), ())
    plan = DeterministicPlanner().plan(case.alert, (), evaluation)
    assert plan.selected_action_id == "query:process"
    assert len(plan.candidates) == 3
    assert plan.candidates[0].call.arguments.window.end == case.alert.as_of
    assert (plan.candidates[0].call.arguments.window.end
            - plan.candidates[0].call.arguments.window.start).total_seconds() == 600


@pytest.mark.asyncio
@pytest.mark.parametrize("index,expected", [
    (1, "TP"), (2, "FP"), (3, "Suspicious"), (4, "Abstain"), (5, "Abstain"),
])
async def test_proposed_five_case_behavior_and_trace(tmp_path, index, expected):
    case, tools = case_tools(index)
    run_id = f"m7-c{index}"
    model = SchemaAwareModel()
    final = await EvidenceAwareInvestigator(
        adapter=model, manifest=manifest(run_id),
        output_dir=tmp_path, rubric=RUBRIC,
    ).run(case, tools, BUDGET)
    bundle = read_trace(tmp_path, run_id)
    assert final.verdict == expected
    assert bundle.final == final
    assert model.calls == 3
    assert [event.event_type for event in bundle.events].count("hypotheses_revised") == 1
    assert [event.event_type for event in bundle.events].count("sufficiency_checked") >= 2
    assert tool_views(bundle) == (["process_tree", "network_events", "asset"]
                                  if index == 1 else
                                  ["process_tree", "asset", "network_events"]
                                  if index == 2 else
                                  ["process_tree", "asset", "network_events", "history"])
    if index == 3:
        assert final.risk_flags == ("approval_execution_mismatch",)
        assert final.stop_reason == "no_available_tool"
    if index in (4, 5):
        assert final.risk_flags == ()
        snapshots = [event.payload["state"] for event in bundle.events
                     if event.event_type == "state_snapshot"]
        assert {item["status"] for item in snapshots[0]["evidence"]["missing"]} == {"unqueried"}
        final_missing = {item["gap_id"]: item["status"]
                         for item in snapshots[-1]["evidence"]["missing"]}
        assert final_missing == {
            "current_process_behavior": "partial",
            "current_network_effects": "unavailable",
            "approval_coverage": "unavailable",
        }


@pytest.mark.asyncio
async def test_last_tool_budget_forces_abstain_without_post_tool_model(tmp_path):
    case, tools = case_tools(3)
    budget = Budget(max_tool_calls=3)
    model = SchemaAwareModel()
    final = await EvidenceAwareInvestigator(
        adapter=model, manifest=manifest("m7-hard-stop", budget),
        output_dir=tmp_path, rubric=RUBRIC,
    ).run(case, tools, budget)
    assert final.verdict == "Abstain"
    assert final.stop_reason == "tool_budget"
    # A hard stop cannot spend tokens on the optional final consolidation.
    assert model.calls == 1


@pytest.mark.asyncio
async def test_step_budget_abstain_preserves_grounded_risk(tmp_path):
    case, tools = case_tools(3)
    budget = Budget(max_investigation_steps=3)
    final = await EvidenceAwareInvestigator(
        adapter=SchemaAwareModel(), manifest=manifest("m7-step-stop", budget),
        output_dir=tmp_path, rubric=RUBRIC,
    ).run(case, tools, budget)
    assert final.verdict == "Abstain"
    assert final.stop_reason == "step_budget"
    assert "approval_execution_mismatch" in final.risk_flags


@pytest.mark.asyncio
@pytest.mark.parametrize("index,expected", [(1, "TP"), (2, "FP")])
async def test_last_tool_can_close_only_when_program_gates_are_already_sufficient(
    tmp_path, index, expected
):
    case, tools = case_tools(index)
    budget = Budget(max_tool_calls=3)
    model = SchemaAwareModel()
    final = await EvidenceAwareInvestigator(
        adapter=model, manifest=manifest(f"m7-last-close-{index}", budget),
        output_dir=tmp_path, rubric=RUBRIC,
    ).run(case, tools, budget)
    assert final.verdict == expected
    assert final.stop_reason == "tool_budget"
    assert model.calls == 1


@pytest.mark.asyncio
async def test_model_cannot_upgrade_deterministic_sufficiency(tmp_path):
    case, tools = case_tools(1)
    final = await EvidenceAwareInvestigator(
        adapter=SchemaAwareModel(corrupt_sufficiency=True),
        manifest=manifest("m7-invalid-explanation"), output_dir=tmp_path,
        rubric=RUBRIC,
    ).run(case, tools, BUDGET)
    assert final.verdict == "Abstain"
    assert final.stop_reason == "protocol_error"


def test_malformed_approval_payloads_remain_unknown_instead_of_crashing():
    occurred = load_public(DATA / "public/c2.json").alert.occurred_at
    process = {"host": "OPS-017", "user": "svc-backup", "job_id": "BACKUP-42",
               "script_hash": "h-approved", "parameters": ["backup", "validate"]}
    base = {"approval_register_complete": True,
            "approval_register_window": {"start": "2026-09-01T02:10:00+00:00",
                                           "end": "2026-09-01T02:20:00+00:00"}}
    malformed = [
        {**base, "approved_jobs": [None]},
        {**base, "approved_jobs": [{"host": "OPS-017", "user": "svc-backup",
                                      "job_id": "BACKUP-42", "script_hash": "h-approved",
                                      "parameters": True,
                                      "window": {"start": "2026-09-01T02:00:00+00:00",
                                                 "end": "2026-09-01T03:00:00+00:00"}}]},
        {**base, "approved_jobs": [{"host": "OPS-017", "user": "svc-backup",
                                      "job_id": "BACKUP-42", "script_hash": "h-approved",
                                      "parameters": ["backup", "validate"],
                                      "window": {"start": "2026-09-01T02:00:00",
                                                 "end": "2026-09-01T03:00:00"}}]},
    ]
    assert all(_approval(process, item, occurred, coverage_complete=True)[0] == "unknown"
               for item in malformed)


def _mutated_world2_with_extra_connection():
    fixture = load_environment(DATA / "environment/world-2.json", remap_ids=False)
    records = dict(fixture.records_by_tool)
    network = next(record for record in records["siem"]
                   if record.payload.get("view") == "network_events")
    payload = {**network.payload, "destination_ip": "198.51.100.99",
               "all_connections_captured": True}
    extra = replace(network, record_id="extra-network-counterevidence",
                    payload=payload, content_sha256=content_hash(payload))
    records["siem"] = records["siem"] + (extra,)
    rules = tuple(
        replace(rule, record_ids=rule.record_ids + (extra.record_id,))
        if rule.tool == "siem" and rule.argument_constraints.get("view") == "network_events"
        else rule for rule in fixture.query_rules
    )
    return replace(fixture, records_by_tool=records, query_rules=rules)


def _mutate_world2_record(view, mutate):
    fixture = load_environment(DATA / "environment/world-2.json", remap_ids=False)
    records = dict(fixture.records_by_tool)
    changed = []
    for record in records["siem"]:
        if record.payload.get("view") == view:
            payload = mutate(dict(record.payload))
            record = replace(record, payload=payload, content_sha256=content_hash(payload))
        changed.append(record)
    records["siem"] = tuple(changed)
    return replace(fixture, records_by_tool=records)


def _world2_with_extra_process_counterevidence():
    fixture = load_environment(DATA / "environment/world-2.json", remap_ids=False)
    records = dict(fixture.records_by_tool)
    process = next(record for record in records["siem"]
                   if record.payload.get("view") == "process_tree")
    payload = {**process.payload, "script_observations": [
        {"operation": "read", "object": "credential-store", "authorized": False},
        {"operation": "send", "object": "credential-bytes", "destination": "10.20.0.8"},
    ]}
    extra = replace(process, record_id="extra-process-counterevidence",
                    payload=payload, content_sha256=content_hash(payload))
    records["siem"] = records["siem"] + (extra,)
    rules = tuple(
        replace(rule, record_ids=rule.record_ids + (extra.record_id,))
        if rule.tool == "siem" and rule.argument_constraints.get("view") == "process_tree"
        else rule for rule in fixture.query_rules
    )
    return replace(fixture, records_by_tool=records, query_rules=rules)


def _world2_with_conflicting_approval_register():
    fixture = load_environment(DATA / "environment/world-2.json", remap_ids=False)
    records = dict(fixture.records_by_tool)
    approval = records["asset"][0]
    payload = {**approval.payload, "approved_jobs": []}
    conflict = replace(approval, record_id="conflicting-complete-approval",
                       payload=payload, content_sha256=content_hash(payload),
                       source_system="independent-change-register",
                       independence_group="change-02")
    records["asset"] = records["asset"] + (conflict,)
    rules = tuple(
        replace(rule, record_ids=rule.record_ids + (conflict.record_id,))
        if rule.tool == "asset" else rule for rule in fixture.query_rules
    )
    return replace(fixture, records_by_tool=records, query_rules=rules)


@pytest.mark.asyncio
async def test_additional_out_of_scope_connection_blocks_false_close(tmp_path):
    case = load_public(DATA / "public/c2.json")
    tools = MockToolServer(_mutated_world2_with_extra_connection(), simulate_latency=False)
    final = await EvidenceAwareInvestigator(
        adapter=SchemaAwareModel(), manifest=manifest("m7-c2-counterevidence"),
        output_dir=tmp_path, rubric=RUBRIC,
    ).run(case, tools, BUDGET)
    assert final.verdict != "FP"


@pytest.mark.asyncio
@pytest.mark.parametrize("fixture_factory", [
    _world2_with_extra_process_counterevidence,
    _world2_with_conflicting_approval_register,
    lambda: _mutate_world2_record(
        "network_events",
        lambda payload: {**payload,
                         "observed_destinations": ["10.20.0.8", "203.0.113.200"]}),
])
async def test_counterevidence_in_later_process_or_multi_target_field_blocks_fp(
    tmp_path, fixture_factory
):
    case = load_public(DATA / "public/c2.json")
    tools = MockToolServer(fixture_factory(), simulate_latency=False)
    run_id = "m7-counter-" + str(abs(hash(fixture_factory)))
    final = await EvidenceAwareInvestigator(
        adapter=SchemaAwareModel(), manifest=manifest(run_id),
        output_dir=tmp_path, rubric=RUBRIC,
    ).run(case, tools, BUDGET)
    assert final.verdict != "FP"


@pytest.mark.asyncio
async def test_unregistered_tool_result_cannot_satisfy_grounding_gate():
    case, tools = case_tools(1)
    window = TimeWindow(case.alert.as_of - timedelta(minutes=10), case.alert.as_of)
    call = ToolCall("siem", SIEMQuery(
        "process_tree", window, host=case.alert.host,
        process_id=case.alert.process_id, limit=50))
    result = await tools.siem(
        call.arguments, ToolContext("forged-run", "forged-call", case.alert.as_of, 5000))
    evaluation = evaluate_sufficiency(
        case.alert, EvidenceRegistry(case.alert),
        (AcquiredResult(call, result, (), ()),), RUBRIC)
    assert evaluation.result.tp_checks[0].criterion_id == "G0"
    assert evaluation.result.tp_checks[0].outcome == "unmet"
    assert evaluation.result.sufficient_for is None


@pytest.mark.asyncio
async def test_registered_cached_copy_remains_grounded():
    case, tools = case_tools(1)
    window = TimeWindow(case.alert.as_of - timedelta(minutes=10), case.alert.as_of)
    call = ToolCall("siem", SIEMQuery(
        "process_tree", window, host=case.alert.host,
        process_id=case.alert.process_id, limit=50))
    first = await tools.siem(
        call.arguments, ToolContext("cached-run", "call-1", case.alert.as_of, 5000))
    second = replace(first, call_id="call-2")
    registry = EvidenceRegistry(case.alert)
    one = registry.register_tool_result(first)
    two = registry.register_tool_result(second)
    evaluation = evaluate_sufficiency(
        case.alert, registry,
        (AcquiredResult(call, first, one.evidence_ids, one.operational_ids),
         AcquiredResult(call, second, two.evidence_ids, two.operational_ids)),
        RUBRIC)
    assert evaluation.result.tp_checks[0].outcome == "met"


@pytest.mark.asyncio
async def test_complete_history_can_replace_partial_asset_approval_check(tmp_path):
    case = load_public(DATA / "public/c1.json")
    fixture = load_environment(DATA / "environment/world-1.json", remap_ids=False)
    rules = tuple(
        replace(rule, status="partial",
                coverage=replace(rule.coverage, completeness="partial",
                                 missing_sources=("approval_archive",)))
        if rule.tool == "asset" else rule for rule in fixture.query_rules
    )
    tools = MockToolServer(replace(fixture, query_rules=rules), simulate_latency=False)
    run_id = "m7-history-approval"
    final = await EvidenceAwareInvestigator(
        adapter=SchemaAwareModel(), manifest=manifest(run_id),
        output_dir=tmp_path, rubric=RUBRIC,
    ).run(case, tools, BUDGET)
    assert final.verdict == "TP"
    assert tool_views(read_trace(tmp_path, run_id))[-1] == "history"
