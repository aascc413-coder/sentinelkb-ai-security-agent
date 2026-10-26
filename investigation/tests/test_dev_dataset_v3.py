"""M10c frozen 20-case development dataset checks."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from dataclasses import asdict
from pathlib import Path
import shutil

import pytest

from benchmark.m8a import EngineeringFakeModel
from evaluation.annotation_loader import annotation_for_case, load_annotations
from evaluation.behavior import score_behavior
from evaluation.evaluator import score_run
from evaluation.oracle_loader import load_oracle
from evaluation.replay import replay_run
from evidence_investigation.agents.investigator import (
    EvidenceAwareInvestigator, required_prompt_hashes,
)
from evidence_investigation.state.contracts import Budget, RunManifest
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.normalization import compare_static
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.state.rubric import load_rubric
from evidence_investigation.tools.fixture_loader import load_environment
from evidence_investigation.tools.server import MockToolServer


LAB = Path(__file__).resolve().parents[1]
DATA = LAB / "datasets/powershell-dev-v3"
PREVIOUS = LAB / "datasets/powershell-dev-v2"
ANNOTATIONS = LAB / "evaluation/annotations/powershell-dev-v3.json"
RUBRIC = load_rubric(LAB / "rubrics/powershell-v1.json")
BUDGET = Budget()


def _load_script(name):
    spec = importlib.util.spec_from_file_location(name, LAB / f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifest(run_id, environment):
    return RunManifest(
        run_id, "proposed", "fake-m10c-v1", {"temperature": 0},
        required_prompt_hashes(), "powershell-dev-v3", environment.fixture_version,
        "powershell-v1", "test", 10, True, BUDGET, {},
    )


def test_v3_audit_annotations_and_three_counterfactual_groups():
    report = _load_script("dataset_split_audit").audit_dataset(DATA)
    assert report["case_count"] == 20
    assert report["family_count"] == 12
    assert report["split_counts"] == {"dev": 20}
    assert [[item["case_id"] for item in group["cases"]]
            for group in report["duplicate_visible_groups"]] == [
                ["C4", "C5"], ["C10", "C11"], ["C17", "C18"],
            ]
    labels = load_annotations(ANNOTATIONS)
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    assert [item.case_id for item in labels.cases] == [f"C{number}" for number in range(1, 21)]
    for row in manifest["cases"]:
        oracle = load_oracle(DATA / row["oracle"])
        assert annotation_for_case(labels, oracle, BUDGET).case_id == row["case_id"]


def test_v3_preserves_all_v2_case_bytes():
    current = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    previous = json.loads((PREVIOUS / "manifest.json").read_text(encoding="utf-8"))
    current_rows = {row["case_id"]: row for row in current["cases"]}
    for old in previous["cases"]:
        new = current_rows[old["case_id"]]
        assert new == old
        for partition in ("public", "environment", "oracle"):
            assert (DATA / new[partition]).read_bytes() == (PREVIOUS / old[partition]).read_bytes()


def test_v3_builder_reproduces_frozen_bytes(tmp_path):
    builder = _load_script("build_dev_dataset_v3")
    builder.ROOT = tmp_path / "powershell-dev-v3"
    builder.ANNOTATIONS = tmp_path / "powershell-dev-v3.json"
    builder.main()
    for source in [DATA / "manifest.json", *DATA.glob("*/*.json")]:
        rebuilt = builder.ROOT / source.relative_to(DATA)
        assert b"\r\n" not in source.read_bytes()
        assert source.read_bytes() == rebuilt.read_bytes()
    assert ANNOTATIONS.read_bytes() == builder.ANNOTATIONS.read_bytes()


def test_m10c_protocol_freeze_binds_prompts_rubric_budget_and_author_guide():
    freeze_path = LAB / "evaluation/freeze/powershell-dev-v3.json"
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    assert freeze["dataset_version"] == "powershell-dev-v3"
    assert freeze["annotation_version"] == "powershell-dev-eval-v3"
    assert freeze["rubric_version"] == "powershell-v1"
    assert freeze["budget_profile"] == asdict(BUDGET)
    repository = LAB.parent
    for relative, expected in freeze["file_sha256"].items():
        assert hashlib.sha256((repository / relative).read_bytes()).hexdigest() == expected


def test_third_counterfactual_pair_is_equal_with_opposite_truth():
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    rows = {row["case_id"]: row for row in manifest["cases"]}
    left, right = rows["C17"], rows["C18"]
    p17, p18 = (load_public(DATA / row["public"]) for row in (left, right))
    e17, e18 = (load_environment(DATA / row["environment"]) for row in (left, right))
    o17, o18 = (load_oracle(DATA / row["oracle"]) for row in (left, right))
    assert compare_static(p17, e17, p18, e18).equal
    assert o17.ground_truth != o18.ground_truth
    assert o17.acceptable_verdicts == o18.acceptable_verdicts == ("Abstain",)


def test_v3_visible_partitions_have_no_author_labels():
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    forbidden = ('"case_id"', '"family_id"', '"split"', '"ground_truth"',
                 '"critical_fact_keys"', '"acceptable_verdicts"', '"oracle_only"')
    for row in manifest["cases"]:
        public = (DATA / row["public"]).read_text(encoding="utf-8")
        environment = (DATA / row["environment"]).read_text(encoding="utf-8")
        assert not any(marker in public or marker in environment for marker in forbidden)


@pytest.mark.parametrize("field,value", [
    ("operational_status", "empty"),
    ("retryable", False),
])
def test_recordless_operational_fact_must_match_a_fixture_envelope(tmp_path, field, value):
    copied = tmp_path / "powershell-dev-v3"
    shutil.copytree(DATA, copied)
    oracle_path = copied / "oracle/c15.json"
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    oracle["complete_world_evidence"]["E4"][field] = value
    oracle_path.write_text(json.dumps(oracle, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8", newline="\n")
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["file_sha256"]["oracle/c15.json"] = hashlib.sha256(
        oracle_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8", newline="\n")
    with pytest.raises(ProtocolViolation, match="ungrounded_annotation"):
        _load_script("dataset_split_audit").audit_dataset(copied)


@pytest.mark.parametrize("case_id,fact_key,mutation", [
    ("C15", "E4", lambda fact: fact.pop("retryable")),
    ("C16", "E2", lambda fact: fact.__setitem__("operational_status", "partial")),
    ("C16", "E2", lambda fact: fact.pop("arguments")),
])
def test_recordless_operational_fact_requires_exact_envelope_scope(
        tmp_path, case_id, fact_key, mutation):
    copied = tmp_path / "powershell-dev-v3"
    shutil.copytree(DATA, copied)
    oracle_path = copied / f"oracle/{case_id.lower()}.json"
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    mutation(oracle["complete_world_evidence"][fact_key])
    oracle_path.write_text(json.dumps(oracle, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8", newline="\n")
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    relative = f"oracle/{case_id.lower()}.json"
    manifest["file_sha256"][relative] = hashlib.sha256(oracle_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8", newline="\n")
    with pytest.raises(ProtocolViolation, match="ungrounded_annotation"):
        _load_script("dataset_split_audit").audit_dataset(copied)


def test_record_fact_cannot_silently_become_an_operational_annotation(tmp_path):
    copied = tmp_path / "powershell-dev-v3"
    shutil.copytree(DATA, copied)
    oracle_path = copied / "oracle/c16.json"
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    oracle["complete_world_evidence"]["E1"].update({
        "operational_status": "partial",
        "arguments": {"view": "process_tree", "host": "WS-116"},
    })
    oracle_path.write_text(json.dumps(oracle, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8", newline="\n")
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["file_sha256"]["oracle/c16.json"] = hashlib.sha256(
        oracle_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8", newline="\n")
    with pytest.raises(ProtocolViolation, match="mixed_annotation"):
        _load_script("dataset_split_audit").audit_dataset(copied)


def test_scoped_unavailable_arguments_cannot_match_a_different_rule(tmp_path):
    copied = tmp_path / "powershell-dev-v3"
    shutil.copytree(DATA, copied)
    oracle_path = copied / "oracle/c16.json"
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    oracle["complete_world_evidence"]["E4"]["arguments"] = {
        "entity_type": "host", "entity": "WS-116",
    }
    oracle_path.write_text(json.dumps(oracle, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8", newline="\n")
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["file_sha256"]["oracle/c16.json"] = hashlib.sha256(
        oracle_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8", newline="\n")
    with pytest.raises(ProtocolViolation, match="ungrounded_annotation"):
        _load_script("dataset_split_audit").audit_dataset(copied)


def test_future_dataset_versions_require_scope_for_unavailable_facts(tmp_path):
    copied = tmp_path / "powershell-dev-v3"
    shutil.copytree(DATA, copied)
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["dataset_version"] = "powershell-test-v1"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8", newline="\n")
    with pytest.raises(ProtocolViolation, match="ungrounded_annotation"):
        _load_script("dataset_split_audit").audit_dataset(copied)


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id,expected", [
    ("C13", "TP"),
    ("C14", "FP"),
    ("C15", "Suspicious"),
    ("C16", "Abstain"),
    ("C17", "Abstain"),
    ("C18", "Abstain"),
    ("C19", "Abstain"),
    ("C20", "TP"),
])
async def test_proposed_expected_behavior_on_m10c_cases(tmp_path, case_id, expected):
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    row = next(item for item in manifest["cases"] if item["case_id"] == case_id)
    case = load_public(DATA / row["public"])
    environment = load_environment(DATA / row["environment"])
    output = tmp_path / case_id
    final = await EvidenceAwareInvestigator(
        adapter=EngineeringFakeModel(), manifest=_manifest("m10c-" + case_id, environment),
        output_dir=output, rubric=RUBRIC,
    ).run(case, MockToolServer(environment, simulate_latency=False), BUDGET)
    assert final.verdict == expected


@pytest.mark.asyncio
async def test_mismatch_timeout_case_scores_user_history_and_retry_correctly(tmp_path):
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    row = next(item for item in manifest["cases"] if item["case_id"] == "C15")
    case = load_public(DATA / row["public"])
    environment = load_environment(DATA / row["environment"])
    run_id = "m10c-c15-behavior"
    final = await EvidenceAwareInvestigator(
        adapter=EngineeringFakeModel(), manifest=_manifest(run_id, environment),
        output_dir=tmp_path, rubric=RUBRIC,
    ).run(case, MockToolServer(environment, simulate_latency=False), BUDGET)
    report = score_behavior(replay_run(tmp_path / run_id), load_oracle(DATA / row["oracle"]))
    assert final.verdict == "Suspicious"
    assert report.metrics["tool_selection_accuracy"].value == 1
    assert report.metrics["action_annotation_coverage"].value == 1
    assert sum(action["automatic_retry"] for action in report.actions) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id,metric", [
    ("C16", "critical_evidence_recall"),
    ("C20", "sufficiency_pass_rate"),
    ("C20", "discriminating_evidence_recall"),
])
async def test_empty_scope_evidence_is_acquired_cited_and_scored(tmp_path, case_id, metric):
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    row = next(item for item in manifest["cases"] if item["case_id"] == case_id)
    case = load_public(DATA / row["public"])
    environment = load_environment(DATA / row["environment"])
    run_id = f"m10c-score-{case_id}-{metric}"
    await EvidenceAwareInvestigator(
        adapter=EngineeringFakeModel(), manifest=_manifest(run_id, environment),
        output_dir=tmp_path, rubric=RUBRIC,
    ).run(case, MockToolServer(environment, simulate_latency=False), BUDGET)
    annotations = load_annotations(ANNOTATIONS)
    oracle = load_oracle(DATA / row["oracle"])
    report = score_run(
        replay_run(tmp_path / run_id), oracle,
        annotation=annotation_for_case(annotations, oracle, BUDGET),
    )
    assert report.metrics[metric].value == 1
