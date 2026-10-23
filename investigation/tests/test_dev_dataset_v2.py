"""M10b expanded development dataset authoring and behavior checks."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from benchmark.m8a import EngineeringFakeModel
from evaluation.annotation_loader import annotation_for_case, load_annotations
from evaluation.oracle_loader import load_oracle
from evidence_investigation.agents.investigator import (
    EvidenceAwareInvestigator, required_prompt_hashes,
)
from evidence_investigation.state.contracts import Budget, RunManifest
from evidence_investigation.state.normalization import compare_static
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.state.rubric import load_rubric
from evidence_investigation.tools.fixture_loader import load_environment
from evidence_investigation.tools.server import MockToolServer

LAB = Path(__file__).resolve().parents[1]
DATA = LAB / "datasets/powershell-dev-v2"
ANNOTATIONS = LAB / "evaluation/annotations/powershell-dev-v2.json"
RUBRIC = load_rubric(LAB / "rubrics/powershell-v1.json")
BUDGET = Budget()


def _load_script(name):
    spec = importlib.util.spec_from_file_location(name, LAB / f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_expanded_dataset_audit_and_frozen_annotations():
    report = _load_script("dataset_split_audit").audit_dataset(DATA)
    assert report["case_count"] == 12
    assert report["family_count"] == 7
    assert report["split_counts"] == {"dev": 12}
    assert [[item["case_id"] for item in group["cases"]]
            for group in report["duplicate_visible_groups"]] == [
                ["C4", "C5"], ["C10", "C11"],
            ]
    labels = load_annotations(ANNOTATIONS)
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    assert [item.case_id for item in labels.cases] == [f"C{number}" for number in range(1, 13)]
    for row in manifest["cases"]:
        oracle = load_oracle(DATA / row["oracle"])
        assert annotation_for_case(labels, oracle, BUDGET).case_id == row["case_id"]


def test_new_counterfactual_pair_is_statically_equal_but_truth_differs():
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    rows = {item["case_id"]: item for item in manifest["cases"]}
    left, right = rows["C10"], rows["C11"]
    p10, p11 = (load_public(DATA / row["public"]) for row in (left, right))
    e10, e11 = (load_environment(DATA / row["environment"]) for row in (left, right))
    o10, o11 = (load_oracle(DATA / row["oracle"]) for row in (left, right))
    assert compare_static(p10, e10, p11, e11).equal
    assert o10.ground_truth != o11.ground_truth
    assert o10.acceptable_verdicts == o11.acceptable_verdicts == ("Abstain",)


def test_expanded_visible_partitions_do_not_contain_author_labels():
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    forbidden = ('"case_id"', '"family_id"', '"split"', '"ground_truth"',
                 '"critical_fact_keys"', '"acceptable_verdicts"', '"oracle_only"')
    for row in manifest["cases"]:
        public = (DATA / row["public"]).read_text(encoding="utf-8")
        environment = (DATA / row["environment"]).read_text(encoding="utf-8")
        assert not any(marker in public or marker in environment for marker in forbidden)


def test_first_five_cases_preserve_seed_json_bytes():
    seed_root = LAB / "datasets"
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    for row in manifest["cases"][:5]:
        for partition in ("public", "environment", "oracle"):
            relative = row[partition]
            assert (DATA / relative).read_bytes() == (seed_root / relative).read_bytes()


def test_dev_dataset_builder_reproduces_frozen_bytes(tmp_path):
    builder = _load_script("build_dev_dataset")
    builder.ROOT = tmp_path / "powershell-dev-v2"
    builder.ANNOTATIONS = tmp_path / "powershell-dev-v2.json"
    builder.main()
    for source in [DATA / "manifest.json", *DATA.glob("*/*.json")]:
        rebuilt = builder.ROOT / source.relative_to(DATA)
        assert b"\r\n" not in source.read_bytes()
        assert source.read_bytes() == rebuilt.read_bytes()
    assert ANNOTATIONS.read_bytes() == builder.ANNOTATIONS.read_bytes()


def _manifest(run_id, environment):
    return RunManifest(
        run_id, "proposed", "fake-m10b-v1", {"temperature": 0},
        required_prompt_hashes(), "powershell-dev-v2", environment.fixture_version,
        "powershell-v1", "test", 10, True, BUDGET, {},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id,expected", [
    ("C6", "TP"), ("C7", "FP"), ("C8", "FP"), ("C9", "Suspicious"),
    ("C10", "Abstain"), ("C11", "Abstain"), ("C12", "TP"),
])
async def test_proposed_expected_behavior_on_new_dev_cases(tmp_path, case_id, expected):
    manifest_data = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    row = next(item for item in manifest_data["cases"] if item["case_id"] == case_id)
    case = load_public(DATA / row["public"])
    environment = load_environment(DATA / row["environment"])
    final = await EvidenceAwareInvestigator(
        adapter=EngineeringFakeModel(), manifest=_manifest("m10b-" + case_id, environment),
        output_dir=tmp_path, rubric=RUBRIC,
    ).run(case, MockToolServer(environment, simulate_latency=False), BUDGET)
    assert final.verdict == expected
