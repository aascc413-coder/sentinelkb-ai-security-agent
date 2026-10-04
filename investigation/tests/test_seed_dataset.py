"""Seed semantics and package boundary integration, independent of M3 server."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

from evidence_investigation.state.public_loader import load_public
from evidence_investigation.state.normalization import compare_static
from evidence_investigation.tools.fixture_loader import load_environment

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
from evaluation.oracle_loader import load_oracle


def test_all_seed_files_load_and_annotations_cross_reference():
    spec = importlib.util.spec_from_file_location("dataset_summary", LAB / "scripts/dataset_summary.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.summarize()
    assert (summary["public_cases"], summary["physical_environments"], summary["oracle_cases"]) == (5, 4, 5)
    assert summary["paired_static_comparison"]["equal"]
    assert [case["observable_critical_denominator"] for case in summary["cases"]][-2:] == [0, 0]


def test_twins_same_physical_environment_and_public_but_distinct_hidden_world():
    manifest = json.loads((LAB / "datasets/manifest.json").read_text())
    a, b = manifest["cases"][-2:]
    assert a["environment"] == b["environment"]
    p4, p5 = (load_public(LAB / "datasets" / e["public"]) for e in (a, b))
    e4, e5 = (load_environment(LAB / "datasets" / e["environment"]) for e in (a, b))
    assert p4 == p5 and e4 == e5 and compare_static(p4, e4, p5, e5).equal
    o4, o5 = (load_oracle(LAB / "datasets" / e["oracle"]) for e in (a, b))
    assert o4.ground_truth != o5.ground_truth
    assert o4.acceptable_verdicts == o5.acceptable_verdicts == ("Abstain",)
    assert o4.complete_world_evidence["E6"] != o5.complete_world_evidence["E6"]
    assert "E6" not in o4.observable_fact_keys


@pytest.mark.parametrize("index", [1, 2, 3, 4, 5])
def test_public_and_environment_never_contain_author_annotations(index):
    public = load_public(LAB / f"datasets/public/c{index}.json")
    envpath = "shared-pair" if index >= 4 else f"world-{index}"
    env = load_environment(LAB / f"datasets/environment/{envpath}.json")
    assert public.alert.alert_id.startswith("alert-") and len(public.alert.alert_id) == 70
    assert all(r.record_id.startswith("record-") for records in env.records_by_tool.values() for r in records)
    assert all(r.independence_group.startswith("group-") for records in env.records_by_tool.values() for r in records)
    payloads = [public.alert.raw] + [r.payload for records in env.records_by_tool.values() for r in records]
    serialized = json.dumps(payloads)
    for field in ('"ground_truth"', '"sufficient_sets"', '"critical_fact_keys"', '"acceptable_verdicts"', '"case_id"', '"oracle_only"'):
        assert field not in serialized


def test_mirrored_measurements_retain_same_event_and_independence_group():
    env = load_environment(LAB / "datasets/environment/world-1.json")
    pair = [r for r in env.records_by_tool["siem"] if r.payload["view"] == "process_tree"]
    assert len(pair) == 2 and pair[0].record_id != pair[1].record_id
    assert pair[0].payload == pair[1].payload
    assert pair[0].content_sha256 == pair[1].content_sha256
    assert pair[0].independence_group == pair[1].independence_group


def test_alternate_approval_paths_share_one_oracle_fact_and_critical_denominator():
    oracle = load_oracle(LAB / "datasets/oracle/c1.json")
    env = load_environment(LAB / "datasets/environment/world-1.json", remap_ids=False)
    approval = oracle.complete_world_evidence["E4"]
    assert oracle.critical_fact_keys == ("E1", "E2", "E4")
    assert oracle.sufficient_sets["TP"] == (("E1", "E2", "E4"),)
    assert approval["source_tools"] == ["asset", "history"]
    known = {r.record_id: tool for tool, records in env.records_by_tool.items() for r in records}
    assert {known[rid] for rid in approval["record_ids"]} == {"asset", "history"}
    expected = next(a for a in oracle.expected_actions if "asset" in a.acceptable_tools)
    assert expected.acceptable_tools == ("asset", "history") and expected.when_missing_fact_keys == ("E4",)


def test_c3_no_observable_attack_proof_and_no_determinate_sufficient_set():
    oracle = load_oracle(LAB / "datasets/oracle/c3.json")
    env = load_environment(LAB / "datasets/environment/world-3.json")
    assert oracle.sufficient_sets == {"TP": (), "FP": ()}
    assert "E6" in oracle.critical_fact_keys and "E6" not in oracle.observable_fact_keys
    process = next(r.payload for r in env.records_by_tool["siem"] if r.payload["view"] == "process_tree")
    assert process["script_body"] is None and process["job_id"] == "J-9"
    assert all(r.payload["reputation"] == "unknown" for r in env.records_by_tool["threat_intel"])
    assert all(r.status == "unavailable" and not r.retryable for r in env.query_rules if r.tool == "history")


def test_authoring_reproduction_has_exact_frozen_bytes(tmp_path):
    spec = importlib.util.spec_from_file_location("build_seed", LAB / "scripts/build_seed_dataset.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = tmp_path
    module.main()
    for source in (LAB / "datasets").rglob("*.json"):
        assert b"\r\n" not in source.read_bytes()
        assert hashlib.sha256(source.read_bytes()).digest() == hashlib.sha256((tmp_path / source.relative_to(LAB / "datasets")).read_bytes()).digest()


@pytest.mark.parametrize("problem", ["hidden_observable", "source_mismatch", "unused_hash"])
def test_summary_rejects_corrupt_annotations_and_unused_file_hash(tmp_path, problem):
    import shutil
    from evidence_investigation.state.errors import ProtocolViolation
    root = tmp_path / "datasets"
    shutil.copytree(LAB / "datasets", root)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if problem == "unused_hash":
        rel = "public/unused.json"
        (root / rel).write_bytes((root / "public/c1.json").read_bytes())
        manifest["file_sha256"][rel] = "0" * 64
    else:
        rel = "oracle/c4.json" if problem == "hidden_observable" else "oracle/c1.json"
        path = root / rel
        data = json.loads(path.read_text())
        if problem == "hidden_observable":
            data["observable_fact_keys"].append("E6")
        else:
            data["complete_world_evidence"]["E1"]["source"] = "asset"
        path.write_text(json.dumps(data), encoding="utf-8")
        manifest["file_sha256"][rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("dataset_summary_bad", LAB / "scripts/dataset_summary.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(ProtocolViolation):
        module.summarize(root)
