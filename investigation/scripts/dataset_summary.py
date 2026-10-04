"""Developer/evaluation entry point; private manifest/oracle never enter src/."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))  # evaluation is deliberately outside the runtime package.

from evaluation.oracle_loader import load_oracle
from evidence_investigation.state.codec import encode
from evidence_investigation.state.content import load_json
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.normalization import compare_static
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.state.rubric import load_rubric
from evidence_investigation.tools.fixture_loader import load_environment


def summarize(root: Path = LAB / "datasets") -> dict:
    root = root.resolve()
    manifest = load_json(root / "manifest.json")
    if set(manifest) != {"dataset_version", "purpose", "rubric_version", "cases", "file_sha256", "boundary"}:
        raise ProtocolViolation("invalid_manifest", "Manifest keys differ from the frozen authoring contract")
    expected_paths = {str(p.relative_to(root)).replace("\\", "/") for folder in ("public", "environment", "oracle")
                      for p in (root / folder).glob("*.json")}
    if set(manifest["file_sha256"]) != expected_paths:
        raise ProtocolViolation("invalid_manifest", "All and only dataset JSON files must be hashed")

    def file(rel: str) -> Path:
        path = (root / rel).resolve()
        if not path.is_relative_to(root) or rel not in manifest["file_sha256"]:
            raise ProtocolViolation("invalid_manifest", "Dataset path escapes or is not hashed")
        if hashlib.sha256(path.read_bytes()).hexdigest() != manifest["file_sha256"][rel]:
            raise ProtocolViolation("dataset_hash_mismatch", rel)
        return path

    # Verify declared files even when no case mapping currently reaches them.
    for relative in manifest["file_sha256"]:
        file(relative)

    rubric = load_rubric(LAB / "rubrics" / "powershell-v1.json")
    if manifest["rubric_version"] != rubric.rubric_version:
        raise ProtocolViolation("rubric_version_mismatch", "Dataset and rubric must share frozen version")
    reports, worlds, publics, case_ids = [], {}, {}, []
    for entry in manifest["cases"]:
        if set(entry) != {"case_id", "public", "environment", "oracle"}:
            raise ProtocolViolation("invalid_manifest", "Case mapping keys are closed")
        case_id = entry["case_id"]
        if case_id in case_ids:
            raise ProtocolViolation("duplicate_case", case_id)
        case_ids.append(case_id)
        public = load_public(file(entry["public"]), remap_ids=False)
        env = load_environment(file(entry["environment"]), remap_ids=False)
        oracle = load_oracle(file(entry["oracle"]))
        if oracle.case_id != case_id or oracle.rubric_version != rubric.rubric_version or public.alert.as_of != env.as_of:
            raise ProtocolViolation("dataset_mapping_mismatch", case_id)
        record_tools = {r.record_id: tool for tool, records in env.records_by_tool.items() for r in records}
        record_tools[public.alert.raw_reference.record_id] = "alert"
        known = set(record_tools)
        for fact_key, fact in oracle.complete_world_evidence.items():
            if type(fact) is not dict:
                raise ProtocolViolation("invalid_annotation", f"{case_id}/{fact_key}: structured annotation required")
            refs = fact.get("record_ids", [])
            if type(refs) is not list or any(type(ref) is not str for ref in refs):
                raise ProtocolViolation("invalid_annotation", f"{case_id}/{fact_key}: record_ids must be strings")
            if set(refs) - known:
                raise ProtocolViolation("dangling_annotation", f"{case_id}/{fact_key}")
            source = fact.get("source")
            if source == "oracle_only":
                if refs or fact_key in oracle.observable_fact_keys:
                    raise ProtocolViolation("hidden_fact_leak", f"{case_id}/{fact_key}")
            else:
                source_tools = fact.get("source_tools") if source == "tool" else [source]
                if (type(source_tools) is not list or not source_tools or
                    any(type(tool) is not str or tool not in {*env.records_by_tool, "alert"} for tool in source_tools) or
                    len(set(source_tools)) != len(source_tools) or any(record_tools[ref] not in source_tools for ref in refs)):
                    raise ProtocolViolation("annotation_source_mismatch", f"{case_id}/{fact_key}")
                if source == "tool" and set(source_tools) != {record_tools[ref] for ref in refs}:
                    raise ProtocolViolation("annotation_source_mismatch", f"{case_id}/{fact_key}: tool set must match actual references")
            if source != "oracle_only" and fact_key in oracle.observable_fact_keys and not refs:
                # Failure envelopes are observable operational facts, not events.
                if fact.get("operational_status") != "unavailable" or not any(
                    rule.tool == source and rule.status == "unavailable" and rule.error_code == fact.get("reason")
                    for rule in env.query_rules
                ):
                    raise ProtocolViolation("ungrounded_annotation", f"{case_id}/{fact_key}")
        publics[case_id], worlds[case_id] = public, env
        critical_observable = set(oracle.critical_fact_keys) & set(oracle.observable_fact_keys)
        reports.append({"case_id": case_id, "records_by_tool": {k: len(v) for k, v in env.records_by_tool.items()},
                        "rules": len(env.query_rules), "ground_truth": oracle.ground_truth,
                        "acceptable_verdicts": list(oracle.acceptable_verdicts),
                        "observable_critical_denominator": len(critical_observable),
                        "sufficient_sets": encode(oracle.sufficient_sets)})
    paired = compare_static(publics["C4"], worlds["C4"], publics["C5"], worlds["C5"])
    if not paired.equal:
        raise ProtocolViolation("paired_input_mismatch", str(paired.differences))
    pair_paths = [entry["environment"] for entry in manifest["cases"] if entry["case_id"] in ("C4", "C5")]
    if len(pair_paths) != 2 or len(set(pair_paths)) != 1:
        raise ProtocolViolation("paired_environment_mismatch", "Twins must use one physical fixture")
    if len(reports) != 5 or len({e["environment"] for e in manifest["cases"]}) != 4:
        raise ProtocolViolation("seed_size_mismatch", "Seed dataset requires five cases / four environments")
    return {"dataset_version": manifest["dataset_version"], "purpose": manifest["purpose"],
            "public_cases": len(reports), "physical_environments": 4, "oracle_cases": len(reports),
            "rubric_version": rubric.rubric_version, "rubric_canonical_sha256": rubric.canonical_sha256,
            "cases": reports, "paired_static_comparison": encode(paired),
            "boundary": "Static and fixture validation only; no model, runtime sufficiency evaluator or algorithm comparison."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(summarize(), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result, encoding="utf-8")
    print(result, end="")


if __name__ == "__main__":
    main()
