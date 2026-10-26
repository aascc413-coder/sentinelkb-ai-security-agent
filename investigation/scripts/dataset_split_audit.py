"""Audit dataset integrity and group-safe dev/test splits.

This is an authoring/evaluation command. It may read oracle files; runtime and
agent code must never import it. The audit deliberately treats ``family_id``
as the indivisible split group so counterfactual twins and template variants
cannot be divided between development and blind test cohorts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
import sys

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))

from evaluation.oracle_loader import load_oracle
from evidence_investigation.state.content import load_json, require_text
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.normalization import (
    NORMALIZATION_SHA256, NORMALIZATION_VERSION, compare_static,
)
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.tools.fixture_loader import load_environment

_MANIFEST_KEYS = {
    "dataset_version", "purpose", "rubric_version", "cases", "file_sha256", "boundary",
}
_CASE_KEYS = {"case_id", "public", "environment", "oracle"}
_DATA_FOLDERS = ("public", "environment", "oracle")


def audit_dataset(root: Path = LAB / "datasets") -> dict:
    """Validate a frozen dataset and return a deterministic split summary."""
    root = root.resolve()
    manifest = load_json(root / "manifest.json")
    if type(manifest) is not dict or set(manifest) != _MANIFEST_KEYS:
        raise ProtocolViolation("invalid_manifest", "Manifest keys differ from the frozen contract")
    for field in ("dataset_version", "purpose", "rubric_version", "boundary"):
        require_text(manifest[field], f"manifest.{field}")
    if type(manifest["cases"]) is not list or not manifest["cases"]:
        raise ProtocolViolation("invalid_manifest", "Manifest must contain at least one case")
    if type(manifest["file_sha256"]) is not dict:
        raise ProtocolViolation("invalid_manifest", "file_sha256 must be an object")

    expected_paths = {
        path.relative_to(root).as_posix()
        for folder in _DATA_FOLDERS
        for path in (root / folder).rglob("*.json")
    }
    if set(manifest["file_sha256"]) != expected_paths:
        raise ProtocolViolation("invalid_manifest", "All and only dataset JSON files must be hashed")

    def checked_file(relative: object, expected_folder: str) -> Path:
        if type(relative) is not str:
            raise ProtocolViolation("invalid_manifest", "Dataset paths must be strings")
        normalized = relative.replace("\\", "/")
        if normalized != relative or not normalized.startswith(expected_folder + "/"):
            raise ProtocolViolation("invalid_manifest", f"Invalid {expected_folder} path: {relative}")
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or relative not in manifest["file_sha256"]:
            raise ProtocolViolation("invalid_manifest", "Dataset path escapes or is not hashed")
        expected_hash = manifest["file_sha256"][relative]
        if (type(expected_hash) is not str or len(expected_hash) != 64
                or any(character not in "0123456789abcdef" for character in expected_hash)):
            raise ProtocolViolation("invalid_manifest", f"Invalid SHA256 for {relative}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
            raise ProtocolViolation("dataset_hash_mismatch", relative)
        return path

    # Reject orphaned or tampered files even if no case mapping references them.
    for relative in sorted(expected_paths):
        folder = relative.split("/", 1)[0]
        checked_file(relative, folder)

    case_ids: set[str] = set()
    oracle_paths: set[str] = set()
    mapped_paths: set[str] = set()
    family_splits: dict[str, set[str]] = defaultdict(set)
    split_counts: Counter[str] = Counter()
    family_counts: Counter[str] = Counter()
    loaded_cases: list[dict] = []

    for entry in manifest["cases"]:
        if type(entry) is not dict or set(entry) != _CASE_KEYS:
            raise ProtocolViolation("invalid_manifest", "Case mapping keys are closed")
        case_id = entry["case_id"]
        require_text(case_id, "manifest.case_id")
        if case_id in case_ids:
            raise ProtocolViolation("duplicate_case", case_id)
        case_ids.add(case_id)
        public_path = checked_file(entry["public"], "public")
        environment_path = checked_file(entry["environment"], "environment")
        oracle_path = checked_file(entry["oracle"], "oracle")
        oracle_relative = entry["oracle"]
        if oracle_relative in oracle_paths:
            raise ProtocolViolation("duplicate_oracle_mapping", oracle_relative)
        oracle_paths.add(oracle_relative)
        mapped_paths.update((entry["public"], entry["environment"], oracle_relative))

        public = load_public(public_path, remap_ids=False)
        environment = load_environment(environment_path, remap_ids=False)
        oracle = load_oracle(oracle_path)
        if oracle.case_id != case_id:
            raise ProtocolViolation("dataset_mapping_mismatch", f"Oracle mismatch for {case_id}")
        if oracle.rubric_version != manifest["rubric_version"]:
            raise ProtocolViolation("rubric_version_mismatch", case_id)
        if public.alert.as_of != environment.as_of:
            raise ProtocolViolation("dataset_mapping_mismatch", f"as_of mismatch for {case_id}")

        record_tools = {
            record.record_id: tool
            for tool, records in environment.records_by_tool.items()
            for record in records
        }
        record_tools[public.alert.raw_reference.record_id] = "alert"
        known_record_ids = set(record_tools)
        for fact_key, fact in oracle.complete_world_evidence.items():
            if type(fact) is not dict:
                raise ProtocolViolation(
                    "invalid_annotation", f"{case_id}/{fact_key}: structured annotation required"
                )
            references = fact.get("record_ids", [])
            if type(references) is not list or any(type(item) is not str for item in references):
                raise ProtocolViolation(
                    "invalid_annotation", f"{case_id}/{fact_key}: record_ids must be strings"
                )
            if set(references) - known_record_ids:
                raise ProtocolViolation("dangling_annotation", f"{case_id}/{fact_key}")
            source = fact.get("source")
            if source == "oracle_only":
                if references or fact_key in oracle.observable_fact_keys:
                    raise ProtocolViolation("hidden_fact_leak", f"{case_id}/{fact_key}")
                continue
            source_tools = fact.get("source_tools") if source == "tool" else [source]
            if (type(source_tools) is not list or not source_tools
                    or any(type(tool) is not str
                           or tool not in {*environment.records_by_tool, "alert"}
                           for tool in source_tools)
                    or len(set(source_tools)) != len(source_tools)
                    or any(record_tools[item] not in source_tools for item in references)):
                raise ProtocolViolation("annotation_source_mismatch", f"{case_id}/{fact_key}")
            if source == "tool" and set(source_tools) != {record_tools[item] for item in references}:
                raise ProtocolViolation(
                    "annotation_source_mismatch",
                    f"{case_id}/{fact_key}: tools must match actual references",
                )
            if fact_key in oracle.observable_fact_keys and not references:
                operational_status = fact.get("operational_status")
                if operational_status not in {
                    "empty", "partial", "unavailable", "timeout", "error",
                }:
                    raise ProtocolViolation("ungrounded_annotation", f"{case_id}/{fact_key}")
                matching_rules = [
                    rule for rule in environment.query_rules
                    if rule.tool == source and rule.status == operational_status
                ]
                arguments = fact.get("arguments")
                if operational_status != "unavailable":
                    if type(arguments) is not dict:
                        raise ProtocolViolation("ungrounded_annotation", f"{case_id}/{fact_key}")
                    matching_rules = [
                        rule for rule in matching_rules
                        if rule.argument_constraints == arguments
                    ]
                if operational_status in {"unavailable", "timeout", "error"}:
                    matching_rules = [
                        rule for rule in matching_rules
                        if rule.error_code == fact.get("reason")
                    ]
                if operational_status in {"timeout", "error"} \
                        and type(fact.get("retryable")) is not bool:
                    raise ProtocolViolation("ungrounded_annotation", f"{case_id}/{fact_key}")
                if "retryable" in fact:
                    matching_rules = [
                        rule for rule in matching_rules
                        if rule.retryable is fact.get("retryable")
                    ]
                if not matching_rules:
                    raise ProtocolViolation("ungrounded_annotation", f"{case_id}/{fact_key}")

        family_splits[oracle.family_id].add(oracle.split)
        split_counts[oracle.split] += 1
        family_counts[oracle.family_id] += 1
        loaded_cases.append({
            "case_id": case_id,
            "family_id": oracle.family_id,
            "split": oracle.split,
            "public": public,
            "environment": environment,
        })

    unused_paths = expected_paths - mapped_paths
    if unused_paths:
        raise ProtocolViolation(
            "orphaned_dataset_file",
            "Every hashed dataset file must be referenced: " + ", ".join(sorted(unused_paths)),
        )

    leaking_families = {
        family: sorted(splits) for family, splits in family_splits.items() if len(splits) != 1
    }
    if leaking_families:
        raise ProtocolViolation(
            "family_split_leakage",
            "A family_id must be wholly assigned to one split: "
            + json.dumps(leaking_families, sort_keys=True),
        )

    parents = list(range(len(loaded_cases)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for left in range(len(loaded_cases)):
        for right in range(left + 1, len(loaded_cases)):
            first, second = loaded_cases[left], loaded_cases[right]
            comparison = compare_static(
                first["public"], first["environment"],
                second["public"], second["environment"],
            )
            if comparison.equal:
                union(left, right)

    visible_groups: dict[int, list[dict[str, str]]] = defaultdict(list)
    for index, item in enumerate(loaded_cases):
        visible_groups[find(index)].append({
            "case_id": item["case_id"],
            "family_id": item["family_id"],
            "split": item["split"],
        })

    for members in visible_groups.values():
        families = {member["family_id"] for member in members}
        splits = {member["split"] for member in members}
        if len(members) > 1 and (len(families) != 1 or len(splits) != 1):
            raise ProtocolViolation(
                "visible_input_split_leakage",
                "Statically equivalent model-visible inputs need one family and split: "
                + ", ".join(member["case_id"] for member in members),
            )

    duplicate_visible_groups = [
        {"visible_group_id": f"VG{number:03d}", "cases": members}
        for number, members in enumerate(
            (members for _, members in sorted(visible_groups.items()) if len(members) > 1), 1
        )
    ]
    families_by_split = {
        split: sorted(family for family, splits in family_splits.items() if split in splits)
        for split in sorted(split_counts)
    }
    return {
        "dataset_version": manifest["dataset_version"],
        "rubric_version": manifest["rubric_version"],
        "case_count": len(case_ids),
        "family_count": len(family_splits),
        "split_counts": dict(sorted(split_counts.items())),
        "family_case_counts": dict(sorted(family_counts.items())),
        "families_by_split": families_by_split,
        "duplicate_visible_groups": duplicate_visible_groups,
        "visible_normalization": {
            "version": NORMALIZATION_VERSION,
            "sha256": NORMALIZATION_SHA256,
        },
        "checks": {
            "manifest_and_hashes": "passed",
            "typed_case_mappings": "passed",
            "oracle_fact_references": "passed",
            "family_group_split": "passed",
            "identical_visible_input_grouping": "passed",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=LAB / "datasets")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit_dataset(args.dataset), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result, encoding="utf-8", newline="\n")
    print(result, end="")


if __name__ == "__main__":
    main()
