"""Dataset expansion must preserve blind split groups and frozen bytes."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

import pytest

from evidence_investigation.state.errors import ProtocolViolation

LAB = Path(__file__).resolve().parents[1]


def _module():
    spec = importlib.util.spec_from_file_location(
        "dataset_split_audit", LAB / "scripts/dataset_split_audit.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _copy_dataset(tmp_path: Path) -> Path:
    target = tmp_path / "datasets"
    shutil.copytree(LAB / "datasets", target)
    return target


def _rewrite_oracle(root: Path, relative: str, mutate) -> None:
    path = root / relative
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8", newline="\n")
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["file_sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8", newline="\n")


def test_seed_dataset_passes_group_split_audit():
    report = _module().audit_dataset()
    assert report["case_count"] == 5
    assert report["split_counts"] == {"dev": 5}
    assert report["family_case_counts"] == {
        "powershell-indistinguishable-pair-v1": 2,
        "powershell-seed-v1": 3,
    }
    assert [[row["case_id"] for row in group["cases"]]
            for group in report["duplicate_visible_groups"]] == [["C4", "C5"]]
    assert report["visible_normalization"]["version"] == "visible-metadata-v1"
    assert len(report["visible_normalization"]["sha256"]) == 64
    assert set(report["checks"].values()) == {"passed"}


def test_envelope_identity_difference_still_forms_one_visible_group(tmp_path):
    root = _copy_dataset(tmp_path)
    source = root / "environment/shared-pair.json"
    copied = root / "environment/shared-pair-copy.json"
    fixture = json.loads(source.read_text(encoding="utf-8"))
    fixture["environment_id"] = "different-envelope-id"
    copied.write_text(json.dumps(fixture, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8", newline="\n")
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][-1]["environment"] = "environment/shared-pair-copy.json"
    manifest["file_sha256"]["environment/shared-pair-copy.json"] = hashlib.sha256(
        copied.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    report = _module().audit_dataset(root)
    assert [row["case_id"] for row in report["duplicate_visible_groups"][0]["cases"]] == [
        "C4", "C5",
    ]


def test_family_cannot_cross_dev_and_test(tmp_path):
    root = _copy_dataset(tmp_path)
    _rewrite_oracle(root, "oracle/c3.json", lambda value: value.update(split="test"))
    with pytest.raises(ProtocolViolation, match="family_split_leakage"):
        _module().audit_dataset(root)


@pytest.mark.parametrize("change", ["family", "split"])
def test_identical_visible_inputs_stay_in_one_group(tmp_path, change):
    root = _copy_dataset(tmp_path)

    def mutate(value):
        if change == "family":
            value["family_id"] = "wrong-independent-family"
        else:
            value["split"] = "test"

    _rewrite_oracle(root, "oracle/c5.json", mutate)
    expected = "visible_input_split_leakage" if change == "family" else "family_split_leakage"
    with pytest.raises(ProtocolViolation, match=expected):
        _module().audit_dataset(root)


def test_identical_visible_inputs_cannot_cross_both_family_and_split(tmp_path):
    root = _copy_dataset(tmp_path)

    def mutate(value):
        value.update(family_id="wrong-independent-family", split="test")

    _rewrite_oracle(root, "oracle/c5.json", mutate)
    with pytest.raises(ProtocolViolation, match="visible_input_split_leakage"):
        _module().audit_dataset(root)


def test_correctly_hashed_orphan_file_is_rejected(tmp_path):
    root = _copy_dataset(tmp_path)
    orphan = root / "public/orphan.json"
    orphan.write_bytes((root / "public/c1.json").read_bytes())
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["file_sha256"]["public/orphan.json"] = hashlib.sha256(orphan.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ProtocolViolation, match="orphaned_dataset_file"):
        _module().audit_dataset(root)


def test_case_mapping_cannot_escape_declared_partition(tmp_path):
    root = _copy_dataset(tmp_path)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][0]["public"] = "oracle/c1.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ProtocolViolation, match="Invalid public path"):
        _module().audit_dataset(root)


def test_case_mapping_paths_must_be_strings(tmp_path):
    root = _copy_dataset(tmp_path)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][0]["oracle"] = ["oracle/c1.json"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ProtocolViolation, match="paths must be strings"):
        _module().audit_dataset(root)
