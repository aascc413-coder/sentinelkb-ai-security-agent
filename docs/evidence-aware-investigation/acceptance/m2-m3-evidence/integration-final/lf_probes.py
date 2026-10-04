"""Fixed physical newline policy changes byte hashes, not investigation facts."""
from copy import deepcopy
import json
from pathlib import Path

from probes import LAB


def test_all_dataset_json_are_lf_and_match_old_canonical_fact_semantics():
    old = Path(__file__).parent.parent / "canonical-final-retest/investigation/datasets"
    for current in (LAB / "datasets").rglob("*.json"):
        raw = current.read_bytes()
        assert b"\r\n" not in raw
        before = json.loads((old / current.relative_to(LAB / "datasets")).read_bytes())
        after = json.loads(raw)
        if current.name == "manifest.json":
            before.pop("file_sha256")
            after.pop("file_sha256")
        assert before == after, current


def test_attributes_only_force_dataset_json_and_builder_explicitly_writes_lf():
    root = Path(__file__).parent
    rules = [line for line in (root / ".gitattributes").read_text().splitlines()
             if line and not line.startswith("#")]
    assert rules == ["investigation/datasets/*.json text eol=lf",
                     "investigation/datasets/**/*.json text eol=lf"]
    builder = (LAB / "scripts/build_seed_dataset.py").read_text(encoding="utf8")
    assert 'newline="\\n"' in builder
