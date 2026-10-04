import hashlib
import json
from pathlib import Path

import pytest

from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.rubric import COLUMNS, CRITERION_IDS, load_rubric

RUBRIC = Path(__file__).resolve().parents[1] / "rubrics/powershell-v1.json"


def test_frozen_gate_groups_and_five_columns():
    rubric = load_rubric(RUBRIC, expected_sha256=hashlib.sha256(RUBRIC.read_bytes()).hexdigest())
    assert tuple(c.criterion_id for c in rubric.criteria) == CRITERION_IDS
    assert rubric.policy.fp_required == ("G0", "G1", "B1", "B2", "B3")
    assert all(getattr(criterion, column) for criterion in rubric.criteria for column in COLUMNS)
    assert rubric.policy.hard_stops == ("tool_budget", "token_budget", "step_budget", "deadline")
    assert rubric.policy.suspicious_allowed_stops == ("no_useful_action", "no_available_tool")
    assert len(rubric.suspicious_patterns) == 2


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(unknown=True),
    lambda d: d.update(rubric_version="powershell-v2"),
    lambda d: d["criteria"][0].update(unknown=True),
    lambda d: d["criteria"][0].update(program_checks=[]),
    lambda d: d["criteria"].pop(),
    lambda d: d["policy"].update(fp_required=["B1"]),
    lambda d: d["policy"]["decision_rules"].append("For C3 use Suspicious"),
    lambda d: d["scope"].append("Special WS-041 decision"),
    lambda d: d["scope"].append("Harmless looking unreviewed rule change"),
    lambda d: d["suspicious_patterns"][0].update(program_checks=[False]),
])
def test_closed_and_frozen_semantics_reject_changes(tmp_path, mutation):
    data = json.loads(RUBRIC.read_text(encoding="utf-8"))
    mutation(data)
    path = tmp_path / "changed.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ProtocolViolation):
        load_rubric(path)


def test_whitespace_changes_keep_semantic_hash_but_not_file_hash(tmp_path):
    original = load_rubric(RUBRIC)
    path = tmp_path / "reformatted.json"
    path.write_text(json.dumps(json.loads(RUBRIC.read_text(encoding="utf-8")), sort_keys=True), encoding="utf-8")
    alternate = load_rubric(path)
    assert original.canonical_sha256 == alternate.canonical_sha256
    assert original.sha256 != alternate.sha256
    with pytest.raises(ProtocolViolation, match="file byte hash"):
        load_rubric(path, expected_sha256=original.sha256)


def test_duplicate_json_keys_rejected(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"rubric_version":"powershell-v1","rubric_version":"powershell-v1"}')
    with pytest.raises(ProtocolViolation, match="duplicate JSON key"):
        load_rubric(path)


def test_safety_obligations_are_explicit():
    rubric = load_rubric(RUBRIC)
    by_id = {c.criterion_id: c for c in rubric.criteria}
    assert any("asset and history" in x for x in by_id["G4"].program_checks)
    assert any("equivalent complete history" in x for x in by_id["G3"].program_checks)
    assert any("detector_claim" in x for x in by_id["G2"].program_checks)
    assert any("host-wide" in x for x in by_id["B3"].program_checks)
    assert any("Both groups met" in x for x in rubric.policy.decision_rules)
    assert any("hard-stop" in x for x in rubric.policy.decision_rules)
