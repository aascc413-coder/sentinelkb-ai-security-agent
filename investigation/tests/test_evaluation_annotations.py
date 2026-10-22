"""Frozen labels are typed, budget-bound and isolated from visible inputs."""

from dataclasses import replace
from pathlib import Path

import pytest

from evaluation.annotation_loader import annotation_for_case, load_annotations
from evaluation.oracle_loader import load_oracle
from evidence_investigation.state.content import reject_hidden_metadata
from evidence_investigation.state.contracts import Budget
from evidence_investigation.state.errors import ProtocolViolation


ROOT = Path(__file__).resolve().parents[1]


def test_frozen_annotations_cover_five_cases_and_exact_budget():
    labels = load_annotations(ROOT / "evaluation/annotations/powershell-dev-v1.json")
    assert [item.case_id for item in labels.cases] == ["C1", "C2", "C3", "C4", "C5"]
    for number in range(1, 6):
        oracle = load_oracle(ROOT / f"datasets/oracle/c{number}.json")
        assert annotation_for_case(labels, oracle, Budget()).case_id == f"C{number}"


def test_annotation_budget_rubric_references_and_conflicts_are_rejected():
    labels = load_annotations(ROOT / "evaluation/annotations/powershell-dev-v1.json")
    oracle = load_oracle(ROOT / "datasets/oracle/c1.json")
    with pytest.raises(ProtocolViolation, match="budget"):
        annotation_for_case(labels, oracle, replace(Budget(), max_tool_calls=5))
    with pytest.raises(ProtocolViolation, match="rubric"):
        annotation_for_case(replace(labels, rubric_version="other"), oracle, Budget())
    bad = replace(labels.cases[0], discriminating_fact_keys=("hidden",))
    with pytest.raises(ProtocolViolation, match="dangling_reference"):
        annotation_for_case(replace(labels, cases=(bad,) + labels.cases[1:]), oracle, Budget())
    conflict = replace(labels.cases[0], required_abstention=True, avoidable_abstention=True,
                       required_human_review=True)
    with pytest.raises(ProtocolViolation, match="both required and avoidable"):
        annotation_for_case(replace(labels, cases=(conflict,) + labels.cases[1:]), oracle, Budget())


@pytest.mark.parametrize("key", ["discriminating_fact_keys", "risk_clue_fact_keys",
                                 "required_abstention", "budget_profile"])
def test_evaluation_labels_are_rejected_at_visible_boundary(key):
    with pytest.raises(ProtocolViolation, match="hidden_metadata"):
        reject_hidden_metadata({key: []})
