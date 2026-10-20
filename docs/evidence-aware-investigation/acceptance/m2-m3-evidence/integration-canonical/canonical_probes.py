"""Independent checks for one fact acquired through equivalent tool paths."""
from collections import defaultdict
import json

import pytest

from probes import LAB, copy_data, modify, module
from evaluation.oracle_loader import load_oracle
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.tools.fixture_loader import load_environment


def test_approval_alternatives_are_one_canonical_fact_and_three_critical_facts():
    oracle = load_oracle(LAB / "datasets/oracle/c1.json")
    assert "E4H" not in oracle.complete_world_evidence
    assert "E4H" not in oracle.observable_fact_keys and "E4H" not in oracle.critical_fact_keys
    assert set(oracle.critical_fact_keys) == {"E1", "E2", "E4"}
    assert oracle.sufficient_sets == {"TP": (("E1", "E2", "E4"),), "FP": ()}
    approval = oracle.complete_world_evidence["E4"]
    assert approval["source"] == "tool" and approval["source_tools"] == ["asset", "history"]
    env = load_environment(LAB / "datasets/environment/world-1.json", remap_ids=False)
    records = {r.record_id: (tool, r) for tool, entries in env.records_by_tool.items() for r in entries}
    acquired = [records[rid] for rid in approval["record_ids"]]
    assert {tool for tool, _ in acquired} == {"asset", "history"}
    assert len({rec.independence_group for _, rec in acquired}) == 1
    assert all(rec.payload["host"] == "WS-041" and rec.payload["approved_jobs"] == [] for _, rec in acquired)
    windows = [rec.payload.get("approval_register_window", rec.payload.get("register_window")) for _, rec in acquired]
    assert all(window == windows[0] for window in windows)
    action = next(a for a in oracle.expected_actions if set(a.acceptable_tools) == {"asset", "history"})
    assert action.when_missing_fact_keys == ("E4",) and action.argument_constraints == {"host": "WS-041"}
    assert all("E4H" not in a.when_missing_fact_keys and "E4H" not in a.when_observed_fact_keys for a in oracle.expected_actions)
    summary = module("dataset_summary").summarize()
    assert next(case for case in summary["cases"] if case["case_id"] == "C1")["observable_critical_denominator"] == 3


@pytest.mark.parametrize("tools", [["asset"], ["asset", "history", "attack"], [],
    ["asset", "history", "history"], ["asset", "unknown"], "asset"])
def test_canonical_source_tools_exactly_match_all_referenced_tool_types(tmp_path, tools):
    root = copy_data(tmp_path)
    modify(root, "oracle/c1.json", lambda doc: doc["complete_world_evidence"]["E4"].update(source_tools=tools))
    with pytest.raises(ProtocolViolation, match="annotation_source_mismatch"):
        module("dataset_summary").summarize(root)
