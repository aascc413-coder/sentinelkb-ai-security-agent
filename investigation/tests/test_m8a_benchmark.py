"""M8a artifact runner integration acceptance."""

from __future__ import annotations

import json

import pytest

from benchmark.m8a import METHODS, replay_artifact, run_benchmark


@pytest.mark.asyncio
async def test_m8a_main_matrix_archives_and_replays_without_model_or_tools(tmp_path):
    artifact = tmp_path / "m8a"
    inventory = await run_benchmark(
        artifact, repeats=1, budget_values=(), code_revision="test-revision"
    )

    assert inventory["run_count"] == len(METHODS) * 5
    assert all(row["status"] == "valid" for row in inventory["runs"])
    assert all(row["leakage_finding_count"] == 0 for row in inventory["runs"])
    assert all(row["annotations_applied"] for row in inventory["runs"])
    assert {row["method"] for row in inventory["runs"]} == set(METHODS)
    assert [row["verdict"] for row in inventory["runs"]
            if row["method"] == "proposed"] == [
                "TP", "FP", "Suspicious", "Abstain", "Abstain"
            ]
    assert {row["verdict"] for row in inventory["runs"]
            if row["method"] != "proposed"} == {"Abstain"}

    result = replay_artifact(artifact)
    assert result["replayed_runs"] == 25
    assert result["reports"] == len(METHODS)
    summary = (artifact / "reports" / "summary.md").read_text(encoding="utf-8")
    assert "fake model" in summary.lower()
    assert "does not establish method superiority" in summary
    assert "M8b" in summary

    proposed = json.loads(
        (artifact / "reports" / "main" / "proposed.json").read_text(encoding="utf-8")
    )
    assert proposed["metric_totals"]["model_proposal_error_rate"] == {
        "denominator": 0, "numerator": 0, "value": None
    }


@pytest.mark.asyncio
async def test_m8a_nondefault_budget_does_not_reuse_frozen_annotations(tmp_path):
    artifact = tmp_path / "m8a-budget"
    inventory = await run_benchmark(
        artifact, repeats=1, budget_values=(2,), methods=("proposed",),
        cases=("C1",), code_revision="test-revision",
    )
    main, smoke = inventory["runs"]
    assert main["annotations_applied"] is True
    assert smoke["cohort"] == "budget-2"
    assert smoke["annotations_applied"] is False
    assert replay_artifact(artifact)["replayed_runs"] == 2
