"""Hand-calculated classification and safety counts, including failure cohorts."""

from dataclasses import replace

import pytest

from evaluation.contracts import CaseScore
from evaluation.metrics import aggregate_verdict_metrics
from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import Budget, RunManifest, Usage


def score(run_id, truth, verdict, status="valid", case_id=None, false_close=False):
    return CaseScore(run_id, case_id or run_id, status, truth, verdict, false_close,
                     None, {}, Usage(), ())


def manifests_for(scores):
    return {s.run_id: RunManifest(
        run_id=s.run_id, method="proposed", model_snapshot="fake", model_parameters={},
        prompt_hashes={}, dataset_version="seed-v1", tool_snapshot="local",
        rubric_version="none", code_revision="test", seed=None, seed_supported=False,
        budget=Budget(), price_snapshot={},
    ) for s in scores}


def summarize(scores, **kwargs):
    return aggregate_verdict_metrics(
        scores, method=kwargs.pop("method", "proposed"),
        dataset_version=kwargs.pop("dataset_version", "seed-v1"),
        manifests=kwargs.pop("manifests", manifests_for(scores)), **kwargs,
    )


def test_hand_calculated_confusion_and_every_metric():
    rows = [
        score("m-tp1", "malicious", "TP"), score("m-tp2", "malicious", "TP"),
        score("m-fp", "malicious", "FP"), score("m-s", "malicious", "Suspicious"),
        score("m-a", "malicious", "Abstain"),
        score("b-tp", "benign", "TP"), score("b-fp", "benign", "FP"),
        score("b-s", "benign", "Suspicious"), score("b-a", "benign", "Abstain"),
        score("m-fail", "malicious", "FP", "protocol_failure"),
        score("b-fail", "benign", None, "infrastructure_failure"),
    ]
    report = summarize(rows)
    assert report.aggregate.attempted_runs == 11
    assert report.valid_runs == 9 and report.aggregate.failed_runs == 2
    assert report.aggregate.independent_cases == 11
    assert report.confusion == {
        "malicious": {"TP": 2, "FP": 1, "Suspicious": 1, "Abstain": 1, "failed": 1},
        "benign": {"TP": 1, "FP": 1, "Suspicious": 1, "Abstain": 1, "failed": 1},
    }
    assert report.attempted_by_truth == {"malicious": 6, "benign": 5}
    assert report.valid_by_truth == {"malicious": 5, "benign": 4}
    assert report.failed_by_truth == {"malicious": 1, "benign": 1}
    assert report.run_status_counts == {"valid": 9, "protocol_failure": 1, "infrastructure_failure": 1}
    expected = {
        "decision_coverage": (5, 9), "attempted_decision_coverage": (5, 11),
        "selective_accuracy": (3, 5), "overall_resolved_accuracy": (3, 9),
        "attack_precision": (2, 3), "attack_recall": (2, 5), "attack_f1": (4, 8),
        "benign_precision": (1, 2), "benign_recall": (1, 4), "benign_f1": (2, 6),
        "false_close_rate": (1, 5), "false_closure_proportion": (1, 2),
        "human_review_rate": (4, 9), "suspicious_rate": (2, 9),
        "abstention_rate": (2, 9), "suspicious_attack_proportion": (1, 2),
        "run_failure_rate": (2, 11),
    }
    assert set(report.aggregate.metrics) == set(expected)
    for name, (numerator, denominator) in expected.items():
        metric = report.aggregate.metrics[name]
        assert (metric.numerator, metric.denominator) == (numerator, denominator)
        assert metric.value == pytest.approx(numerator / denominator)


def test_empty_input_has_counts_and_null_ratios():
    report = summarize([])
    assert report.aggregate.attempted_runs == report.valid_runs == report.aggregate.failed_runs == 0
    assert report.aggregate.independent_cases == 0
    assert all(m.numerator == m.denominator == 0 and m.value is None
               for m in report.aggregate.metrics.values())
    assert encode(report)["aggregate"]["metrics"]["attack_f1"]["value"] is None


def test_all_failed_attempts_are_retained_and_not_correct_abstentions():
    report = summarize([
        score("m", "malicious", "Abstain", "protocol_failure"),
        score("b", "benign", None, "infrastructure_failure"),
    ])
    assert report.aggregate.attempted_runs == report.aggregate.failed_runs == 2
    assert report.valid_runs == 0 and report.failed_by_truth["malicious"] == 1
    assert report.aggregate.metrics["attempted_decision_coverage"].value == 0
    assert report.aggregate.metrics["run_failure_rate"].value == 1
    for name in ("decision_coverage", "false_close_rate", "human_review_rate", "attack_f1"):
        assert report.aggregate.metrics[name].value is None
    assert report.confusion["malicious"]["Abstain"] == 0


def test_all_human_review_has_zero_recall_but_undefined_precision_and_f1():
    metrics = summarize([score("m", "malicious", "Abstain"),
                         score("b", "benign", "Suspicious")]).aggregate.metrics
    assert metrics["decision_coverage"].value == metrics["attack_recall"].value == 0
    assert metrics["benign_recall"].value == 0
    assert metrics["selective_accuracy"].value is None
    assert metrics["human_review_rate"].value == 1
    for name in ("attack_precision", "attack_f1", "benign_precision", "benign_f1"):
        assert metrics[name].value is None
    assert (metrics["attack_f1"].numerator, metrics["attack_f1"].denominator) == (0, 1)


def test_predictions_all_wrong_have_defined_zero_f1():
    metrics = summarize([score("m", "malicious", "FP"),
                         score("b", "benign", "TP")]).aggregate.metrics
    for prefix in ("attack", "benign"):
        assert metrics[f"{prefix}_precision"].value == 0
        assert metrics[f"{prefix}_recall"].value == 0
        assert metrics[f"{prefix}_f1"].value == 0
    assert metrics["false_close_rate"].value == 1


def test_no_attack_truth_is_not_a_measured_zero_recall():
    metrics = summarize([score("b", "benign", "TP")]).aggregate.metrics
    assert metrics["attack_precision"].value == 0
    assert metrics["attack_recall"].value is None
    assert metrics["attack_f1"].value is None


def test_false_close_recomputed_and_repeated_runs_do_not_inflate_independent_cases():
    report = summarize([
        score("r1", "malicious", "FP", case_id="same", false_close=False),
        score("r2", "malicious", "TP", case_id="same", false_close=True),
        score("r3", "benign", "FP", false_close=True),
    ])
    assert report.aggregate.independent_cases == 2 and report.aggregate.attempted_runs == 3
    assert report.aggregate.metrics["false_close_rate"].numerator == 1
    assert report.aggregate.metrics["false_closure_proportion"].value == 0.5


@pytest.mark.parametrize("overrides", [
    {"run_status": "failed"}, {"ground_truth": "unknown"}, {"verdict": "bad"},
    {"verdict": None}, {"run_id": ""}, {"case_id": " "},
    {"run_status": "protocol_failure", "verdict": "bad"},
])
def test_invalid_input_is_rejected(overrides):
    with pytest.raises(ValueError):
        summarize([replace(score("r", "malicious", "TP"), **overrides)])


def test_duplicate_run_id_rejected_even_when_case_score_is_identical():
    row = score("r", "malicious", "TP")
    with pytest.raises(ValueError, match="duplicate run_id"):
        summarize([row, row])


def test_inconsistent_truth_for_same_case_is_rejected():
    with pytest.raises(ValueError, match="inconsistent ground_truth"):
        summarize([score("r1", "malicious", "TP", case_id="same"),
                   score("r2", "benign", "FP", case_id="same")])


@pytest.mark.parametrize("field,value", [("method", "react"), ("dataset_version", "other")])
def test_mixed_cohort_cannot_be_relabeled(field, value):
    rows = [score("r1", "malicious", "TP"), score("r2", "benign", "FP")]
    manifests = manifests_for(rows)
    manifests["r2"] = replace(manifests["r2"], **{field: value})
    with pytest.raises(ValueError, match="mixed method or dataset_version"):
        summarize(rows, manifests=manifests)


@pytest.mark.parametrize("kind", ["missing", "extra", "mismatched_id"])
def test_manifest_membership_is_exact(kind):
    rows = [score("r", "malicious", "TP")]
    manifests = manifests_for(rows)
    if kind == "missing":
        manifests.clear()
    elif kind == "extra":
        manifests["extra"] = replace(manifests["r"], run_id="extra")
    else:
        manifests["r"] = replace(manifests["r"], run_id="another")
    with pytest.raises(ValueError):
        summarize(rows, manifests=manifests)
