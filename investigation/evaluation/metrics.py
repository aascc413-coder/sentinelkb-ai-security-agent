"""Classification/safety counts for one method and dataset version.

Only final valid deliveries enter decision metrics. Failed attempts remain in
the confusion table and coverage denominator. These are descriptive run-level
counts; repeated samples do not create additional independent cases.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from evidence_investigation.state.contracts import RunManifest

from .contracts import AggregateMetrics, CaseScore, MetricCount

_TRUTHS = ("malicious", "benign")
_VERDICTS = ("TP", "FP", "Suspicious", "Abstain")
_STATUSES = ("valid", "protocol_failure", "infrastructure_failure")
_METHODS = ("direct", "fixed", "react", "proposed", "fixed_all")


@dataclass(frozen=True)
class VerdictMetricsReport:
    """Aggregate contract plus explicit denominators and failed-run accounting."""

    aggregate: AggregateMetrics
    valid_runs: int
    confusion: dict[str, dict[str, int]]
    attempted_by_truth: dict[str, int]
    valid_by_truth: dict[str, int]
    failed_by_truth: dict[str, int]
    run_status_counts: dict[str, int]


def _ratio(numerator: int, denominator: int) -> MetricCount:
    return MetricCount(numerator, denominator,
                       numerator / denominator if denominator else None)


def _f1(correct: int, predicted: int, truth_count: int) -> MetricCount:
    # Keep the formula's counts even when one constituent metric is undefined.
    numerator, denominator = 2 * correct, predicted + truth_count
    value = numerator / denominator if predicted and truth_count else None
    return MetricCount(numerator, denominator, value)


def _nonempty(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")


def aggregate_verdict_metrics(
    scores: Iterable[CaseScore], *, method: str, dataset_version: str,
    manifests: Mapping[str, RunManifest],
) -> VerdictMetricsReport:
    """Summarize one explicitly verified cohort, rejecting invalid input.

    ``manifests`` must contain exactly these run IDs, including failed runs.
    Their method/dataset fields prevent silently relabeling a mixed cohort.
    Failed runs may retain a recognized proposed verdict, but it is never
    counted as a delivered decision. ``CaseScore.false_close`` is not trusted:
    false closure is derived from valid delivery + world truth + final verdict.
    """
    if method not in _METHODS:
        raise ValueError(f"unknown method: {method!r}")
    _nonempty(dataset_version, "dataset_version")
    rows = tuple(scores)
    seen: set[str] = set()
    case_truth: dict[str, str] = {}
    confusion = {truth: dict.fromkeys((*_VERDICTS, "failed"), 0) for truth in _TRUTHS}
    statuses = dict.fromkeys(_STATUSES, 0)
    for score in rows:
        if not isinstance(score, CaseScore):
            raise ValueError("scores must contain CaseScore instances")
        _nonempty(score.run_id, "run_id")
        _nonempty(score.case_id, "case_id")
        if score.run_id in seen:
            raise ValueError(f"duplicate run_id: {score.run_id}")
        seen.add(score.run_id)
        if score.run_status not in _STATUSES:
            raise ValueError(f"unknown run_status: {score.run_status!r}")
        if score.ground_truth not in _TRUTHS:
            raise ValueError(f"unknown ground_truth: {score.ground_truth!r}")
        if score.verdict is not None and score.verdict not in _VERDICTS:
            raise ValueError(f"unknown verdict: {score.verdict!r}")
        if score.run_status == "valid" and score.verdict is None:
            raise ValueError("valid run requires a final verdict")
        if score.case_id in case_truth and case_truth[score.case_id] != score.ground_truth:
            raise ValueError(f"inconsistent ground_truth for case_id: {score.case_id}")
        case_truth[score.case_id] = score.ground_truth
        manifest = manifests.get(score.run_id)
        if not isinstance(manifest, RunManifest) or manifest.run_id != score.run_id:
            raise ValueError(f"missing or mismatched manifest for run_id: {score.run_id}")
        if manifest.method != method or manifest.dataset_version != dataset_version:
            raise ValueError("mixed method or dataset_version; aggregate each cohort separately")
        statuses[score.run_status] += 1
        column = score.verdict if score.run_status == "valid" else "failed"
        confusion[score.ground_truth][column] += 1
    if set(manifests) != seen:
        raise ValueError("manifests must match the scored run IDs exactly")

    attempted_by_truth = {truth: sum(confusion[truth].values()) for truth in _TRUTHS}
    failed_by_truth = {truth: confusion[truth]["failed"] for truth in _TRUTHS}
    valid_by_truth = {truth: attempted_by_truth[truth] - failed_by_truth[truth]
                      for truth in _TRUTHS}
    malicious, benign = confusion["malicious"], confusion["benign"]
    a, b, c, d = malicious["TP"], benign["TP"], malicious["FP"], benign["FP"]
    valid = statuses["valid"]
    decided = a + b + c + d
    suspicious = malicious["Suspicious"] + benign["Suspicious"]
    abstained = malicious["Abstain"] + benign["Abstain"]
    failed = len(rows) - valid
    metrics = {
        "decision_coverage": _ratio(decided, valid),
        "attempted_decision_coverage": _ratio(decided, len(rows)),
        "selective_accuracy": _ratio(a + d, decided),
        "overall_resolved_accuracy": _ratio(a + d, valid),
        "attack_precision": _ratio(a, a + b),
        "attack_recall": _ratio(a, valid_by_truth["malicious"]),
        "attack_f1": _f1(a, a + b, valid_by_truth["malicious"]),
        "benign_precision": _ratio(d, c + d),
        "benign_recall": _ratio(d, valid_by_truth["benign"]),
        "benign_f1": _f1(d, c + d, valid_by_truth["benign"]),
        "false_close_rate": _ratio(c, valid_by_truth["malicious"]),
        "false_closure_proportion": _ratio(c, c + d),
        "human_review_rate": _ratio(suspicious + abstained, valid),
        "suspicious_rate": _ratio(suspicious, valid),
        "abstention_rate": _ratio(abstained, valid),
        "suspicious_attack_proportion": _ratio(malicious["Suspicious"], suspicious),
        "run_failure_rate": _ratio(failed, len(rows)),
    }
    aggregate = AggregateMetrics(
        method=method, dataset_version=dataset_version, attempted_runs=len(rows),
        independent_cases=len(case_truth), failed_runs=failed, metrics=metrics,
        confidence_intervals={},  # No inference or significance claim from dev runs.
    )
    return VerdictMetricsReport(aggregate, valid, confusion, attempted_by_truth,
                                valid_by_truth, failed_by_truth, statuses)
