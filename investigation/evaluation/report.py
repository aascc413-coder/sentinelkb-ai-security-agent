"""Evaluation entry point that preserves failed attempts in cohort reports."""

from dataclasses import dataclass, replace
from pathlib import Path
from math import ceil
import json

from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import RunManifest, Usage
from evidence_investigation.state.errors import ProtocolViolation
from .annotation_loader import annotation_for_case
from .behavior import BehaviorReport, score_behavior
from .contracts import CaseScore, EvaluationAnnotationSet, MetricCount, OracleCase
from .evaluator import score_run
from .leakage import (CapturedRequest, LeakagePolicy, inspect_request, load_capture_bundle,
                      validate_capture)
from .metrics import VerdictMetricsReport, aggregate_verdict_metrics
from .replay import replay_run


@dataclass(frozen=True)
class RunEvaluation:
    score: CaseScore
    behavior: BehaviorReport | None
    input_request_count: int
    leakage_finding_count: int
    annotation_version: str | None


@dataclass(frozen=True)
class EvaluationReport:
    verdicts: VerdictMetricsReport
    runs: tuple[RunEvaluation, ...]
    limits: tuple[str, ...]
    efficiency: dict
    metric_totals: dict[str, MetricCount]
    annotation_version: str | None


def aggregate_case_metrics(runs):
    """Pool primitive numerators/denominators; never average per-run ratios."""
    names = sorted({name for run in runs if run.score.run_status == "valid"
                    for name in run.score.metrics})
    result = {}
    for name in names:
        rows = [run.score.metrics[name] for run in runs
                if run.score.run_status == "valid" and name in run.score.metrics]
        numerator = sum(row.numerator for row in rows)
        denominator = sum(row.denominator for row in rows)
        result[name] = MetricCount(numerator, denominator,
                                   numerator / denominator if denominator else None)
    return result


def summarize_efficiency(runs):
    """Descriptive nearest-rank quantiles; missing measurements stay missing.

    The all-attempt cohort includes failed runs in its denominator. Successful
    determinate means a valid TP/FP that matches truth (not just any decision).
    Currency amounts are intentionally not pooled across currencies.
    """
    cohorts = {"all_attempts": tuple(runs)}
    cohorts["correct_determinate"] = tuple(r for r in cohorts["all_attempts"]
        if r.score.run_status == "valid" and
        (r.score.verdict, r.score.ground_truth) in {("TP", "malicious"), ("FP", "benign")})
    result = {}
    for name, rows in cohorts.items():
        fields = {}
        for key in ("tool_attempts", "backend_calls", "steps", "elapsed_ms",
                    "measured_input_tokens", "measured_output_tokens", "tool_cost_units"):
            values = sorted(r.behavior.measurement[key] for r in rows
                            if r.behavior is not None and r.behavior.measurement[key] is not None
                            and (not key.startswith("measured_") or
                                 r.behavior.measurement["cost_comparison_eligible"]))
            n = len(values)
            fields[key] = {"values": values, "measured_runs": n,
                           "attempted_runs": len(rows),
                           "mean": sum(values) / n if n else None,
                           "p50": values[ceil(.5*n)-1] if n else None,
                           "p95": values[ceil(.95*n)-1] if n else None}
        result[name] = fields
    return result


def evaluate_run(run_dir: str | Path, oracle: OracleCase, manifest: RunManifest, *,
                 captured_requests: tuple[CapturedRequest, ...] = (),
                 leakage_policy: LeakagePolicy | None = None,
                 annotation_set: EvaluationAnnotationSet | None = None) -> RunEvaluation:
    """Expectations are experiment-side inputs, never supplied to the agent.

    A missing/corrupt trace or request capture is retained as a failed CaseScore.
    Actual calls (including repair) must have captures; detecting hidden inputs
    invalidates that run. This does not assert all natural-language leakage is
    detectable; use dedicated canaries and source checks in the frozen policy.
    """
    usage = Usage(usage_complete=False)
    findings = 0
    try:
        replay = replay_run(run_dir)
        usage = replay.usage
        if encode(replay.manifest) != encode(manifest):
            raise ProtocolViolation("manifest_mismatch", "trace differs from experiment manifest")
        if len(captured_requests) != usage.model_calls:
            raise ProtocolViolation("missing_request_capture", "every model attempt requires captured input")
        for index, capture in enumerate(captured_requests, 1):
            validate_capture(capture)
            if capture.request_index != index:
                raise ProtocolViolation("request_sequence", "request capture indices must be contiguous")
            if not capture.forwarded:
                raise ProtocolViolation("request_not_forwarded", "blocked request cannot validate a completed model attempt")
            # Preserve boundary findings even when the reporting policy omits
            # the capture policy's canaries. Reinspection may add findings.
            findings += len(set(capture.findings) | set(inspect_request(capture.request, leakage_policy)))
        if findings:
            raise ProtocolViolation("model_input_leakage", f"{findings} hidden-input finding(s)")
        annotation = (annotation_for_case(annotation_set, oracle, replay.manifest.budget)
                      if annotation_set is not None else None)
        score = score_run(replay, oracle, annotation=annotation)
        behavior = score_behavior(replay, oracle)
        metrics = {**score.metrics, **behavior.metrics}
        probability = replay.final.p_attack
        metrics["probability_missing_rate"] = MetricCount(int(probability is None), 1,
                                                          float(probability is None))
        error = None if probability is None else (probability - int(oracle.ground_truth == "malicious")) ** 2
        metrics["brier_score"] = MetricCount(0 if error is None else error,
                                            int(error is not None), error)
        version = annotation_set.annotation_version if annotation_set is not None else None
        return RunEvaluation(replace(score, metrics=metrics), behavior, len(captured_requests), findings,
                             version)
    except (ProtocolViolation, OSError) as exc:
        failure = CaseScore(manifest.run_id, oracle.case_id, "protocol_failure",
                            oracle.ground_truth, None, False, None, {}, usage,
                            (f"{type(exc).__name__}: {exc}",))
        version = annotation_set.annotation_version if annotation_set is not None else None
        return RunEvaluation(failure, None, len(captured_requests), findings, version)


def evaluate_persisted_run(run_dir: str | Path, capture_path: str | Path,
                           oracle: OracleCase, manifest: RunManifest, **kwargs) -> RunEvaluation:
    try:
        bundle = load_capture_bundle(capture_path, manifest.run_id)
    except (ProtocolViolation, OSError) as exc:
        usage = Usage(usage_complete=False)
        try:
            usage = replay_run(run_dir).usage
        except (ProtocolViolation, OSError):
            pass
        score = CaseScore(manifest.run_id, oracle.case_id, "protocol_failure",
                          oracle.ground_truth, None, False, None, {}, usage,
                          (f"{type(exc).__name__}: {exc}",))
        annotations = kwargs.get("annotation_set")
        version = annotations.annotation_version if annotations is not None else None
        return RunEvaluation(score, None, 0, 0, version)
    return evaluate_run(run_dir, oracle, manifest, captured_requests=bundle.captures, **kwargs)


def save_evaluation_report(path: str | Path, report: EvaluationReport) -> None:
    """Write one immutable, machine-readable cohort report."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(encode(report), stream, ensure_ascii=False, indent=1, allow_nan=False)
    except FileExistsError as exc:
        raise ProtocolViolation("report_exists", "evaluation report is immutable") from exc


def aggregate_report(runs, *, method, dataset_version, manifests) -> EvaluationReport:
    runs = tuple(runs)
    versions = {run.annotation_version for run in runs}
    if len(versions) > 1:
        raise ValueError("cannot aggregate runs scored with different evaluation annotations")
    annotation_version = next(iter(versions), None)
    verdicts = aggregate_verdict_metrics((run.score for run in runs), method=method,
                                         dataset_version=dataset_version, manifests=manifests)
    return EvaluationReport(verdicts, runs, (
        "Structured fixture grounding only; free-text inference claims are unscored.",
        "Unknown discriminating/budget-specific labels remain NA, never inferred from truth.",
        "Raw run measurements are retained; small dev samples establish no statistical advantage.",
    ), summarize_efficiency(runs), aggregate_case_metrics(runs), annotation_version)
