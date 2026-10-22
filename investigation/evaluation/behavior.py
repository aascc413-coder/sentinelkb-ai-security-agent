"""State-conditioned action scoring and explicit efficiency counts, offline only."""

from dataclasses import dataclass
from .contracts import MetricCount, OracleCase
from .replay import ReplayResult
from .evaluator import matched_fact_keys
from evidence_investigation.state.content import content_hash


@dataclass(frozen=True)
class BehaviorReport:
    metrics: dict[str, MetricCount]
    actions: tuple[dict, ...]
    measurement: dict


def _ratio(n, d):
    return MetricCount(n, d, n / d if d else None)


def _matches(constraints, actual):
    if isinstance(constraints, dict):
        return isinstance(actual, dict) and all(
            key in actual and _matches(value, actual[key]) for key, value in constraints.items())
    return type(constraints) is type(actual) and constraints == actual


def score_behavior(replay: ReplayResult, oracle: OracleCase) -> BehaviorReport:
    """Score annotated decisions; automatic retries are attempts, not decisions.

    Unnecessary-call detection is a conservative lower bound: repeated identical
    requests or a repeated permanently unavailable query. No information-gain
    label is invented from an empty response. Costs are run-level measurements;
    aggregation/quantiles can use the returned raw measurements later.
    """
    outcomes = {e.payload["call_id"]: e.payload for e in replay.events
                if e.event_type == "tool_returned"}
    observed = set()
    for fact in replay.facts.values():
        if not fact.call_ids:
            observed.update(matched_fact_keys(fact, oracle))
    seen, unavailable = set(), set()
    signatures = {}
    actions = []
    annotated = correct = decisions = successful = complete = unnecessary = 0
    attempts = 0
    for event in replay.events:
        body = event.payload
        if event.event_type == "tool_requested":
            attempts += 1
            cid = body["call_id"]
            outcome = outcomes[cid]
            signature = content_hash({"tool": body["tool"], "arguments": body["arguments"],
                                      "snapshot": replay.manifest.tool_snapshot})
            signatures[cid] = signature
            retry = outcome.get("retry_of") is not None
            redundant = not retry and signature in seen
            unnecessary += int(redundant or signature in unavailable)
            applicable = [a for a in oracle.expected_actions
                          if set(a.when_observed_fact_keys) <= observed
                          and not (set(a.when_missing_fact_keys) & observed)]
            acceptable = any(body["tool"] in a.acceptable_tools and
                             _matches(a.argument_constraints, body["arguments"])
                             for a in applicable)
            if not retry:
                decisions += 1
                annotated += bool(applicable)
                correct += bool(applicable) and acceptable
            actions.append({"call_id": cid, "observed_before": sorted(observed),
                            "automatic_retry": retry, "annotated": bool(applicable),
                            "acceptable": acceptable if applicable and not retry else None,
                            "known_redundant": redundant or signature in unavailable})
        elif event.event_type == "tool_returned":
            cid = body["call_id"]
            result = body["result"]
            if result is not None and not body.get("protocol_error_code") and not body.get("late"):
                successful += result["status"] in {"ok", "empty", "partial"}
                complete += (result["status"] in {"ok", "empty"}
                             and result["coverage"]["completeness"] == "complete"
                             and not result["coverage"]["truncated"]
                             and not result["coverage"]["missing_sources"])
                if result["status"] == "unavailable" and not result["retryable"]:
                    unavailable.add(signatures[cid])
                if (result["status"] in {"ok", "empty"}
                        and result["coverage"]["completeness"] == "complete"
                        and not result["coverage"]["truncated"]
                        and not result["coverage"]["missing_sources"]):
                    seen.add(signatures[cid])
            for fact in replay.facts.values():
                if cid in fact.call_ids:
                    observed.update(matched_fact_keys(fact, oracle))
    reconciliations = [e.payload for e in replay.events if e.event_type == "budget_reconciled"]
    unknown = sum(p.get("actual_usage") is None or not p["actual_usage"].get("usage_complete", False)
                  for p in reconciliations)
    usage = replay.usage
    measurement = {
        "tool_attempts": usage.tool_attempts, "backend_calls": usage.backend_calls,
        "cache_hits": usage.cache_hits, "steps": usage.steps, "model_calls": usage.model_calls,
        "tool_cost_units": usage.tool_cost_units, "elapsed_ms": usage.elapsed_ms,
        "simulated_tool_latency_ms": usage.simulated_tool_latency_ms,
        "measured_input_tokens": usage.input_tokens if usage.usage_complete else None,
        "measured_output_tokens": usage.output_tokens if usage.usage_complete else None,
        "usage_complete": usage.usage_complete, "unknown_usage_attempts": unknown,
        "input_estimates": [p["estimated_input_tokens"] for p in reconciliations],
        "output_reservations": [p["reserved_output_tokens"] for p in reconciliations],
        "model_cost": usage.model_cost, "currency": usage.currency,
        "cost_comparison_eligible": usage.usage_complete and unknown == 0 and len(reconciliations) == usage.model_calls,
    }
    metrics = {"tool_selection_accuracy": _ratio(correct, annotated),
               "action_annotation_coverage": _ratio(annotated, decisions),
               "tool_call_success_rate": _ratio(successful, attempts),
               "complete_result_rate": _ratio(complete, attempts),
               "known_unnecessary_tool_call_rate": _ratio(unnecessary, attempts)}
    return BehaviorReport(metrics, tuple(actions), measurement)
