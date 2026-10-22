"""Deterministic M7 candidate generation and frozen priority policy."""

from __future__ import annotations

from datetime import timedelta

from evidence_investigation.state.contracts import (
    Alert, AssetQuery, CandidateAction, HistoryQuery, InvestigationPlan,
    Hypothesis, ObservationPrediction, SIEMQuery, TimeWindow, ToolAction, ToolCall,
)

from .sufficiency import AcquiredResult, SufficiencyEvaluation


_ORDER = {"process": 0, "asset": 1, "network": 2, "history": 3}


def _priority(discrimination, critical_gap, counterevidence, availability,
              normalized_cost, redundancy=0.0):
    return (3 * discrimination + 2 * critical_gap + counterevidence + availability
            - normalized_cost - redundancy)


def _candidate(name, call, gap, rationale, *, discrimination=2, critical_gap=2,
               counterevidence=2, availability=1, cost=2 / 3,
               malicious_ids=(), benign_ids=()):
    observations = {
        "process": ("Grounded unauthorized behavior in the current process instance.",
                    "Execution fields and behavior match a concrete approved task."),
        "asset": ("Complete approval coverage has no matching operation.",
                  "A complete approval record matches host, account, time, job, script and parameters."),
        "network": ("Same-instance effects include an unauthorized destination or attack-linked transfer.",
                    "Complete same-instance effects remain inside the approved destination scope."),
        "history": ("Complete history contradicts the claimed authorization or establishes a material new behavior.",
                    "Complete history supplies an equivalent matching approval record."),
    }[name]
    outcomes = (
        ObservationPrediction(observations[0], tuple(malicious_ids), tuple(benign_ids),
                              "May satisfy or strengthen a TP gate."),
        ObservationPrediction(observations[1], tuple(benign_ids), tuple(malicious_ids),
                              "May satisfy or strengthen an FP gate."),
        ObservationPrediction("Partial or unavailable coverage leaves the gate unknown.",
                              (), (), "Cannot close the decision gap."),
    )
    return CandidateAction(
        f"query:{name}", call, (gap,), outcomes, discrimination, critical_gap,
        counterevidence, availability, cost, 0.0,
        _priority(discrimination, critical_gap, counterevidence, availability, cost),
        rationale,
    )


class DeterministicPlanner:
    """Finite family policy; it does not inspect fixture or oracle contents."""

    def plan(self, alert: Alert, ledger: tuple[AcquiredResult, ...],
             evaluation: SufficiencyEvaluation,
             hypotheses: tuple[Hypothesis, ...] = ()) -> InvestigationPlan:
        if evaluation.result.sufficient_for is not None:
            return InvestigationPlan("finalize", None, (), "No decision uncertainty remains.",
                                     "All deterministic gates for a verdict are met.")
        malicious_ids = tuple(item.hypothesis_id for item in hypotheses if item.kind == "malicious")
        benign_ids = tuple(item.hypothesis_id for item in hypotheses if item.kind == "benign")
        def attempted(call):
            return any(item.call == call for item in ledger)
        process_payloads = [record.payload for item in ledger
                            if item.result.tool == "siem"
                            and getattr(item.call.arguments, "view", None) == "process_tree"
                            for record in item.result.records]
        observations = [value for payload in process_payloads
                        if isinstance(payload.get("script_observations"), list)
                        for value in payload["script_observations"]]
        malicious_signal = any(
            isinstance(value, dict) and (
                value.get("authorized") is False or value.get("operation") == "send")
            for value in observations
        )
        operation_signal = any(payload.get("job_id") or payload.get("script_hash")
                               for payload in process_payloads)
        window = TimeWindow(alert.as_of - timedelta(minutes=10), alert.as_of)
        history_window = TimeWindow(alert.as_of - timedelta(days=1), alert.as_of)
        process_call = ToolCall("siem", SIEMQuery(
            "process_tree", window, host=alert.host,
            process_id=alert.process_id, limit=50)) if alert.host else None
        asset_call = ToolCall("asset", AssetQuery(alert.host, alert.as_of)) if alert.host else None
        network_call = ToolCall("siem", SIEMQuery(
            "network_events", window, host=alert.host,
            process_id=alert.process_id, limit=50)) if alert.host else None
        history_call = ToolCall("history", HistoryQuery(
            "host", alert.host, history_window, host=alert.host,
            user=alert.user, limit=50)) if alert.host else None
        process_attempted = bool(process_call and attempted(process_call))
        candidates = []
        if process_call is not None and not attempted(process_call):
            candidates.append(_candidate(
                "process", process_call,
                "current_process_behavior",
                "Resolve actual execution content and stable process identity.",
                availability=2,
                malicious_ids=malicious_ids, benign_ids=benign_ids,
            ))
        if asset_call is not None and not attempted(asset_call):
            candidates.append(_candidate(
                "asset", asset_call,
                "approval_coverage", "Test the strongest concrete authorized-operation explanation.",
                discrimination=2 if process_attempted else 1,
                critical_gap=2 if process_attempted else 1,
                counterevidence=2 if process_attempted else 1,
                availability=2 if operation_signal or process_attempted and not malicious_signal else 1,
                cost=1 / 3,
                malicious_ids=malicious_ids, benign_ids=benign_ids,
            ))
        if network_call is not None and not attempted(network_call):
            candidates.append(_candidate(
                "network", network_call,
                "current_network_effects", "Resolve same-instance effects and approved target scope.",
                discrimination=2 if process_attempted else 1,
                critical_gap=2 if process_attempted else 1,
                counterevidence=2 if malicious_signal else 1,
                availability=2 if malicious_signal else 1,
                malicious_ids=malicious_ids, benign_ids=benign_ids,
            ))
        core_attempted = all(call is not None and attempted(call)
                             for call in (process_call, asset_call, network_call))
        if core_attempted and history_call is not None and not attempted(history_call):
            candidates.append(_candidate(
                "history", history_call,
                "approval_history", "Seek an independent approval-history path after core checks did not close the case.",
                critical_gap=1,
                malicious_ids=malicious_ids, benign_ids=benign_ids,
            ))
        candidates.sort(key=lambda item: (-item.priority, _ORDER[item.action_id.split(":", 1)[1]]))
        candidates = tuple(candidates[:3])
        if not candidates:
            return InvestigationPlan(
                "finalize", None, (), "Remaining uncertainty cannot be reduced by this versioned action catalog.",
                "All legal useful family actions were attempted, unavailable, or redundant.",
            )
        return InvestigationPlan(
            "query", candidates[0].action_id, candidates,
            evaluation.result.missing_gap_ids[0] if evaluation.result.missing_gap_ids
            else "Competing explanations remain unresolved.",
            "Selected the highest frozen priority; unselected candidates remain recorded for audit.",
        )


def selected_tool_action(plan: InvestigationPlan) -> ToolAction:
    """Narrow Proposed internal planning state to the shared public action."""
    if plan.action != "query" or plan.selected_action_id is None:
        raise ValueError("plan does not select a tool")
    selected = next((item for item in plan.candidates
                     if item.action_id == plan.selected_action_id), None)
    if selected is None:
        raise ValueError("selected action is not present in candidates")
    return ToolAction("tool", selected.call.tool, selected.call.arguments)
