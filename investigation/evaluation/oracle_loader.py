"""Offline-only oracle loading; no imports from tool/environment implementations."""

from datetime import datetime, timedelta
from pathlib import Path
from typing import get_type_hints

from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.content import load_json, require_text, validate_document
from evidence_investigation.state.contracts import (
    AssetQuery, AttackQuery, HistoryQuery, SIEMQuery, TIQuery,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.validation import (
    require_known_references, require_time_window, require_unique, require_utc,
)

from .contracts import OracleCase

_QUERY_TYPES = {"siem": SIEMQuery, "threat_intel": TIQuery, "asset": AssetQuery,
                "history": HistoryQuery, "attack": AttackQuery}


def _validate_action_constraints(action) -> None:
    """Partial constraints must be valid together for at least one named tool.

    Missing fields are allowed because these are match predicates, not complete
    tool calls. A union of unrelated fields cannot manufacture an impossible
    cross-tool action. This uses public Query contracts only, never tool code.
    """
    failures = []
    for tool in action.acceptable_tools:
        try:
            hints = get_type_hints(_QUERY_TYPES[tool])
            if set(action.argument_constraints) - set(hints):
                raise ProtocolViolation("unknown_constraint", "Constraint does not belong to query type")
            for name, value in action.argument_constraints.items():
                decoded = decode(hints[name], value)
                if name == "window":
                    require_time_window(decoded, "expected_action.window")
                    maximum = timedelta(hours=24) if tool == "siem" else timedelta(days=30)
                    if decoded.end - decoded.start > maximum:
                        raise ProtocolViolation("window_too_wide", "Expected action exceeds allowed window")
                elif name == "as_of":
                    require_utc(decoded, "expected_action.as_of")
                elif name == "limit" and not 1 <= decoded <= 50:
                    raise ProtocolViolation("invalid_limit", "Expected action limit must be in 1..50")
                elif isinstance(decoded, str):
                    require_text(decoded, "expected_action." + name)
                elif isinstance(decoded, tuple):
                    for item in decoded:
                        require_text(item, "expected_action." + name)
            return
        except ProtocolViolation as exc:
            failures.append(tool + ": " + exc.code)
    raise ProtocolViolation("invalid_action_constraints",
                            "No acceptable tool supports these constraints: " + "; ".join(failures))


def validate_oracle(case: OracleCase) -> OracleCase:
    validate_document(OracleCase, encode(case))
    if decode(OracleCase, encode(case)) != case:
        raise ProtocolViolation("invalid_dataset_structure", "OracleCase must use typed contract fields")
    for name in ("case_id", "family_id", "rubric_version", "annotation_rationale"):
        require_text(getattr(case, name), "oracle." + name)
    world = set(case.complete_world_evidence)
    for key in world:
        require_text(key, "world fact key")
    for name in ("observable_fact_keys", "critical_fact_keys", "distractor_fact_keys"):
        keys = getattr(case, name)
        require_unique(keys, name)
        require_known_references(keys, world, name)
    observable = set(case.observable_fact_keys)
    if set(case.critical_fact_keys) & set(case.distractor_fact_keys):
        raise ProtocolViolation("conflicting_annotation", "Critical facts cannot also be distractors")
    if set(case.distractor_fact_keys) - observable:
        raise ProtocolViolation("unobservable_distractor", "Distractor facts must be observable")
    if set(case.sufficient_sets) - {"TP", "FP"}:
        raise ProtocolViolation("invalid_sufficient_verdict", "Only TP/FP can have sufficient sets")
    for verdict, combinations in case.sufficient_sets.items():
        seen = set()
        for combination in combinations:
            if not combination:
                raise ProtocolViolation("empty_sufficient_set", "No-evidence sufficient combination is invalid")
            require_unique(combination, "sufficient combination")
            require_known_references(combination, observable, "sufficient combination")
            normalized = frozenset(combination)
            if normalized in seen:
                raise ProtocolViolation("duplicate_sufficient_set", "Duplicate sufficient combination")
            seen.add(normalized)
    require_unique(case.acceptable_verdicts, "acceptable_verdicts")
    if not case.acceptable_verdicts:
        raise ProtocolViolation("empty_verdicts", "Oracle must declare acceptable verdicts")
    correct = "TP" if case.ground_truth == "malicious" else "FP"
    wrong = "FP" if correct == "TP" else "TP"
    if wrong in case.acceptable_verdicts or case.sufficient_sets.get(wrong):
        raise ProtocolViolation("truth_mismatch", "Determinate verdict contradicts world truth")
    has_sufficient = bool(case.sufficient_sets.get(correct))
    if case.resolvable_with_full_observable_evidence != has_sufficient:
        raise ProtocolViolation("resolvability_mismatch", "Resolvability must agree with observable sufficient sets")
    if (correct in case.acceptable_verdicts) != has_sufficient:
        raise ProtocolViolation("acceptable_verdict_mismatch", "Determinate accepted verdict needs a sufficient set")
    for action in case.expected_actions:
        require_unique(action.when_observed_fact_keys, "action observed facts")
        require_unique(action.when_missing_fact_keys, "action missing facts")
        require_known_references(action.when_observed_fact_keys, observable, "action observed facts")
        require_known_references(action.when_missing_fact_keys, world, "action missing facts")
        if set(action.when_observed_fact_keys) & set(action.when_missing_fact_keys):
            raise ProtocolViolation("contradictory_action", "Fact cannot be both observed and missing")
        require_unique(action.acceptable_tools, "acceptable_tools")
        if not action.acceptable_tools:
            raise ProtocolViolation("empty_action_tools", "Expected action must declare an acceptable tool")
        require_text(action.evidence_goal, "evidence_goal")
        _validate_action_constraints(action)
    return case


def load_oracle(path: str | Path) -> OracleCase:
    document = load_json(path)
    validate_document(OracleCase, document)
    return validate_oracle(decode(OracleCase, document))
