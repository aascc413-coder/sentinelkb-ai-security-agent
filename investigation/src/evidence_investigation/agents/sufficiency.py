"""Deterministic powershell-v1 gate and risk-pattern evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from evidence_investigation.runtime.registry import EvidenceRegistry, canonical_hash
from evidence_investigation.state.content import content_hash
from evidence_investigation.state.contracts import (
    Alert, CriterionCheck, SufficiencyResult, ToolCall, ToolResult,
)
from evidence_investigation.state.rubric import FamilyRubric
from evidence_investigation.state.errors import ProtocolViolation


@dataclass(frozen=True)
class AcquiredResult:
    call: ToolCall
    result: ToolResult
    evidence_ids: tuple[str, ...]
    operational_ids: tuple[str, ...]


@dataclass(frozen=True)
class SufficiencyEvaluation:
    result: SufficiencyResult
    risk_flags: tuple[str, ...]
    risk_evidence_ids: tuple[str, ...]


def _complete(result: ToolResult | None) -> bool:
    return bool(result and result.status in {"ok", "empty"}
                and result.coverage.completeness == "complete"
                and not result.coverage.truncated and not result.coverage.missing_sources)


def _items(ledger, tool, view=None):
    values = []
    for acquired in ledger:
        if acquired.result.tool != tool:
            continue
        if view is not None and getattr(acquired.call.arguments, "view", None) != view:
            continue
        values.append(acquired)
    return values


def _latest(ledger, tool, view=None):
    values = _items(ledger, tool, view)
    return values[-1] if values else None


def _records(acquired):
    return () if acquired is None else acquired.result.records


def _evidence_id(registry, tool, payload):
    key = f"{tool}:{canonical_hash(payload)}"
    for evidence in registry.facts():
        if evidence.fact_key == key:
            return evidence.evidence_id
    return None


def _record_views(registry, acquired):
    values = []
    seen = set()
    for record in _records(acquired):
        evidence_id = _evidence_id(registry, acquired.result.tool, record.payload)
        key = evidence_id or (acquired.result.tool, canonical_hash(record.payload))
        if key in seen:
            continue
        seen.add(key)
        values.append((record.payload, evidence_id, record))
    return tuple(values)


def _network_destinations(rows):
    destinations = set()
    for payload, _, _ in rows:
        value = payload.get("destination_ip")
        if isinstance(value, str) and value:
            destinations.add(value)
        for field in ("observed_destinations", "destinations"):
            values = payload.get(field)
            if isinstance(values, list):
                destinations.update(item for item in values
                                    if isinstance(item, str) and item)
    return destinations


def _observation_signatures(values):
    """Compare structured behavior as an order-independent closed set.

    Source records may describe operations with JSON objects.  The approval
    record must repeat the complete expected operation objects; unknown or
    malformed values fail closed instead of being coerced to strings.
    """
    if not isinstance(values, list) or not all(isinstance(item, (str, dict)) for item in values):
        return None
    return tuple(sorted(canonical_hash(item) for item in values))


def _has_direct_attack_behavior(observations, network_destinations):
    """Recognize a small frozen vocabulary of directly observed harmful effects."""
    structured = [item for item in observations if isinstance(item, dict)]
    sensitive_objects = {
        "credential-store", "browser-credential-store", "private-key-store",
        "security-account-manager", "lsass-memory",
    }
    reads = [item for item in structured
             if item.get("operation") in {"read", "dump", "export"}
             and item.get("object") in sensitive_objects
             and item.get("authorized") is False]
    outbound = [item for item in structured
                if item.get("operation") in {"send", "upload"}
                and isinstance(item.get("destination"), str)
                and item.get("destination") in network_destinations]
    exfiltration = any(
        (isinstance(read.get("produces"), str) and bool(read["produces"])
         and sent.get("object") == read["produces"])
        or (read.get("object") == "credential-store"
            and sent.get("object") == "credential-bytes")
        for read in reads for sent in outbound
    )
    destructive = any(
        item.get("operation") in {"encrypt", "delete"}
        and item.get("authorized") is False
        and isinstance(item.get("affected_count"), int)
        and not isinstance(item.get("affected_count"), bool)
        and item["affected_count"] >= 10
        for item in structured
    )
    return exfiltration or destructive


def _behavior_matches_approval(observations, matching_job):
    if not observations or not isinstance(matching_job, dict):
        return False
    expected = matching_job.get("expected_observations")
    if expected is None:
        return tuple(observations) == (
            "read approved backup source", "validate backup checksum",
            "write approved backup destination",
        )
    observed_signatures = _observation_signatures(observations)
    expected_signatures = _observation_signatures(expected)
    return bool(observed_signatures and expected_signatures
                and observed_signatures == expected_signatures)


def _dt(value):
    try:
        parsed = datetime.fromisoformat(value) if isinstance(value, str) else None
        return parsed if parsed is not None and parsed.utcoffset() is not None else None
    except (ValueError, OverflowError):
        return None


def _check(cid, outcome, ids=(), reason=""):
    return CriterionCheck(cid, outcome, tuple(dict.fromkeys(x for x in ids if x)), reason)


def _approval(process_payload, asset_payload, occurred_at, *, coverage_complete):
    if not coverage_complete:
        return "unknown", None, ()
    if not process_payload or not process_payload.get("host") or not process_payload.get("user"):
        return "unknown", None, ()
    if not asset_payload or asset_payload.get("approval_register_complete") is not True:
        return "unknown", None, ()
    register_window = asset_payload.get("approval_register_window")
    if not isinstance(register_window, dict):
        return "unknown", None, ()
    start, end = _dt(register_window.get("start")), _dt(register_window.get("end"))
    if not start or not end or not start <= occurred_at < end:
        return "unknown", None, ()
    jobs = asset_payload.get("approved_jobs")
    if not isinstance(jobs, list):
        return "unknown", None, ()
    if not jobs:
        return "none", None, ()
    actual_parameters = process_payload.get("parameters")
    actual = (
        process_payload.get("host"), process_payload.get("user"),
        process_payload.get("job_id"), process_payload.get("script_hash"),
        tuple(actual_parameters) if isinstance(actual_parameters, list) else None,
    )
    actual_complete = (all(actual[:4]) and isinstance(actual_parameters, list)
                       and all(isinstance(item, str) for item in actual_parameters))
    mismatches = []
    malformed = False
    comparable = False
    for job in jobs:
        if not isinstance(job, dict):
            malformed = True
            continue
        window = job.get("window")
        jstart = _dt(window.get("start")) if isinstance(window, dict) else None
        jend = _dt(window.get("end")) if isinstance(window, dict) else None
        parameters = job.get("parameters")
        expected = (job.get("host"), job.get("user"), job.get("job_id"),
                    job.get("script_hash"),
                    tuple(parameters) if isinstance(parameters, list) else None)
        expected_complete = (all(expected[:4]) and isinstance(parameters, list)
                             and all(isinstance(item, str) for item in parameters)
                             and jstart is not None and jend is not None)
        if not expected_complete:
            malformed = True
            continue
        if actual_complete and actual == expected and jstart <= occurred_at < jend:
            return "match", job, ()
        if actual_complete and job.get("host") == actual[0] and job.get("user") == actual[1] and jstart and jend \
                and jstart <= occurred_at < jend:
            comparable = True
            names = ("host", "user", "job_id", "script_hash", "parameters")
            mismatches.extend(name for name, left, right in zip(names, actual, expected) if left != right)
    if mismatches and comparable:
        return "mismatch", None, tuple(dict.fromkeys(mismatches))
    return ("unknown" if malformed or not actual_complete else "none"), None, ()


def evaluate_sufficiency(alert: Alert, registry: EvidenceRegistry,
                         ledger: tuple[AcquiredResult, ...], rubric: FamilyRubric) -> SufficiencyEvaluation:
    process_acq = _latest(ledger, "siem", "process_tree")
    network_acq = _latest(ledger, "siem", "network_events")
    asset_acq = _latest(ledger, "asset")
    history_acq = _latest(ledger, "history")
    process_rows = _record_views(registry, process_acq) if process_acq else ()
    network_rows = _record_views(registry, network_acq) if network_acq else ()
    asset_rows = _record_views(registry, asset_acq) if asset_acq else ()
    history_rows = _record_views(registry, history_acq) if history_acq else ()
    process = process_rows[0] if process_rows else (None, None, None)
    network = network_rows[0] if network_rows else (None, None, None)
    asset = asset_rows[0] if asset_rows else (None, None, None)
    pp, peid, prec = process
    np, neid, nrec = network
    network_scope_ids = tuple(dict.fromkeys(
        (neid, *(network_acq.operational_ids if network_acq else ()))
    ))
    approval_entries = [(payload, evidence_id, record, asset_acq)
                        for payload, evidence_id, record in asset_rows]
    approval_entries.extend(
        ({**payload, "approval_register_window": payload["register_window"]},
         evidence_id, record, history_acq)
        for payload, evidence_id, record in history_rows
        if payload.get("approval_register_complete") is True
        and isinstance(payload.get("register_window"), dict)
    )
    complete_approvals = [entry for entry in approval_entries
                          if entry[3] is not None and _complete(entry[3].result)]
    ap = complete_approvals[0][0] if complete_approvals else None
    approval_ids = tuple(entry[1] for entry in complete_approvals if entry[1])
    approval_records = tuple(entry[2] for entry in complete_approvals)
    approval_complete = bool(complete_approvals)
    alert_ids = tuple(e.evidence_id for e in registry.facts() if e.source.kind == "alert")

    alert_grounded = content_hash(alert.raw) == alert.raw_reference.content_sha256
    provenance_ok = alert_grounded
    for acquired in ledger:
        for record in acquired.result.records:
            provenance_ok &= canonical_hash(record.payload) == record.content_sha256
            mapped = _evidence_id(registry, acquired.result.tool, record.payload)
            provenance_ok &= mapped is not None
            if mapped is not None:
                fact = registry.get(mapped)
                provenance_ok &= acquired.result.call_id in registry.source_call_ids(fact.fact_key)
        for eid in acquired.evidence_ids + acquired.operational_ids:
            try:
                fact = registry.get(eid)
            except ProtocolViolation:
                provenance_ok = False
            else:
                provenance_ok &= acquired.result.call_id in registry.source_call_ids(fact.fact_key)
        if not acquired.result.records and acquired.result.status in {
            "empty", "partial", "unavailable", "timeout", "error"
        }:
            provenance_ok &= bool(acquired.operational_ids)
    g0_ids = alert_ids + tuple(eid for acquired in ledger for eid in acquired.evidence_ids)
    g0 = _check("G0", "met" if provenance_ok else "unmet", g0_ids,
                "All used facts retain validated alert/tool provenance." if provenance_ok
                else "At least one used source reference failed deterministic provenance checks.")

    same_instance = False
    known_conflict = False
    process_payloads = [row[0] for row in process_rows]
    if process_payloads:
        pg = pp.get("process_guid")
        process_consistent = bool(pg and all(
            item.get("process_guid") == pg
            and item.get("host") == pp.get("host") == alert.host
            and item.get("process_id") == pp.get("process_id") == alert.process_id
            for item in process_payloads
        ))
        comparisons = [row[0] for row in network_rows]
        network_consistent = bool(comparisons) and all(
            item.get("process_guid") == pg
            and pp.get("host") == item.get("host") == alert.host
            and pp.get("process_id") == item.get("process_id") == alert.process_id
            for item in comparisons
        )
        complete_empty_network = bool(
            network_acq and not network_rows and _complete(network_acq.result)
        )
        same_instance = process_consistent and (network_consistent or complete_empty_network)
        known_conflict = any(
            (item.get("process_guid") and pg and item.get("process_guid") != pg)
            or (item.get("host") and item.get("host") != pp.get("host"))
            or (item.get("process_id") and item.get("process_id") != pp.get("process_id"))
            for item in process_payloads
        ) or any(
            (item.get("process_guid") and pg and item.get("process_guid") != pg)
            or (item.get("host") and item.get("host") != pp.get("host"))
            or (item.get("process_id") and item.get("process_id") != pp.get("process_id"))
            for item in comparisons
        )
    activity_start = alert.as_of - timedelta(minutes=10)
    process_times = [_dt(row[0].get("occurred_at")) for row in process_rows]
    network_times = [_dt(row[0].get("occurred_at")) for row in network_rows]
    times_ok = bool(process_rows
                    and all(value and activity_start <= value < alert.as_of
                            for value in process_times)
                    and (all(value and activity_start <= value < alert.as_of
                             for value in network_times) if network_rows
                         else network_acq and _complete(network_acq.result)))
    g1_out = "met" if same_instance and times_ok else "unmet" if known_conflict else "unknown"
    g1 = _check("G1", g1_out, (peid, *network_scope_ids),
                "Process and network observations share a stable instance and valid timestamps."
                if g1_out == "met" else "Current behavior lacks a verified same-instance correlation chain.")

    process_time = _dt(pp.get("occurred_at")) if pp else None
    approval_checks = [
        _approval(pp or {}, payload, process_time or alert.occurred_at,
                  coverage_complete=True)
        for payload, _, _, _ in complete_approvals
    ]
    states = {item[0] for item in approval_checks}
    matches = [item[1] for item in approval_checks if item[0] == "match"]
    mismatch_fields = tuple(dict.fromkeys(
        field for item in approval_checks for field in item[2]))
    matching_job = matches[0] if matches else None
    match_scopes = set()
    invalid_match_scope = False
    for job in matches:
        destinations = job.get("allowed_destinations") if isinstance(job, dict) else None
        if not isinstance(destinations, list) or not all(isinstance(x, str) for x in destinations):
            invalid_match_scope = True
        else:
            match_scopes.add(tuple(sorted(destinations)))
    if not approval_checks:
        approval_state = "unknown"
    elif ("unknown" in states or ("match" in states and len(states) > 1)
          or len(match_scopes) > 1 or invalid_match_scope):
        approval_state = "conflict"
        matching_job = None
    elif "match" in states:
        approval_state = "match"
    elif "mismatch" in states:
        approval_state = "mismatch"
    elif states == {"none"}:
        approval_state = "none"
    else:
        approval_state = "unknown"
    observation_fields = [row[0].get("script_observations") for row in process_rows]
    observations = [item for value in observation_fields if isinstance(value, list)
                    for item in value]
    observations_known = bool(observation_fields) and all(
        isinstance(value, list) for value in observation_fields)
    malicious_chain = bool(
        observations_known and same_instance
        and _has_direct_attack_behavior(observations, _network_destinations(network_rows))
    )
    g2_out = "met" if malicious_chain and approval_state in {"none", "mismatch"} else \
        "unmet" if approval_state == "match" else "unknown"
    g2 = _check("G2", g2_out, (peid, *network_scope_ids, *approval_ids),
                "Grounded same-instance observations establish a recognized unauthorized harmful effect."
                if g2_out == "met" else "No verified unauthorized malicious behavior chain is available.")

    g3_out = "met" if approval_state in {"none", "mismatch"} else \
        "unmet" if approval_state == "match" else "unknown"
    g3 = _check("G3", g3_out, (peid, *approval_ids),
                "Complete approval coverage tests and rejects the concrete benign explanation."
                if g3_out == "met" else "The strongest benign explanation is matching or not completely testable.")

    coverage_ok = bool(process_acq and _complete(process_acq.result)
                       and network_acq and _complete(network_acq.result)
                       and approval_complete)
    quality_ok = all(row[2] is not None and row[2].reliability.level in {"high", "medium"}
                     for row in process_rows + network_rows) and all(
                         record.reliability.level in {"high", "medium"}
                         for record in approval_records) and bool(
                             process_rows and approval_records)
    g4_out = "met" if coverage_ok and quality_ok else "unknown"
    g4 = _check("G4", g4_out, (peid, *network_scope_ids, *approval_ids),
                "Material process, network and approval scopes have complete reliable coverage."
                if g4_out == "met" else "At least one material behavior or approval scope is incomplete.")

    b1_out = "met" if approval_state == "match" else \
        "unmet" if approval_state in {"none", "mismatch"} else "unknown"
    b1 = _check("B1", b1_out, (peid, *approval_ids),
                "Actual host, account, time, job, script and parameters match an approved operation."
                if b1_out == "met" else "No fully matching approved operation was verified.")

    behavior_match = bool(
        observations_known and _behavior_matches_approval(observations, matching_job)
    )
    destinations = _network_destinations(network_rows)
    allowed_values = matching_job.get("allowed_destinations") if matching_job else None
    allowed = (set(allowed_values) if isinstance(allowed_values, list)
               and all(isinstance(item, str) for item in allowed_values) else None)
    network_complete = bool(
        network_acq and _complete(network_acq.result)
        and (not network_rows or all(
            row[0].get("all_connections_captured") is True for row in network_rows
        ))
    )
    b2_met = (b1_out == "met" and behavior_match and same_instance and network_complete
              and allowed is not None and destinations <= allowed)
    b2_known_bad = b1_out == "unmet" or (b1_out == "met" and (
        observations_known and not behavior_match
        or network_complete and allowed is not None and not destinations <= allowed))
    b2 = _check("B2", "met" if b2_met else "unmet" if b2_known_bad else "unknown",
                (peid, *network_scope_ids, *approval_ids),
                "Observed behavior and same-instance effects stay inside the approved backup scope."
                if b2_met else "Current behavior is outside the approved scope or remains unverified.")

    b3_met = b1_out == "met" and b2_met and g2_out != "met" and coverage_ok
    b3_bad = g2_out == "met" or b2_known_bad
    b3 = _check("B3", "met" if b3_met else "unmet" if b3_bad else "unknown",
                (peid, *network_scope_ids, *approval_ids),
                "Complete alert-scoped checks found no unresolved malicious counterevidence."
                if b3_met else "Material risk counterevidence exists or the checked scope is incomplete.")

    tp_checks = (g0, g1, g2, g3, g4)
    fp_checks = (g0, g1, b1, b2, b3)
    tp_met = all(x.outcome == "met" for x in tp_checks)
    fp_met = all(x.outcome == "met" for x in fp_checks)
    sufficient = "TP" if tp_met and not fp_met else "FP" if fp_met and not tp_met else None
    conflict = tp_met and fp_met
    risk_flags = ()
    risk_ids = ()
    if approval_state == "mismatch" and mismatch_fields and pp and ap \
            and pp.get("host") == ap.get("host") == alert.host and pp.get("user") == alert.user:
        risk_flags = ("approval_execution_mismatch",)
        risk_ids = tuple(x for x in (peid, *approval_ids) if x)

    missing = []
    if process_acq is None or not _complete(process_acq.result): missing.append("current_process_behavior")
    if network_acq is None or not _complete(network_acq.result): missing.append("current_network_effects")
    if not approval_complete: missing.append("approval_coverage")
    if risk_flags and not _items(ledger, "history"): missing.append("approval_history")
    discriminating = tuple(dict.fromkeys(
        (eid for check in (tp_checks if sufficient == "TP" else fp_checks if sufficient == "FP" else ())
         for eid in check.evidence_ids)
    )) or risk_ids
    unresolved = (("Both TP and FP gate groups are met.",) if conflict else
                  (() if sufficient else ("Malicious and benign explanations remain unresolved.",)))
    return SufficiencyEvaluation(SufficiencyResult(
        rubric.rubric_version, tp_checks, fp_checks, sufficient,
        unresolved, discriminating, tuple(missing), provenance_ok,
    ), risk_flags, risk_ids)
