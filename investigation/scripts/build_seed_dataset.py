"""Authoring-only deterministic synthetic data builder; never imported by agents.

Writes the reviewed five-case specification. It contains oracle annotations and
belongs outside src/. Runtime loaders never execute this authoring program.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "datasets"
ASOF = "2026-09-01T02:20:00+00:00"
OCCURRED = "2026-09-01T02:14:00+00:00"
PUBLISHED = "2026-09-01T02:19:00+00:00"
WINDOW = {"start": "2026-09-01T02:10:00+00:00", "end": ASOF}
HISTORY_WINDOW = {"start": "2026-08-31T02:20:00+00:00", "end": ASOF}
TOOLS = ("siem", "threat_intel", "asset", "history", "attack")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def identifier(slot):
    return hashlib.sha256(("frozen-seed-2026-v1/" + slot).encode()).hexdigest()[:32]


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def build(case_index, host, user, process, *, paired=False):
    seed = "shared" if paired else str(case_index)
    raw = {"rule_name": "Suspicious PowerShell execution", "process_name": "powershell.exe",
           "detector_claim": "possible encoded execution", "command_body_retained": False,
           "host": host, "user": user, "process_id": process, "occurred_at": OCCURRED}
    alert = {"alert_id": identifier(seed + "/alert"), "alert_type": "powershell_execution",
             "occurred_at": OCCURRED, "as_of": ASOF, "host": host, "user": user,
             "process_id": process, "command_line": None if paired else "powershell.exe -EncodedCommand [body not retained]",
             "raw": raw, "raw_reference": {"record_id": identifier(seed + "/alert-record"),
                                           "json_pointer": "", "content_sha256": digest(raw)}}
    env = {"environment_id": identifier(seed + "/environment"), "as_of": ASOF,
           "records_by_tool": {tool: [] for tool in TOOLS}, "query_rules": [],
           "fixture_version": "synthetic-v1"}
    facts = {"E0": {"source": "alert", "record_ids": [alert["raw_reference"]["record_id"]],
                    "observation": "PowerShell detector fired; detector claim is not verified behavior"}}

    def record(tool, label, payload, source, group, fact):
        rid = identifier(seed + "/" + label)
        env["records_by_tool"][tool].append({"record_id": rid, "payload": payload,
            "content_sha256": digest(payload), "source_system": source,
            "independence_group": group, "reliability": {"level": "high",
            "basis": "Frozen synthetic source measurement, not model-generated",
            "policy_version": "source-policy-v1"}})
        facts.setdefault(fact, {"source": tool, "record_ids": [], "observation": payload})["record_ids"].append(rid)
        return rid

    def coverage(scope, window=None, complete=True, missing=()):
        return {"scope": scope, "window": window, "completeness": "complete" if complete else "partial",
                "truncated": False, "missing_sources": list(missing)}

    def rule(tool, constraints, ids, cov, status="ok", error=None):
        env["query_rules"].append({"tool": tool, "argument_constraints": constraints,
             "record_ids": ids, "status": status, "coverage": cov,
             "retryable": False, "error_code": error})

    def siem(view, extras, fact, *, partial=False, missing=(), mirror=False):
        base = {"view": view, "host": host, "user": user, "process_id": process,
                "process_guid": identifier(seed + "/instance"), "event_id": identifier(seed + "/event/" + view),
                "occurred_at": OCCURRED, "observed_at": PUBLISHED, **extras}
        source = "edr" if view == "process_tree" else "network-sensor"
        group = "edr-01" if view == "process_tree" else "network-01"
        ids = [record("siem", view, base, source, group, fact)]
        if mirror:
            ids.append(record("siem", view + "-mirror", base, "siem-edr-mirror", group, fact))
        rule("siem", {"view": view, "host": host}, ids,
             coverage({"view": view, "host": host, "user": None, "process_id": None}, WINDOW,
                      not partial, missing), "partial" if partial else "ok")
        # Different views expose the same event identities and source group.
        for other in ("host_events", "user_events"):
            copy = {**base, "view": other}
            rid = record("siem", view + "/" + other, copy, source, group, fact)
            constraints = {"view": other, "host": host} if other == "host_events" else {"view": other, "user": user}
            existing = next((r for r in env["query_rules"] if r["tool"] == "siem" and r["argument_constraints"] == constraints), None)
            if existing:
                existing["record_ids"].append(rid)
                if partial:
                    existing["status"] = "partial"
                    existing["coverage"] = coverage({"view": other, "host": host, "user": user, "process_id": None}, WINDOW, False, missing)
            else:
                rule("siem", constraints, [rid], coverage({"view": other, "host": host, "user": user, "process_id": None}, WINDOW,
                     not partial, missing), "partial" if partial else "ok")

    def asset(approval, fact, *, partial=False):
        payload = {"host": host, "published_at": PUBLISHED, "purpose": "operations" if host.startswith("OPS") else "workstation",
                   "system_type": "Windows", "critical_asset": False, "department": "synthetic-operations",
                   "approval_register_complete": not partial, "approval_register_window": WINDOW,
                   "approved_jobs": approval}
        rid = record("asset", "asset", payload, "change-register", "change-01", fact)
        rule("asset", {"host": host}, [rid], coverage({"host": host, "as_of": ASOF}, complete=not partial,
             missing=("approval_archive",) if partial else ()), "partial" if partial else "ok")

    def ti(kind, value, verdict, fact):
        payload = {"indicator_type": kind, "value": value, "published_at": PUBLISHED,
                   "reputation": verdict, "provider": "local-mock", "not_a_real_ioc_assessment": True}
        rid = record("threat_intel", "ti/" + kind + "/" + value, payload, "mock-ti", "ti-01", fact)
        rule("threat_intel", {"indicator_type": kind, "value": value}, [rid],
             coverage({"indicator_type": kind, "value": value, "as_of": ASOF}))

    def history(extras, fact, *, prior=False):
        for kind, entity in (("host", host), ("user", user)):
            payload = {"entity_type": kind, "entity": entity, "host": host, "user": user,
                       "occurred_at": "2026-08-31T12:00:00+00:00" if prior else OCCURRED,
                       "observed_at": PUBLISHED, **extras}
            rid = record("history", "history/" + kind, payload, "history-store", extras.get("source_group", "history-01"), fact)
            rule("history", {"entity_type": kind, "entity": entity}, [rid],
                 coverage({"entity_type": kind, "entity": entity, "host": host, "user": user, "command_line": None}, HISTORY_WINDOW))

    def unavailable(tool, constraints, window, reason, fact):
        rule(tool, constraints, [], coverage(constraints, window, False, (reason,)), "unavailable", reason)
        facts.setdefault(fact, {"source": tool, "record_ids": [], "operational_status": "unavailable", "reason": reason})

    def attack(fact):
        payload = {"snapshot_version": "attack-local-v1", "published_at": "2026-08-01T00:00:00+00:00",
                   "technique_id": "T1059.001", "behavior_terms": ["PowerShell"],
                   "description": "PowerShell execution can occur in authorized and unauthorized activity; mapping is not an attack verdict."}
        rid = record("attack", "attack", payload, "local-attack-knowledge", "knowledge-01", fact)
        rule("attack", {"snapshot_version": "attack-local-v1"}, [rid], coverage({"snapshot_version": "attack-local-v1"}))

    if case_index == 1:
        siem("process_tree", {"parent_process": "WINWORD.EXE", "child_process": [],
             "script_observations": [{"operation": "read", "object": "credential-store", "authorized": False},
                                     {"operation": "send", "object": "credential-bytes", "destination": "203.0.113.66"}]}, "E1", mirror=True)
        siem("network_events", {"destination_ip": "203.0.113.66", "destination_port": 443,
             "sensor_observations": ["credential-store read associated with this process instance", "credential-byte outbound transmission"]}, "E2")
        ti("ip", "203.0.113.66", "malicious", "E3")
        asset([], "E4")
        history({"approved_jobs": [], "approval_register_complete": True, "source_group": "change-01",
                 "register_window": WINDOW}, "E4")
        # Alternative acquisition of one approval fact, not extra evidence.
        facts["E4"]["source"] = "tool"
        facts["E4"]["source_tools"] = ["asset", "history"]
        # Preserve the separate low-value historic login.
        for kind, entity in (("host", host), ("user", user)):
            rid = record("history", "login/" + kind, {"entity_type": kind, "entity": entity, "host": host,
                 "user": user, "occurred_at": "2026-08-31T12:00:00+00:00", "observed_at": PUBLISHED,
                 "action": "interactive_logon", "outcome": "success"}, "auth-log", "auth-01", "E6")
            next(r for r in env["query_rules"] if r["tool"] == "history" and r["argument_constraints"]["entity_type"] == kind)["record_ids"].append(rid)
        attack("E5")
        sufficient = {"TP": [["E1", "E2", "E4"]], "FP": []}
        critical, distractor, verdicts = ["E1", "E2", "E4"], ["E5", "E6"], ["TP"]
    elif case_index == 2:
        approved = {"host": host, "user": user, "job_id": "BACKUP-42", "script_hash": "h-approved",
                    "parameters": ["backup", "validate"], "window": {"start": "2026-09-01T02:00:00+00:00", "end": "2026-09-01T03:00:00+00:00"},
                    "allowed_destinations": ["10.20.0.8"]}
        siem("process_tree", {"parent_process": "management-task.exe", "child_process": [],
             "job_id": "BACKUP-42", "script_hash": "h-approved", "parameters": ["backup", "validate"],
             "script_observations": ["read approved backup source", "validate backup checksum", "write approved backup destination"]}, "E1")
        asset([approved], "E2")
        siem("network_events", {"destination_ip": "10.20.0.8", "destination_port": 443,
             "job_id": "BACKUP-42", "observed_destinations": ["10.20.0.8"], "all_connections_captured": True}, "E3")
        history({"job_id": "BACKUP-42", "script_hash": "h-approved", "parameters": ["backup", "validate"], "periodic": True}, "E4", prior=True)
        ti("hash", "h-approved", "unknown", "E5")
        attack("E6")
        sufficient = {"TP": [], "FP": [["E1", "E2", "E3"]]}
        critical, distractor, verdicts = ["E1", "E2", "E3"], ["E6"], ["FP"]
    elif case_index == 3:
        asset([{"host": host, "user": user, "job_id": "J-7", "script_hash": "h-7", "parameters": ["backup"],
                "window": {"start": "2026-09-01T02:00:00+00:00", "end": "2026-09-01T03:00:00+00:00"}}], "E1")
        siem("process_tree", {"parent_process": "management-task.exe", "job_id": "J-9", "script_hash": "h-9",
             "parameters": ["export", "external"], "script_body": None}, "E2", partial=True, missing=("script_body",))
        siem("network_events", {"destination_ip": "198.51.100.27", "destination_port": 443, "new_destination": True,
             "payload_captured": False}, "E3")
        ti("ip", "198.51.100.27", "unknown", "E4")
        ti("hash", "h-9", "unknown", "E4")
        for kind, entity in (("host", host), ("user", user)):
            unavailable("history", {"entity_type": kind, "entity": entity}, HISTORY_WINDOW, "history_retention_unavailable", "E5")
        facts["E6"] = {"source": "oracle_only", "record_ids": [], "script_body": "Synthetic hidden credential theft and transmission"}
        attack("E7")
        sufficient = {"TP": [], "FP": []}
        critical, distractor, verdicts = ["E1", "E2", "E3", "E6"], ["E7"], ["Suspicious", "Abstain"]
    else:
        siem("process_tree", {"parent_process": None, "child_process": None, "command_line": None},
             "E1", partial=True, missing=("parent_process", "child_process", "command_line"))
        unavailable("siem", {"view": "network_events", "host": host}, WINDOW, "network_source_unavailable", "E2")
        asset([], "E3", partial=True)
        for kind, entity in (("host", host), ("user", user)):
            unavailable("history", {"entity_type": kind, "entity": entity}, HISTORY_WINDOW, "history_source_unavailable", "E4")
        attack("E5")
        facts["E6"] = {"source": "oracle_only", "record_ids": [], "script_body": "Synthetic hidden malicious script" if case_index == 4 else "Synthetic hidden approved maintenance script",
                       "authorization_matched": case_index == 5}
        sufficient = {"TP": [], "FP": []}
        critical, distractor, verdicts = ["E6"], ["E5"], ["Abstain"]
    observable = [key for key, value in facts.items() if value["source"] != "oracle_only"]
    expectations = []
    for view, fact in (("process_tree", "E1" if case_index != 3 else "E2"),
                       ("network_events", "E2" if case_index == 1 or paired else "E3")):
        expectations.append({"when_observed_fact_keys": ["E0"], "when_missing_fact_keys": [fact],
             "acceptable_tools": ["siem"], "argument_constraints": {"view": view, "host": host, "process_id": process},
             "evidence_goal": "Check actual process behavior or related network behavior and coverage"})
    approval_fact = "E4" if case_index == 1 else "E2" if case_index == 2 else "E1" if case_index == 3 else "E3"
    expectations.append({"when_observed_fact_keys": ["E0"], "when_missing_fact_keys": [approval_fact],
        "acceptable_tools": ["asset", "history"] if case_index == 1 else ["asset"],
        "argument_constraints": {"host": host}, "evidence_goal": "Check matched authorization; an approval window alone is insufficient"})
    oracle = {"case_id": f"C{case_index}", "family_id": "powershell-seed-v1" if not paired else "powershell-indistinguishable-pair-v1",
        "split": "dev", "ground_truth": "benign" if case_index in (2, 5) else "malicious",
        "complete_world_evidence": facts, "observable_fact_keys": observable,
        "critical_fact_keys": critical, "distractor_fact_keys": distractor, "sufficient_sets": sufficient,
        "acceptable_verdicts": verdicts, "resolvable_with_full_observable_evidence": case_index in (1, 2),
        "expected_actions": expectations, "rubric_version": "powershell-v1",
        "annotation_rationale": "Independent synthetic annotation from minimal-cases.md; only observed, grounded evidence supports decisions. Hidden world truth is not an agent hint."}
    return {"alert": alert}, env, oracle


def main():
    mapping = []
    for index, spec in enumerate((("WS-041", "analyst-a", "p-101"), ("OPS-017", "svc-backup", "p-202"),
                                  ("OPS-023", "svc-maint", "p-303"), ("WS-088", "operator-b", "p-404"),
                                  ("WS-088", "operator-b", "p-404")), 1):
        public, env, oracle = build(index, *spec, paired=index >= 4)
        public_path, oracle_path = f"public/c{index}.json", f"oracle/c{index}.json"
        env_path = "environment/shared-pair.json" if index >= 4 else f"environment/world-{index}.json"
        write(ROOT / public_path, public)
        if index != 5:
            write(ROOT / env_path, env)
        write(ROOT / oracle_path, oracle)
        mapping.append({"case_id": f"C{index}", "public": public_path, "environment": env_path, "oracle": oracle_path})
    files = {str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest()
             for folder in ("public", "environment", "oracle") for p in sorted((ROOT / folder).glob("*.json"))}
    write(ROOT / "manifest.json", {"dataset_version": "synthetic-v1", "purpose": "engineering seed; not a statistical benchmark",
        "rubric_version": "powershell-v1", "cases": mapping, "file_sha256": files,
        "boundary": "Authoring/evaluation only. Runtime receives one PublicCase; tool server owns its mapped environment. All cases are dev."})
    print("Wrote 5 public cases, 4 physical environments, 5 oracle cases; paired inputs are identical.")


if __name__ == "__main__":
    main()
