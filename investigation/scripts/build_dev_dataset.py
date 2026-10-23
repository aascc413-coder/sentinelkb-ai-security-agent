"""Build the 12-case PowerShell development dataset (M10b authoring only).

The first five cases are byte-equivalent semantic copies of the frozen seed.
Seven new cases exercise structured approved behavior, direct destructive
effects, approval mismatch and an indistinguishable telemetry-gap pair.
Oracle labels are written only to the authoring/evaluation partition.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_seed_dataset as seed_v1

LAB = Path(__file__).resolve().parents[1]
ROOT = LAB / "datasets" / "powershell-dev-v2"
ANNOTATIONS = LAB / "evaluation" / "annotations" / "powershell-dev-v2.json"
ASOF = seed_v1.ASOF
OCCURRED = seed_v1.OCCURRED
PUBLISHED = seed_v1.PUBLISHED
WINDOW = seed_v1.WINDOW
HISTORY_WINDOW = seed_v1.HISTORY_WINDOW
TOOLS = seed_v1.TOOLS


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def identifier(slot):
    return hashlib.sha256(("powershell-dev-2026-v2/" + slot).encode()).hexdigest()[:32]


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8", newline="\n")


class CaseBuilder:
    def __init__(self, case_id, family_id, host, user, process, *, shared_seed=None):
        self.case_id, self.family_id = case_id, family_id
        self.host, self.user, self.process_id = host, user, process
        self.seed = shared_seed or case_id.lower()
        raw = {
            "rule_name": "Suspicious PowerShell execution",
            "process_name": "powershell.exe",
            "detector_claim": "possible encoded or policy-sensitive execution",
            "command_body_retained": False,
            "host": host, "user": user, "process_id": process, "occurred_at": OCCURRED,
        }
        self.alert = {
            "alert_id": identifier(self.seed + "/alert"),
            "alert_type": "powershell_execution",
            "occurred_at": OCCURRED, "as_of": ASOF,
            "host": host, "user": user, "process_id": process,
            "command_line": "powershell.exe -EncodedCommand [body retained by EDR fields]",
            "raw": raw,
            "raw_reference": {
                "record_id": identifier(self.seed + "/alert-record"),
                "json_pointer": "", "content_sha256": digest(raw),
            },
        }
        self.env = {
            "environment_id": identifier(self.seed + "/environment"), "as_of": ASOF,
            "records_by_tool": {tool: [] for tool in TOOLS}, "query_rules": [],
            "fixture_version": "powershell-dev-v2",
        }
        self.facts = {
            "E0": {
                "source": "alert", "record_ids": [self.alert["raw_reference"]["record_id"]],
                "observation": "PowerShell detector fired; detector text is not verified behavior.",
            }
        }

    def record(self, tool, label, payload, source, group, fact):
        record_id = identifier(self.seed + "/" + label)
        self.env["records_by_tool"][tool].append({
            "record_id": record_id, "payload": payload, "content_sha256": digest(payload),
            "source_system": source, "independence_group": group,
            "reliability": {
                "level": "high", "basis": "Frozen synthetic source measurement",
                "policy_version": "source-policy-v1",
            },
        })
        self.facts.setdefault(fact, {
            "source": tool, "record_ids": [], "observation": payload,
        })["record_ids"].append(record_id)
        return record_id

    @staticmethod
    def coverage(scope, window=None, *, complete=True, missing=()):
        return {
            "scope": scope, "window": window,
            "completeness": "complete" if complete else "partial",
            "truncated": False, "missing_sources": list(missing),
        }

    def rule(self, tool, constraints, record_ids, coverage, *, status="ok", error=None):
        self.env["query_rules"].append({
            "tool": tool, "argument_constraints": constraints,
            "record_ids": record_ids, "status": status, "coverage": coverage,
            "retryable": False, "error_code": error,
        })

    def process(self, *, observations, parent, job_id, script_hash, parameters,
                fact="E1", partial=False, missing=()):
        payload = {
            "view": "process_tree", "host": self.host, "user": self.user,
            "process_id": self.process_id, "process_guid": identifier(self.seed + "/instance"),
            "event_id": identifier(self.seed + "/event/process"),
            "occurred_at": OCCURRED, "observed_at": PUBLISHED,
            "parent_process": parent, "child_process": [],
            "job_id": job_id, "script_hash": script_hash, "parameters": parameters,
            "script_observations": observations,
        }
        record_id = self.record("siem", "process", payload, "edr", "edr-01", fact)
        self.rule(
            "siem", {"view": "process_tree", "host": self.host}, [record_id],
            self.coverage({"view": "process_tree", "host": self.host,
                           "user": None, "process_id": None}, WINDOW,
                          complete=not partial, missing=missing),
            status="partial" if partial else "ok",
        )

    def network(self, destinations, *, fact="E2", partial=False, missing=()):
        payload = {
            "view": "network_events", "host": self.host, "user": self.user,
            "process_id": self.process_id, "process_guid": identifier(self.seed + "/instance"),
            "event_id": identifier(self.seed + "/event/network"),
            "occurred_at": OCCURRED, "observed_at": PUBLISHED,
            "observed_destinations": destinations, "all_connections_captured": not partial,
        }
        if destinations:
            payload["destination_ip"] = destinations[0]
            payload["destination_port"] = 443
        record_id = self.record("siem", "network", payload, "network-sensor", "network-01", fact)
        self.rule(
            "siem", {"view": "network_events", "host": self.host}, [record_id],
            self.coverage({"view": "network_events", "host": self.host,
                           "user": None, "process_id": None}, WINDOW,
                          complete=not partial, missing=missing),
            status="partial" if partial else "ok",
        )

    def unavailable(self, tool, constraints, window, reason, fact):
        self.rule(tool, constraints, [], self.coverage(constraints, window, complete=False,
                                                       missing=(reason,)),
                  status="unavailable", error=reason)
        self.facts[fact] = {
            "source": tool, "record_ids": [], "operational_status": "unavailable",
            "reason": reason,
        }

    def asset(self, jobs, *, fact="E3", partial=False):
        payload = {
            "host": self.host, "published_at": PUBLISHED,
            "purpose": "managed-workstation", "system_type": "Windows",
            "critical_asset": False, "department": "synthetic-enterprise",
            "approval_register_complete": not partial,
            "approval_register_window": WINDOW, "approved_jobs": jobs,
        }
        record_id = self.record("asset", "asset", payload, "change-register", "change-01", fact)
        self.rule(
            "asset", {"host": self.host}, [record_id],
            self.coverage({"host": self.host, "as_of": ASOF}, complete=not partial,
                          missing=("approval_archive",) if partial else ()),
            status="partial" if partial else "ok",
        )

    def history(self, payload_fields, *, fact="E4"):
        payload = {
            "entity_type": "user", "entity": self.user,
            "host": self.host, "user": self.user,
            "occurred_at": "2026-08-31T12:00:00+00:00", "observed_at": PUBLISHED,
            **payload_fields,
        }
        record_id = self.record("history", "history", payload, "history-store", "history-01", fact)
        self.rule(
            "history", {"entity_type": "user", "entity": self.user}, [record_id],
            self.coverage({"entity_type": "user", "entity": self.user,
                           "host": self.host, "user": self.user,
                           "command_line": None}, HISTORY_WINDOW),
        )

    def attack(self, *, fact="E5"):
        payload = {
            "snapshot_version": "attack-local-v1", "published_at": "2026-08-01T00:00:00+00:00",
            "technique_id": "T1059.001", "behavior_terms": ["powershell_execution"],
            "description": "PowerShell occurs in authorized and unauthorized activity; mapping is not a verdict.",
        }
        record_id = self.record("attack", "attack", payload, "local-attack-knowledge",
                                "knowledge-01", fact)
        self.rule("attack", {"snapshot_version": "attack-local-v1"}, [record_id],
                  self.coverage({"snapshot_version": "attack-local-v1"}))

    def ti(self, value, reputation="unknown", *, fact="E7"):
        payload = {
            "indicator_type": "ip", "value": value, "published_at": PUBLISHED,
            "reputation": reputation, "provider": "local-mock",
            "not_a_real_ioc_assessment": True,
        }
        record_id = self.record("threat_intel", "ti/" + value, payload, "mock-ti", "ti-01", fact)
        self.rule("threat_intel", {"indicator_type": "ip", "value": value}, [record_id],
                  self.coverage({"indicator_type": "ip", "value": value, "as_of": ASOF}))

    def oracle(self, *, ground_truth, critical, distractors, sufficient_sets,
               acceptable_verdicts, expected_actions, hidden=None, rationale):
        if hidden is not None:
            self.facts["E6"] = {"source": "oracle_only", "record_ids": [], **hidden}
        observable = [key for key, value in self.facts.items()
                      if value["source"] != "oracle_only"]
        return {
            "case_id": self.case_id, "family_id": self.family_id, "split": "dev",
            "ground_truth": ground_truth, "complete_world_evidence": self.facts,
            "observable_fact_keys": observable, "critical_fact_keys": critical,
            "distractor_fact_keys": distractors, "sufficient_sets": sufficient_sets,
            "acceptable_verdicts": acceptable_verdicts,
            "resolvable_with_full_observable_evidence": bool(
                sufficient_sets.get("TP") or sufficient_sets.get("FP")
            ),
            "expected_actions": expected_actions, "rubric_version": "powershell-v1",
            "annotation_rationale": rationale,
        }

    def action(self, tool, missing, goal, constraints):
        return {
            "when_observed_fact_keys": ["E0"], "when_missing_fact_keys": [missing],
            "acceptable_tools": [tool], "argument_constraints": constraints,
            "evidence_goal": goal,
        }

    def standard_actions(self, *, include_history=False):
        actions = [
            self.action("siem", "E1", "Inspect grounded current process behavior.",
                        {"view": "process_tree", "host": self.host, "process_id": self.process_id}),
            self.action("siem", "E2", "Inspect same-instance network effects and coverage.",
                        {"view": "network_events", "host": self.host, "process_id": self.process_id}),
            self.action("asset", "E3", "Check execution details against complete approvals.",
                        {"host": self.host}),
        ]
        if include_history:
            actions.append(self.action("history", "E4", "Check comparable user history.",
                                       {"entity_type": "user", "entity": self.user}))
        return actions

    def result(self, oracle):
        return {"alert": self.alert}, self.env, oracle


def approved_job(builder, *, job_id, script_hash, parameters, observations, destinations):
    return {
        "host": builder.host, "user": builder.user, "job_id": job_id,
        "script_hash": script_hash, "parameters": parameters,
        "window": {"start": "2026-09-01T02:00:00+00:00",
                   "end": "2026-09-01T03:00:00+00:00"},
        "allowed_destinations": destinations,
        "expected_observations": observations,
    }


def build_new(case_id):
    if case_id == "C6":
        b = CaseBuilder(case_id, "powershell-office-exfil-v1", "WS-106", "analyst-c", "p-606")
        observations = [
            {"operation": "read", "object": "browser-credential-store", "authorized": False,
             "produces": "browser-secrets"},
            {"operation": "upload", "object": "browser-secrets", "destination": "203.0.113.106"},
        ]
        b.process(observations=observations, parent="WINWORD.EXE", job_id="DOC-UNKNOWN",
                  script_hash="h-office-unknown", parameters=["collect", "upload"])
        b.network(["203.0.113.106"])
        b.asset([])
        b.ti("203.0.113.106", "malicious")
        b.attack()
        oracle = b.oracle(
            ground_truth="malicious", critical=["E1", "E2", "E3"], distractors=["E5", "E7"],
            sufficient_sets={"TP": [["E1", "E2", "E3"]], "FP": []},
            acceptable_verdicts=["TP"], expected_actions=b.standard_actions(),
            rationale="Unauthorized browser-secret collection and same-instance upload, with complete negative approval coverage.",
        )
    elif case_id == "C7":
        b = CaseBuilder(case_id, "powershell-office-approved-v1", "WS-107", "finance-a", "p-707")
        observations = [
            {"operation": "read", "object": "approved-spreadsheet", "authorized": True},
            {"operation": "write", "object": "approved-report", "authorized": True},
        ]
        job = approved_job(b, job_id="REPORT-7", script_hash="h-report-7",
                           parameters=["report", "monthly"], observations=observations,
                           destinations=[])
        b.process(observations=observations, parent="EXCEL.EXE", job_id="REPORT-7",
                  script_hash="h-report-7", parameters=["report", "monthly"])
        b.network([])
        b.asset([job])
        b.attack()
        oracle = b.oracle(
            ground_truth="benign", critical=["E1", "E2", "E3"], distractors=["E5"],
            sufficient_sets={"TP": [], "FP": [["E1", "E2", "E3"]]},
            acceptable_verdicts=["FP"], expected_actions=b.standard_actions(),
            rationale="Structured behavior, parameters and zero-network scope match the approved reporting job.",
        )
    elif case_id == "C8":
        b = CaseBuilder(case_id, "powershell-remote-admin-v1", "OPS-108", "svc-rmm", "p-808")
        observations = [
            {"operation": "read", "object": "approved-update-package", "authorized": True},
            {"operation": "write", "object": "approved-service-config", "authorized": True},
        ]
        job = approved_job(b, job_id="RMM-88", script_hash="h-rmm-88",
                           parameters=["patch", "validate"], observations=observations,
                           destinations=["10.30.0.18"])
        b.process(observations=observations, parent="rmm-agent.exe", job_id="RMM-88",
                  script_hash="h-rmm-88", parameters=["patch", "validate"])
        b.network(["10.30.0.18"])
        b.asset([job])
        b.history({"job_id": "RMM-88", "periodic": True})
        b.attack()
        oracle = b.oracle(
            ground_truth="benign", critical=["E1", "E2", "E3"], distractors=["E4", "E5"],
            sufficient_sets={"TP": [], "FP": [["E1", "E2", "E3"]]},
            acceptable_verdicts=["FP"], expected_actions=b.standard_actions(),
            rationale="Remote administration activity exactly matches the approved job and network target.",
        )
    elif case_id == "C9":
        b = CaseBuilder(case_id, "powershell-remote-admin-v1", "OPS-109", "svc-rmm", "p-909")
        observations = [
            {"operation": "export", "object": "system-inventory", "authorized": True},
            {"operation": "upload", "object": "inventory", "destination": "198.51.100.109"},
        ]
        approved = approved_job(b, job_id="RMM-90", script_hash="h-rmm-90",
                                parameters=["patch", "validate"], observations=observations,
                                destinations=["10.30.0.19"])
        b.process(observations=observations, parent="rmm-agent.exe", job_id="RMM-91",
                  script_hash="h-rmm-91", parameters=["inventory", "external"])
        b.network(["198.51.100.109"])
        b.asset([approved])
        b.history({"destination_ip": "198.51.100.109", "first_seen": True,
                   "comparable_history_complete": True})
        b.ti("198.51.100.109", "unknown")
        b.attack()
        oracle = b.oracle(
            ground_truth="malicious", critical=["E1", "E2", "E3", "E4"],
            distractors=["E5", "E7"], sufficient_sets={"TP": [], "FP": []},
            acceptable_verdicts=["Suspicious", "Abstain"],
            expected_actions=b.standard_actions(include_history=True),
            hidden={"script_intent": "Synthetic hidden unauthorized collection"},
            rationale="Job, hash, parameters and destination mismatch approval; behavior lacks direct attack proof.",
        )
    elif case_id in {"C10", "C11"}:
        b = CaseBuilder(case_id, "powershell-telemetry-gap-pair-v1", "WS-110", "operator-d",
                        "p-1010", shared_seed="shared-10-11")
        b.process(observations=[], parent="signed-admin.exe", job_id=None, script_hash=None,
                  parameters=[], partial=True, missing=("script_body", "job_id", "script_hash"))
        b.unavailable("siem", {"view": "network_events", "host": b.host}, WINDOW,
                      "network_retention_unavailable", "E2")
        b.asset([], partial=True)
        b.unavailable("history", {"entity_type": "user", "entity": b.user}, HISTORY_WINDOW,
                      "history_retention_unavailable", "E4")
        b.attack()
        oracle = b.oracle(
            ground_truth="malicious" if case_id == "C10" else "benign",
            critical=["E6"], distractors=["E5"], sufficient_sets={"TP": [], "FP": []},
            acceptable_verdicts=["Abstain"], expected_actions=b.standard_actions(include_history=True),
            hidden={"script_intent": "destructive" if case_id == "C10" else "approved repair"},
            rationale="Counterfactual pair has identical visible alert and tool world; decisive intent is hidden.",
        )
    elif case_id == "C12":
        b = CaseBuilder(case_id, "powershell-direct-destructive-v1", "WS-112", "employee-e", "p-1212")
        observations = [{
            "operation": "encrypt", "object": "user-documents", "authorized": False,
            "affected_count": 250,
        }]
        b.process(observations=observations, parent="invoice-viewer.exe", job_id="NONE",
                  script_hash="h-destructive-12", parameters=["encrypt", "recursive"])
        b.network([])
        b.asset([])
        b.attack()
        oracle = b.oracle(
            ground_truth="malicious", critical=["E1", "E2", "E3"], distractors=["E5"],
            sufficient_sets={"TP": [["E1", "E2", "E3"]], "FP": []},
            acceptable_verdicts=["TP"], expected_actions=b.standard_actions(),
            rationale="High-quality EDR directly records unauthorized encryption; complete network and approval scopes exclude alternatives.",
        )
    else:
        raise ValueError(case_id)
    return b.result(oracle)


def annotation(case_id):
    values = {
        "C6": (["E1", "E2", "E3"], ["E1", "E2"], False, True, False,
               "Direct exfiltration chain and complete approval coverage support determinate TP."),
        "C7": (["E1", "E2", "E3"], [], False, True, False,
               "Structured behavior and zero-network scope match a concrete approval."),
        "C8": (["E1", "E2", "E3"], [], False, True, False,
               "Remote administration behavior and destination match a concrete approval."),
        "C9": (["E1", "E2", "E3", "E4"], ["E1", "E2", "E3", "E4"], False, False, True,
               "Approval mismatch and new external target justify escalation without direct attack proof."),
        "C10": ([], [], True, False, True,
                "Visible evidence is indistinguishable from benign C11; decisive intent is hidden."),
        "C11": ([], [], True, False, True,
                "Visible evidence is indistinguishable from malicious C10; decisive intent is hidden."),
        "C12": (["E1", "E2", "E3"], ["E1"], False, True, False,
                "Direct unauthorized destructive effect plus complete scopes supports determinate TP."),
    }
    discriminating, risk, required, avoidable, human, rationale = values[case_id]
    return {
        "case_id": case_id, "discriminating_fact_keys": discriminating,
        "risk_clue_fact_keys": risk, "required_abstention": required,
        "avoidable_abstention": avoidable, "required_human_review": human,
        "rationale": rationale,
    }


def main():
    mappings = []
    seed_specs = (
        ("WS-041", "analyst-a", "p-101"), ("OPS-017", "svc-backup", "p-202"),
        ("OPS-023", "svc-maint", "p-303"), ("WS-088", "operator-b", "p-404"),
        ("WS-088", "operator-b", "p-404"),
    )
    for index, spec in enumerate(seed_specs, 1):
        public, env, oracle = seed_v1.build(index, *spec, paired=index >= 4)
        public_path, oracle_path = f"public/c{index}.json", f"oracle/c{index}.json"
        env_path = "environment/shared-pair.json" if index >= 4 else f"environment/world-{index}.json"
        write(ROOT / public_path, public)
        if index != 5:
            write(ROOT / env_path, env)
        write(ROOT / oracle_path, oracle)
        mappings.append({"case_id": f"C{index}", "public": public_path,
                         "environment": env_path, "oracle": oracle_path})
    for number in range(6, 13):
        case_id = f"C{number}"
        public, env, oracle = build_new(case_id)
        public_path, oracle_path = f"public/c{number}.json", f"oracle/c{number}.json"
        env_path = ("environment/shared-10-11.json" if number in (10, 11)
                    else f"environment/world-{number}.json")
        write(ROOT / public_path, public)
        if number != 11:
            write(ROOT / env_path, env)
        write(ROOT / oracle_path, oracle)
        mappings.append({"case_id": case_id, "public": public_path,
                         "environment": env_path, "oracle": oracle_path})
    files = {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for folder in ("public", "environment", "oracle")
        for path in sorted((ROOT / folder).glob("*.json"))
    }
    write(ROOT / "manifest.json", {
        "dataset_version": "powershell-dev-v2", "purpose": "M10 development dataset; not blind test",
        "rubric_version": "powershell-v1", "cases": mappings, "file_sha256": files,
        "boundary": "Authoring/evaluation only. Twelve dev cases; no statistical or blind-test claim.",
    })
    original_annotations = json.loads(
        (LAB / "evaluation/annotations/powershell-dev-v1.json").read_text(encoding="utf-8")
    )
    write(ANNOTATIONS, {
        **original_annotations,
        "annotation_version": "powershell-dev-eval-v2",
        "cases": original_annotations["cases"] + [annotation(f"C{n}") for n in range(6, 13)],
    })
    print("Wrote powershell-dev-v2: 12 dev cases, 10 physical environments, 12 oracle cases.")


if __name__ == "__main__":
    main()
