"""Build the 20-case PowerShell development dataset (M10c authoring only).

The frozen M10b cases are copied byte-for-byte from powershell-dev-v2. Eight
new cases extend operational failure, conflicting-source, distractor, duplicate
record and determinate behavior coverage without changing the v2 artifact.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_dev_dataset as v2


LAB = Path(__file__).resolve().parents[1]
SOURCE = LAB / "datasets" / "powershell-dev-v2"
ROOT = LAB / "datasets" / "powershell-dev-v3"
ANNOTATIONS_SOURCE = LAB / "evaluation" / "annotations" / "powershell-dev-v2.json"
ANNOTATIONS = LAB / "evaluation" / "annotations" / "powershell-dev-v3.json"


class CaseBuilder(v2.CaseBuilder):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.env["fixture_version"] = "powershell-dev-v3"

    def operational(self, tool, constraints, window, *, status, reason, fact, retryable=False):
        self.env["query_rules"].append({
            "tool": tool,
            "argument_constraints": constraints,
            "record_ids": [],
            "status": status,
            "coverage": self.coverage(constraints, window, complete=False, missing=(reason,)),
            "retryable": retryable,
            "error_code": reason,
        })
        self.facts[fact] = {
            "source": tool,
            "record_ids": [],
            "arguments": constraints,
            "operational_status": status,
            "reason": reason,
            "retryable": retryable,
        }

    def empty_network(self, *, fact="E2"):
        constraints = {"view": "network_events", "host": self.host}
        self.env["query_rules"].append({
            "tool": "siem",
            "argument_constraints": constraints,
            "record_ids": [],
            "status": "empty",
            "coverage": self.coverage(
                {"view": "network_events", "host": self.host,
                 "user": None, "process_id": None}, v2.WINDOW,
            ),
            "retryable": False,
            "error_code": None,
        })
        self.facts[fact] = {
            "source": "siem",
            "record_ids": [],
            "arguments": constraints,
            "operational_status": "empty",
            "observation": "Complete network scope returned zero matching events.",
        }


def approved_job(builder, *, job_id, script_hash, parameters, observations, destinations):
    return v2.approved_job(
        builder,
        job_id=job_id,
        script_hash=script_hash,
        parameters=parameters,
        observations=observations,
        destinations=destinations,
    )


def build_new(case_id):
    if case_id == "C13":
        b = CaseBuilder(case_id, "powershell-office-exfil-v1", "WS-113", "developer-f", "p-1313")
        observations = [
            {"operation": "read", "object": "private-key-store", "authorized": False,
             "produces": "ssh-private-key-blob"},
            {"operation": "send", "object": "ssh-private-key-blob",
             "destination": "203.0.113.113"},
        ]
        b.process(observations=observations, parent="code-editor.exe", job_id="NONE",
                  script_hash="h-key-exfil-13", parameters=["collect", "send"])
        b.network(["203.0.113.113"])
        b.asset([])
        b.ti("203.0.113.113", "benign")
        b.attack()
        oracle = b.oracle(
            ground_truth="malicious", critical=["E1", "E2", "E3"],
            distractors=["E5", "E7"], sufficient_sets={"TP": [["E1", "E2", "E3"]], "FP": []},
            acceptable_verdicts=["TP"], expected_actions=b.standard_actions(),
            rationale="Unauthorized private-key collection and same-instance transfer outweigh benign TI metadata.",
        )
    elif case_id == "C14":
        b = CaseBuilder(case_id, "powershell-approved-inventory-v1", "OPS-114", "svc-inventory", "p-1414")
        observations = [
            {"operation": "read", "object": "software-inventory", "authorized": True},
            {"operation": "write", "object": "inventory-report", "authorized": True},
        ]
        job = approved_job(b, job_id="INV-14", script_hash="h-inventory-14",
                           parameters=["inventory", "publish"], observations=observations,
                           destinations=["10.40.0.14"])
        b.process(observations=observations, parent="inventory-agent.exe", job_id="INV-14",
                  script_hash="h-inventory-14", parameters=["inventory", "publish"])
        b.network(["10.40.0.14"])
        first = b.env["records_by_tool"]["siem"][-1]
        duplicate = copy.deepcopy(first)
        duplicate["record_id"] = v2.identifier(b.seed + "/network-duplicate")
        b.env["records_by_tool"]["siem"].append(duplicate)
        b.env["query_rules"][-1]["record_ids"].append(duplicate["record_id"])
        b.facts["E2"]["record_ids"].append(duplicate["record_id"])
        b.asset([job])
        b.attack()
        oracle = b.oracle(
            ground_truth="benign", critical=["E1", "E2", "E3"], distractors=["E5"],
            sufficient_sets={"TP": [], "FP": [["E1", "E2", "E3"]]},
            acceptable_verdicts=["FP"], expected_actions=b.standard_actions(),
            rationale="Duplicate same-source network records do not add support; the deduplicated activity matches approval.",
        )
    elif case_id == "C15":
        b = CaseBuilder(case_id, "powershell-mismatch-timeout-v1", "OPS-115", "svc-ops", "p-1515")
        observations = [
            {"operation": "export", "object": "system-inventory", "authorized": True},
            {"operation": "upload", "object": "inventory", "destination": "198.51.100.115"},
        ]
        job = approved_job(b, job_id="OPS-14", script_hash="h-ops-14",
                           parameters=["inventory", "internal"], observations=observations,
                           destinations=["10.41.0.15"])
        b.process(observations=observations, parent="ops-agent.exe", job_id="OPS-15",
                  script_hash="h-ops-15", parameters=["inventory", "external"])
        b.network(["198.51.100.115"])
        b.asset([job])
        b.operational("history", {"entity_type": "user", "entity": b.user}, v2.HISTORY_WINDOW,
                      status="timeout", reason="tool_timeout", fact="E4", retryable=True)
        b.attack()
        oracle = b.oracle(
            ground_truth="malicious", critical=["E1", "E2", "E3"], distractors=["E5"],
            sufficient_sets={"TP": [], "FP": []},
            acceptable_verdicts=["Suspicious", "Abstain"],
            expected_actions=b.standard_actions(include_history=True),
            hidden={"script_intent": "unauthorized external inventory transfer"},
            rationale="Execution mismatches approval; retryable history failure preserves escalation without proving attack intent.",
        )
    elif case_id == "C16":
        b = CaseBuilder(case_id, "powershell-partial-destructive-v1", "WS-116", "employee-g", "p-1616")
        observations = [{
            "operation": "encrypt", "object": "team-documents", "authorized": False,
            "affected_count": 40,
        }]
        b.process(observations=observations, parent="archive-viewer.exe", job_id="NONE",
                  script_hash="h-partial-16", parameters=["encrypt"], partial=True,
                  missing=("process_start",))
        b.empty_network()
        b.asset([])
        b.unavailable("history", {"entity_type": "user", "entity": b.user},
                      v2.HISTORY_WINDOW, "history_retention_unavailable", "E4")
        b.attack()
        oracle = b.oracle(
            ground_truth="malicious", critical=["E1", "E2", "E3"], distractors=["E5"],
            sufficient_sets={"TP": [], "FP": []}, acceptable_verdicts=["Abstain"],
            expected_actions=b.standard_actions(include_history=True),
            rationale="A harmful-looking partial record cannot satisfy complete process coverage and requires human review.",
        )
    elif case_id in {"C17", "C18"}:
        b = CaseBuilder(case_id, "powershell-approval-conflict-pair-v1", "WS-117", "contractor-h",
                        "p-1718", shared_seed="shared-17-18")
        observations = [
            {"operation": "read", "object": "diagnostic-settings", "authorized": True},
            {"operation": "write", "object": "diagnostic-report", "authorized": True},
        ]
        job = approved_job(b, job_id="DIAG-17", script_hash="h-diagnostic-17",
                           parameters=["diagnose", "publish"], observations=observations,
                           destinations=["10.42.0.17"])
        b.process(observations=observations, parent="signed-helper.exe", job_id="DIAG-17",
                  script_hash="h-diagnostic-17", parameters=["diagnose", "publish"])
        b.network(["10.42.0.17"])
        b.asset([job])
        asset_rule = b.env["query_rules"][-1]
        conflict_payload = copy.deepcopy(b.env["records_by_tool"]["asset"][-1]["payload"])
        conflict_payload["approved_jobs"] = []
        conflict_id = b.record(
            "asset", "asset-conflict", conflict_payload,
            "secondary-change-register", "change-02", "E3",
        )
        asset_rule["record_ids"].append(conflict_id)
        b.history({"approval_feed_conflict": True, "comparable_history_complete": True})
        b.attack()
        oracle = b.oracle(
            ground_truth="malicious" if case_id == "C17" else "benign",
            critical=["E3", "E6"], distractors=["E5"], sufficient_sets={"TP": [], "FP": []},
            acceptable_verdicts=["Abstain"], expected_actions=b.standard_actions(include_history=True),
            hidden={"script_intent": "approval record tampering" if case_id == "C17" else "approved diagnostics"},
            rationale="Independent approval sources conflict, so identical visible evidence cannot resolve intent.",
        )
    elif case_id == "C19":
        b = CaseBuilder(case_id, "powershell-ti-distractor-v1", "WS-119", "analyst-i", "p-1919")
        observations = [{"operation": "query", "object": "security-settings", "authorized": None}]
        b.process(observations=observations, parent="terminal.exe", job_id="NONE",
                  script_hash="h-query-19", parameters=["query"])
        b.empty_network()
        b.asset([])
        b.operational("history", {"entity_type": "user", "entity": b.user}, v2.HISTORY_WINDOW,
                      status="error", reason="history_backend_error", fact="E4",
                      retryable=False)
        b.ti("203.0.113.250", "malicious")
        b.attack()
        oracle = b.oracle(
            ground_truth="benign", critical=[], distractors=["E5", "E7"],
            sufficient_sets={"TP": [], "FP": []}, acceptable_verdicts=["Abstain"],
            expected_actions=b.standard_actions(include_history=True),
            rationale="Unlinked malicious TI and a permanent history failure cannot determine current behavior.",
        )
    elif case_id == "C20":
        b = CaseBuilder(case_id, "powershell-direct-destructive-v1", "WS-120", "employee-j", "p-2020")
        observations = [{
            "operation": "delete", "object": "shared-documents", "authorized": False,
            "affected_count": 75,
        }]
        b.process(observations=observations, parent="document-converter.exe", job_id="NONE",
                  script_hash="h-delete-20", parameters=["delete", "recursive"])
        b.empty_network()
        b.asset([])
        b.attack()
        oracle = b.oracle(
            ground_truth="malicious", critical=["E1", "E2", "E3"], distractors=["E5"],
            sufficient_sets={"TP": [["E1", "E2", "E3"]], "FP": []},
            acceptable_verdicts=["TP"], expected_actions=b.standard_actions(),
            rationale="Direct unauthorized bulk deletion plus complete approval and zero-network scopes supports early TP.",
        )
    else:
        raise ValueError(case_id)
    return b.result(oracle)


def annotation(case_id):
    values = {
        "C13": (["E1", "E2", "E3"], ["E1", "E2"], False, True, False,
                "Private-key exfiltration and negative approval coverage support determinate TP."),
        "C14": (["E1", "E2", "E3"], [], False, True, False,
                "Deduplicated behavior and destination match a concrete approved inventory job."),
        "C15": (["E1", "E2", "E3"], ["E1", "E2", "E3"], False, False, True,
                "Known approval mismatch remains a verified risk despite retryable history failure."),
        "C16": ([], ["E1"], True, False, True,
                "Partial process coverage blocks a determinate conclusion despite a harmful-looking record."),
        "C17": ([], [], True, False, True,
                "Visible evidence is identical to benign C18 under conflicting approval sources."),
        "C18": ([], [], True, False, True,
                "Visible evidence is identical to malicious C17 under conflicting approval sources."),
        "C19": ([], ["E7"], True, False, True,
                "Unlinked TI reputation and unavailable history cannot discriminate the current execution."),
        "C20": (["E1", "E2", "E3"], ["E1"], False, True, False,
                "Direct unauthorized bulk deletion supports determinate TP and early stopping."),
    }
    discriminating, risk, required, avoidable, human, rationale = values[case_id]
    return {
        "case_id": case_id,
        "discriminating_fact_keys": discriminating,
        "risk_clue_fact_keys": risk,
        "required_abstention": required,
        "avoidable_abstention": avoidable,
        "required_human_review": human,
        "rationale": rationale,
    }


def main():
    source_manifest = json.loads((SOURCE / "manifest.json").read_text(encoding="utf-8"))
    mappings = copy.deepcopy(source_manifest["cases"])
    for relative in sorted(source_manifest["file_sha256"]):
        source = SOURCE / relative
        destination = ROOT / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)

    for number in range(13, 21):
        case_id = f"C{number}"
        public, environment, oracle = build_new(case_id)
        public_path = f"public/c{number}.json"
        oracle_path = f"oracle/c{number}.json"
        environment_path = ("environment/shared-17-18.json" if number in (17, 18)
                            else f"environment/world-{number}.json")
        v2.write(ROOT / public_path, public)
        if number != 18:
            v2.write(ROOT / environment_path, environment)
        v2.write(ROOT / oracle_path, oracle)
        mappings.append({
            "case_id": case_id,
            "public": public_path,
            "environment": environment_path,
            "oracle": oracle_path,
        })

    files = {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for folder in ("public", "environment", "oracle")
        for path in sorted((ROOT / folder).glob("*.json"))
    }
    v2.write(ROOT / "manifest.json", {
        "dataset_version": "powershell-dev-v3",
        "purpose": "Frozen M10 development dataset; not blind test",
        "rubric_version": "powershell-v1",
        "cases": mappings,
        "file_sha256": files,
        "boundary": "Authoring/evaluation only. Twenty dev cases; no statistical or blind-test claim.",
    })

    old_annotations = json.loads(ANNOTATIONS_SOURCE.read_text(encoding="utf-8"))
    v2.write(ANNOTATIONS, {
        **old_annotations,
        "annotation_version": "powershell-dev-eval-v3",
        "cases": old_annotations["cases"] + [annotation(f"C{number}") for number in range(13, 21)],
    })
    print("Wrote powershell-dev-v3: 20 dev cases, 17 physical environments, 20 oracle cases.")


if __name__ == "__main__":
    main()
