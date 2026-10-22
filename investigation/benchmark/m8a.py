"""M8a fake-model engineering benchmark and offline replay.

This is an integration acceptance runner, not an empirical model comparison.
The deterministic adapter sees only the actual public model request.  Oracle,
annotations and semantic case IDs are introduced only after each trace closes.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from dataclasses import replace
from datetime import datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
from typing import Iterable

from evaluation.annotation_loader import load_annotations
from evaluation.leakage import CapturingModelAdapter, LeakagePolicy, save_capture_bundle
from evaluation.oracle_loader import load_oracle
from evaluation.report import (
    aggregate_report, evaluate_persisted_run, save_evaluation_report,
)
from evidence_investigation.agents.investigator import (
    EvidenceAwareInvestigator, required_prompt_hashes as proposed_prompt_hashes,
)
from evidence_investigation.baselines.common import required_prompt_hashes
from evidence_investigation.baselines.direct import DirectBaseline
from evidence_investigation.baselines.fixed import FixedWorkflowBaseline
from evidence_investigation.baselines.react import ReActBaseline
from evidence_investigation.runtime.model import FakeScriptedModel
from evidence_investigation.runtime.trace import read_trace
from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.contracts import Budget, RunManifest, Usage
from evidence_investigation.state.content import load_json
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.state.rubric import load_rubric
from evidence_investigation.tools.fixture_loader import load_environment
from evidence_investigation.tools.server import MockToolServer


LAB = Path(__file__).resolve().parents[1]
DATA = LAB / "datasets"
ANNOTATIONS = LAB / "evaluation" / "annotations" / "powershell-dev-v1.json"
RUBRIC = LAB / "rubrics" / "powershell-v1.json"
PROMPTS = LAB / "src" / "evidence_investigation" / "prompts"
METHODS = ("direct", "fixed", "fixed_all", "react", "proposed")
DEFAULT_BUDGETS = (2, 4, 6, 8)
MODEL_SNAPSHOT = "fake-engineering-visible-input-v1"
FORMAT_VERSION = "m8a-engineering-benchmark-v1"


def _json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(encode(value), ensure_ascii=False, indent=1,
                               sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _file_hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _revision() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=LAB, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _visible_json(messages, required_key: str | None = None) -> dict:
    for message in reversed(messages):
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            continue
        try:
            value = json.loads(content)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and (required_key is None or required_key in value):
            return value
    raise ValueError(f"model request has no visible JSON object containing {required_key!r}")


def _evidence_ids(context: dict) -> list[str]:
    ids = []
    for key in ("evidence", "operational_evidence"):
        for item in context.get(key, []):
            if isinstance(item, dict) and isinstance(item.get("evidence_id"), str):
                ids.append(item["evidence_id"])
    return list(dict.fromkeys(ids))


def _conservative_final(context: dict) -> dict:
    return {
        "verdict": "Abstain",
        "disposition": "human_review",
        "stop_reason": "no_useful_action",
        "p_attack": None,
        "claims": [],
        "final_evidence_ids": _evidence_ids(context),
        "unresolved_questions": [
            "The fake engineering model does not make a determinate security judgment."
        ],
        "risk_flags": [],
        "abstain_reason": "Conservative policy of the deterministic engineering adapter.",
        "confidence_status": "uncalibrated",
    }


class EngineeringFakeModel(FakeScriptedModel):
    """Schema-aware deterministic adapter with no case/oracle lookup.

    Token counts are synthetic constants.  They exercise accounting paths and
    are never represented as provider billing or real model efficiency.
    """

    def __init__(self):
        # A fresh adapter is created for every run.  The generous finite script
        # preserves FakeScriptedModel's fail-closed exhaustion behavior.
        super().__init__([self._respond] * 64, input_tokens=100, output_tokens=50)

    def _respond(self, messages, output_schema, max_output_tokens, timeout_seconds):
        title = output_schema.get("title", "")
        if "假设提案" in title:
            context = _visible_json(messages, "previous_hypotheses")
            previous = {item["hypothesis_id"]: item
                        for item in context["previous_hypotheses"]}
            version = max((item["version"] for item in previous.values()), default=0) + 1
            output = {
                "hypotheses": [
                    {
                        "hypothesis_id": "malicious", "version": version,
                        "explanation": "The execution may be unauthorized or harmful.",
                        "kind": "malicious", "status": "open",
                        "expected_observations": ["unauthorized behavior or harmful effects"],
                        "falsifying_observations": ["complete matching authorization"],
                        "supporting_evidence": [], "disconfirming_evidence": [],
                        "supersedes": "malicious" if previous else None,
                    },
                    {
                        "hypothesis_id": "benign", "version": version,
                        "explanation": "The execution may be approved administrative activity.",
                        "kind": "benign", "status": "open",
                        "expected_observations": ["matching approval and scoped effects"],
                        "falsifying_observations": ["unauthorized or harmful effects"],
                        "supporting_evidence": [], "disconfirming_evidence": [],
                        "supersedes": "benign" if previous else None,
                    },
                ],
                "links": [],
            }
        elif "充分性解释" in title:
            supplied = _visible_json(messages, "program_result")["program_result"]
            tp_ids = {item["criterion_id"] for item in supplied["tp_checks"]}
            output = {
                "rubric_version": supplied["rubric_version"],
                "criteria": supplied["tp_checks"] + [
                    item for item in supplied["fp_checks"]
                    if item["criterion_id"] not in tp_ids
                ],
                "unresolved_alternatives": supplied["unresolved_alternatives"],
            }
        elif "公共动作联合类型" in title:
            context = _visible_json(messages, "alert")
            alert, attempts = context["alert"], context["budget_usage"]["tool_attempts"]
            as_of = datetime.fromisoformat(alert["as_of"])
            window = {"start": (as_of - timedelta(minutes=10)).isoformat(),
                      "end": as_of.isoformat()}
            if attempts == 0:
                output = {"action": "tool", "tool": "siem", "arguments": {
                    "view": "process_tree", "window": window, "host": alert["host"],
                    "user": None, "process_id": alert["process_id"], "limit": 50,
                }}
            elif attempts == 1:
                output = {"action": "tool", "tool": "asset", "arguments": {
                    "host": alert["host"], "as_of": alert["as_of"],
                }}
            elif attempts == 2:
                output = {"action": "tool", "tool": "siem", "arguments": {
                    "view": "network_events", "window": window, "host": alert["host"],
                    "user": None, "process_id": alert["process_id"], "limit": 50,
                }}
            elif attempts == 3:
                entity_type = "user" if alert.get("user") else "host"
                entity = alert.get("user") or alert["host"]
                output = {"action": "tool", "tool": "history", "arguments": {
                    "entity_type": entity_type, "entity": entity,
                    "window": {"start": (as_of - timedelta(days=1)).isoformat(),
                               "end": as_of.isoformat()},
                    "host": alert["host"], "user": alert.get("user"),
                    "command_line": None, "limit": 50,
                }}
            else:
                output = {"action": "finish", "final": _conservative_final(context)}
        elif "最终评估输出" in title:
            output = _conservative_final(_visible_json(messages, "alert"))
        else:  # pragma: no cover - adding a schema requires an explicit design choice
            raise ValueError(f"unsupported fake-model schema: {title!r}")
        return output, Usage(input_tokens=100, output_tokens=50, usage_complete=True)


def _copy_inputs(target: Path, dataset: dict) -> dict[str, str]:
    sources = [DATA / "manifest.json", RUBRIC, ANNOTATIONS, Path(__file__)]
    sources += [DATA / name for name in dataset["file_sha256"]]
    prompt_names = set()
    for method in METHODS[:-1]:
        prompt_names.update(required_prompt_hashes(method))
    prompt_names.update(proposed_prompt_hashes())
    sources += [PROMPTS / name for name in sorted(prompt_names)]
    hashes = {}
    for source in sources:
        if source == Path(__file__):
            relative = Path("runner") / source.name
        elif DATA in source.parents or source == DATA / "manifest.json":
            relative = Path("datasets") / source.relative_to(DATA)
        elif source == RUBRIC:
            relative = Path("rubrics") / source.name
        elif source == ANNOTATIONS:
            relative = Path("annotations") / source.name
        else:
            relative = Path("prompts") / source.name
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        hashes[relative.as_posix()] = _file_hash(destination)
    return dict(sorted(hashes.items()))


def _case_rows(dataset: dict, selected: Iterable[str] | None = None) -> list[dict]:
    wanted = None if selected is None else set(selected)
    rows = [row for row in dataset["cases"] if wanted is None or row["case_id"] in wanted]
    if wanted is not None and {row["case_id"] for row in rows} != wanted:
        raise ValueError("selected cases must exist in the dataset manifest")
    return rows


def _method(method, adapter, manifest, run_root, rubric):
    if method == "direct":
        return DirectBaseline(adapter, manifest, run_root)
    if method in {"fixed", "fixed_all"}:
        return FixedWorkflowBaseline(adapter, manifest, run_root,
                                     include_all_tools=method == "fixed_all")
    if method == "react":
        return ReActBaseline(adapter, manifest, run_root)
    if method == "proposed":
        return EvidenceAwareInvestigator(
            adapter=adapter, manifest=manifest, output_dir=run_root, rubric=rubric
        )
    raise ValueError(method)


def _run_id(index: int, cohort: str, method: str, case_id: str, repeat: int) -> str:
    digest = sha256(f"{cohort}|{method}|{case_id}|{repeat}".encode()).hexdigest()[:12]
    return f"run-{index:04d}-{digest}"


async def _execute_run(*, root, run_root, row, method, repeat, cohort, budget,
                       index, dataset, code_revision, annotations, rubric):
    run_id = _run_id(index, cohort, method, row["case_id"], repeat)
    case = load_public(DATA / row["public"])
    environment = load_environment(DATA / row["environment"])
    oracle = load_oracle(DATA / row["oracle"])
    policy = LeakagePolicy(semantic_case_ids=tuple(item["case_id"] for item in dataset["cases"]))
    adapter = CapturingModelAdapter(EngineeringFakeModel(), policy=policy, mode="detect")
    prompt_hashes = (proposed_prompt_hashes() if method == "proposed"
                     else required_prompt_hashes(method))
    manifest = RunManifest(
        run_id=run_id, method=method, model_snapshot=MODEL_SNAPSHOT,
        model_parameters={"temperature": 0, "usage": "synthetic-constant-100-in-50-out",
                          "runner_sha256": _file_hash(Path(__file__))},
        prompt_hashes=prompt_hashes, dataset_version=dataset["dataset_version"],
        tool_snapshot=environment.fixture_version, rubric_version=dataset["rubric_version"],
        code_revision=code_revision, seed=repeat, seed_supported=True,
        budget=budget, price_snapshot={},
    )
    tools = MockToolServer(environment, simulate_latency=False)
    final = await _method(method, adapter, manifest, run_root, rubric).run(case, tools, budget)
    trace_dir = run_root / run_id
    capture_path = trace_dir / "model-requests.json"
    save_capture_bundle(capture_path, run_id, adapter.captures)
    applied = annotations if encode(annotations.budget_profile) == encode(budget) else None
    evaluation = evaluate_persisted_run(
        trace_dir, capture_path, oracle, manifest,
        leakage_policy=policy, annotation_set=applied,
    )
    bundle = read_trace(run_root, run_id)
    files = [trace_dir / name for name in
             ("manifest.json", "events.jsonl", "final.json", "model-requests.json")]
    return {
        "run_id": run_id, "cohort": cohort, "method": method,
        "case_id": row["case_id"], "repeat": repeat,
        "budget": encode(budget), "annotations_applied": applied is not None,
        "status": evaluation.score.run_status, "verdict": evaluation.score.verdict,
        "stop_reason": final.stop_reason, "trace_dir": trace_dir.relative_to(root).as_posix(),
        "capture_path": capture_path.relative_to(root).as_posix(),
        "model_request_count": evaluation.input_request_count,
        "leakage_finding_count": evaluation.leakage_finding_count,
        "usage": encode(bundle.final_payload["usage"]),
        "files": {path.relative_to(root).as_posix(): _file_hash(path) for path in files},
        "evaluation": evaluation, "manifest": manifest,
    }


def _report_markdown(records: list[dict], input_hashes: dict) -> str:
    lines = [
        "# M8a Fake Model Engineering Acceptance",
        "",
        "> This batch uses a deterministic fake model and five development fixtures. "
        "It validates engineering flow, persistence, replay and metric plumbing. "
        "It does not establish method superiority or real model quality.",
        "",
        "## Main matrix (raw run counts)", "",
        "| method | attempted | valid | TP | FP | Suspicious | Abstain | failed |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for method in METHODS:
        rows = [item for item in records if item["cohort"] == "main" and item["method"] == method]
        counts = Counter(item["verdict"] for item in rows if item["status"] == "valid")
        valid = sum(item["status"] == "valid" for item in rows)
        lines.append(f"| {method} | {len(rows)} | {valid} | {counts['TP']} | {counts['FP']} | "
                     f"{counts['Suspicious']} | {counts['Abstain']} | {len(rows)-valid} |")
    lines += ["", "## Budget smoke (raw run counts)", "",
              "| tool budget | method | attempted | valid | failed | verdict counts |",
              "|---:|---|---:|---:|---:|---|"]
    budgets = sorted({item["budget"]["max_tool_calls"] for item in records
                      if item["cohort"].startswith("budget-")})
    for budget in budgets:
        for method in METHODS:
            rows = [item for item in records
                    if item["cohort"] == f"budget-{budget}" and item["method"] == method]
            if not rows:
                continue
            valid = sum(item["status"] == "valid" for item in rows)
            counts = Counter(item["verdict"] for item in rows if item["status"] == "valid")
            lines.append(f"| {budget} | {method} | {len(rows)} | {valid} | {len(rows)-valid} | "
                         f"{dict(sorted(counts.items()))} |")
    failed = [item for item in records if item["status"] != "valid"]
    representatives = [item for item in records if item["status"] == "valid"][:2] + failed[:2]
    lines += ["", "## Archive and interpretation", "",
              f"- Runs archived: **{len(records)}**.",
              f"- Failed runs retained: **{len(failed)}**.",
              f"- Frozen input files: **{len(input_hashes)}**.",
              "- Default-budget annotations are applied only when the complete Budget matches.",
              "- Synthetic token counts exercise accounting paths; they are not provider usage or cost.",
              "- Repeats verify deterministic execution and do not increase independent case count.",
              "- M8b with a real model remains outside this acceptance result.",
              "", "Representative traces:"]
    lines += [f"- `{item['trace_dir']}` ({item['method']}, {item['case_id']}, "
              f"{item['status']}, {item['verdict']})" for item in representatives]
    return "\n".join(lines) + "\n"


async def run_benchmark(output: str | Path, *, repeats: int = 3,
                        budget_values: tuple[int, ...] = DEFAULT_BUDGETS,
                        methods: tuple[str, ...] = METHODS,
                        cases: tuple[str, ...] | None = None,
                        code_revision: str | None = None) -> dict:
    """Create one immutable benchmark artifact directory."""
    root = Path(output).resolve()
    if repeats < 1 or any(method not in METHODS for method in methods):
        raise ValueError("invalid repeats or method")
    root.mkdir(parents=True, exist_ok=False)
    dataset = load_json(DATA / "manifest.json")
    selected = _case_rows(dataset, cases)
    annotations = load_annotations(ANNOTATIONS)
    rubric = load_rubric(RUBRIC)
    revision = code_revision or _revision()
    input_hashes = _copy_inputs(root / "inputs", dataset)
    config = {
        "format_version": FORMAT_VERSION,
        "statement": "fake model engineering acceptance; no superiority claim",
        "dataset_version": dataset["dataset_version"],
        "rubric_version": dataset["rubric_version"],
        "annotation_version": annotations.annotation_version,
        "model_snapshot": MODEL_SNAPSHOT,
        "methods": list(methods), "cases": [row["case_id"] for row in selected],
        "main_repeats": repeats, "budget_smoke": list(budget_values),
        "code_revision": revision, "input_hashes": input_hashes,
        "rerun": f"python -m benchmark.m8a run --output <new-directory> --repeats {repeats}",
        "replay": "python -m benchmark.m8a replay --artifact <this-directory>",
    }
    _json(root / "config.json", config)
    records, report_paths, index = [], {}, 0

    async def cohort(name: str, budget: Budget, cohort_repeats: int):
        nonlocal index
        run_root = root / "runs" / name
        grouped = {method: [] for method in methods}
        manifests = {method: {} for method in methods}
        for method in methods:
            for row in selected:
                for repeat in range(1, cohort_repeats + 1):
                    index += 1
                    record = await _execute_run(
                        root=root, run_root=run_root, row=row, method=method,
                        repeat=repeat, cohort=name, budget=budget, index=index,
                        dataset=dataset, code_revision=revision, annotations=annotations,
                        rubric=rubric,
                    )
                    grouped[method].append(record["evaluation"])
                    manifests[method][record["run_id"]] = record["manifest"]
                    records.append(record)
        for method in methods:
            report = aggregate_report(
                grouped[method], method=method, dataset_version=dataset["dataset_version"],
                manifests=manifests[method],
            )
            path = root / "reports" / name / f"{method}.json"
            save_evaluation_report(path, report)
            report_paths[f"{name}/{method}"] = path.relative_to(root).as_posix()

    await cohort("main", Budget(), repeats)
    for value in budget_values:
        await cohort(f"budget-{value}", Budget(max_tool_calls=value), 1)

    public_records = [{key: value for key, value in record.items()
                       if key not in {"evaluation", "manifest"}} for record in records]
    (root / "reports" / "summary.md").write_text(
        _report_markdown(public_records, input_hashes), encoding="utf-8"
    )
    hashed_paths = sorted(path for path in root.rglob("*")
                          if path.is_file() and path.name not in {"inventory.json", "checksums.sha256"})
    inventory = {
        "format_version": FORMAT_VERSION, "config": "config.json",
        "run_count": len(public_records), "runs": public_records,
        "reports": report_paths, "summary": "reports/summary.md",
        "artifact_hashes": {path.relative_to(root).as_posix(): _file_hash(path)
                            for path in hashed_paths},
    }
    _json(root / "inventory.json", inventory)
    checksummed = sorted(path for path in root.rglob("*")
                         if path.is_file() and path.name != "checksums.sha256")
    (root / "checksums.sha256").write_text("".join(
        f"{_file_hash(path)}  {path.relative_to(root).as_posix()}\n" for path in checksummed
    ), encoding="utf-8")
    return inventory


def _verify_checksums(root: Path) -> int:
    lines = (root / "checksums.sha256").read_text(encoding="utf-8").splitlines()
    for line in lines:
        expected, relative = line.split("  ", 1)
        path = root / relative
        if not path.is_file() or _file_hash(path) != expected:
            raise ValueError(f"artifact checksum mismatch: {relative}")
    return len(lines)


def replay_artifact(artifact: str | Path) -> dict:
    """Re-evaluate persisted traces and captures without a model or tool call."""
    root = Path(artifact).resolve()
    checked = _verify_checksums(root)
    inventory, config = load_json(root / "inventory.json"), load_json(root / "config.json")
    dataset = load_json(root / "inputs" / "datasets" / "manifest.json")
    annotations = load_annotations(root / "inputs" / "annotations" / ANNOTATIONS.name)
    case_map = {row["case_id"]: row for row in dataset["cases"]}
    policy = LeakagePolicy(semantic_case_ids=tuple(case_map))
    grouped, manifests = {}, {}
    for record in inventory["runs"]:
        run_dir = root / record["trace_dir"]
        manifest = decode(RunManifest, load_json(run_dir / "manifest.json"))
        row = case_map[record["case_id"]]
        oracle = load_oracle(root / "inputs" / "datasets" / row["oracle"])
        applied = annotations if record["annotations_applied"] else None
        evaluation = evaluate_persisted_run(
            run_dir, root / record["capture_path"], oracle, manifest,
            leakage_policy=policy, annotation_set=applied,
        )
        if evaluation.score.run_status != record["status"] or evaluation.score.verdict != record["verdict"]:
            raise ValueError(f"replay changed run result: {record['run_id']}")
        key = (record["cohort"], record["method"])
        grouped.setdefault(key, []).append(evaluation)
        manifests.setdefault(key, {})[manifest.run_id] = manifest
    for key, runs in grouped.items():
        cohort, method = key
        recomputed = aggregate_report(
            runs, method=method, dataset_version=config["dataset_version"],
            manifests=manifests[key],
        )
        persisted = load_json(root / inventory["reports"][f"{cohort}/{method}"])
        if encode(recomputed) != persisted:
            raise ValueError(f"recomputed report differs: {cohort}/{method}")
    return {"format_version": FORMAT_VERSION, "verified_files": checked,
            "replayed_runs": len(inventory["runs"]), "reports": len(grouped)}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="execute a new immutable M8a batch")
    run.add_argument("--output", required=True)
    run.add_argument("--repeats", type=int, default=3)
    run.add_argument("--budget-scan", default="2,4,6,8")
    replay = commands.add_parser("replay", help="verify and re-evaluate an existing batch")
    replay.add_argument("--artifact", required=True)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "run":
        budgets = tuple(int(value) for value in args.budget_scan.split(",") if value)
        result = asyncio.run(run_benchmark(args.output, repeats=args.repeats,
                                           budget_values=budgets))
        print(json.dumps({"artifact": str(Path(args.output).resolve()),
                          "runs": result["run_count"]}, ensure_ascii=False))
    else:
        print(json.dumps(replay_artifact(args.artifact), ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
