"""M8b real-model exploratory benchmark with an explicit spend guard.

The five development cases are public design fixtures.  Results are useful for
finding runtime and prompt failures, but are not evidence of generalization or
method superiority.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
from pathlib import Path
import shutil

from evaluation.annotation_loader import load_annotations
from evaluation.leakage import CapturingModelAdapter, LeakagePolicy, save_capture_bundle
from evaluation.oracle_loader import load_oracle
from evaluation.report import aggregate_report, evaluate_persisted_run, save_evaluation_report
from evidence_investigation.agents.investigator import required_prompt_hashes as proposed_prompt_hashes
from evidence_investigation.baselines.common import required_prompt_hashes
from evidence_investigation.runtime.model import ModelError, ModelFormatError, OpenAICompatAdapter
from evidence_investigation.runtime.trace import read_trace
from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.contracts import Budget, RunManifest, Usage
from evidence_investigation.state.content import load_json
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.state.rubric import load_rubric
from evidence_investigation.tools.fixture_loader import load_environment
from evidence_investigation.tools.server import MockToolServer

from benchmark.m8a import (
    ANNOTATIONS,
    DATA,
    LAB,
    METHODS,
    PROMPTS,
    RUBRIC,
    _case_rows,
    _file_hash,
    _json,
    _method,
    _revision,
    _verify_checksums,
)


FORMAT_VERSION = "m8b-real-model-exploration-v1"
COMPARISON_FORMAT_VERSION = "m9b-real-model-comparison-v1"
DEFAULT_ENV = LAB.parent / "code" / "python" / ".env"
DEFAULT_CAP_CNY = 7.0
CAP_FX_CNY_PER_USD = 8.0
DEEPSEEK_PRICES_USD_PER_MILLION = {
    "offpeak": {"input_cache_hit": 0.003, "input_cache_miss": 0.15, "output": 0.6},
    "peak": {"input_cache_hit": 0.006, "input_cache_miss": 0.3, "output": 1.2},
}
PRICE_SOURCE = "https://api-docs.deepseek.com/quick_start/pricing/"
PRICE_SNAPSHOT_DATE = "2026-10-24"


def load_env(path: str | Path) -> dict[str, str]:
    """Load simple KEY=VALUE settings without ever persisting the secret."""
    result: dict[str, str] = {}
    for raw in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip().strip('"').strip("'")
    required = ("OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL")
    missing = [name for name in required if not result.get(name)]
    if missing:
        raise ValueError(f"missing required environment values: {', '.join(missing)}")
    return result


def price_deepseek_usage(raw: dict, tier: str) -> tuple[float, str] | None:
    """Price measured tokens; absent cache detail is conservatively all miss."""
    prices = DEEPSEEK_PRICES_USD_PER_MILLION.get(tier)
    if prices is None:
        raise ValueError("billing tier must be peak or offpeak")
    prompt = raw.get("prompt_tokens")
    completion = raw.get("completion_tokens")
    hit = raw.get("prompt_cache_hit_tokens")
    miss = raw.get("prompt_cache_miss_tokens")
    if any(type(value) is not int or value < 0 for value in (prompt, completion)):
        return None
    if (type(hit) is not int or hit < 0 or type(miss) is not int or miss < 0
            or hit + miss != prompt):
        hit, miss = 0, prompt
    cost = (
        hit * prices["input_cache_hit"]
        + miss * prices["input_cache_miss"]
        + completion * prices["output"]
    ) / 1_000_000
    return cost, "USD"


@dataclass
class SpendLedger:
    cap_cny: float
    fx_cny_per_usd: float = CAP_FX_CNY_PER_USD
    spent_usd: float = 0.0
    priced_calls: int = 0
    unpriced_calls: int = 0

    def __post_init__(self):
        for value, name in ((self.cap_cny, "cap_cny"),
                            (self.fx_cny_per_usd, "fx_cny_per_usd")):
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value <= 0):
                raise ValueError(f"{name} must be positive and finite")

    @property
    def spent_cny_guard(self) -> float:
        return self.spent_usd * self.fx_cny_per_usd

    def reserve_call(self, messages, max_output_tokens: int) -> None:
        # Character count is a deliberately conservative input-token proxy for
        # these text-only JSON prompts.  Peak, cache-miss rates protect the cap
        # even when the run itself is billed off peak.
        input_chars = len(json.dumps(messages, ensure_ascii=False, separators=(",", ":")))
        peak = DEEPSEEK_PRICES_USD_PER_MILLION["peak"]
        reserve_usd = (
            input_chars * peak["input_cache_miss"]
            + max_output_tokens * peak["output"]
        ) / 1_000_000
        if (self.spent_usd + reserve_usd) * self.fx_cny_per_usd > self.cap_cny:
            raise ModelError("M8b authorized spend cap would be exceeded")

    def record(self, usage: Usage | None) -> None:
        if usage is None or usage.model_cost is None or usage.currency != "USD":
            self.unpriced_calls += 1
            return
        self.spent_usd += usage.model_cost
        self.priced_calls += 1


class SpendGuardedAdapter:
    def __init__(self, adapter, ledger: SpendLedger):
        self.adapter = adapter
        self.ledger = ledger

    async def complete(self, messages, output_schema, max_output_tokens, timeout_seconds):
        self.ledger.reserve_call(messages, max_output_tokens)
        try:
            output, usage = await self.adapter.complete(
                messages, output_schema, max_output_tokens, timeout_seconds
            )
        except ModelFormatError as exc:
            self.ledger.record(exc.usage)
            raise
        self.ledger.record(usage)
        return output, usage

    async def aclose(self):
        await self.adapter.aclose()


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


def _run_id(index: int, method: str, case_id: str, model: str) -> str:
    digest = sha256(f"m8b|{method}|{case_id}|{model}".encode()).hexdigest()[:12]
    return f"run-{index:04d}-{digest}"


async def _execute_run(*, root, run_root, row, method, index, dataset,
                       code_revision, annotations, rubric, budget, config, ledger,
                       billing_tier):
    run_id = _run_id(index, method, row["case_id"], config["model"])
    case = load_public(DATA / row["public"])
    environment = load_environment(DATA / row["environment"])
    oracle = load_oracle(DATA / row["oracle"])
    policy = LeakagePolicy(semantic_case_ids=tuple(item["case_id"] for item in dataset["cases"]))
    base = OpenAICompatAdapter(
        api_key=config["api_key"],
        base_url=config["base_url"],
        model=config["model"],
        timeout_seconds=budget.max_time_seconds,
        request_parameters={"thinking": {"type": "disabled"}},
        usage_pricer=lambda raw: price_deepseek_usage(raw, billing_tier),
    )
    adapter = CapturingModelAdapter(SpendGuardedAdapter(base, ledger), policy=policy, mode="detect")
    prompt_hashes = proposed_prompt_hashes() if method == "proposed" else required_prompt_hashes(method)
    price_snapshot = {
        "provider": "DeepSeek official API",
        "source": PRICE_SOURCE,
        "snapshot_date": PRICE_SNAPSHOT_DATE,
        "billing_tier": billing_tier,
        "prices_usd_per_million_tokens": DEEPSEEK_PRICES_USD_PER_MILLION[billing_tier],
        "cap_fx_cny_per_usd": ledger.fx_cny_per_usd,
    }
    manifest = RunManifest(
        run_id=run_id,
        method=method,
        model_snapshot=f"{config['model']}@official-{PRICE_SNAPSHOT_DATE}",
        model_parameters={
            "temperature": 0,
            "thinking": "disabled",
            "response_format": "json_object",
            "runner_sha256": _file_hash(Path(__file__)),
        },
        prompt_hashes=prompt_hashes,
        dataset_version=dataset["dataset_version"],
        tool_snapshot=environment.fixture_version,
        rubric_version=dataset["rubric_version"],
        code_revision=code_revision,
        seed=None,
        seed_supported=False,
        budget=budget,
        price_snapshot=price_snapshot,
    )
    tools = MockToolServer(environment, simulate_latency=False)
    try:
        final = await _method(method, adapter, manifest, run_root, rubric).run(case, tools, budget)
    finally:
        await adapter.aclose()
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
        "run_id": run_id,
        "cohort": "main",
        "method": method,
        "case_id": row["case_id"],
        "budget": encode(budget),
        "annotations_applied": applied is not None,
        "status": evaluation.score.run_status,
        "verdict": evaluation.score.verdict,
        "stop_reason": final.stop_reason,
        "trace_dir": trace_dir.relative_to(root).as_posix(),
        "capture_path": capture_path.relative_to(root).as_posix(),
        "model_request_count": evaluation.input_request_count,
        "leakage_finding_count": evaluation.leakage_finding_count,
        "usage": encode(bundle.final_payload["usage"]),
        "files": {path.relative_to(root).as_posix(): _file_hash(path) for path in files},
        "evaluation": evaluation,
        "manifest": manifest,
    }


def _report_markdown(records: list[dict], ledger: SpendLedger, input_hashes: dict) -> str:
    lines = [
        "# M8b Real Model Exploratory Report",
        "",
        "> This batch uses one real model on five public development fixtures. "
        "It is an exploratory runtime check and does not establish generalization "
        "or method superiority.",
        "",
        "## Raw outcomes", "",
        "| method | attempted | valid | TP | FP | Suspicious | Abstain | failed |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for method in METHODS:
        rows = [item for item in records if item["method"] == method]
        counts = Counter(item["verdict"] for item in rows if item["status"] == "valid")
        valid = sum(item["status"] == "valid" for item in rows)
        lines.append(
            f"| {method} | {len(rows)} | {valid} | {counts['TP']} | {counts['FP']} | "
            f"{counts['Suspicious']} | {counts['Abstain']} | {len(rows)-valid} |"
        )
    lines += [
        "", "## Per-case records", "",
        "| case | method | status | verdict | stop reason | model calls | input tokens | output tokens | cost USD |",
        "|---|---|---|---|---|---:|---:|---:|---:|",
    ]
    for item in records:
        usage = item["usage"]
        cost = usage["model_cost"]
        shown_cost = "unknown" if cost is None else f"{cost:.8f}"
        lines.append(
            f"| {item['case_id']} | {item['method']} | {item['status']} | "
            f"{item['verdict']} | {item['stop_reason']} | {usage['model_calls']} | "
            f"{usage['input_tokens']} | {usage['output_tokens']} | {shown_cost} |"
        )
    failed = [item for item in records if item["status"] != "valid"]
    lines += [
        "", "## Spend and archive", "",
        f"- Authorized cap: **{ledger.cap_cny:.2f} CNY**.",
        f"- Calculated provider charge: **${ledger.spent_usd:.6f} USD**.",
        f"- Conservative cap accounting: **{ledger.spent_cny_guard:.4f} CNY** "
        f"at {ledger.fx_cny_per_usd:.2f} CNY/USD.",
        f"- Priced calls: **{ledger.priced_calls}**; calls without complete pricing fields: "
        f"**{ledger.unpriced_calls}**.",
        f"- Runs archived: **{len(records)}**; failed runs retained: **{len(failed)}**.",
        f"- Frozen input files: **{len(input_hashes)}**.",
        "- Costs are calculated from provider-reported token counters and the frozen official price snapshot; "
        "the provider dashboard remains the billing authority.",
        "- If a response omits a valid cache hit/miss split, all of its input tokens are priced as cache misses.",
        "- Results that conflict with expectations remain in the archive unchanged.",
    ]
    if failed:
        lines += ["", "Failed traces:"] + [
            f"- `{item['trace_dir']}` ({item['method']}, {item['case_id']}, {item['stop_reason']})"
            for item in failed
        ]
    return "\n".join(lines) + "\n"


async def run_benchmark(output: str | Path, *, env_file: str | Path = DEFAULT_ENV,
                        cap_cny: float = DEFAULT_CAP_CNY, billing_tier: str = "offpeak",
                        methods: tuple[str, ...] = METHODS,
                        cases: tuple[str, ...] | None = None,
                        code_revision: str | None = None) -> dict:
    root = Path(output).resolve()
    if any(method not in METHODS for method in methods):
        raise ValueError("invalid method")
    if billing_tier not in DEEPSEEK_PRICES_USD_PER_MILLION:
        raise ValueError("billing tier must be peak or offpeak")
    root.mkdir(parents=True, exist_ok=False)
    dataset = load_json(DATA / "manifest.json")
    selected = _case_rows(dataset, cases)
    annotations = load_annotations(ANNOTATIONS)
    rubric = load_rubric(RUBRIC)
    revision = code_revision or _revision()
    env = load_env(env_file)
    config_secret = {
        "api_key": env["OPENAI_API_KEY"],
        "base_url": env["OPENAI_BASE_URL"],
        "model": env["OPENAI_MODEL"],
    }
    input_hashes = _copy_inputs(root / "inputs", dataset)
    ledger = SpendLedger(cap_cny)
    public_config = {
        "format_version": FORMAT_VERSION,
        "statement": "real-model exploratory run; no generalization or superiority claim",
        "provider": "DeepSeek official API",
        "base_url": config_secret["base_url"],
        "model": config_secret["model"],
        "api_key_stored": False,
        "model_parameters": {"temperature": 0, "thinking": "disabled", "response_format": "json_object"},
        "dataset_version": dataset["dataset_version"],
        "rubric_version": dataset["rubric_version"],
        "annotation_version": annotations.annotation_version,
        "methods": list(methods),
        "cases": [row["case_id"] for row in selected],
        "budget": encode(Budget()),
        "authorized_cap_cny": cap_cny,
        "cap_fx_cny_per_usd": ledger.fx_cny_per_usd,
        "billing_tier": billing_tier,
        "price_source": PRICE_SOURCE,
        "price_snapshot_date": PRICE_SNAPSHOT_DATE,
        "prices_usd_per_million_tokens": DEEPSEEK_PRICES_USD_PER_MILLION[billing_tier],
        "code_revision": revision,
        "input_hashes": input_hashes,
        "rerun": "python -m benchmark.m8b run --output <new-directory> --env-file <local-.env>",
        "replay": "python -m benchmark.m8b replay --artifact <this-directory>",
    }
    _json(root / "config.json", public_config)
    budget = Budget()
    records = []
    grouped = {method: [] for method in methods}
    manifests = {method: {} for method in methods}
    run_root = root / "runs" / "main"
    index = 0
    for method in methods:
        for row in selected:
            index += 1
            record = await _execute_run(
                root=root, run_root=run_root, row=row, method=method, index=index,
                dataset=dataset, code_revision=revision, annotations=annotations,
                rubric=rubric, budget=budget, config=config_secret, ledger=ledger,
                billing_tier=billing_tier,
            )
            grouped[method].append(record["evaluation"])
            manifests[method][record["run_id"]] = record["manifest"]
            records.append(record)
            print(json.dumps({
                "completed": index,
                "total": len(methods) * len(selected),
                "method": method,
                "case": row["case_id"],
                "verdict": record["verdict"],
                "spent_cny_guard": round(ledger.spent_cny_guard, 6),
            }, ensure_ascii=False), flush=True)
    report_paths = {}
    for method in methods:
        report = aggregate_report(
            grouped[method], method=method, dataset_version=dataset["dataset_version"],
            manifests=manifests[method],
        )
        path = root / "reports" / "main" / f"{method}.json"
        save_evaluation_report(path, report)
        report_paths[f"main/{method}"] = path.relative_to(root).as_posix()
    public_records = [
        {key: value for key, value in record.items() if key not in {"evaluation", "manifest"}}
        for record in records
    ]
    (root / "reports" / "summary.md").write_text(
        _report_markdown(public_records, ledger, input_hashes), encoding="utf-8"
    )
    hashed_paths = sorted(path for path in root.rglob("*")
                          if path.is_file() and path.name not in {"inventory.json", "checksums.sha256"})
    inventory = {
        "format_version": FORMAT_VERSION,
        "config": "config.json",
        "run_count": len(public_records),
        "runs": public_records,
        "reports": report_paths,
        "summary": "reports/summary.md",
        "spend": {
            "calculated_usd": ledger.spent_usd,
            "cap_accounting_cny": ledger.spent_cny_guard,
            "authorized_cap_cny": ledger.cap_cny,
            "priced_calls": ledger.priced_calls,
            "unpriced_calls": ledger.unpriced_calls,
        },
        "artifact_hashes": {
            path.relative_to(root).as_posix(): _file_hash(path) for path in hashed_paths
        },
    }
    _json(root / "inventory.json", inventory)
    checksummed = sorted(path for path in root.rglob("*")
                         if path.is_file() and path.name != "checksums.sha256")
    (root / "checksums.sha256").write_text("".join(
        f"{_file_hash(path)}  {path.relative_to(root).as_posix()}\n" for path in checksummed
    ), encoding="utf-8")
    return inventory


def replay_artifact(artifact: str | Path) -> dict:
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
        oracle = load_oracle(root / "inputs" / "datasets" / case_map[record["case_id"]]["oracle"])
        applied = annotations if record["annotations_applied"] else None
        evaluation = evaluate_persisted_run(
            run_dir, root / record["capture_path"], oracle, manifest,
            leakage_policy=policy, annotation_set=applied,
        )
        if (evaluation.score.run_status != record["status"]
                or evaluation.score.verdict != record["verdict"]):
            raise ValueError(f"replay changed run result: {record['run_id']}")
        key = (record["cohort"], record["method"])
        grouped.setdefault(key, []).append(evaluation)
        manifests.setdefault(key, {})[manifest.run_id] = manifest
    for (cohort, method), runs in grouped.items():
        recomputed = aggregate_report(
            runs, method=method, dataset_version=config["dataset_version"],
            manifests=manifests[(cohort, method)],
        )
        persisted = load_json(root / inventory["reports"][f"{cohort}/{method}"])
        if encode(recomputed) != persisted:
            raise ValueError(f"recomputed report differs: {cohort}/{method}")
    return {
        "format_version": FORMAT_VERSION,
        "verified_files": checked,
        "replayed_runs": len(inventory["runs"]),
        "reports": len(grouped),
    }


def _repair_count(root: Path, record: dict) -> int:
    trace = Path(record["trace_dir"])
    bundle = read_trace(root / trace.parent, trace.name)
    repaired = {
        event.payload.get("call_id")
        for event in bundle.events
        if (event.event_type == "model_output_recorded"
            and event.payload.get("repaired_output") is not None)
    }
    return len(repaired)


def _proposed_records(inventory: dict) -> dict[str, dict]:
    rows = [item for item in inventory["runs"] if item["method"] == "proposed"]
    indexed = {item["case_id"]: item for item in rows}
    if len(indexed) != len(rows):
        raise ValueError("duplicate proposed case in artifact")
    return indexed


def _comparison_rows(baseline: dict[str, dict], candidate: dict[str, dict],
                     baseline_repairs: dict[str, int], candidate_repairs: dict[str, int]):
    if set(baseline) != set(candidate):
        raise ValueError("baseline and candidate proposed case sets differ")
    rows = []
    all_cases = {"model_calls": [0, 0], "repair_count": [0, 0]}
    paired = {"input_tokens": [0, 0], "output_tokens": [0, 0],
              "model_cost_usd": [0.0, 0.0],
              "cases": 0, "priced_cases": 0}
    for case_id in sorted(baseline):
        before, after = baseline[case_id], candidate[case_id]
        before_usage, after_usage = before["usage"], after["usage"]
        complete = bool(before_usage["usage_complete"] and after_usage["usage_complete"])
        before_cost = (before_usage["model_cost"]
                       if before_usage.get("currency") == "USD" else None)
        after_cost = (after_usage["model_cost"]
                      if after_usage.get("currency") == "USD" else None)
        before_view = {
            "status": before["status"], "verdict": before["verdict"],
            "stop_reason": before["stop_reason"],
            "model_calls": before_usage["model_calls"],
            "input_tokens": before_usage["input_tokens"] if before_usage["usage_complete"] else None,
            "output_tokens": before_usage["output_tokens"] if before_usage["usage_complete"] else None,
            "model_cost_usd": before_cost,
            "repair_count": baseline_repairs[case_id],
        }
        after_view = {
            "status": after["status"], "verdict": after["verdict"],
            "stop_reason": after["stop_reason"],
            "model_calls": after_usage["model_calls"],
            "input_tokens": after_usage["input_tokens"] if after_usage["usage_complete"] else None,
            "output_tokens": after_usage["output_tokens"] if after_usage["usage_complete"] else None,
            "model_cost_usd": after_cost,
            "repair_count": candidate_repairs[case_id],
        }
        delta = {
            "model_calls": after_view["model_calls"] - before_view["model_calls"],
            "repair_count": after_view["repair_count"] - before_view["repair_count"],
            "input_tokens": None,
            "output_tokens": None,
            "model_cost_usd": None,
        }
        for key in ("model_calls", "repair_count"):
            all_cases[key][0] += before_view[key]
            all_cases[key][1] += after_view[key]
        if complete:
            delta["input_tokens"] = after_view["input_tokens"] - before_view["input_tokens"]
            delta["output_tokens"] = after_view["output_tokens"] - before_view["output_tokens"]
            paired["cases"] += 1
            for key in ("input_tokens", "output_tokens"):
                paired[key][0] += before_view[key]
                paired[key][1] += after_view[key]
            if before_cost is not None and after_cost is not None:
                delta["model_cost_usd"] = after_cost - before_cost
                paired["model_cost_usd"][0] += before_cost
                paired["model_cost_usd"][1] += after_cost
                paired["priced_cases"] += 1
        rows.append({
            "case_id": case_id,
            "baseline": before_view,
            "candidate": after_view,
            "delta_candidate_minus_baseline": delta,
            "outcome_changed": (
                before_view["status"], before_view["verdict"], before_view["stop_reason"]
            ) != (
                after_view["status"], after_view["verdict"], after_view["stop_reason"]
            ),
        })
    paired_totals = {
        "complete_usage_case_count": paired.pop("cases"),
        "priced_case_count": paired.pop("priced_cases"),
        **{key: {"baseline": values[0], "candidate": values[1],
                 "delta_candidate_minus_baseline": values[1] - values[0]}
           for key, values in paired.items()},
    }
    all_totals = {
        key: {"baseline": values[0], "candidate": values[1],
              "delta_candidate_minus_baseline": values[1] - values[0]}
        for key, values in all_cases.items()
    }
    return rows, all_totals, paired_totals


def compare_artifacts(baseline: str | Path, candidate: str | Path) -> dict:
    """Verify and compare Proposed runs without calling a model or tool."""
    roots = (Path(baseline).resolve(), Path(candidate).resolve())
    replayed = tuple(replay_artifact(root) for root in roots)
    inventories = tuple(load_json(root / "inventory.json") for root in roots)
    configs = tuple(load_json(root / "config.json") for root in roots)
    comparable_fields = (
        "provider", "base_url", "model", "model_parameters", "dataset_version",
        "rubric_version", "annotation_version", "cases", "budget", "billing_tier",
        "price_snapshot_date", "prices_usd_per_million_tokens",
    )
    mismatches = [name for name in comparable_fields if configs[0].get(name) != configs[1].get(name)]
    frozen_prefixes = ("datasets/", "annotations/", "rubrics/")
    frozen_hashes = tuple({key: value for key, value in config["input_hashes"].items()
                           if key.startswith(frozen_prefixes)} for config in configs)
    if frozen_hashes[0] != frozen_hashes[1]:
        mismatches.append("frozen_input_hashes")
    if mismatches:
        raise ValueError("artifacts are not comparable: " + ", ".join(mismatches))
    proposed = tuple(_proposed_records(item) for item in inventories)
    repairs = tuple({case_id: _repair_count(root, record)
                     for case_id, record in records.items()}
                    for root, records in zip(roots, proposed))
    rows, all_totals, paired_totals = _comparison_rows(
        proposed[0], proposed[1], repairs[0], repairs[1]
    )
    return {
        "format_version": COMPARISON_FORMAT_VERSION,
        "statement": (
            "paired exploratory comparison on public development fixtures; "
            "no generalization or superiority claim"
        ),
        "baseline": {"path": str(roots[0]), "code_revision": configs[0]["code_revision"],
                     "replay": replayed[0]},
        "candidate": {"path": str(roots[1]), "code_revision": configs[1]["code_revision"],
                      "replay": replayed[1]},
        "rows": rows,
        "all_case_totals": all_totals,
        "paired_complete_usage_totals": paired_totals,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="execute a new immutable M8b batch")
    run.add_argument("--output", required=True)
    run.add_argument("--env-file", default=str(DEFAULT_ENV))
    run.add_argument("--cap-cny", type=float, default=DEFAULT_CAP_CNY)
    run.add_argument("--billing-tier", choices=("offpeak", "peak"), default="offpeak")
    run.add_argument("--methods", default=",".join(METHODS))
    run.add_argument("--cases", default="")
    replay = commands.add_parser("replay", help="verify and re-evaluate an existing batch")
    replay.add_argument("--artifact", required=True)
    compare = commands.add_parser("compare", help="verify and compare two real-model batches")
    compare.add_argument("--baseline", required=True)
    compare.add_argument("--candidate", required=True)
    compare.add_argument("--output")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "run":
        result = asyncio.run(run_benchmark(
            args.output, env_file=args.env_file, cap_cny=args.cap_cny,
            billing_tier=args.billing_tier,
            methods=tuple(value for value in args.methods.split(",") if value),
            cases=tuple(value for value in args.cases.split(",") if value) or None,
        ))
        print(json.dumps({
            "artifact": str(Path(args.output).resolve()),
            "runs": result["run_count"],
            "spend": result["spend"],
        }, ensure_ascii=False))
    elif args.command == "replay":
        print(json.dumps(replay_artifact(args.artifact), ensure_ascii=False))
    else:
        comparison = compare_artifacts(args.baseline, args.candidate)
        rendered = json.dumps(comparison, ensure_ascii=False, indent=1)
        if args.output:
            target = Path(args.output)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(rendered + "\n", encoding="utf-8")
            print(json.dumps({"output": str(target.resolve()),
                              "paired_cases": len(comparison["rows"])}, ensure_ascii=False))
        else:
            print(rendered)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
