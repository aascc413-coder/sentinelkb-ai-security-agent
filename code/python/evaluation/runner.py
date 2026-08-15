"""Run a reproducible end-to-end RAG evaluation against the local API."""

from __future__ import annotations

import argparse
import json
import statistics
import time
import unicodedata
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ABSTAIN_MARKERS = (
    "无法回答",
    "无法确定",
    "没有相关",
    "没有提供",
    "没有找到",
    "没有任何关于",
    "未提供",
    "未提及",
    "未涉及",
    "不包含",
    "未找到",
    "知识库没有",
    "上下文中没有",
    "资料中没有",
)


def normalize(value: str) -> str:
    return "".join(unicodedata.normalize("NFKC", value).lower().split())


def source_basename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def is_retryable_error(exc: Exception) -> bool:
    message = str(exc)
    return any(token in message for token in ("RateLimitError", "HTTP 429", "HTTP 502", "timed out"))


def evaluate_case(case: dict[str, Any], response: dict[str, Any], latency_ms: float) -> dict[str, Any]:
    answer = str(response.get("answer", ""))
    normalized_answer = normalize(answer)
    sources = [source_basename(str(item.get("source", ""))) for item in response.get("sources", [])]
    should_abstain = bool(case.get("should_abstain", False))
    abstained = should_abstain and any(
        normalize(marker) in normalized_answer for marker in ABSTAIN_MARKERS
    )

    groups = case.get("required_term_groups", [])
    matched_groups = [
        any(normalize(str(term)) in normalized_answer for term in group)
        for group in groups
    ]
    fact_coverage = sum(matched_groups) / len(matched_groups) if matched_groups else 1.0
    expected_source = str(case.get("expected_source", "")).lower()
    source_hit = expected_source in sources if expected_source else True

    if should_abstain:
        passed = abstained
    else:
        passed = fact_coverage >= float(case.get("minimum_fact_coverage", 1.0)) and source_hit

    return {
        "id": case["id"],
        "question": case["question"],
        "passed": passed,
        "should_abstain": should_abstain,
        "abstained": abstained,
        "fact_coverage": round(fact_coverage, 4),
        "source_hit": source_hit,
        "expected_source": case.get("expected_source"),
        "returned_sources": sources,
        "confidence": response.get("confidence", 0.0),
        "latency_ms": round(latency_ms, 2),
        "answer_excerpt": answer[:240].replace("\n", " "),
    }


def request_json(url: str, *, method: str = "GET", payload: dict[str, Any] | None = None, timeout: float = 90.0) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc


def upload_document(base_url: str, path: Path, timeout: float) -> dict[str, Any]:
    boundary = f"----SentinelKBEval{uuid.uuid4().hex}"
    prefix = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
    ).encode("utf-8")
    body = prefix + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}/api/ingest/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Upload {path.name} failed with HTTP {exc.code}: {detail}") from exc


def build_summary(results: list[dict[str, Any]], elapsed_ms: float) -> dict[str, Any]:
    latencies = [float(item["latency_ms"]) for item in results]
    answerable = [item for item in results if not item["should_abstain"]]
    abstention = [item for item in results if item["should_abstain"]]
    return {
        "case_count": len(results),
        "passed": sum(1 for item in results if item["passed"]),
        "pass_rate": round(sum(1 for item in results if item["passed"]) / max(len(results), 1), 4),
        "fact_coverage": round(statistics.mean(item["fact_coverage"] for item in answerable), 4) if answerable else 0.0,
        "source_hit_rate": round(statistics.mean(float(item["source_hit"]) for item in answerable), 4) if answerable else 0.0,
        "abstention_accuracy": round(statistics.mean(float(item["abstained"]) for item in abstention), 4) if abstention else 0.0,
        "retry_count": sum(int(item.get("retry_count", 0)) for item in results),
        "api_error_count": sum(1 for item in results if item.get("error")),
        "latency_p50_ms": round(percentile(latencies, 0.50), 2),
        "latency_p95_ms": round(percentile(latencies, 0.95), 2),
        "total_elapsed_ms": round(elapsed_ms, 2),
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# SentinelKB RAG 评测报告",
        "",
        f"- 数据集：{report['dataset']['name']} `{report['dataset']['version']}`",
        f"- 运行时间：{report['generated_at']}",
        f"- API：`{report['base_url']}`",
        f"- 通过率：**{summary['passed']}/{summary['case_count']} ({summary['pass_rate']:.0%})**",
        f"- 关键事实覆盖率：**{summary['fact_coverage']:.0%}**",
        f"- 来源命中率：**{summary['source_hit_rate']:.0%}**",
        f"- 拒答准确率：**{summary['abstention_accuracy']:.0%}**",
        f"- 瞬时错误重试：`{summary['retry_count']}` 次；最终 API 错误：`{summary['api_error_count']}` 个",
        f"- 延迟：P50 `{summary['latency_p50_ms']:.0f} ms`，P95 `{summary['latency_p95_ms']:.0f} ms`",
        "",
        "| 用例 | 结果 | 事实覆盖 | 来源命中 | 拒答 | 重试 | 延迟(ms) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for item in report["results"]:
        lines.append(
            f"| {item['id']} | {'PASS' if item['passed'] else 'FAIL'} | "
            f"{item['fact_coverage']:.0%} | {'是' if item['source_hit'] else '否'} | "
            f"{'是' if item['abstained'] else '否'} | {item.get('retry_count', 0)} | {item['latency_ms']:.0f} |"
        )
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> dict[str, Any]:
    dataset_path = Path(args.dataset).resolve()
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    base_url = args.base_url.rstrip("/")
    health = request_json(f"{base_url}/api/health", timeout=args.timeout)
    uploads: list[dict[str, Any]] = []
    if not args.skip_upload:
        for relative_path in dataset.get("documents", []):
            path = (dataset_path.parent / relative_path).resolve()
            response = upload_document(base_url, path, args.timeout)
            uploads.append({"file": path.name, "status": response.get("status")})

    results: list[dict[str, Any]] = []
    started = time.perf_counter()
    for index, case in enumerate(dataset["cases"], start=1):
        case_started = time.perf_counter()
        response = None
        final_error: Exception | None = None
        retry_count = 0
        for attempt in range(args.retries + 1):
            try:
                response = request_json(
                    f"{base_url}/api/qa/ask",
                    method="POST",
                    payload={"question": case["question"]},
                    timeout=args.timeout,
                )
                break
            except Exception as exc:
                final_error = exc
                if attempt >= args.retries or not is_retryable_error(exc):
                    break
                retry_count += 1
                delay = args.retry_backoff * (2 ** attempt)
                print(f"  transient model error; retry {retry_count}/{args.retries} in {delay:.1f}s")
                time.sleep(delay)

        if response is not None:
            item = evaluate_case(case, response, (time.perf_counter() - case_started) * 1000)
            item["retry_count"] = retry_count
        else:
            exc = final_error or RuntimeError("No model response")
            item = {
                "id": case["id"],
                "question": case["question"],
                "passed": False,
                "should_abstain": bool(case.get("should_abstain", False)),
                "abstained": False,
                "fact_coverage": 0.0,
                "source_hit": False,
                "expected_source": case.get("expected_source"),
                "returned_sources": [],
                "confidence": 0.0,
                "latency_ms": round((time.perf_counter() - case_started) * 1000, 2),
                "error": f"{type(exc).__name__}: {exc}",
                "answer_excerpt": "",
                "retry_count": retry_count,
            }
        results.append(item)
        print(f"[{index:02d}/{len(dataset['cases']):02d}] {'PASS' if item['passed'] else 'FAIL'} {item['id']} ({item['latency_ms']:.0f} ms)")
        if index < len(dataset["cases"]) and args.request_interval > 0:
            time.sleep(args.request_interval)

    elapsed_ms = (time.perf_counter() - started) * 1000
    report = {
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "base_url": base_url,
        "health": health,
        "dataset": {"name": dataset["name"], "version": dataset["version"]},
        "uploads": uploads,
        "summary": build_summary(results, elapsed_ms),
        "results": results,
    }
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "rag_eval_latest.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (output_dir / "rag_eval_latest.md").write_text(render_markdown(report), encoding="utf-8")
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument(
        "--dataset",
        default=str(Path(__file__).with_name("security_rag_cases.json")),
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).parents[3] / "docs" / "evaluation"),
    )
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--skip-upload", action="store_true")
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--retry-backoff", type=float, default=4.0)
    parser.add_argument("--request-interval", type=float, default=1.0)
    return parser.parse_args()


def main() -> int:
    report = run(parse_args())
    summary = report["summary"]
    print(
        f"\nPass rate {summary['pass_rate']:.0%} | facts {summary['fact_coverage']:.0%} | "
        f"sources {summary['source_hit_rate']:.0%} | abstention {summary['abstention_accuracy']:.0%} | "
        f"P95 {summary['latency_p95_ms']:.0f} ms"
    )
    return 0 if summary["pass_rate"] >= 0.8 else 1


if __name__ == "__main__":
    raise SystemExit(main())
