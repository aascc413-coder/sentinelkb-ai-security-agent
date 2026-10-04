"""Five-case tool replay; no model calls, verdicts, or oracle access.

Manifest is developer-side wiring. Each invocation supplies only PublicCase to
the caller and EnvironmentFixture to the server. This is not an Agent runner.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from evidence_investigation.state.codec import encode
from evidence_investigation.state.content import load_json
from evidence_investigation.state.contracts import (
    AssetQuery, AttackQuery, HistoryQuery, SIEMQuery, TIQuery, TimeWindow, ToolContext,
)
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.tools.diff_report import compare_responses, normalization_policy
from evidence_investigation.tools.fixture_loader import load_environment
from evidence_investigation.tools.server import MockToolServer
from datetime import timedelta

LAB = Path(__file__).resolve().parents[1]


def representative_queries(alert):
    """Tool-layer equivalence probes, not an authorized planner action sequence.

    Unknown entities deliberately test server filtering. Dispatcher enforcement
    that planner entities came from observations belongs to M4.
    """
    window = TimeWindow(alert.as_of - timedelta(minutes=10), alert.as_of)
    history_window = TimeWindow(alert.as_of - timedelta(days=1), alert.as_of)
    queries = []
    for view in ("host_events", "user_events", "process_tree", "network_events"):
        queries.append(("siem", SIEMQuery(view, window, alert.host, alert.user, alert.process_id)))
        queries.append(("siem", SIEMQuery(view, window, alert.host, alert.user, alert.process_id, 1)))
        queries.append(("siem", SIEMQuery(view, window, "unobserved-host", alert.user, alert.process_id)))
        queries.append(("siem", SIEMQuery(view, TimeWindow(window.start, alert.occurred_at), alert.host, alert.user, alert.process_id)))
    queries.extend([("asset", AssetQuery(alert.host, alert.as_of)),
                    ("asset", AssetQuery("unobserved-host", alert.as_of))])
    for kind, entity in (("host", alert.host), ("user", alert.user), ("command", "unobserved-command")):
        queries.append(("history", HistoryQuery(kind, entity, history_window, alert.host, alert.user)))
    queries.extend([("threat_intel", TIQuery("ip", "192.0.2.1", alert.as_of)),
                    ("threat_intel", TIQuery("domain", "example.test", alert.as_of)),
                    ("threat_intel", TIQuery("hash", "h-unobserved", alert.as_of)),
                    ("attack", AttackQuery("attack-local-v1", technique_ids=("T1059.001",))),
                    ("attack", AttackQuery("attack-local-v1", behavior_terms=("PowerShell",))),
                    ("attack", AttackQuery("attack-local-v1", technique_ids=("T0000",)))])
    return queries


async def replay():
    root = LAB / "datasets"
    manifest = load_json(root / "manifest.json")
    results, servers = {}, {}
    for entry in manifest["cases"]:
        public = load_public(root / entry["public"])
        server = MockToolServer(load_environment(root / entry["environment"]), simulate_latency=False)
        servers[entry["case_id"]] = server
        alert = public.alert
        window = TimeWindow(alert.as_of - timedelta(minutes=10), alert.as_of)
        calls = []

        async def invoke(tool, query):
            ctx = ToolContext("replay-run", f"replay-call-{len(calls)}", alert.as_of, 5000)
            response = await getattr(server, tool)(query, ctx)
            calls.append({"tool": tool, "arguments": encode(query), "result": encode(response)})
            return response

        for view in ("process_tree", "network_events"):
            await invoke("siem", SIEMQuery(view, window, alert.host, alert.user, alert.process_id))
        await invoke("asset", AssetQuery(alert.host, alert.as_of))
        await invoke("history", HistoryQuery("user", alert.user, TimeWindow(alert.as_of - timedelta(days=1), alert.as_of), alert.host, alert.user))
        indicators = {(kind, record["payload"][key]) for call in calls for record in call["result"]["records"]
                      for kind, key in (("ip", "destination_ip"), ("hash", "script_hash"))
                      if isinstance(record["payload"].get(key), str)}
        for kind, value in sorted(indicators):
            await invoke("threat_intel", TIQuery(kind, value, alert.as_of))
        await invoke("attack", AttackQuery("attack-local-v1", technique_ids=("T1059.001",)))
        cached = await invoke("siem", SIEMQuery("process_tree", window, alert.host, alert.user, alert.process_id))
        assert cached.simulated_cost_units == 0
        results[entry["case_id"]] = {"calls": calls, "stats": encode(server.stats())}

    alert = load_public(root / "public/c4.json").alert
    left, right = (MockToolServer(load_environment(root / "environment/shared-pair.json"), simulate_latency=False) for _ in range(2))
    comparisons = []
    for index, (tool, query) in enumerate(representative_queries(alert)):
        a = await getattr(left, tool)(query, ToolContext("left-run", f"left-{index}", alert.as_of, 5000))
        b = await getattr(right, tool)(query, ToolContext("right-run", f"right-{index}", alert.as_of, 5000))
        comparisons.append({"tool": tool, "arguments": encode(query), "comparison": compare_responses(a, b)})
    return {"kind": "M3 tool integration, no model or verdict benchmark", "dataset_version": manifest["dataset_version"],
            "cases": results, "paired_queries": len(comparisons),
            "paired_equal": all(c["comparison"]["equal"] for c in comparisons),
            "normalization_policy": normalization_policy(), "paired_comparisons": comparisons,
            "limits": "Finite representative queries; actual model-request equivalence deferred to M5."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=LAB / "runs/seed-tool-replay.json")
    args = parser.parse_args()
    report = asyncio.run(replay())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"cases": {case: [call["result"]["status"] for call in result["calls"]]
                               for case, result in report["cases"].items()},
                      "paired_queries": report["paired_queries"], "paired_equal": report["paired_equal"],
                      "report": str(args.output)}, ensure_ascii=False, indent=2))
    if not report["paired_equal"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
