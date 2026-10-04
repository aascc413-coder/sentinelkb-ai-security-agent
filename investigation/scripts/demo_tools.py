"""Offline generic tool demo, not a replay of the M2 C1-C5 dataset."""

import asyncio
from datetime import datetime, timedelta, timezone
import json

from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import (
    Coverage, Reliability, SIEMQuery, TimeWindow, ToolContext, ToolRecord,
)
from evidence_investigation.tools.contracts import EnvironmentFixture, FixtureRule
from evidence_investigation.tools.server import MockToolServer, content_hash


async def main():
    as_of = datetime(2026, 9, 1, 2, 20, tzinfo=timezone.utc)
    window = TimeWindow(as_of-timedelta(minutes=10), as_of)
    payload = {"view":"process_tree", "host":"demo-host", "process_id":"demo-process",
               "occurred_at":(as_of-timedelta(minutes=2)).isoformat(),
               "observed_at":(as_of-timedelta(minutes=1)).isoformat(),
               "command_line":"PowerShell -File task.ps1"}
    record = ToolRecord("opaque-record", payload, content_hash(payload), "mock-siem",
                        "local-sensor", Reliability("high", "offline demo", "demo-v1"))
    coverage = Coverage({"host":"demo-host", "view":"process_tree"}, window, "complete", False, ())
    rule = FixtureRule("siem", {"host":"demo-host", "view":"process_tree"},
                       (record.record_id,), "ok", coverage, False, None)
    fixture = EnvironmentFixture("opaque-demo", as_of, {"siem":(record,)}, (rule,), "demo-v1")
    server = MockToolServer(fixture, simulate_latency=False)
    query = SIEMQuery("process_tree", window, "demo-host", process_id="demo-process")
    results = []
    for call in ("first", "cached"):
        result = await server.siem(query, ToolContext("demo-run", call, as_of, 1000))
        results.append({"call_id":result.call_id, "status":result.status,
                        "records":len(result.records), "cost_units":result.simulated_cost_units,
                        "simulated_latency_ms":result.simulated_latency_ms})
    unknown = SIEMQuery("process_tree", window, "unknown-host")
    missing = await server.siem(unknown, ToolContext("demo-run", "unknown", as_of, 1000))
    results.append({"call_id":missing.call_id, "status":missing.status,
                    "coverage":missing.coverage.completeness, "error_code":missing.error_code})
    print(json.dumps({"mode":"generic offline demo; not M2 replay", "calls":results,
                      "stats":encode(server.stats())}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
