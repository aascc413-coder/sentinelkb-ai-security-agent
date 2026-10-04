"""Independent timeout assertions include elapsed admission time, not scheduler guesses."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from evidence_investigation.state.contracts import (
    Coverage, Reliability, SIEMQuery, TimeWindow, ToolContext, ToolRecord,
)
from evidence_investigation.tools.contracts import EnvironmentFixture, FixtureRule
from evidence_investigation.tools.server import MockToolServer, content_hash

AS_OF = datetime(2026, 9, 1, 2, 20, tzinfo=timezone.utc)
WINDOW = TimeWindow(AS_OF - timedelta(minutes=10), AS_OF)


class AdmissionClock:
    def __init__(self, overhead_ms: int):
        self.overhead_seconds: float = overhead_ms / 1000.0
        self.reads: int = 0

    def __call__(self) -> float:
        self.reads += 1
        return 0.0 if self.reads == 1 else self.overhead_seconds


def server(overhead_ms: int):
    payload = {"view": "process_tree", "host": "h", "process_id": "p",
               "occurred_at": WINDOW.start.isoformat(), "observed_at": AS_OF.isoformat()}
    record = ToolRecord("opaque", payload, content_hash(payload), "sensor", "group",
                        Reliability("high", "test source", "v1"))
    coverage = Coverage({"view": "process_tree", "host": "h"}, WINDOW, "complete", False, ())
    rule = FixtureRule("siem", {"view": "process_tree", "host": "h"}, (record.record_id,),
                       "ok", coverage, False, None)
    env = EnvironmentFixture("opaque-env", AS_OF, {"siem": (record,)}, (rule,), "v1")
    clock = AdmissionClock(overhead_ms)
    return MockToolServer(env, simulate_latency=False, clock=clock), clock


@pytest.mark.asyncio
async def test_ten_ms_admission_consumes_deadline_leaving_forty_ms_backend():
    tool, clock = server(10)
    query = SIEMQuery("process_tree", WINDOW, "h", process_id="p")
    result = await tool.siem(query, ToolContext("run", "first", AS_OF, 50))
    assert result.status == "timeout" and result.records == () and result.retryable
    assert result.simulated_latency_ms == 40 and result.simulated_cost_units == 2.0
    assert result.actual_duration_ms == 10
    assert tool.stats().attempts == tool.stats().backend_calls == 1 and tool.stats().cache_hits == 0
    retry = await tool.siem(query, ToolContext("run", "retry", AS_OF, 1000))
    assert retry.status == "ok" and retry.records
    assert retry.simulated_cost_units == 2.0 and tool.stats().backend_calls == 2


@pytest.mark.asyncio
async def test_admission_exceeding_deadline_never_starts_or_charges_backend():
    tool, clock = server(60)
    result = await tool.siem(SIEMQuery("process_tree", WINDOW, "h"), ToolContext("run", "late", AS_OF, 50))
    assert result.status == "timeout" and result.records == () and result.retryable
    assert result.error_code == "deadline_exhausted"
    assert result.simulated_cost_units == result.simulated_latency_ms == 0
    assert result.actual_duration_ms == 60 and tool.stats().backend_calls == 0


def test_server_source_is_frozen_copy():
    import evidence_investigation.tools.server as implementation
    assert Path(implementation.__file__).resolve().is_relative_to(Path(__file__).parent)
