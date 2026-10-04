"""M4 Trace 记录器测试：三件套落盘、事件校验、离线重放读取。"""

import json
from datetime import datetime, timezone

import pytest

from evidence_investigation.runtime.trace import TraceRecorder, read_trace
from evidence_investigation.state.contracts import (
    Budget, FinalAssessment, RunManifest, Usage,
)
from evidence_investigation.state.errors import ProtocolViolation

UTC = timezone.utc


def make_manifest(run_id="run-1"):
    return RunManifest(
        run_id=run_id, method="direct", model_snapshot="fake-1",
        model_parameters={"temperature": 0}, prompt_hashes={"final": "abc"},
        dataset_version="test", tool_snapshot="test-v1", rubric_version="none",
        code_revision="test", seed=None, seed_supported=False,
        budget=Budget(), price_snapshot={},
    )


def make_final():
    return FinalAssessment(
        verdict="Abstain", disposition="human_review", stop_reason="tool_budget",
        p_attack=None, claims=(), final_evidence_ids=(), unresolved_questions=("q",),
        risk_flags=("r",), abstain_reason="预算耗尽", confidence_status="uncalibrated",
    )


def test_three_files_written_and_replayable(tmp_path):
    recorder = TraceRecorder("run-1", make_manifest(), tmp_path,
                             usage_provider=lambda: Usage(input_tokens=10, output_tokens=5))
    first = recorder.emit("alert_received", {"alert": "a-1"}, step=0,
                          state_version_after=1)
    second = recorder.emit("tool_requested", {"call_id": "c-1", "tool": "siem"}, step=1,
                           state_version_after=2)
    assert (first.sequence, second.sequence) == (1, 2)
    assert first.timestamp.tzinfo is not None
    assert second.usage_snapshot.input_tokens == 10
    path = recorder.finalize(make_final())
    assert path.exists() and path.name == "final.json"
    run_dir = tmp_path / "run-1"
    assert {p.name for p in run_dir.iterdir()} == {"manifest.json", "events.jsonl", "final.json"}
    bundle = read_trace(tmp_path, "run-1")
    assert bundle.manifest.run_id == "run-1"
    assert [e.event_type for e in bundle.events] == ["alert_received", "tool_requested"]
    assert bundle.final.verdict == "Abstain"
    assert bundle.final_payload["event_count"] == 2


def test_unknown_event_type_rejected(tmp_path):
    recorder = TraceRecorder("run-2", make_manifest(), tmp_path,
                             usage_provider=Usage)
    with pytest.raises(ProtocolViolation, match="unknown_event"):
        recorder.emit("made_up_event", {})


def test_emit_after_finalize_rejected(tmp_path):
    recorder = TraceRecorder("run-3", make_manifest(), tmp_path, usage_provider=Usage)
    recorder.finalize(make_final())
    with pytest.raises(ProtocolViolation, match="trace_finalized"):
        recorder.emit("error", {})


def test_double_finalize_rejected(tmp_path):
    recorder = TraceRecorder("run-4", make_manifest(), tmp_path, usage_provider=Usage)
    recorder.finalize(make_final())
    with pytest.raises(ProtocolViolation, match="trace_finalized"):
        recorder.finalize(make_final())


def test_non_encodable_payload_rejected(tmp_path):
    recorder = TraceRecorder("run-5", make_manifest(), tmp_path, usage_provider=Usage)
    with pytest.raises(ProtocolViolation):
        recorder.emit("error", {"bad": object()})


def test_events_jsonl_is_line_oriented(tmp_path):
    recorder = TraceRecorder("run-6", make_manifest(), tmp_path, usage_provider=Usage)
    recorder.emit("alert_received", {"n": 1})
    recorder.emit("error", {"n": 2})
    lines = (tmp_path / "run-6" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and all(json.loads(line)["sequence"] for line in lines)
