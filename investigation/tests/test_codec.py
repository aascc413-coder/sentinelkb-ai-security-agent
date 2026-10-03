"""M1 编解码测试：契约对象 ↔ JSON 往返一致；非法输入被拒绝。"""

from datetime import datetime, timezone

import pytest

from evidence_investigation.state import codec
from evidence_investigation.state.contracts import (
    Alert,
    Claim,
    Coverage,
    Evidence,
    FinalAssessment,
    RawReference,
    Reliability,
    Source,
    TimeWindow,
    ToolRecord,
    ToolResult,
)
from evidence_investigation.state.errors import ProtocolViolation

UTC = timezone.utc
T0 = datetime(2026, 9, 1, 2, 14, 0, tzinfo=UTC)

ALERT = Alert(
    alert_id="a-1",
    alert_type="powershell_encoded",
    occurred_at=T0,
    as_of=datetime(2026, 9, 1, 2, 20, tzinfo=UTC),
    host="WS-041",
    user=None,
    process_id="p-101",
    command_line="powershell -enc AAAA",
    raw={"rule": "suspicious-encoded", "score": 7},
    raw_reference=RawReference("rec-1", "/alerts/0", "ab" * 32),
)

EVIDENCE = Evidence(
    evidence_id="e-1",
    fact_key="WS-041/process/p-101/exec",
    evidence_type="process_execution",
    subject="WS-041",
    predicate="executed",
    value="powershell -enc AAAA",
    occurred_at=T0,
    observed_at=datetime(2026, 9, 1, 2, 15, tzinfo=UTC),
    valid_until=None,
    source=Source("alert", "edr", "snap-1", None),
    raw_reference=RawReference("rec-1", "/alerts/0", "ab" * 32),
    reliability=Reliability("high", "edr record", "pol-1"),
    independence_group="g-1",
)

TOOL_RESULT = ToolResult(
    call_id="c-1",
    tool="siem",
    status="ok",
    records=(
        ToolRecord(
            record_id="r-1",
            payload={"cmdline": "powershell -enc AAAA", "pid": 101},
            content_sha256="cd" * 32,
            source_system="siem",
            independence_group="siem-1",
            reliability=Reliability("medium", "log source", "pol-1"),
        ),
    ),
    coverage=Coverage(
        scope={"host": "WS-041"},
        window=TimeWindow(T0, datetime(2026, 9, 1, 3, 14, tzinfo=UTC)),
        completeness="complete",
        truncated=False,
        missing_sources=(),
    ),
    snapshot_version="snap-1",
    error_code=None,
    retryable=False,
    simulated_cost_units=2.0,
    simulated_latency_ms=200,
    actual_duration_ms=3,
)

FINAL = FinalAssessment(
    verdict="Abstain",
    disposition="human_review",
    stop_reason="tool_budget",
    p_attack=None,
    claims=(),
    final_evidence_ids=("e-1",),
    unresolved_questions=("脚本正文缺失",),
    risk_flags=("编码执行",),
    abstain_reason="预算耗尽且证据不足",
    confidence_status="uncalibrated",
)


@pytest.mark.parametrize(
    ("tp", "obj"),
    [(Alert, ALERT), (Evidence, EVIDENCE), (ToolResult, TOOL_RESULT), (FinalAssessment, FINAL)],
)
def test_round_trip(tp, obj):
    data = codec.encode(obj)
    restored = codec.decode(tp, data)
    assert restored == obj


def test_encode_datetime_is_iso_string():
    data = codec.encode(ALERT)
    assert data["occurred_at"] == "2026-09-01T02:14:00+00:00"
    assert isinstance(data["raw"], dict)


def test_decode_naive_datetime_still_parses():
    # 解码不强制 UTC；UTC 约束在使用点由 validation 强制。
    data = codec.encode(ALERT)
    data["occurred_at"] = "2026-09-01T02:14:00"
    restored = codec.decode(Alert, data)
    assert restored.occurred_at.tzinfo is None


def test_decode_unknown_field_rejected():
    data = codec.encode(ALERT)
    data["phantom"] = 1
    with pytest.raises(ProtocolViolation, match="decode_unknown_field"):
        codec.decode(Alert, data)


def test_decode_missing_required_field_rejected():
    data = codec.encode(ALERT)
    del data["alert_id"]
    with pytest.raises(ProtocolViolation, match="decode_missing_field"):
        codec.decode(Alert, data)


def test_decode_bad_datetime_rejected():
    with pytest.raises(ProtocolViolation, match="invalid_datetime"):
        codec.decode(datetime, "not-a-date")


def test_decode_bool_as_int_rejected():
    with pytest.raises(ProtocolViolation, match="decode_type_mismatch"):
        codec.decode(int, True)


def test_decode_union_picks_matching_branch():
    from evidence_investigation.state.contracts import SIEMQuery, ToolCall

    call_data = {
        "tool": "siem",
        "arguments": {
            "view": "network_events",
            "window": {"start": "2026-09-01T02:14:00+00:00",
                       "end": "2026-09-01T03:14:00+00:00"},
        },
    }
    call = codec.decode(ToolCall, call_data)
    assert isinstance(call.arguments, SIEMQuery)
    assert call.arguments.view == "network_events"
    assert call.arguments.window == TimeWindow(
        datetime(2026, 9, 1, 2, 14, tzinfo=UTC),
        datetime(2026, 9, 1, 3, 14, tzinfo=UTC),
    )


# ── M1-A1：嵌套 JsonValue 递归解码 ──────────────────────────────

def test_decode_nested_json_value():
    from evidence_investigation.state.contracts import JsonValue

    deep = {"process": {"pid": 123, "children": [{"cmd": "pwsh", "ports": [443, 8080]}]}}
    assert codec.decode(JsonValue, deep) == deep


def test_alert_with_deep_raw_round_trip():
    deep_raw = {
        "rule": "suspicious-encoded",
        "event": {"parent": {"name": "WINWORD.EXE", "pid": 900},
                  "children": [{"pid": 101, "cmd": "powershell -enc AAAA"}],
                  "tags": [1, True, None, 2.5]},
    }
    alert = Alert(
        alert_id="a-2", alert_type="powershell_encoded",
        occurred_at=T0, as_of=datetime(2026, 9, 1, 2, 20, tzinfo=UTC),
        host="WS-041", user="analyst-a", process_id="p-101",
        command_line="powershell -enc AAAA",
        raw=deep_raw,
        raw_reference=RawReference("rec-1", "/alerts/0", "ab" * 32),
    )
    assert codec.decode(Alert, codec.encode(alert)) == alert


def test_tool_record_payload_nested_round_trip():
    restored = codec.decode(ToolResult, codec.encode(TOOL_RESULT))
    assert restored.records[0].payload == {"cmdline": "powershell -enc AAAA", "pid": 101}


# ── M1-A3：float 接受合法 JSON 整数 ─────────────────────────────

def test_decode_float_accepts_integer_literal():
    assert codec.decode(float, 1) == 1.0
    assert codec.decode(float, 0) == 0.0


def test_decode_float_rejects_bool():
    with pytest.raises(ProtocolViolation, match="decode_type_mismatch"):
        codec.decode(float, True)


# ── M1-A4：NaN / Infinity 拒绝 ──────────────────────────────────

def test_encode_rejects_non_finite():
    import math

    with pytest.raises(ProtocolViolation, match="non_finite_number"):
        codec.encode(float("nan"))
    with pytest.raises(ProtocolViolation, match="non_finite_number"):
        codec.encode(float("inf"))


def test_decode_rejects_non_finite():
    with pytest.raises(ProtocolViolation, match="non_finite_number"):
        codec.decode(float, float("nan"))
    with pytest.raises(ProtocolViolation, match="non_finite_number"):
        codec.decode(
            __import__("evidence_investigation.state.contracts", fromlist=["JsonValue"]).JsonValue,
            {"x": float("inf")},
        )


# ── M1-A6：字典键类型校验 ───────────────────────────────────────

def test_decode_dict_with_tool_name_keys_rejects_unknown():
    from evidence_investigation.state.contracts import ToolName

    with pytest.raises(ProtocolViolation, match="decode_type_mismatch"):
        codec.decode(dict[ToolName, int], {"hidden_tool": 1})


def test_decode_dict_with_tool_name_keys_accepts_known():
    from evidence_investigation.state.contracts import ToolName

    out = codec.decode(dict[ToolName, int], {"siem": 1, "asset": 2})
    assert out == {"siem": 1, "asset": 2}
