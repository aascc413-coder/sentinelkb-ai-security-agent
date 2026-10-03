"""M1 校验层测试（P2.1 验收：错误引用、错误时区、非法参数均被拒绝）。"""

from datetime import datetime, timedelta, timezone

import pytest

from evidence_investigation.state import validation
from evidence_investigation.state.contracts import (
    Alert,
    Claim,
    Evidence,
    FinalAssessment,
    RawReference,
    Reliability,
    SIEMQuery,
    Source,
    TimeWindow,
    TIQuery,
)
from evidence_investigation.state.errors import ProtocolViolation

UTC = timezone.utc
PLUS8 = timezone(timedelta(hours=8))
T0 = datetime(2026, 9, 1, 2, 14, tzinfo=UTC)


def _alert(**overrides):
    base = dict(
        alert_id="a-1",
        alert_type="powershell_encoded",
        occurred_at=T0,
        as_of=T0.replace(minute=20),
        host="WS-041",
        user="analyst-a",
        process_id="p-101",
        command_line=None,
        raw={"rule": "suspicious"},
        raw_reference=RawReference("rec-1", "/alerts/0", "ab" * 32),
    )
    base.update(overrides)
    return Alert(**base)


def _evidence(**overrides):
    base = dict(
        evidence_id="e-1",
        fact_key="WS-041/process/p-101/exec",
        evidence_type="process_execution",
        subject="WS-041",
        predicate="executed",
        value="powershell -enc ...",
        occurred_at=T0,
        observed_at=T0.replace(minute=15),
        valid_until=None,
        source=Source("alert", "edr", "snap-1", None),
        raw_reference=RawReference("rec-1", "/alerts/0", "ab" * 32),
        reliability=Reliability("high", "edr record", "pol-1"),
        independence_group="g-1",
    )
    base.update(overrides)
    return validation.validate_evidence(Evidence(**base))


# ── 时区 ─────────────────────────────────────────────────────────

def test_naive_datetime_rejected():
    with pytest.raises(ProtocolViolation, match="not_utc"):
        validation.require_utc(datetime(2026, 9, 1, 2, 14), "x")


def test_non_utc_offset_rejected():
    with pytest.raises(ProtocolViolation, match="not_utc"):
        validation.require_utc(datetime(2026, 9, 1, 10, 14, tzinfo=PLUS8), "x")


def test_utc_accepted():
    assert validation.require_utc(T0, "x") is T0


# ── 时间窗与告警 ────────────────────────────────────────────────

def test_window_start_not_before_end_rejected():
    with pytest.raises(ProtocolViolation, match="invalid_window"):
        validation.require_time_window(TimeWindow(T0, T0))


def test_alert_occurred_after_as_of_rejected():
    with pytest.raises(ProtocolViolation, match="occurred_after_as_of"):
        validation.validate_alert(_alert(occurred_at=T0.replace(minute=30)))


# ── 概率与成本 ──────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [-0.1, 1.01, 2])
def test_probability_out_of_range_rejected(bad):
    with pytest.raises(ProtocolViolation, match="invalid_probability"):
        validation.require_probability(bad, "p_attack")


def test_probability_none_allowed():
    assert validation.require_probability(None, "p_attack") is None


def test_negative_cost_rejected():
    with pytest.raises(ProtocolViolation, match="negative_cost"):
        validation.require_non_negative(-1, "cost")


# ── 引用与子集 ──────────────────────────────────────────────────

def test_dangling_reference_rejected():
    with pytest.raises(ProtocolViolation, match="dangling_reference"):
        validation.require_known_references(["e-9"], ["e-1", "e-2"], "claim 引用")


def test_duplicate_id_rejected():
    with pytest.raises(ProtocolViolation, match="duplicate_id"):
        validation.require_unique(["e-1", "e-1"], "evidence")


def test_final_evidence_must_be_subset():
    with pytest.raises(ProtocolViolation, match="dangling_reference"):
        validation.require_final_evidence_subset(["e-2"], ["e-1"])


# ── 来源-call 一致性 ────────────────────────────────────────────

def test_tool_source_without_call_id_rejected():
    with pytest.raises(ProtocolViolation, match="missing_call_id"):
        _evidence(source=Source("tool", "siem", "snap-1", None))


def test_alert_source_without_call_id_accepted():
    _evidence()  # 不抛异常即通过


# ── 查询参数 ────────────────────────────────────────────────────

def test_siem_query_invalid_limit_rejected():
    q = SIEMQuery(
        view="process_tree",
        window=TimeWindow(T0, T0 + timedelta(hours=1)),
        limit=0,
    )
    with pytest.raises(ProtocolViolation, match="invalid_limit"):
        validation.validate_query(q)


def test_ti_query_empty_value_rejected():
    with pytest.raises(ProtocolViolation, match="missing_entity"):
        validation.validate_query(TIQuery("ip", "  ", T0))


def test_siem_query_valid_accepted():
    q = SIEMQuery(
        view="process_tree",
        window=TimeWindow(T0, T0 + timedelta(hours=1)),
        host="WS-041",
    )
    assert validation.validate_query(q) is q


# ── M1-A5：查询分型校验缺口 ─────────────────────────────────────

def test_siem_limit_above_50_rejected():
    q = SIEMQuery(
        view="process_tree", window=TimeWindow(T0, T0 + timedelta(hours=1)),
        host="WS-041", limit=51,
    )
    with pytest.raises(ProtocolViolation, match="invalid_limit"):
        validation.validate_query(q)


def test_siem_limit_non_integer_rejected():
    q = SIEMQuery(
        view="process_tree", window=TimeWindow(T0, T0 + timedelta(hours=1)),
        host="WS-041", limit=1.5,
    )
    with pytest.raises(ProtocolViolation, match="invalid_limit"):
        validation.validate_query(q)


def test_host_events_without_host_or_user_rejected():
    q = SIEMQuery(
        view="host_events", window=TimeWindow(T0, T0 + timedelta(hours=1)),
        host=None, user=None,
    )
    with pytest.raises(ProtocolViolation, match="missing_entity"):
        validation.validate_query(q)


def test_user_events_without_user_rejected():
    q = SIEMQuery(
        view="user_events", window=TimeWindow(T0, T0 + timedelta(hours=1)),
        host=None, user=None,
    )
    with pytest.raises(ProtocolViolation, match="missing_entity"):
        validation.validate_query(q)


def test_siem_window_over_24h_rejected():
    q = SIEMQuery(
        view="process_tree", window=TimeWindow(T0, T0 + timedelta(hours=25)),
        host="WS-041",
    )
    with pytest.raises(ProtocolViolation, match="window_too_wide"):
        validation.validate_query(q)


def test_history_window_over_30d_rejected():
    from evidence_investigation.state.contracts import HistoryQuery

    q = HistoryQuery(
        entity_type="host", entity="WS-041",
        window=TimeWindow(T0, T0 + timedelta(days=31)),
    )
    with pytest.raises(ProtocolViolation, match="window_too_wide"):
        validation.validate_query(q)


def test_history_window_30d_accepted():
    from evidence_investigation.state.contracts import HistoryQuery

    q = HistoryQuery(
        entity_type="host", entity="WS-041",
        window=TimeWindow(T0, T0 + timedelta(days=30)),
    )
    assert validation.validate_query(q) is q


# ── M1-A4：NaN / Infinity ───────────────────────────────────────

def test_non_negative_rejects_nan_and_inf():
    import math

    with pytest.raises(ProtocolViolation, match="invalid_number"):
        validation.require_non_negative(math.nan, "cost")
    with pytest.raises(ProtocolViolation, match="invalid_number"):
        validation.require_non_negative(math.inf, "cost")


def test_probability_rejects_nan():
    import math

    with pytest.raises(ProtocolViolation, match="invalid_probability"):
        validation.require_probability(math.nan, "p_attack")


# ── 最终评估 ────────────────────────────────────────────────────

def _final(**overrides):
    base = dict(
        verdict="TP",
        disposition="escalate",
        stop_reason="sufficient",
        p_attack=0.9,
        claims=(Claim("c-1", "WS-041", "executed", "enc", ("e-1",), "t", "observation"),),
        final_evidence_ids=("e-1",),
        unresolved_questions=(),
        risk_flags=(),
        abstain_reason=None,
        confidence_status="uncalibrated",
    )
    base.update(overrides)
    return FinalAssessment(**base)


def test_final_with_dangling_claim_reference_rejected():
    bad_claim = Claim("c-1", "h", "p", "v", ("e-9",), "t", "observation")
    with pytest.raises(ProtocolViolation, match="dangling_reference"):
        validation.validate_final_assessment(_final(claims=(bad_claim,)), ["e-1"])


def test_protocol_error_with_tp_rejected():
    with pytest.raises(ProtocolViolation, match="invalid_final_combination"):
        validation.validate_final_assessment(
            _final(stop_reason="protocol_error"), ["e-1"]
        )


def test_final_valid_accepted():
    assert validation.validate_final_assessment(_final(), ["e-1"]) is not None
