"""运行时校验（M1，P2.1 验收：错误引用、错误时区、非法参数均被拒绝）。

全部为确定性检查，不依赖模型；失败抛出 ProtocolViolation(code, message)。
校验范围来自设计稿 4.3 节运行时约束与 V4-3 计量要求。
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import Iterable

from .contracts import (
    Alert,
    AssetQuery,
    AttackQuery,
    Evidence,
    FinalAssessment,
    HistoryQuery,
    SIEMQuery,
    TIQuery,
    TimeWindow,
    ToolArguments,
)
from .errors import ProtocolViolation

_UTC = timedelta(0)
_MAX_SIEM_WINDOW = timedelta(hours=24)  # 设计稿 7 节：SIEM 最大时间窗 24h
_MAX_HISTORY_WINDOW = timedelta(days=30)  # 设计稿 7 节：history 最大时间窗 30d
_MAX_LIMIT = 50  # 设计稿 7 节：结果上限 50


def require_utc(dt: datetime, name: str) -> datetime:
    """必须为带时区的 UTC 时间（offset 为 0），拒绝 naive 与非 UTC 时区。"""
    if dt.tzinfo is None or dt.utcoffset() != _UTC:
        raise ProtocolViolation(
            "not_utc", f"{name} 必须为 UTC（带时区且偏移为 0），收到 {dt!r}"
        )
    return dt


def require_time_window(window: TimeWindow, name: str = "window") -> TimeWindow:
    require_utc(window.start, f"{name}.start")
    require_utc(window.end, f"{name}.end")
    if window.start >= window.end:
        raise ProtocolViolation(
            "invalid_window", f"{name} 要求 start < end，收到 {window.start} >= {window.end}"
        )
    return window


def _require_window_span(window: TimeWindow, maximum: timedelta, name: str) -> None:
    if window.end - window.start > maximum:
        raise ProtocolViolation(
            "window_too_wide", f"{name} 超过最大跨度 {maximum}（设计稿 7 节）"
        )


def require_probability(p: float | None, name: str) -> float | None:
    if p is None:
        return None
    if (
        isinstance(p, bool)
        or not isinstance(p, (int, float))
        or not math.isfinite(p)
        or not 0.0 <= p <= 1.0
    ):
        raise ProtocolViolation(
            "invalid_probability", f"{name} 必须在 [0,1] 或为 None，收到 {p!r}"
        )
    return float(p)


def require_non_negative(value: float, name: str) -> float:
    """非负且必须有限（M1-A4：NaN/Infinity 使比较失效且非合法 JSON 数值）。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ProtocolViolation("invalid_number", f"{name} 必须为有限数值，收到 {value!r}")
    if value < 0:
        raise ProtocolViolation("negative_cost", f"{name} 必须非负，收到 {value!r}")
    return float(value)


def _require_limit(limit: int, name: str = "limit") -> None:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ProtocolViolation("invalid_limit", f"{name} 必须为整数，收到 {limit!r}")
    if not 1 <= limit <= _MAX_LIMIT:
        raise ProtocolViolation(
            "invalid_limit", f"{name} 必须在 1–{_MAX_LIMIT} 之间，收到 {limit}"
        )


def _require_entity(value: str | None, name: str) -> str:
    if value is None or not str(value).strip():
        raise ProtocolViolation("missing_entity", f"{name} 不能为空")
    return str(value)


def require_not_after(published: datetime, as_of: datetime, name: str) -> None:
    """数据发布时间不得晚于 as_of（设计稿 11 节：禁止用未来 TI 解答过去事件）。"""
    if published > as_of:
        raise ProtocolViolation(
            "published_after_as_of", f"{name} 发布时间 {published} 晚于 as_of {as_of}"
        )


def require_unique(ids: Iterable[str], name: str) -> None:
    seen: set[str] = set()
    for item in ids:
        if item in seen:
            raise ProtocolViolation("duplicate_id", f"{name} 存在重复 ID：{item}")
        seen.add(item)


def require_known_references(
    referenced: Iterable[str], known: Iterable[str], name: str
) -> None:
    """引用的 ID 必须存在（如 evidence_id / call_id）。"""
    known_set = set(known)
    for item in referenced:
        if item not in known_set:
            raise ProtocolViolation(
                "dangling_reference", f"{name} 引用了不存在的 ID：{item}"
            )


def require_final_evidence_subset(
    final_evidence_ids: Iterable[str], available_evidence_ids: Iterable[str]
) -> None:
    """最终证据必须是已获得事实的子集（设计稿 4.3）。"""
    require_known_references(final_evidence_ids, available_evidence_ids, "最终证据")


def require_source_call_consistency(evidence: Evidence) -> None:
    """tool/knowledge 来源的事实必须有可追溯 call_id（contracts.py Source 注释）。"""
    if evidence.source.kind in ("tool", "knowledge") and not evidence.source.call_id:
        raise ProtocolViolation(
            "missing_call_id",
            f"证据 {evidence.evidence_id} 来源为 {evidence.source.kind}，必须携带 call_id",
        )


def validate_query(query: ToolArguments) -> ToolArguments:
    """工具请求参数校验（M1-A5：按具体 Query 类型检查 limit/窗口/实体）。

    实体必须属于 alert/已获记录的检查由 M4 Dispatcher 依据 Registry 承接，
    此处校验参数自身的类型、范围与必备实体。
    """
    if isinstance(query, SIEMQuery):
        require_time_window(query.window)
        _require_window_span(query.window, _MAX_SIEM_WINDOW, "SIEM 查询窗口")
        _require_limit(query.limit)
        if query.view == "user_events":
            _require_entity(query.user, "user_events 查询的 user")
        else:  # host_events / process_tree / network_events 以 host 为锚
            _require_entity(query.host, f"{query.view} 查询的 host")
    elif isinstance(query, TIQuery):
        require_utc(query.as_of, "TIQuery.as_of")
        _require_entity(query.value, "TI 查询的 value")
    elif isinstance(query, AssetQuery):
        require_utc(query.as_of, "AssetQuery.as_of")
        _require_entity(query.host, "Asset 查询的 host")
    elif isinstance(query, HistoryQuery):
        require_time_window(query.window)
        _require_window_span(query.window, _MAX_HISTORY_WINDOW, "History 查询窗口")
        _require_limit(query.limit)
        _require_entity(query.entity, "History 查询的 entity")
    elif isinstance(query, AttackQuery):
        _require_entity(query.snapshot_version, "ATT&CK 查询的 snapshot_version")
    else:
        raise ProtocolViolation("unknown_query", f"未知查询类型 {type(query).__name__}")
    return query


def validate_alert(alert: Alert) -> Alert:
    """告警规范化边界：UTC 时间、发布顺序、必填 ID。"""
    require_utc(alert.occurred_at, "alert.occurred_at")
    require_utc(alert.as_of, "alert.as_of")
    if alert.occurred_at > alert.as_of:
        raise ProtocolViolation(
            "occurred_after_as_of",
            f"告警发生时间 {alert.occurred_at} 晚于 as_of {alert.as_of}",
        )
    if not alert.alert_id:
        raise ProtocolViolation("missing_alert_id", "alert_id 不能为空")
    return alert


def validate_evidence(evidence: Evidence) -> Evidence:
    """单条证据校验：时间、来源-call 一致、必填标识。"""
    if evidence.occurred_at is not None:
        require_utc(evidence.occurred_at, f"evidence[{evidence.evidence_id}].occurred_at")
    require_utc(evidence.observed_at, f"evidence[{evidence.evidence_id}].observed_at")
    if evidence.valid_until is not None:
        require_utc(evidence.valid_until, f"evidence[{evidence.evidence_id}].valid_until")
        if evidence.occurred_at is not None and evidence.valid_until < evidence.occurred_at:
            raise ProtocolViolation(
                "invalid_validity", f"证据 {evidence.evidence_id} valid_until 早于 occurred_at"
            )
    if not evidence.evidence_id or not evidence.fact_key:
        raise ProtocolViolation(
            "missing_evidence_identity",
            f"证据缺少 evidence_id/fact_key：{evidence.evidence_id!r}/{evidence.fact_key!r}",
        )
    require_source_call_consistency(evidence)
    return evidence


def validate_final_assessment(
    assessment: FinalAssessment, available_evidence_ids: Iterable[str]
) -> FinalAssessment:
    """最终评估校验：概率范围、最终证据 ⊆ 已获事实、claim 引用存在。"""
    require_probability(assessment.p_attack, "final.p_attack")
    require_final_evidence_subset(assessment.final_evidence_ids, available_evidence_ids)
    claim_evidence_ids = [
        eid for claim in assessment.claims for eid in claim.evidence_ids
    ]
    require_known_references(claim_evidence_ids, available_evidence_ids, "claim 证据引用")
    if assessment.verdict in ("TP", "FP") and assessment.stop_reason == "protocol_error":
        raise ProtocolViolation(
            "invalid_final_combination",
            "protocol_error 停止原因不得与确定性结论 TP/FP 组合（设计稿 4.3）",
        )
    return assessment
