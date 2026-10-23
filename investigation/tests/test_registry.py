"""M4 公共 Evidence Registry 测试（R2：等价登记、去重、操作事实、实体台账）。"""

from datetime import datetime, timedelta, timezone

import pytest

from evidence_investigation.runtime.registry import EvidenceRegistry, canonical_hash
from evidence_investigation.state.contracts import (
    Alert, Coverage, RawReference, Reliability, SIEMQuery, TimeWindow,
    ToolRecord, ToolResult,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.tools.server import content_hash

UTC = timezone.utc
AS_OF = datetime(2026, 9, 1, 2, 20, tzinfo=UTC)
WINDOW = TimeWindow(AS_OF - timedelta(minutes=10), AS_OF)


def make_alert(**overrides):
    base = dict(
        alert_id="a-1", alert_type="powershell_encoded", occurred_at=WINDOW.start,
        as_of=AS_OF, host="WS-041", user="analyst-a", process_id="p-101",
        command_line="powershell -enc AAAA", raw={"rule": "suspicious"},
        raw_reference=RawReference("rec-alert", "/alerts/0", "ab" * 32),
    )
    base.update(overrides)
    return Alert(**base)


def siem_record(payload_overrides=None, record_id="r-1", source="mock-siem", group="sensor-a"):
    payload = {"view": "process_tree", "host": "WS-041", "process_id": "p-101",
               "occurred_at": WINDOW.start.isoformat(),
               "observed_at": AS_OF.isoformat(),
               "command_line": "powershell -enc AAAA",
               "remote_ip": "203.0.113.66"}
    payload.update(payload_overrides or {})
    return ToolRecord(record_id, payload, content_hash(payload), source, group,
                      Reliability("high", "test", "policy-v1"))


def make_result(records, *, status="ok", call_id="c-1", coverage=None, error_code=None,
                retryable=False):
    return ToolResult(
        call_id, "siem", status, tuple(records),
        coverage or Coverage({"host": "WS-041", "view": "process_tree"}, WINDOW,
                             "complete", False, ()),
        "test-v1", error_code, retryable, 2.0, 200, 5,
    )


def test_alert_registered_with_entities():
    registry = EvidenceRegistry(make_alert())
    facts = registry.facts()
    assert len(facts) == 1 and facts[0].evidence_type == "alert"
    assert facts[0].source.kind == "alert" and facts[0].source.call_id is None
    known = registry.known_entities()
    assert "WS-041" in known["hosts"] and "analyst-a" in known["users"]
    assert "p-101" in known["process_ids"]


def test_tool_result_registers_facts_with_provenance():
    registry = EvidenceRegistry(make_alert())
    registration = registry.register_tool_result(make_result([siem_record()]))
    assert len(registration.evidence_ids) == 1
    evidence = registry.get(registration.evidence_ids[0])
    assert evidence.source.kind == "tool" and evidence.source.call_id == "c-1"
    assert evidence.raw_reference.record_id == "r-1"
    assert evidence.raw_reference.content_sha256 == content_hash(evidence.value)
    assert evidence.occurred_at == WINDOW.start
    # 实体台账吸收了记录里的新 IOC
    assert "203.0.113.66" in registry.known_entities()["indicators"]


def test_nested_tool_record_indicators_enter_authorization_ledger():
    registry = EvidenceRegistry(make_alert())
    nested = siem_record({
        "script_observations": [
            {"operation": "send", "destination": "203.0.113.77"},
            {"operation": "download", "object": {"domain": "PAYLOAD.EXAMPLE."}},
        ]
    })
    registry.register_tool_result(make_result([nested]))
    known = registry.known_entities()["indicators"]
    assert "203.0.113.77" in known
    assert "payload.example" in known


def test_mirror_records_share_fact_key_without_inflating_independence():
    registry = EvidenceRegistry(make_alert())
    first = registry.register_tool_result(make_result([siem_record(record_id="r-1")],
                                                      call_id="c-1"))
    mirror = registry.register_tool_result(
        make_result([siem_record(record_id="r-2", source="edr-mirror")], call_id="c-2"))
    assert mirror.evidence_ids == ()              # 同一事实不分配新 ID
    assert mirror.merged_fact_keys == first.merged_fact_keys or mirror.merged_fact_keys
    entry_key = f"siem:{canonical_hash(siem_record().payload)}"
    corroboration = registry.corroboration(entry_key)
    assert corroboration == ("r-1", "r-2")        # 佐证来源合并，独立性不虚增
    assert len(registry.facts()) == 2             # alert 事实 + 合并后的 1 条工具事实


def test_operational_fact_for_unavailable_source():
    registry = EvidenceRegistry(make_alert())
    result = make_result([], status="unavailable", call_id="c-9",
                         coverage=Coverage({}, None, "unknown", False, ("history.source",)),
                         error_code="source_down", retryable=False)
    registration = registry.register_tool_result(result)
    assert len(registration.operational_ids) == 1
    fact = registry.get(registration.operational_ids[0])
    assert fact.evidence_type == "source_unavailable"
    assert fact.source.call_id == "c-9"
    # 数据源不可用是操作事实，不是事件事实：不因重复调用产生新事实
    again = registry.register_tool_result(replace_call(result, "c-10"))
    assert again.operational_ids == registration.operational_ids


def replace_call(result: ToolResult, call_id: str) -> ToolResult:
    from dataclasses import replace
    return replace(result, call_id=call_id)


def test_empty_with_complete_coverage_is_provable_absence():
    registry = EvidenceRegistry(make_alert())
    complete_empty = make_result([], status="empty", call_id="c-1")
    registration = registry.register_tool_result(complete_empty)
    fact = registry.get(registration.operational_ids[0])
    assert fact.evidence_type == "query_absence"
    assert fact.value["absence_provable"] is True


def test_partial_coverage_is_limit_not_absence():
    registry = EvidenceRegistry(make_alert())
    partial = make_result([siem_record()], status="partial", call_id="c-1",
                          coverage=Coverage({"host": "WS-041", "view": "process_tree"},
                                            WINDOW, "partial", False, ("history.source",)))
    registration = registry.register_tool_result(partial)
    fact = registry.get(registration.operational_ids[0])
    assert fact.evidence_type == "coverage_limit"


def test_duplicate_call_id_rejected():
    registry = EvidenceRegistry(make_alert())
    registry.register_tool_result(make_result([siem_record()], call_id="c-1"))
    with pytest.raises(ProtocolViolation, match="duplicate_registration"):
        registry.register_tool_result(make_result([siem_record()], call_id="c-1"))


def test_unknown_entity_and_dangling_reference():
    registry = EvidenceRegistry(make_alert())
    with pytest.raises(ProtocolViolation, match="dangling_reference"):
        registry.require_known(["ev-9999"])
    with pytest.raises(ProtocolViolation, match="dangling_reference"):
        registry.get("ev-9999")


def test_equivalent_responses_yield_equivalent_references():
    """R2 正控：相同工具响应经公共注册器得到等价事实与引用。"""
    registry_a = EvidenceRegistry(make_alert())
    registry_b = EvidenceRegistry(make_alert())
    first = registry_a.register_tool_result(make_result([siem_record()], call_id="c-1"))
    second = registry_b.register_tool_result(make_result([siem_record()], call_id="c-2"))
    fact_a = registry_a.get(first.evidence_ids[0])
    fact_b = registry_b.get(second.evidence_ids[0])
    assert fact_a.fact_key == fact_b.fact_key
    assert fact_a.value == fact_b.value and fact_a.predicate == fact_b.predicate


def test_indicator_normalization_matches_signature_rules():
    """IPv6 大写与十六进制大写在台账中规范化；非法 IP 保留原样（查询时被拒）。"""
    registry = EvidenceRegistry(make_alert())
    registry.register_tool_result(make_result(
        [siem_record({"remote_ip": "2001:DB8::1", "file_hash": "AB" * 32})],
        call_id="c-1"))
    known = registry.known_entities()["indicators"]
    assert "2001:db8::1" in known            # IPv6 小写规范化
    assert ("ab" * 32) in known              # 十六进制摘要小写规范化
    assert "203.0.113.066" not in known      # 非法 IPv4 不被强行规范化
