"""公共 Evidence Registry（M4，四方法共用；R2）。

职责（计划 M4 / 设计稿 4.1）：
- 来源登记：告警与工具返回的事实，确定性字段提取；
- ID 分配与 fact_key 去重：同一事件事实（含镜像日志）共享一个 fact_key，
  首次出现分配 evidence_id，后续出现仅累加佐证来源，不虚增独立性；
- 原文引用：RawReference 携带 record_id 与原文哈希（记录内容不做投影改写）；
- call_id 关联：tool/knowledge 来源一律携带产生它的 call_id；
- coverage/error envelope 保存为操作事实：数据源不可用、部分覆盖、
  完整覆盖下的限定否定（absence）都可以被引用为操作事实——
  它们不是"行为不存在"的事件事实；
- 实体台账：host/user/process/indicator/command 实体来自告警或已获记录，
  供 Dispatcher 强制"调用实体必须来自 alert 或已获记录"。

边界：不访问 oracle；没有接受自由文本的登记入口（模型生成文本无法注册为事实）；
不导入 tools 包（工具结果由 Dispatcher 传入）。fact_key 采用
``tool:payload-canonical-hash`` 的精确重复合并；措辞不同的语义级合并延后到
M2 fixture 适配时评估。迟到响应由 call_id 去重防护：同一结果只能登记一次。
"""

from __future__ import annotations

from copy import deepcopy
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Iterable

from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import (
    Alert, Evidence, JsonValue, RawReference, Reliability, Source, ToolRecord,
    ToolResult,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.validation import validate_evidence

_TOOL_PREDICATE = {
    "siem": "siem_event", "threat_intel": "ti_record", "asset": "asset_record",
    "history": "history_event", "attack": "attack_knowledge",
}
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_HEX_DIGEST = re.compile(r"[0-9a-fA-F]+\Z")
_ALERT_RELIABILITY = Reliability("high", "detector record", "policy-v1")
_ENVELOPE_RELIABILITY = Reliability("high", "tool envelope reported by environment", "policy-v1")


def canonical_hash(value: JsonValue) -> str:
    """Canonical JSON hash；与 tools/server.content_hash 同一规则（sorted/compact/no-NaN）。"""
    raw = json.dumps(encode(value), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    return sha256(raw).hexdigest()


@dataclass(frozen=True)
class Registration:
    """一次登记的产出：新事实 ID、被合并的 fact_key、操作事实 ID、版本号。"""

    evidence_ids: tuple[str, ...]
    merged_fact_keys: tuple[str, ...]
    operational_ids: tuple[str, ...]
    version_after: int


@dataclass
class _FactEntry:
    evidence: Evidence
    record_ids: tuple[str, ...]
    source_systems: tuple[str, ...]
    call_ids: tuple[str, ...]


class EvidenceRegistry:
    """按 run 实例化；告警在构造时登记，工具结果经 register_tool_result 进入。"""

    def __init__(self, alert: Alert):
        if not alert.alert_id:
            raise ProtocolViolation("missing_alert_id", "alert_id 不能为空")
        self._alert = deepcopy(alert)
        self._facts: dict[str, _FactEntry] = {}
        self._operational: dict[str, Evidence] = {}
        self._operational_call_ids: dict[str, tuple[str, ...]] = {}
        self._seen_call_ids: set[str] = set()
        self._counter = 0
        self._version = 0
        self._hosts: set[str] = set()
        self._users: set[str] = set()
        self._process_ids: set[str] = set()
        self._commands: set[str] = set()
        self._entities: set[str] = set()
        self._indicators: set[str] = set()
        self._register_alert_facts()

    # ── 查询接口 ────────────────────────────────────────────────

    @property
    def alert(self) -> Alert:
        return deepcopy(self._alert)

    @property
    def version(self) -> int:
        return self._version

    def get(self, evidence_id: str) -> Evidence:
        for entry in self._facts.values():
            if entry.evidence.evidence_id == evidence_id:
                return deepcopy(entry.evidence)
        for evidence in self._operational.values():
            if evidence.evidence_id == evidence_id:
                return deepcopy(evidence)
        raise ProtocolViolation("dangling_reference", f"未知证据 ID：{evidence_id}")

    def require_known(self, evidence_ids: Iterable[str]) -> None:
        known = {entry.evidence.evidence_id for entry in self._facts.values()}
        known.update(e.evidence_id for e in self._operational.values())
        for item in evidence_ids:
            if item not in known:
                raise ProtocolViolation("dangling_reference", f"引用了未获得的证据：{item}")

    def facts(self) -> tuple[Evidence, ...]:
        return tuple(deepcopy(entry.evidence) for entry in self._facts.values())

    def operational_facts(self) -> tuple[Evidence, ...]:
        return tuple(deepcopy(e) for e in self._operational.values())

    def corroboration(self, fact_key: str) -> tuple[str, ...]:
        """同一 fact_key 的佐证记录（含镜像日志的 record_id 列表）。"""
        entry = self._facts.get(fact_key)
        return entry.record_ids if entry else ()

    def source_call_ids(self, fact_key: str) -> tuple[str, ...]:
        """All completed calls that supplied a registered fact/envelope."""
        entry = self._facts.get(fact_key)
        if entry is not None:
            return entry.call_ids
        return self._operational_call_ids.get(fact_key, ())

    def known_entities(self) -> dict[str, frozenset[str]]:
        """Dispatcher 的实体授权台账（全部来自 alert 或已获记录）。"""
        return {
            "hosts": frozenset(self._hosts), "users": frozenset(self._users),
            "process_ids": frozenset(self._process_ids),
            "commands": frozenset(self._commands),
            "entities": frozenset(self._entities),
            "indicators": frozenset(self._indicators),
        }

    # ── 登记接口 ────────────────────────────────────────────────

    def register_tool_result(self, result: ToolResult) -> Registration:
        """登记一次工具返回：记录事实 + coverage/error 操作事实。"""
        if result.call_id in self._seen_call_ids:
            raise ProtocolViolation(
                "duplicate_registration", f"结果 {result.call_id} 已登记（迟到响应防护）"
            )
        result = deepcopy(result)
        # Validate the complete batch before mutating the registry.
        for record in result.records:
            if canonical_hash(record.payload) != record.content_sha256:
                raise ProtocolViolation("content_hash_mismatch", record.record_id)
            if _parse_utc(record.payload.get("observed_at") or record.payload.get("published_at")) is None:
                raise ProtocolViolation("unregistrable_record", record.record_id)
        counter_before = self._counter
        prepared = {}
        try:
            for record in result.records:
                key = f"{result.tool}:{canonical_hash(record.payload)}"
                if key not in self._facts and key not in prepared:
                    prepared[key] = self._build_fact(result, record)
        except ProtocolViolation:
            self._counter = counter_before
            raise
        self._seen_call_ids.add(result.call_id)
        evidence_ids: list[str] = []
        merged: list[str] = []
        for record in result.records:
            fact_key = f"{result.tool}:{canonical_hash(record.payload)}"
            if fact_key in self._facts:
                entry = self._facts[fact_key]
                entry.record_ids = _append(entry.record_ids, record.record_id)
                entry.source_systems = _append(entry.source_systems, record.source_system)
                entry.call_ids = _append(entry.call_ids, result.call_id)
                merged.append(fact_key)
                continue
            self._facts[fact_key] = _FactEntry(
                prepared[fact_key],
                (record.record_id,), (record.source_system,), (result.call_id,),
            )
            evidence_ids.append(self._facts[fact_key].evidence.evidence_id)
            self._harvest_entities(record.payload)
        operational_ids = self._register_operational(result)
        self._version += 1
        return Registration(tuple(evidence_ids), tuple(merged), tuple(operational_ids), self._version)

    # ── 内部实现 ────────────────────────────────────────────────

    def _next_id(self) -> str:
        self._counter += 1
        return f"ev-{self._counter:04d}"

    def _register_alert_facts(self) -> None:
        alert = self.alert
        payload: JsonValue = {
            "alert_id": alert.alert_id, "alert_type": alert.alert_type,
            "host": alert.host, "user": alert.user,
            "process_id": alert.process_id, "command_line": alert.command_line,
            "occurred_at": alert.occurred_at.isoformat(), "raw": alert.raw,
        }
        evidence = validate_evidence(Evidence(
            evidence_id=self._next_id(),
            fact_key=f"alert:{canonical_hash(payload)}",
            evidence_type="alert", subject=alert.host or alert.alert_id,
            predicate=f"raised:{alert.alert_type}", value=payload,
            occurred_at=alert.occurred_at, observed_at=alert.occurred_at,
            valid_until=None,
            source=Source("alert", "detector", f"alert:{alert.alert_id}", None),
            raw_reference=alert.raw_reference,
            reliability=_ALERT_RELIABILITY,
            independence_group="alert",
        ))
        self._facts[evidence.fact_key] = _FactEntry(evidence, (), (), ())
        self._version += 1
        self._harvest_string("host", alert.host)
        self._harvest_string("user", alert.user)
        self._harvest_string("process_id", alert.process_id)
        self._harvest_string("command_line", alert.command_line)

    def _build_fact(self, result: ToolResult, record: ToolRecord) -> Evidence:
        payload = record.payload
        occurred = _parse_utc(payload.get("occurred_at"))
        observed = _parse_utc(payload.get("observed_at") or payload.get("published_at"))
        if observed is None:
            raise ProtocolViolation(
                "unregistrable_record",
                f"记录 {record.record_id} 缺少可解析的观察/发布时间，不能登记为事实",
            )
        return validate_evidence(Evidence(
            evidence_id=self._next_id(),
            fact_key=f"{result.tool}:{canonical_hash(payload)}",
            evidence_type=f"{result.tool}_record",
            subject=_subject_of(result.tool, payload),
            predicate=_TOOL_PREDICATE[result.tool],
            value=payload,
            occurred_at=occurred, observed_at=observed, valid_until=None,
            source=Source("tool", record.source_system, result.snapshot_version, result.call_id),
            raw_reference=RawReference(record.record_id, "", record.content_sha256),
            reliability=record.reliability,
            independence_group=record.independence_group,
        ))

    def _register_operational(self, result: ToolResult) -> tuple[str, ...]:
        envelope: JsonValue = {
            "tool": result.tool, "status": result.status,
            "error_code": result.error_code, "retryable": result.retryable,
            "coverage": encode(result.coverage),
            "snapshot_version": result.snapshot_version,
        }
        spec: tuple[str, str, JsonValue] | None = None
        if result.status in {"unavailable", "timeout", "error"}:
            spec = (f"source:{result.tool}:{canonical_hash(envelope)}", "source_unavailable", envelope)
        elif result.status == "empty":
            provable = (result.coverage.completeness == "complete"
                        and not result.coverage.truncated
                        and not result.coverage.missing_sources)
            spec = (f"absence:{result.tool}:{canonical_hash(envelope)}",
                    "query_absence" if provable else "coverage_limit",
                    {**envelope, "absence_provable": provable})
        elif result.status == "partial":
            spec = (f"source:{result.tool}:partial:{canonical_hash(envelope)}",
                    "coverage_limit", envelope)
        if spec is None:
            return ()
        fact_key, evidence_type, value = spec
        existing = self._operational.get(fact_key)
        if existing is not None:
            self._operational_call_ids[fact_key] = _append(
                self._operational_call_ids.get(fact_key, ()), result.call_id)
            return (existing.evidence_id,)
        evidence = validate_evidence(Evidence(
            evidence_id=self._next_id(),
            fact_key=fact_key,
            evidence_type=evidence_type,
            subject=result.tool,
            predicate=evidence_type,
            value=value,
            occurred_at=None,
            observed_at=self.alert.as_of,
            valid_until=None,
            source=Source("tool", f"{result.tool}-envelope", result.snapshot_version, result.call_id),
            raw_reference=RawReference(f"call:{result.call_id}", "/envelope", canonical_hash(envelope)),
            reliability=_ENVELOPE_RELIABILITY,
            independence_group=f"{result.tool}-availability",
        ))
        self._operational[fact_key] = evidence
        self._operational_call_ids[fact_key] = (result.call_id,)
        self._version += 1
        return (evidence.evidence_id,)

    # ── 实体采集 ────────────────────────────────────────────────

    def _harvest_entities(self, payload: dict[str, JsonValue]) -> None:
        entity_fields = {
            "host", "user", "account", "process_id", "parent_process_id",
            "entity", "command_line", "cmdline", "command",
        }

        def walk(value: JsonValue) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in entity_fields:
                        self._harvest_string(key, child)
                    if isinstance(child, str):
                        self._harvest_indicator(child)
                    else:
                        walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(payload)

    def _harvest_string(self, field_name: str, value: JsonValue) -> None:
        if not isinstance(value, str) or not value.strip():
            return
        self._entities.add(value)
        if field_name == "host":
            self._hosts.add(value)
        elif field_name in {"user", "account"}:
            self._users.add(value)
        elif field_name in {"process_id", "parent_process_id"}:
            self._process_ids.add(value)
        elif field_name in {"command_line", "cmdline", "command"}:
            self._commands.add(value)

    def _harvest_indicator(self, value: JsonValue) -> None:
        """从记录字符串中确定性识别 IOC 形态（与 signatures 的 TI 规范化一致）。"""
        if not isinstance(value, str) or not value.strip():
            return
        candidate = value.strip()
        try:
            self._indicators.add(str(ipaddress.ip_address(candidate)))
            return
        except ValueError:
            pass
        if len(candidate) in {32, 40, 64, 128} and _HEX_DIGEST.fullmatch(candidate):
            self._indicators.add(candidate.lower())
            return
        if "." not in candidate:
            return
        try:
            domain = candidate.removesuffix(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return
        labels = domain.split(".")
        if len(candidate) <= 253 and len(labels) >= 2 \
                and all(_DOMAIN_LABEL.fullmatch(label) for label in labels):
            self._indicators.add(domain)


def _append(items: tuple[str, ...], value: str) -> tuple[str, ...]:
    return items if value in items else items + (value,)


def _parse_utc(value: JsonValue) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value)
    except ValueError:
        return None
    if stamp.utcoffset() is None or stamp.utcoffset().total_seconds() != 0:
        return None
    return stamp


def _subject_of(tool: ToolName, payload: dict[str, JsonValue]) -> str:
    for key in ("host", "entity", "value", "snapshot_version"):
        candidate = payload.get(key)
        if isinstance(candidate, str) and candidate:
            return candidate
    return tool
