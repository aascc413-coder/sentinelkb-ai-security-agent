"""运行时 Dispatcher（M4）：唯一合法的工具调用通道。

职责（计划 M4 / 设计稿 7 节）：
- 预算准入先行：每次尝试（含非法/缓存/重试）都先 begin_tool_attempt，
  结束时必须 record_tool_result（非法调用记 None），全部计费可审计；
- 校验 tool/参数类型匹配与 M1 参数校验；违规转为 protocol 错误结果；
- 注入 ToolContext（run_id/call_id/as_of/剩余超时），模型不可构造；
- 实体授权：调用实体必须来自 alert 或 Registry 已获记录；
- 瞬态错误（retryable timeout）重试一次（计费）；永久不可用不再重试；
- 迟到响应：deadline 已过仍返回的结果照记费用，但不登记为 Evidence；
- 冗余台账：规范化查询签名去重，重复请求标记 redundant（server 缓存命中、
  成本为 0，attempts 照计）。

边界：只依赖 state 契约与 tools.signatures 的查询规范化；不导入 tools 包根
或环境契约（守卫测试强制）。Evidence 登记由本层自动完成，保证四方法获得
等价的证据引用能力（R2）。
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from uuid import uuid4

from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import (
    AssetQuery, AttackQuery, HistoryQuery, JsonValue, SIEMQuery, TIQuery,
    TimeWindow, ToolArguments, ToolCall, ToolContext, ToolName, ToolResult,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.tools.signatures import canonical_query, validate_call
from .registry import EvidenceRegistry
from .trace import TraceRecorder

_QUERY_TYPES: dict[ToolName, type] = {
    "siem": SIEMQuery, "threat_intel": TIQuery, "asset": AssetQuery,
    "history": HistoryQuery, "attack": AttackQuery,
}
_CACHEABLE = frozenset({"ok", "empty", "partial", "unavailable"})


@dataclass(frozen=True)
class DispatchOutcome:
    """一次调度（含重试）的完整结果；late=True 时 evidence_ids 为空。"""

    call_id: str
    tool: ToolName
    result: ToolResult | None
    evidence_ids: tuple[str, ...] = ()
    operational_ids: tuple[str, ...] = ()
    cache_hit: bool = False
    backend_called: bool = False
    redundant: bool = False
    late: bool = False
    retry_of: str | None = None
    protocol_error_code: str | None = None
    detail: str = ""


class Dispatcher:
    """绑定 run（alert/registry/budget/tools/trace）的顺序调度器。

    顺序语义与 BudgetController 一致：同一时刻至多一个待定工具调用。
    as_of 冻结为告警的 as_of；world 快照版本取自首次成功响应。
    """

    def __init__(
        self, run_id: str, alert_as_of, registry: EvidenceRegistry, budget,
        tools, *, trace: TraceRecorder | None = None,
    ):
        self.run_id = run_id
        self.as_of = alert_as_of
        self.registry = registry
        self.budget = budget
        self.tools = tools
        self.trace = trace
        self._ledger: dict[str, dict[str, JsonValue]] = {}
        self._permanent_unavailable: set[str] = set()
        self.world_snapshot: str | None = None

    # ── 对外入口 ────────────────────────────────────────────────

    async def dispatch(self, call: ToolCall, *, step: int = 0) -> DispatchOutcome:
        """调度一次工具调用。预算耗尽抛 BudgetExceeded；协议违规返回错误结果。"""
        self.budget.begin_tool_attempt()  # 准入先行：非法调用同样计费
        call_id = uuid4().hex
        try:
            validate_call(call.tool, call.arguments)
            canonical = canonical_query(call.arguments)
            self._authorize_entities(call.tool, canonical)
        except ProtocolViolation as exc:
            self.budget.record_tool_result(None)
            try:
                rejected_arguments = encode(call.arguments)
            except ProtocolViolation:
                rejected_arguments = {"unencodable_type": type(call.arguments).__name__}
            self._emit(step, "tool_requested", {"call_id": call_id, "tool": call.tool,
                       "arguments": rejected_arguments, "redundant": False})
            outcome = DispatchOutcome(call_id, call.tool, None,
                                      protocol_error_code=exc.code, detail=exc.message)
            self._emit(step, "tool_returned", outcome)
            return outcome

        signature = f"{call.tool}:{_query_hash(canonical)}"
        redundant = signature in self._ledger
        if signature in self._permanent_unavailable:
            # 永久不可用不再查询：以新 call_id 复制既有结果（缓存命中语义）。
            self._emit(step, "tool_requested", {"call_id": call_id, "tool": call.tool,
                       "arguments": encode(canonical), "redundant": True})
            cached = replace(self._ledger[signature]["result"], call_id=call_id,
                             simulated_cost_units=0.0, simulated_latency_ms=0, actual_duration_ms=0)
            self.budget.record_tool_result(cached, backend_called=False, cache_hit=True)
            outcome = DispatchOutcome(call_id, call.tool, cached, cache_hit=True,
                                      redundant=True)
            self._emit(step, "tool_returned", outcome)
            return outcome

        outcome = await self._invoke(call.tool, canonical, call_id, step, redundant,
                                     signature, retry_of=None)
        self._emit(step, "tool_returned", outcome)
        if (outcome.result is not None and outcome.result.status == "timeout"
                and outcome.result.retryable and outcome.result.error_code == "tool_timeout"
                and not outcome.late):
            retry_id = uuid4().hex
            self.budget.begin_tool_attempt()  # 重试计费
            retry = await self._invoke(call.tool, canonical, retry_id, step,
                                       redundant, signature, retry_of=call_id)
            if retry.result is not None and not retry.late and retry.protocol_error_code is None:
                self._remember(signature, retry.result)
            self._emit(step, "tool_returned", retry)
            return retry
        if outcome.result is not None and not outcome.late and outcome.protocol_error_code is None:
            self._remember(signature, outcome.result)
        return outcome

    # ── 内部实现 ────────────────────────────────────────────────

    async def _invoke(self, tool: ToolName, canonical: ToolArguments, call_id: str,
                      step: int, redundant: bool, signature: str,
                      *, retry_of: str | None) -> DispatchOutcome:
        ctx = ToolContext(self.run_id, call_id, self.as_of,
                          self.budget.remaining_timeout_ms)
        self._emit(step, "tool_requested",
                   {"call_id": call_id, "tool": tool,
                    "arguments": encode(canonical), "redundant": redundant})
        cache_expected = redundant
        try:
            result = await getattr(self.tools, tool)(canonical, ctx)
        except ProtocolViolation as exc:
            # 服务端拒绝（如越界查询）：尝试已发生，费用未知 → usage 不完整。
            self.budget.record_tool_result(None, backend_called=True)
            outcome = DispatchOutcome(call_id, tool, None, backend_called=True,
                                      retry_of=retry_of,
                                      protocol_error_code=exc.code, detail=exc.message)
            return outcome
        except BaseException as exc:
            self.budget.record_tool_result(None, backend_called=True)
            outcome = DispatchOutcome(call_id, tool, None, backend_called=True,
                                      retry_of=retry_of, protocol_error_code="tool_exception",
                                      detail=f"{type(exc).__name__}: {exc}")
            if not isinstance(exc, Exception):
                self._emit(step, "tool_returned", outcome)
                raise
            return outcome
        cache_hit = cache_expected and result.simulated_cost_units == 0.0
        backend_called = not cache_hit
        self.budget.record_tool_result(result, backend_called=backend_called,
                                       cache_hit=cache_hit)
        late = self.budget.stopped_reason == "deadline"
        evidence_ids: tuple[str, ...] = ()
        operational_ids: tuple[str, ...] = ()
        if not late:
            version_before = self.registry.version
            try:
                registration = self.registry.register_tool_result(result)
            except ProtocolViolation as exc:
                return DispatchOutcome(call_id, tool, result, cache_hit=cache_hit,
                                       backend_called=backend_called, redundant=redundant,
                                       retry_of=retry_of, protocol_error_code=exc.code,
                                       detail=exc.message)
            evidence_ids, operational_ids = registration.evidence_ids, registration.operational_ids
            self._emit(step, "evidence_registered",
                       {"call_id": call_id, "evidence_ids": list(evidence_ids),
                        "merged_fact_keys": list(registration.merged_fact_keys),
                        "operational_ids": list(operational_ids),
                        "state_version": registration.version_after,
                        "state_version_before": version_before})
        return DispatchOutcome(
            call_id, tool, result, evidence_ids, operational_ids,
            cache_hit, backend_called, redundant, late, retry_of,
        )

    def _remember(self, signature: str, result: ToolResult) -> None:
        if result.status in _CACHEABLE:
            if result.status == "unavailable" and not result.retryable:
                self._permanent_unavailable.add(signature)
            self._ledger[signature] = {
                "result": deepcopy(result), "status": result.status,
            }
        if self.world_snapshot is None and result.snapshot_version:
            self.world_snapshot = result.snapshot_version

    def _authorize_entities(self, tool: ToolName, query: ToolArguments) -> None:
        known = self.registry.known_entities()
        def require(value: str | None, pool: frozenset[str], name: str) -> None:
            if value is not None and value not in pool:
                raise ProtocolViolation(
                    "unknown_entity",
                    f"{name} {value!r} 不来自告警或已获记录",
                )
        if isinstance(query, SIEMQuery):
            require(query.host, known["hosts"], "host")
            require(query.user, known["users"], "user")
            require(query.process_id, known["process_ids"], "process_id")
        elif isinstance(query, TIQuery):
            canonical_value = canonical_query(query).value
            if canonical_value not in known["indicators"]:
                raise ProtocolViolation(
                    "unknown_entity",
                    f"TI 指标 {canonical_value!r} 不来自告警或已获记录",
                )
        elif isinstance(query, AssetQuery):
            require(query.host, known["hosts"], "host")
        elif isinstance(query, HistoryQuery):
            require(query.entity, known["entities"] | known["indicators"], "entity")
            require(query.host, known["hosts"], "host")
            require(query.user, known["users"], "user")
            require(query.command_line, known["commands"], "command_line")
        elif isinstance(query, AttackQuery):
            return  # 知识快照版本来自工具目录，不属于告警实体

    def _emit(self, step: int, event_type: str, payload) -> None:
        if self.trace is None:
            return
        if event_type == "tool_requested":
            self.trace.emit("tool_requested", payload, step=step,
                            state_version_before=self.registry.version,
                            state_version_after=self.registry.version)
        elif event_type == "tool_returned":
            body = dict(payload.__dict__) if hasattr(payload, "__dict__") else {}
            if body.get("result") is not None:
                body["result"] = encode(body["result"])
            body["state_version"] = self.registry.version
            self.trace.emit("tool_returned", body, step=step,
                            state_version_before=self.registry.version,
                            state_version_after=self.registry.version)
        elif event_type == "evidence_registered":
            self.trace.emit("evidence_registered", payload, step=step,
                            state_version_before=payload.get("state_version_before", 0),
                            state_version_after=payload.get("state_version", 0))
        else:  # pragma: no cover - 防御分支
            self.trace.emit(event_type, {"detail": str(payload)}, step=step)


def _query_hash(query: ToolArguments) -> str:
    from .registry import canonical_hash
    return canonical_hash(encode(query))
