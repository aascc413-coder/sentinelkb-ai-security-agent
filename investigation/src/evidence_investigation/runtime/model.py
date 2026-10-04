"""模型适配层（M4）：ModelAdapter 实现 + V4-3 四态留存与 token 对账。

- FakeScriptedModel：脚本化响应（供全部离线测试与 M8a 工程验收）；
- OpenAICompatAdapter：OpenAI 兼容 chat/completions（httpx，注入 transport
  供测试），JSON 解析失败抛 ModelError；
- run_model_call：规定入口——预算预留 → 调用 → Schema 校验 → 非法输出
  修复一次（计费）→ ModelOutputRecord 四态留存（V4-3A）→ 预算对账
  （V4-3B）。调用方拿到已验证输出或 ProtocolViolation（映射
  stop_reason=protocol_error）/ ModelError（stop_reason=model_error）。

用法缺失语义：provider 未报告 usage 时 actual_usage=None，预算侧保留保守
预留并标记 usage_complete=False；不填零、不混作精确计量（V4-3B）。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any, Callable, Sequence

import httpx

from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import (
    JsonValue, ModelOutputRecord, TokenPlan, Usage,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.schema_loader import validate_model_output


class ModelError(RuntimeError):
    """模型服务不可用/超时/HTTP 失败；调用方映射 stop_reason=model_error。"""


def _extract_content(response_json: dict) -> dict[str, JsonValue]:
    try:
        content = response_json["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ModelError("response missing choices[0].message.content") from exc
    if not isinstance(content, str):
        raise ModelError("message content is not a string")
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    try:
        parsed = json.loads(text)
    except ValueError as exc:
        raise ModelError(f"response is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ModelError("response JSON must be an object")
    return parsed


def _usage_of(response_json: dict) -> Usage | None:
    usage = response_json.get("usage")
    if not isinstance(usage, dict):
        return None
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    if not isinstance(prompt, int) or not isinstance(completion, int):
        return None
    return Usage(input_tokens=prompt, output_tokens=completion, usage_complete=True)


class FakeScriptedModel:
    """按脚本顺序返回响应；脚本项可为 dict、Exception 实例或 Callable。

    每次调用消耗一项；耗尽后抛 ModelError（防止测试静默越界）。
    usage 为合成值：input/output 按脚本项可覆盖（dict 响应时可给
    {"__usage__": (in, out)} 字段，该字段不会进入输出）。
    """

    def __init__(self, script: Sequence[Any], *,
                 input_tokens: int = 100, output_tokens: int = 50):
        self._script = list(script)
        self._input_default, self._output_default = input_tokens, output_tokens
        self.calls = 0

    async def complete(self, messages, output_schema, max_output_tokens, timeout_seconds):
        self.calls += 1
        if not self._script:
            raise ModelError("script exhausted")
        item = self._script.pop(0)
        usage = Usage(input_tokens=self._input_default,
                      output_tokens=self._output_default, usage_complete=True)
        if isinstance(item, BaseException):
            raise item
        if callable(item):
            return item(messages, output_schema, max_output_tokens, timeout_seconds)
        if isinstance(item, dict) and "__usage__" in item:
            usage = Usage(input_tokens=item["__usage__"][0],
                          output_tokens=item["__usage__"][1], usage_complete=True)
            item = {k: v for k, v in item.items() if k != "__usage__"}
        if not isinstance(item, dict):
            raise ModelError("script item must be dict/Exception/Callable")
        return item, usage


class OpenAICompatAdapter:
    """OpenAI 兼容适配器；base_url 形如 https://host/v1。"""

    def __init__(self, *, api_key: str, base_url: str, model: str,
                 timeout_seconds: float = 60.0, transport: httpx.AsyncBaseTransport | None = None):
        if not api_key or not base_url or not model:
            raise ValueError("api_key/base_url/model are required")
        self._api_key, self._base_url, self._model = api_key, base_url.rstrip("/"), model
        self._timeout = timeout_seconds
        self._client = httpx.AsyncClient(
            base_url=self._base_url, timeout=timeout_seconds,
            headers={"Authorization": f"Bearer {api_key}"},
            transport=transport,
        )

    async def complete(self, messages, output_schema, max_output_tokens, timeout_seconds):
        body = {
            "model": self._model,
            "messages": list(messages),
            "temperature": 0,
            "max_tokens": max_output_tokens,
            "response_format": {"type": "json_object"},
        }
        try:
            response = await self._client.post(
                "/chat/completions", json=body,
                timeout=min(self._timeout, timeout_seconds),
            )
        except httpx.HTTPError as exc:
            raise ModelError(f"model service unreachable: {exc}") from exc
        if response.status_code >= 400:
            raise ModelError(f"model service returned {response.status_code}")
        try:
            response_json = response.json()
        except ValueError as exc:
            raise ModelError("model service returned non-JSON body") from exc
        return _extract_content(response_json), _usage_of(response_json)

    async def aclose(self) -> None:
        await self._client.aclose()


@dataclass(frozen=True)
class ModelCallResult:
    """一次（含修复）模型调用的产出；record 为 V4-3A 四态留存。"""

    output: dict[str, JsonValue]
    record: ModelOutputRecord
    token_plans: tuple[TokenPlan, ...]
    repaired: bool
    usage: Usage | None


async def run_model_call(
    budget, adapter, *, run_id: str, phase: str,
    messages: tuple[dict[str, JsonValue], ...],
    schema_name: str, max_output_tokens: int,
    estimated_input_tokens: int | None = None,
    trace=None, step: int = 0,
) -> ModelCallResult:
    """带预算、Schema 校验、一次修复与四态留存的规定模型调用入口。"""
    from evidence_investigation.state.schema_loader import schema_contents

    estimate = estimated_input_tokens if estimated_input_tokens is not None \
        else _estimate_input(messages, schema_name)
    plan = budget.reserve_model(
        estimate, max_output_tokens,
        estimate_note="chars/4 per message plus fixed schema overhead"
        if estimated_input_tokens is None else "caller-supplied estimate",
    )
    if trace is not None:
        trace.emit("budget_checked",
                   {"phase": phase, "kind": "model_reserve",
                    "estimated_input_tokens": estimate,
                    "max_output_tokens": max_output_tokens,
                    "finalization_reserve": plan.finalization_reserve},
                   step=step)

    raw, usage = None, None
    try:
        raw, usage = await adapter.complete(
            list(messages), schema_contents(schema_name), max_output_tokens,
            timeout_seconds=max(1.0, budget.remaining_timeout_ms / 1000),
        )
    except ModelError:
        # 服务失败：费用/usage 未知 → 对账为 None（保留保守预留，不填零）再上抛。
        budget.reconcile_model(plan, None)
        raise
    raw_record = ModelOutputRecord(
        call_id=f"{run_id}:{phase}:{budget.snapshot().model_calls}",
        phase=phase, raw_output=raw, validation_error=None,
        repaired_output=None, accepted_output=raw, token_plan=None,
    )
    try:
        validate_model_output(raw, schema_name)
    except ProtocolViolation as exc:
        # 非法输出：修复一次，修复计入预算（V4-3A）。
        # 顺序预算要求先对账第一次调用，再预留修复调用。
        first_error = f"[{exc.code}] {exc.message}"
        plan_final = budget.reconcile_model(plan, usage)
        repair_plan = budget.reserve_model(
            estimate, max_output_tokens,
            estimate_note="repair attempt after schema violation",
        )
        repair_messages = tuple(messages) + (
            {"role": "user",
             "content": f"上次输出不符合 Schema：{first_error}。请重新只输出符合 Schema 的 JSON 对象。"},
        )
        repaired_raw, repair_usage = await adapter.complete(
            list(repair_messages), schema_contents(schema_name), max_output_tokens,
            timeout_seconds=max(1.0, budget.remaining_timeout_ms / 1000),
        )
        try:
            validate_model_output(repaired_raw, schema_name)
        except ProtocolViolation as second_exc:
            record = _record(raw_record, first_error, repaired_raw, None)
            plan_second = budget.reconcile_model(repair_plan, repair_usage)
            _emit_model_events(trace, step, record, plan_final, plan_second)
            raise ProtocolViolation(
                "model_output_invalid",
                f"修复后仍不符合 Schema：{second_exc.message}",
            ) from second_exc
        record = _record(raw_record, first_error, repaired_raw, repaired_raw)
        plan_second = budget.reconcile_model(repair_plan, repair_usage)
        _emit_model_events(trace, step, record, plan_final, plan_second)
        return ModelCallResult(repaired_raw, record,
                               (plan_final, plan_second), True, repair_usage)
    plan_final = budget.reconcile_model(plan, usage)
    _emit_model_events(trace, step, raw_record, plan_final)
    return ModelCallResult(raw, raw_record, (plan_final,), False, usage)


def _record(base: ModelOutputRecord, error: str, repaired: Any, accepted: Any) -> ModelOutputRecord:
    return ModelOutputRecord(
        call_id=base.call_id, phase=base.phase,
        raw_output=base.raw_output, validation_error=error,
        repaired_output=repaired, accepted_output=accepted,
        token_plan=base.token_plan,
    )


def _emit_model_events(trace, step: int, record: ModelOutputRecord, *plans: TokenPlan) -> None:
    if trace is None:
        return
    trace.emit("model_output_recorded", {
        "call_id": record.call_id, "phase": record.phase,
        "raw_output": encode(record.raw_output),
        "validation_error": record.validation_error,
        "repaired_output": encode(record.repaired_output),
        "accepted_output": encode(record.accepted_output),
    }, step=step)
    for plan in plans:
        trace.emit("budget_reconciled", {
            "phase": record.phase,
            "estimated_input_tokens": plan.estimated_input_tokens,
            "reserved_output_tokens": plan.reserved_output_tokens,
            "actual_usage": encode(plan.actual_usage),
            "reconciliation": plan.reconciliation,
        }, step=step)


def _estimate_input(messages, schema_name: str) -> int:
    """粗估：每条消息内容 chars/4 + Schema 负载 chars/4；无法精确时注明方式。"""
    total = len(schema_name) // 4
    for message in messages:
        content = message.get("content", "") if isinstance(message, dict) else str(message)
        total += len(str(content)) // 4 + 8
    return max(1, total)
