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

import asyncio
from copy import deepcopy
import json
import math
from dataclasses import dataclass
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


class ModelFormatError(ModelError):
    """Provider responded, but content was not a JSON object; preserve billing and text."""

    def __init__(self, message, raw_output, usage):
        super().__init__(message)
        self.raw_output = raw_output
        self.usage = usage


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


def _usage_of(response_json: dict, usage_pricer=None) -> Usage | None:
    usage = response_json.get("usage")
    if not isinstance(usage, dict):
        return None
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    if type(prompt) is not int or type(completion) is not int or min(prompt, completion) < 0:
        return None
    model_cost = currency = None
    if usage_pricer is not None:
        priced = usage_pricer(deepcopy(usage))
        if priced is not None:
            if (not isinstance(priced, tuple) or len(priced) != 2
                    or isinstance(priced[0], bool)
                    or not isinstance(priced[0], (int, float))
                    or not math.isfinite(priced[0]) or priced[0] < 0
                    or not isinstance(priced[1], str) or not priced[1].strip()):
                raise ModelError("usage pricer returned invalid cost")
            model_cost, currency = float(priced[0]), priced[1]
    return Usage(
        input_tokens=prompt,
        output_tokens=completion,
        usage_complete=True,
        model_cost=model_cost,
        currency=currency,
    )


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
    """OpenAI-compatible adapter with optional provider parameters and pricing."""

    def __init__(self, *, api_key: str, base_url: str, model: str,
                 timeout_seconds: float = 60.0, transport: httpx.AsyncBaseTransport | None = None,
                 request_parameters: dict[str, JsonValue] | None = None,
                 usage_pricer: Callable[[dict[str, Any]], tuple[float, str] | None] | None = None):
        if not api_key or not base_url or not model:
            raise ValueError("api_key/base_url/model are required")
        parameters = deepcopy(request_parameters or {})
        reserved = {"model", "messages", "temperature", "max_tokens", "response_format"}
        if not isinstance(parameters, dict) or reserved.intersection(parameters):
            raise ValueError("request_parameters must be an object without reserved fields")
        if usage_pricer is not None and not callable(usage_pricer):
            raise ValueError("usage_pricer must be callable")
        self._api_key, self._base_url, self._model = api_key, base_url.rstrip("/"), model
        self._timeout = timeout_seconds
        self._request_parameters = parameters
        self._usage_pricer = usage_pricer
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
        body.update(deepcopy(self._request_parameters))
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
        usage = (_usage_of(response_json, self._usage_pricer)
                 if isinstance(response_json, dict) else None)
        try:
            output = _extract_content(response_json)
        except ModelError as exc:
            try:
                raw = response_json["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError):
                raw = response_json
            raise ModelFormatError(str(exc), raw, usage) from exc
        return output, usage

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
    trace=None, step: int = 0, output_validator=None,
) -> ModelCallResult:
    """Reserve/reconcile every attempt; record failures before attempting one paid repair.

    output_validator is a shared deterministic validator (e.g. grounding), not a
    sufficiency scorer. It raises ProtocolViolation and uses the same repair path.
    Model records are append-only revisions identified by call_id; the last one
    contains the cumulative raw/validation/repaired/accepted states.
    """
    from evidence_investigation.state.schema_loader import model_schema_contents
    from .budget import BudgetExceeded

    schema = model_schema_contents(schema_name)  # Resolve local refs before provider input.
    schema_instruction = {
        "role": "system",
        "content": (
            "Return exactly one JSON object matching this self-contained JSON Schema. "
            "Treat the schema as output syntax, not investigation evidence.\n"
            + json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        ),
    }
    provider_messages = (schema_instruction, *tuple(messages))
    current_messages = provider_messages
    plans = []
    first_raw = None
    first_error = None
    record_id = None
    for attempt in range(2):
        estimate = (estimated_input_tokens if estimated_input_tokens is not None
                    else _estimate_input(current_messages))
        if attempt and estimated_input_tokens is not None:
            estimate += _estimate_input(current_messages[len(provider_messages):])
        plan = budget.reserve_model(
            estimate, max_output_tokens, finalization=phase == "final",
            estimate_note="caller estimate plus repair prompt" if estimated_input_tokens is not None
            else "chars/4 estimate; not provider billing",
        )
        if record_id is None:
            record_id = f"{run_id}:{phase}:{budget.snapshot().model_calls}"
        raw, usage, failure = None, None, None
        try:
            if trace is not None:
                trace.emit("budget_checked", {
                    "call_id": record_id, "attempt": attempt + 1,
                    "phase": phase, "kind": "model_reserve",
                    "estimated_input_tokens": estimate,
                    "max_output_tokens": max_output_tokens,
                    "finalization_reserve": plan.finalization_reserve,
                }, step=step)
            remaining = budget.remaining_timeout_ms / 1000
            if remaining <= 0:
                raise BudgetExceeded("deadline")
            raw, usage = await asyncio.wait_for(adapter.complete(
                list(current_messages), schema, max_output_tokens,
                timeout_seconds=remaining,
            ), timeout=remaining)
        except ModelFormatError as exc:
            raw, usage = exc.raw_output, exc.usage
            failure = ProtocolViolation("model_output_invalid", str(exc))
        except TimeoutError:
            failure = ModelError("model call timed out")
        except BaseException as exc:
            # Includes task cancellation: release pending and retain unknown charge.
            failure = exc
        try:
            reconciled = budget.reconcile_model(plan, usage)
        except (ValueError, ProtocolViolation) as exc:
            # Malformed provider usage is unknown, not free and not a stuck ledger.
            reconciled = budget.reconcile_model(plan, None)
            failure = ModelError(f"invalid provider usage: {exc}")
        plans.append(reconciled)
        if budget.stopped_reason == "deadline":
            failure = BudgetExceeded("deadline")
        if failure is None:
            try:
                validate_model_output(raw, schema_name)
                if output_validator is not None:
                    output_validator(raw)
            except ProtocolViolation as exc:
                failure = exc
        if attempt == 0:
            first_raw = raw
            first_error = str(failure) if failure is not None else None
        record = ModelOutputRecord(
            call_id=record_id, phase=phase, raw_output=first_raw,
            validation_error=first_error,
            repaired_output=raw if attempt else None,
            accepted_output=raw if failure is None else None, token_plan=None,
        )
        _emit_model_events(trace, step, record, reconciled)
        if failure is None:
            return ModelCallResult(raw, record, tuple(plans), bool(attempt), usage)
        if trace is not None:
            trace.emit("error", {"call_id": record_id, "attempt": attempt + 1,
                                 "phase": phase, "detail": str(failure)}, step=step)
        if not isinstance(failure, ProtocolViolation):
            raise failure
        if attempt:
            raise ProtocolViolation("model_output_invalid", str(failure)) from failure
        current_messages = provider_messages + (
            {"role": "assistant", "content": json.dumps(raw, ensure_ascii=False)},
            {"role": "user", "content": (
                f"Output validation failed: {first_error}. Do not repeat the invalid output. "
                "Return one corrected, complete and concise JSON object within the output limit, "
                "using only available evidence."
            )},
        )
    raise AssertionError("unreachable")


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


def _estimate_input(messages) -> int:
    """Conservative chars/4 estimate over the actual provider messages."""
    total = 0
    for message in messages:
        content = message.get("content", "") if isinstance(message, dict) else str(message)
        total += len(str(content)) // 4 + 8
    return max(1, total)
