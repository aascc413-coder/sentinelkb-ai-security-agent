"""M4 模型适配层测试：Fake 脚本、V4-3 四态留存、修复计费、对账与 OpenAI 兼容解析。"""

from datetime import datetime, timezone

import httpx
import pytest

from evidence_investigation.runtime.budget import BudgetController
from evidence_investigation.runtime.model import (
    FakeScriptedModel, ModelError, OpenAICompatAdapter, run_model_call,
)
from evidence_investigation.state.contracts import Budget
from evidence_investigation.state.errors import ProtocolViolation

UTC = timezone.utc
VALID_FINAL = {
    "verdict": "Abstain", "disposition": "human_review",
    "stop_reason": "no_useful_action", "claims": [], "final_evidence_ids": [],
}
INVALID_FINAL = {"verdict": "TPS", "disposition": "escalate",
                 "stop_reason": "sufficient", "claims": [], "final_evidence_ids": []}


def make_budget(**overrides):
    base = dict(max_tool_calls=6, max_tokens=16000, max_investigation_steps=8)
    base.update(overrides)
    return BudgetController(Budget(**base))


def test_fake_script_consumes_in_order_and_raises_when_exhausted():
    model = FakeScriptedModel([VALID_FINAL, ModelError("boom")])

    async def call():
        return await model.complete([], {}, 500, 10)

    import asyncio
    first = asyncio.run(call())
    assert first[0] == VALID_FINAL and first[1].usage_complete
    with pytest.raises(ModelError, match="boom"):
        asyncio.run(call())
    with pytest.raises(ModelError, match="exhausted"):
        asyncio.run(call())


def test_fake_script_usage_override():
    model = FakeScriptedModel([{"__usage__": (11, 22), **VALID_FINAL}])
    _, usage = asyncio_run(model.complete([], {}, 100, 5))
    assert (usage.input_tokens, usage.output_tokens) == (11, 22)


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)


@pytest.mark.asyncio
async def test_run_model_call_happy_path_records_and_reconciles():
    budget = make_budget()
    model = FakeScriptedModel([VALID_FINAL])
    result = await run_model_call(
        budget, model, run_id="run-1", phase="final",
        messages=({"role": "user", "content": "调查该告警"},),
        schema_name="final_assessment.schema.json", max_output_tokens=800,
        estimated_input_tokens=100,
    )
    assert result.repaired is False
    assert result.record.raw_output == VALID_FINAL
    assert result.record.accepted_output == VALID_FINAL
    assert result.record.validation_error is None
    assert budget.charged_tokens == 150  # 实测 usage（100+50）计费
    assert result.usage.input_tokens == 100 and result.usage.output_tokens == 50


@pytest.mark.asyncio
async def test_invalid_output_repaired_once_and_billed_twice():
    budget = make_budget()
    model = FakeScriptedModel([INVALID_FINAL, VALID_FINAL])
    result = await run_model_call(
        budget, model, run_id="run-1", phase="final",
        messages=({"role": "user", "content": "x"},),
        schema_name="final_assessment.schema.json", max_output_tokens=800,
        estimated_input_tokens=100,
    )
    assert result.repaired is True
    assert result.record.validation_error is not None
    assert result.record.repaired_output == VALID_FINAL
    assert result.record.accepted_output == VALID_FINAL
    assert len(result.token_plans) == 2                    # 原调用 + 修复
    assert budget.snapshot().model_calls == 2              # 修复计费
    assert budget.charged_tokens == 300                    # 两次实测 usage（150×2）


@pytest.mark.asyncio
async def test_invalid_twice_raises_protocol_error_with_four_state_record():
    budget = make_budget()
    model = FakeScriptedModel([INVALID_FINAL, {"verdict": "BAD"}])
    with pytest.raises(ProtocolViolation, match="model_output_invalid"):
        await run_model_call(
            budget, model, run_id="run-1", phase="final",
            messages=({"role": "user", "content": "x"},),
            schema_name="final_assessment.schema.json", max_output_tokens=800,
            estimated_input_tokens=100,
        )
    # 预算照记；无有效最终输出（不能被静默修成 TP/FP）
    assert budget.snapshot().model_calls == 2
    assert budget.charged_tokens == 300


@pytest.mark.asyncio
async def test_trace_records_four_states_and_reconciliation(tmp_path):
    from evidence_investigation.runtime.trace import TraceRecorder, read_trace
    from evidence_investigation.state.contracts import RunManifest

    manifest = RunManifest(
        run_id="run-m", method="proposed", model_snapshot="fake-1",
        model_parameters={}, prompt_hashes={}, dataset_version="test",
        tool_snapshot="test-v1", rubric_version="none", code_revision="test",
        seed=None, seed_supported=False, budget=Budget(), price_snapshot={},
    )
    budget = make_budget()
    model = FakeScriptedModel([INVALID_FINAL, VALID_FINAL])
    trace = TraceRecorder("run-m", manifest, tmp_path, usage_provider=budget.snapshot)
    await run_model_call(
        budget, model, run_id="run-m", phase="final",
        messages=({"role": "user", "content": "x"},),
        schema_name="final_assessment.schema.json", max_output_tokens=800,
        estimated_input_tokens=100, trace=trace,
    )
    bundle = read_trace(tmp_path, "run-m")
    kinds = [e.event_type for e in bundle.events]
    assert "model_output_recorded" in kinds and "budget_reconciled" in kinds
    records = [e for e in bundle.events if e.event_type == "model_output_recorded"]
    assert records[0].payload["accepted_output"] is None
    recorded = records[-1]
    assert recorded.payload["validation_error"] is not None
    assert recorded.payload["accepted_output"] == VALID_FINAL
    reconciled = next(e for e in bundle.events if e.event_type == "budget_reconciled")
    assert reconciled.payload["actual_usage"]["input_tokens"] == 100


@pytest.mark.asyncio
async def test_model_error_reconciles_with_unknown_usage():
    budget = make_budget()
    model = FakeScriptedModel([ModelError("service down")])
    with pytest.raises(ModelError, match="service down"):
        await run_model_call(
            budget, model, run_id="run-1", phase="final",
            messages=({"role": "user", "content": "x"},),
            schema_name="final_assessment.schema.json", max_output_tokens=800,
            estimated_input_tokens=100,
        )
    usage = budget.snapshot()
    assert usage.usage_complete is False      # 缺失 usage 不填零
    assert budget.charged_tokens == 100 + 800  # 保守预留保留


def test_openai_compat_adapter_parses_content_and_usage():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "{\"verdict\": \"TP\"}"}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 34},
        })

    adapter = OpenAICompatAdapter(api_key="k", base_url="https://api.test/v1",
                                  model="test-model", transport=httpx.MockTransport(handler))

    async def call():
        return await adapter.complete([{"role": "user", "content": "hi"}], {}, 100, 5)

    output, usage = asyncio_run(call())
    assert output == {"verdict": "TP"}
    assert (usage.input_tokens, usage.output_tokens) == (12, 34)


def test_openai_compat_adapter_maps_failures():
    def failing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "x"})

    adapter = OpenAICompatAdapter(api_key="k", base_url="https://api.test/v1",
                                  model="m", transport=httpx.MockTransport(failing))
    with pytest.raises(ModelError, match="500"):
        asyncio_run(adapter.complete([], {}, 10, 5))

    def non_json_content(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "not json"}}]})

    adapter2 = OpenAICompatAdapter(api_key="k", base_url="https://api.test/v1",
                                   model="m", transport=httpx.MockTransport(non_json_content))
    with pytest.raises(ModelError, match="not valid JSON"):
        asyncio_run(adapter2.complete([], {}, 10, 5))

    def no_usage(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    adapter3 = OpenAICompatAdapter(api_key="k", base_url="https://api.test/v1",
                                   model="m", transport=httpx.MockTransport(no_usage))
    output, usage = asyncio_run(adapter3.complete([], {}, 10, 5))
    assert output == {} and usage is None     # 缺失 usage → None，不填零
