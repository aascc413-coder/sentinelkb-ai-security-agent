"""Actual adapter-boundary inputs, including repair prompts, are auditable."""

import json

import httpx
import pytest

from evaluation.leakage import (
    CapturingModelAdapter, LeakageBlocked, LeakagePolicy, inspect_request,
    load_capture_bundle, save_capture_bundle,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.runtime.budget import BudgetController
from evidence_investigation.runtime.model import (
    FakeScriptedModel, ModelError, OpenAICompatAdapter, run_model_call,
)
from evidence_investigation.runtime.registry import EvidenceRegistry
from evidence_investigation.state.contracts import Budget
from test_registry import make_alert


CANARY = "__ORACLE_ONLY_9b6c42__"
FINAL = {"verdict": "Abstain", "disposition": "human_review",
         "stop_reason": "no_useful_action", "claims": [], "final_evidence_ids": []}


async def call(model, messages):
    return await run_model_call(
        BudgetController(Budget()), model, run_id="boundary-check", phase="final",
        messages=tuple(messages), schema_name="final_assessment.schema.json",
        max_output_tokens=800, estimated_input_tokens=100,
    )


def test_normal_business_terms_and_public_metadata_are_not_leakage():
    request = {"messages": [{"role": "user", "content": json.dumps({
        "hypotheses": [{"kind": "malicious"}, {"kind": "benign"}],
        "threat_intelligence": {"verdict": "malicious", "source": "mock-tiexpress"},
        "budget": {"max_tool_calls": 6}, "run_id": "run-1", "rubric_version": "powershell-v1",
    })}], "max_output_tokens": 100}
    assert inspect_request(request) == ()


def test_public_planning_rationale_is_not_an_annotation_leak():
    request = {"messages": [{"role": "user", "content": {
        "action": "query", "rationale": "The network source may reduce uncertainty",
        "candidates": [{"rationale": "Check process behavior"}],
    }}]}
    assert inspect_request(request) == ()


@pytest.mark.parametrize("content", [
    {"ground_truth": "malicious"},
    '{"ground_truth":"benign"}',
    'Alert context: {"ground_truth":"benign"} End.',
    '```json\n{"ground_truth":"benign"}\n```',
    json.dumps(json.dumps({"ground_truth": "malicious"})),
])
def test_oracle_keys_are_found_in_structures_and_embedded_json(content):
    findings = inspect_request({"messages": [{"content": content}]})
    assert any(f.rule == "oracle_field" and f.marker == "ground_truth" for f in findings)


def test_custom_policy_source_and_case_ids_use_specific_markers():
    policy = LeakagePolicy(canary_tokens=(CANARY,), semantic_case_ids=("C1", "C3-malicious"),
                           forbidden_sources=("oracle", "datasets/oracle"))
    request = {"content": json.dumps({
        "source": {"path": "D:\\project\\datasets\\oracle\\case.json"},
        "text": f"C1 has hidden label {CANARY}",
    })}
    rules = {f.rule for f in inspect_request(request, policy)}
    assert rules == {"canary", "semantic_case_id", "forbidden_source"}
    assert inspect_request({"content": "C10 and XC1 are unrelated; benign and malicious are allowed."},
                           policy) == ()
    assert inspect_request({"content": {"source": "oracle-database-logs"}}, policy) == ()
    assert any(f.rule == "forbidden_source" for f in inspect_request(
        {"source": {"path": "D:/project/datasets/oracle"}}, policy))


def test_duplicate_source_keys_do_not_hide_the_first_source_in_json_text():
    findings = inspect_request({"content": '{"source":"oracle","source":"siem"}'})
    assert any(f.rule == "forbidden_source" for f in findings)


@pytest.mark.asyncio
@pytest.mark.parametrize("where", ["alert", "tool_result"])
async def test_actual_fake_adapter_inputs_capture_alert_and_tool_canaries(where):
    messages = [{"role": "user", "content": json.dumps({where: {"note": CANARY}})}]
    fake = FakeScriptedModel([FINAL])
    wrapper = CapturingModelAdapter(fake, policy=LeakagePolicy(canary_tokens=(CANARY,)))
    result = await call(wrapper, messages)
    assert result.output == FINAL
    assert fake.calls == 1 and wrapper.captures[0].forwarded
    captured = wrapper.captures[0]
    assert captured.request["messages"][1:] == messages
    assert captured.request["messages"][0]["role"] == "system"
    assert "self-contained JSON Schema" in captured.request["messages"][0]["content"]
    assert captured.request["max_output_tokens"] == 800
    assert captured.request["timeout_seconds"] > 0
    assert captured.request["output_schema"]["type"] == "object"
    assert any(f.rule == "canary" for f in captured.findings)


@pytest.mark.asyncio
async def test_capture_is_isolated_from_caller_adapter_and_reader_mutations():
    class MutatingAdapter:
        async def complete(self, messages, output_schema, max_output_tokens, timeout_seconds):
            messages[0]["content"]["safe"] = "adapter changed"
            output_schema["changed"] = True
            return FINAL, None
    messages = [{"role": "user", "content": {"safe": "original"}}]
    schema = {"type": "object"}
    wrapper = CapturingModelAdapter(MutatingAdapter())
    await wrapper.complete(messages, schema, 50, 1.0)
    assert messages[0]["content"]["safe"] == "original" and "changed" not in schema
    messages[0]["content"]["safe"] = "caller changed"
    wrapper.captures[0].request["messages"][0]["content"]["safe"] = "reader changed"
    assert wrapper.captures[0].request["messages"][0]["content"]["safe"] == "original"
    assert wrapper.captures[0].request["output_schema"] == {"type": "object"}


@pytest.mark.asyncio
async def test_block_mode_captures_but_does_not_forward_or_populate_registry():
    fake = FakeScriptedModel([FINAL])
    wrapper = CapturingModelAdapter(fake, mode="block", policy=LeakagePolicy(canary_tokens=(CANARY,)))
    registry = EvidenceRegistry(make_alert())
    original = registry.facts()
    with pytest.raises(LeakageBlocked):
        await call(wrapper, [{"role": "user", "content": CANARY}])
    assert fake.calls == 0
    assert len(wrapper.captures) == 1 and not wrapper.captures[0].forwarded
    assert registry.facts() == original


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["detect", "block"])
async def test_repair_request_is_audited_at_the_same_boundary(mode):
    fake = FakeScriptedModel([{"verdict": "BAD", "note": CANARY}, FINAL])
    wrapper = CapturingModelAdapter(fake, mode=mode, policy=LeakagePolicy(canary_tokens=(CANARY,)))
    if mode == "block":
        with pytest.raises(LeakageBlocked):
            await call(wrapper, [{"role": "user", "content": "No hidden labels supplied."}])
    else:
        assert (await call(wrapper, [{"role": "user", "content": "No hidden labels supplied."}])).repaired
    assert len(wrapper.captures) == 2
    first, repair = wrapper.captures
    assert first.findings == ()
    assert any(f.rule == "canary" for f in repair.findings)
    assert any(m["role"] == "assistant" and CANARY in m["content"]
               for m in repair.request["messages"])
    assert repair.forwarded is (mode == "detect")
    assert fake.calls == (2 if mode == "detect" else 1)


@pytest.mark.asyncio
async def test_http_transport_body_contains_the_audited_messages():
    wire = []
    policy = LeakagePolicy(canary_tokens=(CANARY,), semantic_case_ids=("C4",))
    def handler(request):
        wire.append(json.loads(request.content))
        return httpx.Response(200, json={
            "choices": [{"message": {"content": json.dumps(FINAL)}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 34},
        })
    adapter = OpenAICompatAdapter(api_key="not-a-real-key", base_url="https://model.invalid/v1",
                                  model="mock", transport=httpx.MockTransport(handler))
    wrapper = CapturingModelAdapter(adapter, policy=policy)
    try:
        await call(wrapper, [{"role": "user", "content": json.dumps({
            "tool_result": {"text": CANARY, "case_id": "C4", "source": "oracle"},
        })}])
    finally:
        await wrapper.aclose()
    captured = wrapper.captures[0]
    assert wire[0]["messages"] == captured.request["messages"]
    assert wire[0]["max_tokens"] == captured.request["max_output_tokens"]
    assert {f.rule for f in inspect_request(wire[0], policy)} == {
        "canary", "semantic_case_id", "oracle_field", "forbidden_source",
    }
    assert "not-a-real-key" not in json.dumps(captured.request)


@pytest.mark.asyncio
async def test_policy_values_are_not_inserted_and_failed_adapter_request_is_retained():
    wrapper = CapturingModelAdapter(FakeScriptedModel([ModelError("service down")]),
                                    policy=LeakagePolicy(canary_tokens=(CANARY,)))
    with pytest.raises(ModelError):
        await call(wrapper, [{"role": "user", "content": "malicious or benign?"}])
    capture = wrapper.captures[0]
    assert capture.forwarded and capture.adapter_error_type == "ModelError"
    assert capture.findings == () and CANARY not in json.dumps(capture.request)


@pytest.mark.asyncio
async def test_block_mode_prevents_http_send():
    wire_calls = []
    def handler(request):
        wire_calls.append(request)
        return httpx.Response(500)
    adapter = OpenAICompatAdapter(api_key="mock", base_url="https://model.invalid/v1",
                                  model="mock", transport=httpx.MockTransport(handler))
    wrapper = CapturingModelAdapter(adapter, mode="block")
    try:
        with pytest.raises(LeakageBlocked):
            await call(wrapper, [{"role": "user", "content": '{"ground_truth":"malicious"}'}])
    finally:
        await wrapper.aclose()
    assert wire_calls == [] and not wrapper.captures[0].forwarded


@pytest.mark.asyncio
async def test_inspection_depth_limit_is_explicit_and_blockable():
    wrapper = CapturingModelAdapter(FakeScriptedModel([FINAL]), mode="block",
                                    policy=LeakagePolicy(max_depth=2))
    with pytest.raises(LeakageBlocked):
        await wrapper.complete([{"role": "user", "content": {"nested": {"x": 1}}}], {}, 10, 1)
    assert any(f.rule == "inspection_limit" for f in wrapper.captures[0].findings)


@pytest.mark.parametrize("policy", [lambda: LeakagePolicy(canary_tokens=("",)),
                                   lambda: LeakagePolicy(semantic_case_ids="C1"),
                                   lambda: LeakagePolicy(max_depth=0)])
def test_invalid_policies_are_rejected(policy):
    with pytest.raises(ValueError):
        policy()


@pytest.mark.asyncio
async def test_capture_bundle_is_immutable_run_bound_and_digest_checked(tmp_path):
    wrapper = CapturingModelAdapter(FakeScriptedModel([FINAL]))
    await call(wrapper, [{"role": "user", "content": "public facts"}])
    path = tmp_path / "evaluation" / "model-requests.json"
    save_capture_bundle(path, "boundary-check", wrapper.captures)
    assert load_capture_bundle(path, "boundary-check").captures == wrapper.captures
    with pytest.raises(ProtocolViolation, match="capture_exists"):
        save_capture_bundle(path, "boundary-check", wrapper.captures)
    with pytest.raises(ProtocolViolation, match="capture_run_mismatch"):
        load_capture_bundle(path, "another-run")
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["bundle"]["captures"][0]["request"]["max_output_tokens"] += 1
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ProtocolViolation, match="digest"):
        load_capture_bundle(path, "boundary-check")


@pytest.mark.asyncio
async def test_structurally_incomplete_capture_is_rejected_even_with_valid_digest(tmp_path):
    from dataclasses import replace
    wrapper = CapturingModelAdapter(FakeScriptedModel([FINAL]))
    await call(wrapper, [{"role": "user", "content": "public facts"}])
    path = tmp_path / "incomplete.json"
    save_capture_bundle(path, "boundary-check", (replace(wrapper.captures[0], request={}),))
    with pytest.raises(ProtocolViolation, match="fields differ"):
        load_capture_bundle(path, "boundary-check")
