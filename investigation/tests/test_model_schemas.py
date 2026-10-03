"""M1 模型输出 Schema 测试（含 R5 公共动作 Schema 与闭合字段验证）。"""

import pytest

from evidence_investigation.state import schema_loader as sl
from evidence_investigation.state.errors import ProtocolViolation

UTC_TS = "2026-09-01T02:14:00Z"

VALID_ACTION = {
    "action": "tool",
    "tool": "siem",
    "arguments": {
        "view": "process_tree",
        "window": {"start": UTC_TS, "end": "2026-09-01T03:14:00Z"},
        "host": "WS-041",
    },
}

VALID_FINAL = {
    "verdict": "Suspicious",
    "disposition": "human_review",
    "stop_reason": "no_useful_action",
    "p_attack": 0.55,
    "claims": [
        {
            "claim_id": "c-1",
            "subject": "OPS-023",
            "predicate": "connected_to",
            "value": "198.51.100.27",
            "evidence_ids": ["e-3"],
            "text": "同进程连接新的外部目标",
            "kind": "observation",
        }
    ],
    "final_evidence_ids": ["e-1", "e-3"],
    "unresolved_questions": ["脚本正文缺失"],
    "risk_flags": ["批准任务不匹配"],
    "abstain_reason": None,
}


# ── 公共动作 Schema（R5） ───────────────────────────────────────

def test_tool_action_valid():
    sl.validate_model_output(VALID_ACTION, sl.ACTION)


def test_finish_action_valid():
    sl.validate_model_output({"action": "finish", "final": VALID_FINAL}, sl.ACTION)


def test_action_rejects_proposed_internal_fields():
    # ReAct 不应被迫填写假设关联等 Proposed 专有字段；公共 Schema 中不存在这些字段，
    # 任何夹带都会因 additionalProperties=false 被拒绝。
    polluted = {**VALID_ACTION, "target_gap_ids": ["g-1"], "discrimination": 2}
    with pytest.raises(ProtocolViolation, match="schema_violation"):
        sl.validate_model_output(polluted, sl.ACTION)


def test_action_rejects_unknown_action_kind():
    with pytest.raises(ProtocolViolation, match="schema_violation"):
        sl.validate_model_output({"action": "think", "note": "..."}, sl.ACTION)


# ── 最终评估 Schema ─────────────────────────────────────────────

def test_final_assessment_valid():
    sl.validate_model_output(VALID_FINAL, sl.FINAL_ASSESSMENT)


def test_final_p_attack_out_of_range_rejected():
    bad = {**VALID_FINAL, "p_attack": 1.5}
    with pytest.raises(ProtocolViolation, match="schema_violation"):
        sl.validate_model_output(bad, sl.FINAL_ASSESSMENT)


def test_final_bad_verdict_rejected():
    bad = {**VALID_FINAL, "verdict": "TPS"}
    with pytest.raises(ProtocolViolation, match="schema_violation"):
        sl.validate_model_output(bad, sl.FINAL_ASSESSMENT)


# ── 假设提案 / 计划 / 充分性 ────────────────────────────────────

def test_hypothesis_proposal_valid():
    sl.validate_model_output(
        {
            "hypotheses": [
                {
                    "hypothesis_id": "h-1",
                    "version": 1,
                    "explanation": "凭证读取后外传",
                    "kind": "malicious",
                    "status": "open",
                    "expected_observations": ["进程树含 WINWORD 父进程"],
                    "falsifying_observations": ["存在匹配的批准任务"],
                }
            ],
            "links": [],
        },
        sl.HYPOTHESIS_PROPOSAL,
    )


def test_hypothesis_kind_restricted():
    with pytest.raises(ProtocolViolation, match="schema_violation"):
        sl.validate_model_output(
            {
                "hypotheses": [
                    {
                        "hypothesis_id": "h-1", "version": 1, "explanation": "x",
                        "kind": "unknown-world", "status": "open",
                        "expected_observations": [], "falsifying_observations": [],
                    }
                ],
                "links": [],
            },
            sl.HYPOTHESIS_PROPOSAL,
        )


def test_plan_candidate_bounds():
    call = {"tool": "asset", "arguments": {"host": "OPS-023", "as_of": UTC_TS}}
    candidate = {
        "action_id": "a-1", "call": call, "target_gap_ids": ["g-1"],
        "outcomes": [{"possible_observation": "存在批准任务", "supports": [],
                      "contradicts": ["h-1"], "impact_on_decision": "可能推翻运维解释"}],
        "discrimination": 2, "critical_gap": 2, "counterevidence": 1,
        "availability": 2, "normalized_cost": 0.2, "redundancy": 0.0,
        "rationale": "优先检查最强良性解释",
    }
    plan = {
        "action": "query", "selected_action_id": "a-1",
        "candidates": [candidate], "largest_uncertainty": "是否获批运维",
        "rationale": "检查批准范围",
    }
    sl.validate_model_output(plan, sl.PLAN)
    bad = {**plan, "candidates": [{**candidate, "discrimination": 3}]}
    with pytest.raises(ProtocolViolation, match="schema_violation"):
        sl.validate_model_output(bad, sl.PLAN)


def test_sufficiency_explanation_valid():
    sl.validate_model_output(
        {
            "rubric_version": "powershell-1.0",
            "criteria": [
                {"criterion_id": "G2", "outcome": "unknown",
                 "evidence_ids": [], "reason": "缺少脚本正文，无法验证行为链"}
            ],
            "unresolved_alternatives": ["获批运维解释未排除"],
        },
        sl.SUFFICIENCY_EXPLANATION,
    )


# ── 闭合字段与格式 ──────────────────────────────────────────────

def test_tool_arguments_closed_fields():
    bad = {
        "action": "tool", "tool": "threat_intel",
        "arguments": {"indicator_type": "ip", "value": "203.0.113.66",
                      "as_of": UTC_TS, "verdict": "malicious"},  # verdict 不可由模型提供
    }
    with pytest.raises(ProtocolViolation, match="schema_violation"):
        sl.validate_model_output(bad, sl.ACTION)


def test_datetime_format_enforced():
    bad = {
        "action": "tool", "tool": "threat_intel",
        "arguments": {"indicator_type": "ip", "value": "203.0.113.66", "as_of": "昨天"},
    }
    with pytest.raises(ProtocolViolation, match="schema_violation"):
        sl.validate_model_output(bad, sl.ACTION)


def test_action_tool_arguments_mismatch_rejected():
    """工具名与参数类型在 Schema 层关联（A8 提前加强，四方法共用同一规则）。"""
    bad = {"action": "tool", "tool": "siem",
           "arguments": {"host": "h", "as_of": UTC_TS}}  # asset 参数配 siem 工具名
    with pytest.raises(ProtocolViolation, match="schema_violation"):
        sl.validate_model_output(bad, sl.ACTION)


def test_unknown_schema_name_rejected():
    with pytest.raises(ProtocolViolation, match="unknown_schema"):
        sl.validate_model_output({}, "nope.schema.json")


def test_schema_contents_returns_action_union():
    contents = sl.schema_contents(sl.ACTION)
    assert "oneOf" in contents
