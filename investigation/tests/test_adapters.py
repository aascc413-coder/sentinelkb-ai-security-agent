"""M1-A7：模型输出 DTO 与运行时对象的显式适配。"""

import pytest

from evidence_investigation.state import adapters
from evidence_investigation.state.contracts import FinalAssessment
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.schema_loader import (
    FINAL_ASSESSMENT,
    validate_model_output,
)

MINIMAL_OUTPUT = {
    "verdict": "TP",
    "disposition": "escalate",
    "stop_reason": "sufficient",
    "claims": [
        {
            "claim_id": "c-1", "subject": "WS-041", "predicate": "executed",
            "value": "powershell -enc AAAA", "evidence_ids": ["e-1"],
            "text": "同进程执行编码命令", "kind": "observation",
        }
    ],
    "final_evidence_ids": ["e-1"],
}


def test_minimal_model_output_maps_to_runtime_object():
    fa = adapters.final_assessment_from_output(MINIMAL_OUTPUT)
    assert isinstance(fa, FinalAssessment)
    assert fa.verdict == "TP"
    assert fa.p_attack is None  # 程序填充缺省
    assert fa.confidence_status == "uncalibrated"  # 永不由模型声明
    assert fa.unresolved_questions == () and fa.risk_flags == () and fa.abstain_reason is None
    assert fa.claims[0].claim_id == "c-1"


def test_full_output_maps_with_optional_fields():
    fa = adapters.final_assessment_from_output(
        {**MINIMAL_OUTPUT, "p_attack": 0.9, "unresolved_questions": ["q"],
         "risk_flags": ["r"], "abstain_reason": None}
    )
    assert fa.p_attack == 0.9 and fa.unresolved_questions == ("q",)


def test_invalid_output_rejected_before_mapping():
    with pytest.raises(ProtocolViolation, match="schema_violation"):
        adapters.final_assessment_from_output({**MINIMAL_OUTPUT, "verdict": "TPS"})


def test_unified_structure_direct_roundtrip():
    """M1-A7 统一结构：最小输出可直接 decode；运行时对象 encode 后过 Schema。"""
    from evidence_investigation.state import codec

    # Schema 可接受的最小输出 → 直接解码（可选字段取缺省）
    decoded = codec.decode(FinalAssessment, MINIMAL_OUTPUT)
    assert decoded.verdict == "TP" and decoded.p_attack is None
    # 完整运行时对象 → encode → Schema 通过
    fa = adapters.final_assessment_from_output(MINIMAL_OUTPUT)
    validate_model_output(codec.encode(fa), FINAL_ASSESSMENT)


def test_adapter_overrides_model_claimed_confidence_status():
    """模型不得主张校准状态：即使输出声明 dev_calibrated，适配后仍为 uncalibrated。"""
    fa = adapters.final_assessment_from_output(
        {**MINIMAL_OUTPUT, "confidence_status": "dev_calibrated"}
    )
    assert fa.confidence_status == "uncalibrated"
