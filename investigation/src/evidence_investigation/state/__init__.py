"""运行时侧契约与校验层（M1）。

公共接口：
- contracts：全部运行时可见 dataclass/Protocol + EventType + V4-3 预留类型
- errors.ProtocolViolation(code, message)
- validation：确定性校验函数（UTC/时间窗/概率/成本/引用/子集/来源一致性）
- codec：encode/decode（dataclass ↔ JSON，datetime ISO 8601）
- schema_loader：validate_model_output(instance, name) / schema_contents(name)

边界：本包不得导入 tools.*（环境侧）与 evaluation.*（oracle/评测侧）。
"""

from .contracts import (
    Alert,
    AttackQuery,
    AssetQuery,
    Budget,
    CandidateAction,
    Claim,
    Coverage,
    Evidence,
    EvidenceLink,
    EvidenceState,
    FinalAssessment,
    HistoryQuery,
    Hypothesis,
    InvestigationPlan,
    InvestigationState,
    InvestigationMethod,
    InvestigationTools,
    TIQuery,
    SIEMQuery,
    MissingEvidence,
    ModelAdapter,
    ModelOutputRecord,
    ObservationPrediction,
    PublicCase,
    RawReference,
    Reliability,
    RunManifest,
    Source,
    StopReason,
    SufficiencyResult,
    CriterionCheck,
    TimeWindow,
    TokenPlan,
    ToolCall,
    ToolContext,
    ToolName,
    ToolRecord,
    ToolResult,
    ToolArguments,
    TraceEvent,
    Usage,
    Verdict,
    EventType,
    JsonValue,
)
from .errors import ProtocolViolation
from .schema_loader import (
    ACTION,
    FINAL_ASSESSMENT,
    HYPOTHESIS_PROPOSAL,
    PLAN,
    SUFFICIENCY_EXPLANATION,
    SCHEMA_NAMES,
    schema_contents,
    validate_model_output,
)

__all__ = [
    "Alert", "AttackQuery", "AssetQuery", "Budget", "CandidateAction", "Claim",
    "Coverage", "Evidence", "EvidenceLink", "EvidenceState", "FinalAssessment",
    "HistoryQuery", "Hypothesis", "InvestigationPlan", "InvestigationState",
    "InvestigationMethod", "InvestigationTools", "TIQuery", "SIEMQuery",
    "MissingEvidence", "ModelAdapter", "ModelOutputRecord",
    "ObservationPrediction", "PublicCase", "RawReference", "Reliability",
    "RunManifest", "Source", "StopReason", "SufficiencyResult", "CriterionCheck",
    "TimeWindow", "TokenPlan", "ToolCall", "ToolContext", "ToolName",
    "ToolRecord", "ToolResult", "ToolArguments", "TraceEvent", "Usage",
    "Verdict", "EventType", "JsonValue", "ProtocolViolation",
    "ACTION", "FINAL_ASSESSMENT", "HYPOTHESIS_PROPOSAL", "PLAN",
    "SUFFICIENCY_EXPLANATION", "SCHEMA_NAMES", "schema_contents",
    "validate_model_output",
]
