"""运行时侧契约（M1，访问边界：Agent Runtime 可见）。

以 docs/evidence-aware-investigation/contracts.py 为蓝本移植，仅保留运行时可见类型；
工具环境侧契约（EnvironmentFixture/FixtureRule）在 tools/contracts.py，
oracle/评测侧契约（OracleCase/CaseScore 等）在包外 evaluation/contracts.py——
本模块不得导入上述两侧（守卫测试强制）。

类型注解不是运行时验证；校验见 validation.py，编解码见 codec.py。
V4-3 预留：ModelOutputRecord（原始模型输出四态留存）与 TokenPlan（预估-对账）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol, TypeAlias

JsonValue: TypeAlias = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)
Verdict: TypeAlias = Literal["TP", "FP", "Suspicious", "Abstain"]
ToolName: TypeAlias = Literal["siem", "threat_intel", "asset", "history", "attack"]
StopReason: TypeAlias = Literal[
    "sufficient", "no_useful_action", "no_available_tool", "tool_budget",
    "token_budget", "step_budget", "deadline", "conflicting_evidence",
    "protocol_error", "model_error",
]


class EventType:
    """Trace 事件类型（设计稿 12 节；V4-3 新增模型输出留存事件）。"""

    ALERT_RECEIVED = "alert_received"
    HYPOTHESES_CREATED = "hypotheses_created"
    HYPOTHESES_REVISED = "hypotheses_revised"
    STATE_SNAPSHOT = "state_snapshot"
    SUFFICIENCY_CHECKED = "sufficiency_checked"
    PLAN_SELECTED = "plan_selected"
    TOOL_REQUESTED = "tool_requested"
    TOOL_RETURNED = "tool_returned"
    EVIDENCE_REGISTERED = "evidence_registered"
    BUDGET_CHECKED = "budget_checked"
    MODEL_OUTPUT_RECORDED = "model_output_recorded"  # V4-3A：原始输出/校验/修复/接受
    BUDGET_RECONCILED = "budget_reconciled"  # V4-3B：预估-实测对账
    FINALIZED = "finalized"
    ERROR = "error"

    ALL: tuple[str, ...] = (
        ALERT_RECEIVED, HYPOTHESES_CREATED, HYPOTHESES_REVISED, STATE_SNAPSHOT,
        SUFFICIENCY_CHECKED, PLAN_SELECTED, TOOL_REQUESTED, TOOL_RETURNED,
        EVIDENCE_REGISTERED, BUDGET_CHECKED, MODEL_OUTPUT_RECORDED,
        BUDGET_RECONCILED, FINALIZED, ERROR,
    )


@dataclass(frozen=True)
class RawReference:
    record_id: str
    json_pointer: str
    content_sha256: str


@dataclass(frozen=True)
class Source:
    kind: Literal["alert", "tool", "knowledge"]
    system: str
    snapshot_version: str
    call_id: str | None  # Required for facts obtained by a tool, including KB.


@dataclass(frozen=True)
class Reliability:
    level: Literal["high", "medium", "low", "unknown"]
    basis: str
    policy_version: str  # Adapter metadata, never an LLM probability.


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    fact_key: str  # Canonical event/field identity; deduplicate copies.
    evidence_type: str
    subject: str
    predicate: str
    value: JsonValue
    occurred_at: datetime | None
    observed_at: datetime
    valid_until: datetime | None
    source: Source
    raw_reference: RawReference
    reliability: Reliability
    independence_group: str


@dataclass(frozen=True)
class EvidenceLink:
    evidence_id: str
    hypothesis_id: str
    stance: Literal["support", "contradict", "neutral"]
    interpretation: str  # Interpretation only; never registered as a fact.
    related_evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    version: int
    explanation: str
    kind: Literal["malicious", "benign", "other"]
    status: Literal["open", "supported", "weakened", "rejected"]
    expected_observations: tuple[str, ...]
    falsifying_observations: tuple[str, ...]
    supporting_evidence: tuple[str, ...] = ()
    disconfirming_evidence: tuple[str, ...] = ()
    supersedes: str | None = None


@dataclass(frozen=True)
class MissingEvidence:
    gap_id: str
    question: str
    hypotheses_to_distinguish: tuple[str, ...]
    decision_blocked: Literal["TP", "FP", "both"]
    status: Literal["unqueried", "partial", "unavailable", "resolved"]
    candidate_tools: tuple[ToolName, ...]


@dataclass
class EvidenceState:
    version: int = 0
    facts: dict[str, Evidence] = field(default_factory=dict)
    links: list[EvidenceLink] = field(default_factory=list)
    missing: list[MissingEvidence] = field(default_factory=list)
    unresolved_conflicts: list[tuple[str, ...]] = field(default_factory=list)


@dataclass(frozen=True)
class Alert:
    alert_id: str
    alert_type: str
    occurred_at: datetime
    as_of: datetime
    host: str | None
    user: str | None
    process_id: str | None
    command_line: str | None
    raw: dict[str, JsonValue]
    raw_reference: RawReference


@dataclass(frozen=True)
class TimeWindow:
    start: datetime
    end: datetime


@dataclass(frozen=True)
class SIEMQuery:
    view: Literal["host_events", "user_events", "process_tree", "network_events"]
    window: TimeWindow
    host: str | None = None
    user: str | None = None
    process_id: str | None = None
    limit: int = 50


@dataclass(frozen=True)
class TIQuery:
    indicator_type: Literal["ip", "domain", "hash"]
    value: str
    as_of: datetime


@dataclass(frozen=True)
class AssetQuery:
    host: str
    as_of: datetime


@dataclass(frozen=True)
class HistoryQuery:
    entity_type: Literal["host", "user", "command"]
    entity: str
    window: TimeWindow
    host: str | None = None
    user: str | None = None
    command_line: str | None = None
    limit: int = 50


@dataclass(frozen=True)
class AttackQuery:
    snapshot_version: str
    behavior_terms: tuple[str, ...] = ()
    technique_ids: tuple[str, ...] = ()


ToolArguments: TypeAlias = SIEMQuery | TIQuery | AssetQuery | HistoryQuery | AttackQuery


@dataclass(frozen=True)
class ToolCall:
    tool: ToolName
    arguments: ToolArguments  # Dispatcher validates tool/argument type match.


@dataclass(frozen=True)
class ToolContext:
    run_id: str
    call_id: str
    as_of: datetime
    remaining_timeout_ms: int  # Injected by runtime, not model arguments.


@dataclass(frozen=True)
class Coverage:
    scope: dict[str, JsonValue]
    window: TimeWindow | None
    completeness: Literal["complete", "partial", "unknown"]
    truncated: bool
    missing_sources: tuple[str, ...]


@dataclass(frozen=True)
class ToolRecord:
    record_id: str
    payload: dict[str, JsonValue]
    content_sha256: str
    source_system: str
    independence_group: str
    reliability: Reliability


@dataclass(frozen=True)
class ToolResult:
    call_id: str
    tool: ToolName
    status: Literal["ok", "empty", "partial", "unavailable", "timeout", "error"]
    records: tuple[ToolRecord, ...]
    coverage: Coverage
    snapshot_version: str
    error_code: str | None
    retryable: bool
    simulated_cost_units: float
    simulated_latency_ms: int
    actual_duration_ms: int


class InvestigationTools(Protocol):
    async def siem(self, query: SIEMQuery, ctx: ToolContext) -> ToolResult: ...
    async def threat_intel(self, query: TIQuery, ctx: ToolContext) -> ToolResult: ...
    async def asset(self, query: AssetQuery, ctx: ToolContext) -> ToolResult: ...
    async def history(self, query: HistoryQuery, ctx: ToolContext) -> ToolResult: ...
    async def attack(self, query: AttackQuery, ctx: ToolContext) -> ToolResult: ...


@dataclass(frozen=True)
class ObservationPrediction:
    possible_observation: str
    supports: tuple[str, ...]
    contradicts: tuple[str, ...]
    impact_on_decision: str


@dataclass(frozen=True)
class CandidateAction:
    action_id: str
    call: ToolCall
    target_gap_ids: tuple[str, ...]
    outcomes: tuple[ObservationPrediction, ...]
    discrimination: int  # Ordinal 0/1/2, not information-theoretic gain.
    critical_gap: int
    counterevidence: int
    availability: int
    normalized_cost: float
    redundancy: float
    priority: float  # Runtime computes from frozen weights.
    rationale: str


@dataclass(frozen=True)
class InvestigationPlan:
    action: Literal["query", "finalize"]
    selected_action_id: str | None
    candidates: tuple[CandidateAction, ...]
    largest_uncertainty: str
    rationale: str


@dataclass(frozen=True)
class CriterionCheck:
    criterion_id: str
    outcome: Literal["met", "unmet", "unknown"]
    evidence_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class SufficiencyResult:
    rubric_version: str
    tp_checks: tuple[CriterionCheck, ...]
    fp_checks: tuple[CriterionCheck, ...]
    sufficient_for: Literal["TP", "FP"] | None
    unresolved_alternatives: tuple[str, ...]
    discriminating_evidence_ids: tuple[str, ...]
    missing_gap_ids: tuple[str, ...]
    grounding_valid: bool


@dataclass(frozen=True)
class Budget:
    max_tool_calls: int = 6
    max_tokens: int = 16000
    max_investigation_steps: int = 8
    max_time_seconds: float = 90.0
    finalization_token_reserve: int = 2500


@dataclass
class Usage:
    tool_attempts: int = 0
    backend_calls: int = 0
    cache_hits: int = 0
    steps: int = 0
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0  # Includes reasoning if provider reports it this way.
    usage_complete: bool = True
    model_cost: float | None = None
    currency: str | None = None
    tool_cost_units: float = 0.0
    elapsed_ms: int = 0
    simulated_tool_latency_ms: int = 0


@dataclass(frozen=True)
class TokenPlan:
    """调用前预估与调用后对账（V4-3B）。

    estimated_* / reserved_* 仅用于调用前控制，不代表服务商计量；
    actual_usage 缺失时保持 None 并在 reconciliation 说明，不填零。
    """

    estimated_input_tokens: int
    reserved_output_tokens: int
    finalization_reserve: int
    estimate_note: str  # 无法准确预估时注明估算方式
    actual_usage: Usage | None = None
    reconciliation: str | None = None  # 超支/缺失/迟到响应等偏差说明


@dataclass(frozen=True)
class ModelOutputRecord:
    """单次模型调用的输出留存（V4-3A）。

    保存原始输出、校验错误、修复后输出与最终接受结果四态；属运行日志，
    不得登记为真实 Evidence——即使内容看似是事实。
    """

    call_id: str
    phase: str  # hypothesis / plan / sufficiency / final / repair …
    raw_output: JsonValue | None
    validation_error: str | None
    repaired_output: JsonValue | None
    accepted_output: JsonValue | None
    token_plan: TokenPlan | None = None


@dataclass(frozen=True)
class Claim:
    claim_id: str
    subject: str
    predicate: str
    value: JsonValue
    evidence_ids: tuple[str, ...]
    text: str
    kind: Literal["observation", "inference", "limitation"]


@dataclass(frozen=True)
class FinalAssessment:
    """最终评估（M1-A7 统一结构）：字段与 final_assessment.schema.json 一一对应。

    可选字段带缺省值，使 Schema 可接受的最小模型输出可直接 decode；
    confidence_status 语义上由程序声明——模型输出经 adapters 适配时被强制
    覆写为 uncalibrated，模型不得自行主张校准状态。
    """

    verdict: Verdict
    disposition: Literal["close_recommended", "escalate", "human_review"]
    stop_reason: StopReason
    p_attack: float | None = None  # Raw estimate, not confidence of sufficiency.
    claims: tuple[Claim, ...] = ()
    final_evidence_ids: tuple[str, ...] = ()
    unresolved_questions: tuple[str, ...] = ()
    risk_flags: tuple[str, ...] = ()
    abstain_reason: str | None = None
    confidence_status: Literal["uncalibrated", "dev_calibrated", "unavailable"] = "uncalibrated"


@dataclass
class InvestigationState:
    run_id: str
    alert: Alert
    budget: Budget
    status: Literal["new", "investigating", "finalized", "failed"] = "new"
    evidence: EvidenceState = field(default_factory=EvidenceState)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    other_hypotheses_possible: bool = True
    usage: Usage = field(default_factory=Usage)
    current_confidence: float | None = None  # Current p_attack, same semantics.
    latest_sufficiency: SufficiencyResult | None = None
    latest_plan: InvestigationPlan | None = None
    completed_call_ids: list[str] = field(default_factory=list)
    final: FinalAssessment | None = None


@dataclass(frozen=True)
class TraceEvent:
    run_id: str
    sequence: int
    timestamp: datetime
    elapsed_ms: int
    step: int
    event_type: str
    state_version_before: int
    state_version_after: int
    payload: dict[str, JsonValue]
    usage_snapshot: Usage


@dataclass(frozen=True)
class PublicCase:
    alert: Alert  # No case family or semantic case ID in model input.


@dataclass(frozen=True)
class RunManifest:
    run_id: str
    method: Literal["direct", "fixed", "react", "proposed", "fixed_all"]
    model_snapshot: str
    model_parameters: dict[str, JsonValue]
    prompt_hashes: dict[str, str]
    dataset_version: str
    tool_snapshot: str
    rubric_version: str
    code_revision: str
    seed: int | None
    seed_supported: bool
    budget: Budget
    price_snapshot: dict[str, JsonValue]


class ModelAdapter(Protocol):
    async def complete(
        self,
        messages: tuple[dict[str, JsonValue], ...],
        output_schema: dict[str, JsonValue],
        max_output_tokens: int,
        timeout_seconds: float,
    ) -> tuple[dict[str, JsonValue], Usage]: ...


class InvestigationMethod(Protocol):
    async def run(
        self, case: PublicCase, tools: InvestigationTools, budget: Budget,
    ) -> FinalAssessment: ...
