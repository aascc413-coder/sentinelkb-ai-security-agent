"""Phase 1 contracts only: no agent, adapter, model calls, or benchmark runner.

Python 3.12 standard library. Boundary validation and serialization are Phase 2.
Runtime contracts must not import OracleCase or otherwise expose it to agents.
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
    verdict: Verdict
    disposition: Literal["close_recommended", "escalate", "human_review"]
    stop_reason: StopReason
    p_attack: float | None  # Raw estimate, not confidence of sufficiency.
    claims: tuple[Claim, ...]
    final_evidence_ids: tuple[str, ...]
    unresolved_questions: tuple[str, ...]
    risk_flags: tuple[str, ...]
    abstain_reason: str | None
    confidence_status: Literal["uncalibrated", "dev_calibrated", "unavailable"]


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
class FixtureRule:
    tool: ToolName
    argument_constraints: dict[str, JsonValue]
    record_ids: tuple[str, ...]
    status: Literal["ok", "empty", "partial", "unavailable", "timeout", "error"]
    coverage: Coverage
    retryable: bool
    error_code: str | None


@dataclass(frozen=True)
class EnvironmentFixture:
    environment_id: str
    as_of: datetime
    records_by_tool: dict[ToolName, tuple[ToolRecord, ...]]
    query_rules: tuple[FixtureRule, ...]  # Per operation/window, not tool-wide.
    fixture_version: str  # Tool server only; never an agent import.


@dataclass(frozen=True)
class ActionExpectation:
    when_observed_fact_keys: tuple[str, ...]
    when_missing_fact_keys: tuple[str, ...]
    acceptable_tools: tuple[ToolName, ...]
    argument_constraints: dict[str, JsonValue]
    evidence_goal: str


@dataclass(frozen=True)
class OracleCase:
    case_id: str
    family_id: str
    split: Literal["dev", "test"]
    ground_truth: Literal["malicious", "benign"]
    complete_world_evidence: dict[str, JsonValue]
    observable_fact_keys: tuple[str, ...]
    critical_fact_keys: tuple[str, ...]
    distractor_fact_keys: tuple[str, ...]
    sufficient_sets: dict[str, tuple[tuple[str, ...], ...]]
    acceptable_verdicts: tuple[Verdict, ...]
    resolvable_with_full_observable_evidence: bool
    expected_actions: tuple[ActionExpectation, ...]
    rubric_version: str
    annotation_rationale: str


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


@dataclass(frozen=True)
class MetricCount:
    numerator: float
    denominator: float
    value: float | None  # None for empty denominator, not 0 or 1.


@dataclass(frozen=True)
class CaseScore:
    run_id: str
    case_id: str  # Evaluator side only.
    run_status: Literal["valid", "protocol_failure", "infrastructure_failure"]
    ground_truth: Literal["malicious", "benign"]
    verdict: Verdict | None
    false_close: bool
    evidence_sufficient: bool | None
    metrics: dict[str, MetricCount]
    usage: Usage
    annotation_notes: tuple[str, ...]


@dataclass(frozen=True)
class AggregateMetrics:
    method: str
    dataset_version: str
    attempted_runs: int
    independent_cases: int
    failed_runs: int
    metrics: dict[str, MetricCount]
    confidence_intervals: dict[str, tuple[float, float] | None]


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
