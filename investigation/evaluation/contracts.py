"""oracle/评测侧契约（M1，包外；Agent 与工具环境不可导入）。

以 docs/evidence-aware-investigation/contracts.py 为蓝本拆分出的评测侧类型。
导入方向约束：本目录只允许导入标准库与 evidence_investigation.state。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from evidence_investigation.state.contracts import JsonValue, ToolName, Verdict, Usage


@dataclass(frozen=True)
class ActionExpectation:
    """状态相关的可接受动作（不脚本化唯一路径）。"""

    when_observed_fact_keys: tuple[str, ...]
    when_missing_fact_keys: tuple[str, ...]
    acceptable_tools: tuple[ToolName, ...]
    argument_constraints: dict[str, JsonValue]
    evidence_goal: str


@dataclass(frozen=True)
class OracleCase:
    """评测侧独占：世界真值、可观测性与评分标准（Agent 不可见）。"""

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
class MetricCount:
    """指标计数：分母为 0 时 value 为 None（NA），不是 0 或 1。"""

    numerator: float
    denominator: float
    value: float | None


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
