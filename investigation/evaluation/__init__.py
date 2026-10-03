"""oracle/评测侧契约（M1，包外目录：物理上不被 src/ 内模块导入）。

本目录属于评测边界：Agent Runtime 与工具环境不得导入 evaluation.*（守卫测试强制）。
评测模块（metrics/evaluator，M5 与并行开发的指标模块）只能导入本目录与
evidence_investigation.state，不得导入 tools.*（环境侧）。

并行开发约定：evaluation/metrics.py 由指标 AI 负责，本文件（contracts.py）
提供 MetricCount 等公共类型，指标模块应从这里导入，不要重复定义。
"""

from .contracts import (
    ActionExpectation,
    AggregateMetrics,
    CaseScore,
    MetricCount,
    OracleCase,
)

__all__ = [
    "ActionExpectation",
    "AggregateMetrics",
    "CaseScore",
    "MetricCount",
    "OracleCase",
]
