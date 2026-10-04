"""Runtime foundations; no environment or evaluation imports.

公共接口（M4）：
- registry.EvidenceRegistry：来源登记、fact_key 去重、操作事实、实体台账
- dispatcher.Dispatcher：唯一合法工具调用通道（预算准入/校验/授权/重试/迟到防护）
- trace.TraceRecorder / read_trace：manifest + events.jsonl + final 三件套与离线重放
- model.FakeScriptedModel / OpenAICompatAdapter / run_model_call：模型调用规定入口
- budget.BudgetController / BudgetExceeded：顺序预算控制器（M3 基础，经独立复核）

导入方向：runtime → state（+ tools.signatures 的查询规范化）；禁止导入
tools 包根/环境契约与 evaluation（守卫测试强制）。
"""

from .budget import BudgetController, BudgetExceeded
from .dispatcher import DispatchOutcome, Dispatcher
from .registry import EvidenceRegistry, Registration
from .trace import TraceBundle, TraceRecorder, read_trace
from .model import (
    FakeScriptedModel,
    ModelCallResult,
    ModelError,
    OpenAICompatAdapter,
    run_model_call,
)

__all__ = [
    "BudgetController", "BudgetExceeded",
    "DispatchOutcome", "Dispatcher",
    "EvidenceRegistry", "Registration",
    "TraceBundle", "TraceRecorder", "read_trace",
    "FakeScriptedModel", "ModelCallResult", "ModelError",
    "OpenAICompatAdapter", "run_model_call",
]
