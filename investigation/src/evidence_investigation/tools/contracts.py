"""工具环境侧契约（M1，访问边界：仅 Mock Tool Server 持有）。

Agent 的输入与可见状态不含本模块类型；工具请求/响应用 state.contracts 中的
ToolCall/ToolResult 表示。M3 的 server.py 依据 EnvironmentFixture 生成 ToolResult。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from evidence_investigation.state.contracts import (
    Coverage,
    JsonValue,
    ToolName,
    ToolRecord,
)


@dataclass(frozen=True)
class FixtureRule:
    """按操作/窗口（而非整个工具）定义的响应规则（设计稿 10 节）。"""

    tool: ToolName
    argument_constraints: dict[str, JsonValue]
    record_ids: tuple[str, ...]
    status: str  # ok/empty/partial/unavailable/timeout/error；M3 收窄为 Literal
    coverage: Coverage
    retryable: bool
    error_code: str | None


@dataclass(frozen=True)
class EnvironmentFixture:
    """单个案例的可查询世界（Tool Server 持有；Agent 不可导入）。"""

    environment_id: str
    as_of: datetime
    records_by_tool: dict[ToolName, tuple[ToolRecord, ...]]
    query_rules: tuple[FixtureRule, ...]  # Per operation/window, not tool-wide.
    fixture_version: str
