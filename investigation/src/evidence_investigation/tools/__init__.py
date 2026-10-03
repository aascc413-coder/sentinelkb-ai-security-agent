"""工具环境侧（M1 契约分区：Mock Tool Server 实现侧，M3 实现 server）。

tools/contracts.py 持有 EnvironmentFixture/FixtureRule——仅 Tool Server 可访问，
Agent Runtime 不得导入（守卫测试强制）；跨边界类型（ToolRecord/Coverage/Reliability）
在 state.contracts 定义，此处引用不重复定义。
"""

from .contracts import EnvironmentFixture, FixtureRule

__all__ = ["EnvironmentFixture", "FixtureRule"]
