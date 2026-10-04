# 不依赖 M2 的通用组件交付

状态：**通用组件自检、独立复核及同一实现提交的双 CI 均通过。** 草稿 [PR #1](https://github.com/aascc413-coder/sentinelkb-ai-security-agent/pull/1) 已建立，尚未合并；完整 M2 / M3 / M4 的剩余依赖见下文。

依据：2026-10-04 用户授权自主拆分、并行实施、验证修复，并优先推进不受外部验收进度影响的工作。使用独立 worktree `D:/project/Agent/m3-independent-foundations`、分支 `codex/m3-independent-foundations`，基础提交 `63fa808`。

## 任务、依赖与文件所有权

| 优先级 | 任务 | 依赖 | 实现者及独占文件 |
|---|---|---|---|
| P0 | 查询规范化、签名及缓存 | 已验收 M1 Query / ToolResult | m3_signatures：tools/signatures.py、test_tool_signatures.py |
| P0 | 规则匹配与记录选择 | M1；签名规范化约定 | m3_selection：tools/selection.py、test_tool_selection.py |
| P0 | Mock 工具服务与集成 | M1；上述两模块 | 主实现：tools/server.py、test_tool_server.py |
| P1 | 预算账本 | 已验收 M1 Budget / Usage / TokenPlan | runtime_budget：runtime/budget.py、runtime/__init__.py、test_budget.py |
| P1 | 独立复核与回归 | 冻结源码 | 交叉复核：签名作者审预算，预算作者审工具模块；原作者修复，主实现整合 |
| P2 | 五案联调、工具响应等价、完整 M3 验收 | M2 实现及冻结数据 | 待父依赖齐备后进行 |

各子代理不提交或推送，由主实现检查版本、汇总证据并统一提交。主工作区与外部 AI 的验收副本未被本轮修改。

## 已记录的假设

- 本轮测试是通用契约样例，不是 M2 的 C1–C5 数据集，不能用它们宣布五案回放完成。
- 记录筛选的字段约定暂定于 `selection.py`，真实 M2 数据适配时需验证。事件窗口为 `[start,end)`；未知筛选元数据造成 partial，不能变为 complete empty。
- 规范化保留主机、用户、进程、命令原文；TI 使用明确的 IOC 等价规则；ATT&CK 参数按大小写敏感集合处理。
- 成本为模拟后端单位，不是货币。缓存请求消耗工具尝试次数，但不执行后端，后端成本及模拟延迟为零。
- 工具服务持有显式环境快照，未实现运行时实体授权、证据注册、自动重试或 Verdict；这些属于后续完整 M4。
- 预算控制采用串行预约；未知 usage 保留额度与 unknown 状态，不能参与严格计量结论。预算控制器不主动中断后端，上层必须使用剩余 timeout。
- 并行分支增加 `codex/**` 的 push CI 触发，继续运行原有两个独立 job。通过分支 CI 不代表父依赖缺失的阶段已完成。

## 外部 M2 交付核对

用户先报告“M2 验收完成”，随后确认指另一 AI 交付的文档。实际文件为 `D:/project/Agent/m2-helper-review/docs/evidence-aware-investigation/acceptance/m2-helper-preparation.md`，其首段明确标注设计审查，不是实现验收；数据集、加载器及判定表尚未实现。故记录为 **M2 设计审查已有交付，M2 工程阶段仍待实现**，不将设计文档写成代码验收通过。

该外部审查包含 Suspicious 门槛、结论覆盖范围、替代充分组合等建议，下一次 M2 实现应逐条处理。保留外部副本中的原文件，不修改或覆盖它。

## 验证与剩余依赖

正式测试最终结果见 `m3-foundations-evidence/tests.log` 和 `tests.xml`，源码与测试文件完整快照见 `snapshot.json`。这些快照及 Git blob 对照对应实现提交 `72e808fefb1ef29726991a9d8d4199e31ee8a9a8` 的提验字节；本次 CI 完成状态更新属于后续文档，不用旧快照冒充当前文档哈希。这是本分支 Python 3.12.10 的新虚拟环境，按已有 21 项 lock 安装，没有新增依赖；`pip check` 无冲突。

| 检查 | 结果 |
|---|---|
| 正式测试 | 275 passed，包含 M1 回归、签名 / 缓存、过滤、工具服务、预算及端到端计量 |
| 工具独立初审 | 144 官方通过；17 探针中 6 失败，定位 T1 / T2 |
| 工具独立复验 | 17 原探针及 32 server 测试全部通过；再加 4 个针对性探针与其它工具专项，共 171 passed |
| 预算独立初审 | 16 官方通过；11 探针中 6 失败，定位 B1 / B2 / B3 |
| 预算独立复验 | 33 官方通过；原探针 9 通过、2 个旧断言因明确拒绝溢出而失败并保留；4 个新探针验证原子拒绝、恢复和未知计量，通过 |
| 离线演示 | 首次后端调用、缓存命中、未知实体 unavailable，计数分别可核对 |
| 产品边界 | `code/python/` 无改动；公共 M1 契约和 M2 预审文件无改动 |
| 实现提交远端 CI | `72e808f` 的 `test` 与 `investigation-tests` 在 push 和 PR 两次运行均 success，见 `m3-foundations-evidence/ci.json` |

远端实现验证：[push run 37144528275](https://github.com/aascc413-coder/sentinelkb-ai-security-agent/actions/runs/37144528275)、[PR run 37144630067](https://github.com/aascc413-coder/sentinelkb-ai-security-agent/actions/runs/37144630067)。两次运行的实际 head SHA 均为 `72e808fefb1ef29726991a9d8d4199e31ee8a9a8`，不是只看总体绿色状态。

### 已修复问题

- T1：完整覆盖判定忽略原始 scope 的 process/user/as_of 限制。现验证完整源范围，保留 source_scope；未证明覆盖时降为 partial。
- T2：等待共享锁未受调用 deadline 约束。现限时获取锁；等待超时返回无后端执行 / 无后端费用的 timeout，取消后不遗留锁。
- B1：有限费用累加后溢出 Infinity。现先验证候选账本，再原子提交；拒绝后可保守结算。
- B2：未使用的非法 Usage 字段仍污染 TokenPlan。现完整类型及非负有限计量校验。
- B3：伪对象可充当 ToolResult。现严格契约校验；未知后端结果明确标记 usage_complete=False。

独立审查在外部冻结副本中进行，原失败日志未覆盖。预算复验保留旧断言失败，不将其隐去；新检查证明选择“拒绝不可表示的费用”后的账本和恢复语义。报告及证据路径记录在 `m3-foundations-evidence/reviews.json`。

完整 M3 的剩余依赖包括 M2 物理 fixture、五案回放、C4/C5 冻结规范化下的工具响应差异报告；M4 仍需 Registry、Dispatcher、Trace 和模型适配层。
