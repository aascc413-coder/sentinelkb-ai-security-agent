# 通用预算组件修复复验

范围仅限 runtime/budget.py 和预算测试，未修改实现，未做 M2 数据集或 M3 案例联调。本审查不替代外部 AI 的正式里程碑验收。

## 冻结版本

基础提交：`63fa8089845a05ad7e45d785b0adf081fa2dd52e`。

| 文件 | SHA-256 |
| --- | --- |
| 新 budget.py | `65ad475884e60c1419754832fd0e2400db8c1ff2dee61218113a1297f4965c3e` |
| runtime-init.py | `aa62f2c64a306fd6d67527bdb3706a442facf1083622eb20ade11a1bb030470a` |
| 新 test_budget.py | `51383c837373db22171752c5bb1e4a46d3397f10304d026b2886bca25e9e56c5` |
| M1 state/contracts.py | `062fc6647467e7f533242b6cb347f6d5f6b58813796320e002b46486a7152a19` |

源码与正式测试先复制至 retest 目录；conftest 将正式测试导入也锁定到冻结版本。运行后工作区源文件和正式测试 hash 仍相同。旧审查目录源码、失败日志及探针均保留。

## 结果

- 新正式预算测试：33 通过。
- 原探针未改动复跑：9 通过，2 失败。两项失败现在是 ValueError 明确拒绝累计 overflow，而非原先接受 Infinity。这两个旧断言没有允许“拒绝异常”的分支，所以保留真实失败记录，不将其改写为通过。
- 新增修复语义探针：4 通过。验证 overflow 原子拒绝、账本未污染、pending 可用 None 收尾，以及未知 backend 工具 usage_complete=False。

原三组问题已经在约定修复语义下关闭：

1. **B1**：累计费用过大被拒绝，旧合计与计数没有部分提交；工具以 None+backend_called=True 收尾，费用仍有限且 usage_complete=False；模型以 None 收尾，保留 reservation、model_cost=None。之后均可继续合法 step，没有 pending 死锁。
2. **B2**：完整 Usage 经过类型编解码及非负检查；model_calls=True、tool_cost_units=NaN、elapsed_ms=-1 都被拒绝，保守 fallback 仍正常。
3. **B3**：SimpleNamespace 伪造 ToolResult 被拒绝；正式回归还覆盖非法状态、retryable 类型、模拟/实际延迟。

正常路径原有结论仍成立：cache attempt 与 backend 费用分开；硬 deadline 后仍结算并保持终止；零 step/零 tool 条件；缺失模型 usage 保守收费；重复或伪造 plan 不能对账。

工具返回 None 且 backend_called=True 时现在明确标记 usage_complete=False；后续已知结果不能覆盖该未知状态。无 backend 的非法请求 None 不降低完整性。

## 局限

- 这是冻结通用组件的独立复验，不证明 Agent 对最终结论的策略可靠性。
- 预算账本仍要求调用者在每步开始时 begin_step，并在异常后保守结算；active backend 中断由调用者执行 remaining_timeout_ms。
- 工具费用字段保留已知费用合计，整体 usage_complete=False 表示不能将其用于完整成本比较。

证据：snapshot.json、official.log/xml、original-probes.log/xml、recovery.log/xml；probe 文件均在当前目录，最初审查及失败证据在上一级目录。
