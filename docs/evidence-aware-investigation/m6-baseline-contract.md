# M6 基线层契约

日期：2026-10-23  
范围：`direct`、`fixed`、`fixed_all`、`react` 的工程实现与公平比较边界。

## 1. 公共运行口径

四种方法共用：

- `EvidenceRegistry`：告警和工具事实登记、去重、证据 ID、实体授权；
- `BudgetController`：工具、步骤、token、时间与最终回答预留；
- `Dispatcher`：参数校验、实体授权、重试、缓存、迟到响应和证据登记；
- `TraceRecorder`：`manifest.json`、`events.jsonl`、`final.json`；
- `ToolAction | FinishAction`：ReAct 和后续 Proposed 适配使用的公共动作边界；
- `FinalAssessment`：统一结论结构和证据引用校验；
- `run_model_call`：Schema 校验、一次修复、用量对账和模型输出四态留存。

实际模型请求包含展开后的自包含 JSON Schema。Provider 收到的消息、评测捕获的消息和预算估算使用同一份 Schema 文本，不依赖 provider 访问本地 `$ref`。

## 2. 方法差异

| 方法 | 工具决策 | 固定动作 | 内部状态 |
|---|---|---|---|
| Direct | 不调用工具 | 一次最终评估 | 公开 Alert 与 Registry 中的初始证据 |
| Fixed | 程序确定 | SIEM `network_events` → TI（无指标则跳过）→ ATT&CK | 公共 Registry |
| Fixed-all | 程序确定 | SIEM → TI → Asset → History → ATT&CK | 公共 Registry |
| ReAct | 模型逐轮选择 ToolAction 或 FinishAction | 无固定工具顺序 | 公开 Alert、Evidence、Operational Evidence、Budget Usage |

Fixed 的 `stage_skipped` 使用 `plan_selected` 事件记录原因。Fixed 与 Fixed-all 的模型只生成最终结论，不能修改工具顺序。ReAct 的模型请求不包含 Hypothesis、MissingEvidence、Sufficiency、判别分数或 Proposed planner 字段。

## 3. 安全结束规则

- 最终证据和 Claim 只能引用 Registry 已登记的 Evidence ID；非法引用进入一次模型修复流程。
- Dispatcher 返回协议错误时，方法立即输出 `Abstain / human_review / protocol_error`，不能在被拒工具动作后关闭告警。
- 原生模型超时统一映射为 `model_error`，并生成可重放的 Abstain 结果。
- 达到工具、步骤、token 或时间预算后，不进行未获准的新调用；输出对应停止原因的 Abstain。
- 工具返回 unavailable、partial 或 empty 仍按公共运行时语义登记操作事实，由后续结论判断使用。

## 4. Prompt 与版本绑定

版本化文件：

- `direct-v1.txt`
- `fixed-final-v1.txt`
- `react-v1.txt`

每个 RunManifest 必须携带当前方法所用 prompt 的原始 UTF-8 字节 SHA-256。名称、hash 或运行预算不匹配时，在创建 trace 前拒绝运行。Schema 版本由代码 revision 和 Schema 文件共同绑定。

## 5. 评测兼容

Direct/Fixed 的顶层 FinalAssessment 与 ReAct `FinishAction.final` 都进入相同的模型原始提案错误率和接受后错误率。明确尝试 Finish 但 final 结构畸形时，也计为错误提案，不能因无法解析而落入 `0/0`。

本里程碑验证基线工程行为、公平接口与记录完整性。FakeScriptedModel 的结果不构成算法效果或真实模型性能结论；统一 benchmark 属于 M8a，真实模型探索属于 M8b。
