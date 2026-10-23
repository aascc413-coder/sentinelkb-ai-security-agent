# M9 调查循环效率修订契约

日期：2026-10-24
父依赖：M8b 真实模型探索

## 1. 问题证据

M8b 正式批次 `m8b-deepseek-20261024-v5` 暴露了两个可以从 Trace 直接确认的问题：

1. Proposed 在每次 Tool Call 后重新生成完整假设。C1 产生 4 次假设调用，C2/C4/C5 在第三次假设修订后已接近 16000 token 上限，最后取得的工具结果无法进入新的模型调用。
2. v1 输出让模型同时填写 `Hypothesis.supporting_evidence` / `disconfirming_evidence` 和 `links`。C2/C4/C5 的首次输出因两份表示不一致触发一次付费修复。

规划器只读取假设 ID 和类型；确定性充分性判定不读取模型生成的假设文本或证据关联。因此逐工具重写不会改变当前工具选择或判定结果。

## 2. 修订决策

### 2.1 调用时机

正常调查只保留三个逻辑模型阶段：

1. 调查开始时生成竞争假设。
2. 所有可用调查动作结束、确定性停止条件成立后，使用完整已获证据集中修订一次假设。
3. 模型解释已经冻结的充分性检查结果，不得改变判定结果或 Evidence ID。

Tool Call 之间由确定性 Planner、Evidence Registry 和 Sufficiency Evaluator 推进。硬预算停止后不再调用模型，由确定性路径收尾。

当三个阶段的首个输出均通过校验时，共产生 3 个实际请求；任何校验失败仍按既有规则最多修复一次，并作为额外付费请求完整记录。

### 2.2 证据关联单一来源

`hypothesis_proposal_v2.schema.json` 只允许模型通过 `links` 表达证据与假设的关系。运行时执行以下检查后，确定性生成 `Hypothesis.supporting_evidence` 与 `disconfirming_evidence`：

- Evidence ID、related Evidence ID 和 Hypothesis ID 必须存在。
- 重复 Link 被拒绝。
- 同一 Evidence 不能同时支持并反驳同一 Hypothesis。
- 修订必须保留完整 Hypothesis 集合、ID 和 kind，并提高 version。

内部 `Hypothesis` 数据结构暂时保留两个证据数组，用于 Trace 与既有读取方兼容；模型不再重复生成它们。

## 3. 不变范围

- 不修改五个开发案例、Oracle、标注或 Rubric。
- 不修改工具候选、优先级、调用参数或停止条件。
- 不修改确定性 TP / FP / Suspicious / Abstain 判定。
- v1 Prompt 和 Schema 继续留在代码包中，历史 Artifact 不重写。

## 4. 验证口径

M9a 只证明工程行为：五案结果与工具路径不变、正常运行每案 3 次模型调用、预算硬停不追加模型调用、完整测试通过、统一假模型 Artifact 可离线重放。

M9b 才能回答真实模型是否减少修复、预算耗尽、token 和费用。M9b 必须新建 Artifact 并获得单独费用授权；五个公开开发案例仍不支持泛化或优越性结论。

复验前提供离线 `benchmark.m8b compare`：先对基线与候选 Artifact 分别做 checksum 和指标重放，再校验模型、参数、预算、数据、Rubric、标注与价格快照一致，最后按 Case 输出 Verdict、停止原因、修复次数、模型调用、token 与费用差异。任一侧 usage 不完整时，对应 token/费用差异保持空值，不把未知成本当作零。
