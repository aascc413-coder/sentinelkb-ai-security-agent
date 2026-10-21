# M5 评测输入与计数口径

2026-10-21，依据 phase-1-design.md §10 与实施计划 M5。本文为后续实现约束，不代表 M5 已完成。

## 开发顺序

1. 分类、安全指标与手算样例：只依赖 CaseScore、世界真值及最终交付，不依赖 Agent。
2. Trace 完整性与重放：从完整 alert 和工具响应重建已获得事实；缺失、重复、乱序调用以及哈希错误均显式失败，不默默补齐。
3. 独立证据评分：根据 oracle 记录标注映射事实，核对来源、语义、可替代充分集合及矛盾；禁止调用运行时自评分。
4. 状态相关动作评分：以动作执行前已获事实匹配可接受工具及关键参数，未标注动作计入覆盖率缺口。
5. 实际模型请求捕获与泄漏检查：检查真实送入 adapter 的 messages，包括格式修复请求；按专用标记、字段与来源识别泄漏，不拦截正常 malicious/benign 业务词。
6. 统一报告与独立验收：手算例、故意泄漏例、虚构证据例、被系统拦截的原始错误及最终结果分开报告。

## 运行与分母

attempted_runs 包含所有尝试；failed_runs 显示协议和基础设施失败。已失败运行不冒充正确 Abstain。分类指标使用有效最终交付的样本，另列有效样本数/失败数，以及以全部 attempted 为分母的决策覆盖率。不能通过丢弃失败提高展示效果。

有效运行分为恶意/良性 × TP/FP/Suspicious/Abstain；另列每种真值的 failed 栏。所有基础比率保存 numerator、denominator，denominator=0 时 value=null（NA）。

令 a=恶意→TP，b=良性→TP，c=恶意→FP，d=良性→FP，N=有效最终交付数，M=有效恶意数，B=有效良性数，D=a+b+c+d：

| 指标 | 分子 / 分母 |
|---|---|
| Decision coverage | D / N；同时给 D / attempted_runs |
| Selective accuracy | (a+d) / D |
| Overall resolved accuracy | (a+d) / N |
| Attack precision | a / (a+b) |
| End-to-end attack recall | a / M |
| Attack F1 | 2a / ((a+b)+M)，若 precision 或 recall 未定义则 NA |
| Benign precision | d / (c+d) |
| End-to-end benign recall | d / B |
| Benign F1 | 2d / ((c+d)+B)，同上 NA 规则 |
| False Close Rate | c / M，另列全部尝试中的恶意数与恶意失败数 |
| False Closure Proportion | c / (c+d) |
| Human review rate | (Suspicious+Abstain) / N |
| Suspicious attack proportion | 恶意 Suspicious / 全部 Suspicious |

上述 F1 规则显式区分“没有预测攻击导致 precision 未定义”与“有预测但全部错误导致 precision=0”。不把缺失值静默改为 0。

重复采样不是新的独立案例：独立案例数按 case_id 去重，family 分组统计后续承接。禁止合并不同 method 或 dataset_version 的运行后给一个不带分层说明的指标。

## 原始错误与最终错误

M4 的 model_output_recorded 是同一逻辑 call_id 的追加状态。原始提案按 call_id 去重统计，修复输出单列；最终 accepted_output 使用最后一条。不得将每次追加记录当成一次新模型调用；模型费用以 budget_reconciled 逐尝试计量。

原始提案 grounding 失败、修复仍失败、最终交付 grounding 失败是不同字段。False Close Rate 只针对最终交付，系统拦截过的错误 FP 单独展示。

缺失 usage 不填零；预估/保守预留与实测 tokens 分开。输出无法完整计量的运行数，严格等 token 成本比较只使用完整计量样本，并报告其覆盖率。

## 边界

5 个公开合成案例仅用于工程调试，不据此声称提升准确率或完成校准。当前 M4 的已知事实引用验证不等于语义 grounding，Trace 读写不等于独立评分；这两项必须由 M5 的后续模块补齐。
