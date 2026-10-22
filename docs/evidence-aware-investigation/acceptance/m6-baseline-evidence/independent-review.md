# M6 独立复核

复核日期：2026-10-23  
复核者：辅助 AI `/root/m5_replay_review`  
被测版本：实现提交前的冻结工作区；最终字节对应 `7cd8887a468cfe581386b0a55db223bed4467516`。  
方式：只读代码审查、独立异常探针与受影响测试；复核者未修改实现。

## 首轮发现与修复

1. 原生 `TimeoutError` 会使 run 缺少 final；现统一为 `model_error` 并安全 Abstain。
2. Dispatcher 拒绝非法实体后，ReAct 仍可能输出 FP；现协议错误立即安全 Abstain。
3. ReAct 的嵌套 `FinishAction.final` 未进入模型提案错误指标；现与顶层 FinalAssessment 同口径评分。
4. 真实 HTTP 请求缺少完整输出和工具契约；现展开所有本地 `$ref`，将自包含 Schema 放入实际 provider messages，并纳入捕获与 token 估算。
5. 畸形 `{"action":"finish","final":"bad"}` 因无法提取 final 而漏记；现将 Finish 意图识别和 payload 提取分开，计为错误提案。

## 复验结论

- 原四项修复探针通过；畸形 Finish 补充探针得到安全 Abstain，提案错误率和覆盖率均为 `1/1`。
- CapturingAdapter 与 HTTP wire 的 Schema 消息一致，自包含 Schema 无 `$ref`，默认 token 估算覆盖实际 Schema 消息。
- 受影响六组测试最终为 **102 passed**。
- 独立复核结论：**通过，无剩余阻塞问题**。

本结论只覆盖工程实现和异常路径，不代表真实模型性能或方法优越性。
