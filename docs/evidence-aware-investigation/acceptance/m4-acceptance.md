# M4 运行时验收记录（修复复验）

日期：2026-10-21。原提验提交：126f0be19b8208cd6e423e7910a9fdf6a720a162。

当前状态：本地技术验证通过，独立最终复验通过，正式提交远端 CI 待核对。此前 311 passed 自检与仅 H1/H2 的辅助复核不足以关闭 M4，已由本轮审查纠正。原始独立发现保存在 m4-evidence/initial-review.md 和 initial-probe-results.json；其中外部探针路径属于当时审查目录，正式可运行回归现已收入 investigation/tests/test_m4_review_regressions.py。

## 本轮修改

| 问题 | 修复与回归 |
|---|---|
| R1 不同时间窗/覆盖语义的空查询合并 | 操作事实 key 使用完整 envelope，含时间窗、快照、覆盖；missing_sources 不得证明 absence；四类参数化测试 |
| R2 异常导致预算 pending | Schema 先校验；首次/修复调用统一生命周期；服务异常、取消、非法参数、工具异常均对账 |
| R3 原始错误丢失 | 每轮先落盘 model_output_recorded 与 budget_reconciled，再决定修复；同 call_id 记录追加修订，不覆盖历史 |
| R4 非 JSON 原文/usage 丢失 | ModelFormatError 携带原始内容和可用 usage；格式修复一次且计费 |
| R5 重试/异常 Trace 不完整 | 重试首次返回、非法请求、永久不可用缓存、工具异常与证据哈希拒绝路径均保留请求和返回 |
| R6 可变证据 | 告警与工具输入隔离、读取副本、记录哈希校验、批次预验证 |
| R7 模型迟到 | 使用真实剩余时间并限制 await；迟到输出保留且收费，accepted_output 为空 |
| R8 同 run_id 混合旧日志 | 运行目录独占创建，拒绝重复 ID、路径片段及 manifest ID 不一致 |
| 终结预留 | phase=final 可以消费终结 token 预留，仍受硬预算与 deadline 约束 |

## 验证

- 当前 main 579c09d 已正式合入本分支，包含已验收 M2/M3。
- 本地完整 investigation 测试：**504 passed**，日志见 m4-evidence/tests.xml。
- Python 3.12.14；通过 PYTHONPATH 指向当前源码与已有辅助复核依赖目录。此为本地复用依赖测试；干净安装由远端 investigation-tests 验证。
- 独立最终复验：m4_fix_review 子代理只读复验通过，504 passed in 2.78s；R1–R8 及补充异常路径无剩余代码验收阻塞。
- Git blob 与 LF 字节 SHA256 索引：m4-evidence/source-index.json；不再混用工作区 CRLF 与提交 LF 字节。
- 全链路测试实际执行 Fake 模型，再从完整原始 alert 和 ToolResult 离线重建 Registry 并核对事实及最终引用。
- A4 使用明确的 synthetic canary receipt 充分条件与有引用的 TP；缺少 receipt 的配对负控拒绝 TP。这只证明预算/验证边界，不代表真实 PowerShell 充分性已完成。
- 虚构引用负控保存原始错误、dangling_reference、修复和最终接受四态。公共 output_validator 注入确定性 grounding 检查，模型文本不进入 Registry。
- 所有模型测试均为 FakeScriptedModel / MockTransport，无付费请求。

## 使用约定与剩余边界

1. model_output_recorded 为同一逻辑调用的追加修订；评分既读取早期错误，也读取最后的接受状态，不可只取第一条或只保留最终安全输出。
2. 最终对象仍通过 state.adapters.final_assessment_from_output 适配，禁止模型自报已校准。调用方须提供公共引用校验；Schema 校验不等于 grounding 或 sufficiency。
3. Registry 目前按工具+精确 payload 去重。跨工具、不同措辞的语义事实合并和真实案例充分性消费由后续评分/调查阶段明确承接，不能宣称已经实现。
4. Trace 文件读写与已覆盖链路重建已验证；完整 M5 离线评分、泄漏检查、实际模型请求边界及逐状态动作评分尚未完成。
5. 不含并发调度、断电恢复或真实提供商兼容性验收。MVP 为顺序运行。
6. 只有正式提交的 test 与 investigation-tests 两个远端 job 都成功并核对提交号后，才关闭 M4。发布、付费模型和真实安全处置保持单独授权。
