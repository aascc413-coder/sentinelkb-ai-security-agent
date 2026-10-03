# M2 预审与实施清单

日期：2026-10-04。父依赖 M1 已完成：CI head `880b8373ef414ee1a812b37832039ac1df474708` 的两个 job 均成功，见 [run 37142463749](https://github.com/aascc413-coder/sentinelkb-ai-security-agent/actions/runs/37142463749)。

状态：**已启动，独立只读预审完成；数据、加载器、判定表与对应测试尚未实现。** 本文件不是 M2 验收通过报告。

预审者：独立子代理 `m2_review_preparation`。依据：[实施计划 v6](../phase-2-implementation-plan.md)、[五个最小案例](../minimal-cases.md)、Phase 1 设计和 M1 契约边界。

## 按依赖排序的实施任务

1. 冻结五案映射与 C4/C5 静态规范化规则：五个案例引用四份物理环境文件，C4/C5 共用同一份环境。
2. 建立五份 public、五份 oracle 和四份 environment 数据。公开输入不含真值、设计 case ID、关键 / 干扰证据标注或预期路径；C3 隐藏脚本只存在 oracle。
3. 分区实现加载与校验：public loader 在 `state/`，环境 loader 在 `tools/`，oracle loader 在包外 `evaluation/`；摘要脚本放 `scripts/`。opaque ID 重映射要保留引用关系，不能把不同对象合并。
4. 冻结 PowerShell 族 G0–G4 / B1–B3 五列判定表、版本与哈希。规则不能按 case ID 分支；区分 met、unmet、unknown；TP / FP 同时满足时视为冲突。
5. 完成加载、非法数据拒绝、公开边界和 C4/C5 静态等价验证及摘要演示；冻结完整文件快照，提交辅助独立复核。
6. 修复复验后，按持续授权提交并推送；两个 CI job 在同一 head SHA 通过后完成 M2，自动进入 M3。

## 有限验收矩阵

| 检查 | 预期 |
|---|---|
| 加载与往返 | 五案契约可恢复，未知字段拒绝 |
| 引用与哈希 | 非法 record / fact key / 充分组合引用拒绝；按冻结 canonical JSON 规则重算原文哈希 |
| 时间 | UTC，事件 / 发布时间不超过 as_of，覆盖窗口合法 |
| 状态与覆盖 | unavailable、partial、complete empty 不混淆；规则记录属于对应工具 |
| C1 | 攻击行为链、独立网络验证、完整授权核查存在；支持 TP 的组合与替代路径明确 |
| C2 | 执行与批准记录逐项匹配、网络完整覆盖；TI unknown 不构成良性证据 |
| C3 | 批准与执行不匹配，正文不可查，history 永久不可用；正常停止可 Suspicious，硬预算停止为 Abstain |
| C4/C5 | 公开业务字段相同，共享环境；process / asset partial，network / history unavailable，无可编造 IOC |
| oracle | C1 / C2 可解；C3–C5 无可观察 TP / FP 充分组合；expected_actions 按证据状态允许替代路径 |
| 判定表 | G0–G4 / B1–B3 五列完整，有版本与摘要；缺失不能作为反证 |
| 访问边界 | 三侧 loader 符合 M1 守卫；公开数据无 oracle-only 标注或隐藏金丝雀 |

## 实施时必须保留的口径

- C4/C5 只可规范化预先列明的动态运行标识，且保留同一性和引用关系。host、user、时间、进程关联、script hash、参数、正文、coverage、错误、可靠度、独立性、cost 与模拟 latency 均保留。正文、覆盖或批准字段被改动时，负向探针必须报告差异。
- `critical_fact_keys` 可包括隐藏事实，后续 Critical Recall 可获得分母使用 `critical ∩ observable`。不可观察世界真值不能强迫 Agent 输出 TP。
- 来源不可用可以成为操作事实，用于解释拒判；它不证明行为不存在。
- G0 要验证语义支持；G1 要进程实例与时间关联；G2 要具体攻击行为；G3 要检查最强良性解释；G4 要来源独立性及适用覆盖。
- B1 逐项核对 host、账号、时间、任务 / 进程、hash / 脚本及参数；B2 验证实际行为符合批准任务；B3 不允许高质量反证未解决，也不能把局部完整覆盖泛化为整台主机安全。
- M2 只验静态边界。实际工具响应等价由 M3 验收，实际模型请求泄漏由 M5 验收；运行时充分性、Registry、预算和指标分别留给 M7、M4、M5。
