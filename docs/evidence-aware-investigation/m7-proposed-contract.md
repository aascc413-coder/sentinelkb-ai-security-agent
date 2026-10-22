# M7 Proposed 调查层契约

## 1. 范围

M7 实现 `powershell-v1` 的 Evidence-Aware 调查闭环，用于工程验收：

1. 生成并修订 2–4 个竞争假设，至少包含一个恶意解释和一个良性解释。
2. 只允许假设引用 Registry 中已经存在的 Evidence。
3. 由程序执行 G0–G4、B1–B3 三值门槛；模型只能解释程序结果。
4. 根据当前可见证据生成不超过 3 个候选动作，并通过公共 `ToolAction` 交给 Dispatcher。
5. 在证据充分、动作耗尽、工具不可用或预算停止时生成 TP、FP、Suspicious 或 Abstain。

本里程碑验证实现与 Trace 是否正确，不证明策略优于基线，也不代表真实 SOC 环境已可用。

## 2. 运行边界

- 运行时只接收 `PublicCase`、冻结的 `FamilyRubric`、工具接口和模型适配器，不导入 oracle 或评测标签。
- Alert 与 ToolResult 是事实来源；模型输出不会写入 Evidence Registry。
- `RunManifest` 必须使用 `method=proposed`，预算与运行参数完全一致，并绑定 `hypothesis-v1.txt` 和 `sufficiency-v1.txt` 的准确 SHA-256。
- 进程、网络、资产和历史查询均经过公共 Dispatcher，因此沿用实体授权、预算、重试、缓存、迟到响应和登记规则。
- Registry 为重复事实保存全部来源 call_id；缓存重查不会制造新事实，也不会丢失来源可追溯性。

## 3. 假设修订

初次输出必须包含恶意与良性假设。每次已接纳工具结果后，模型收到当前公开 Evidence 和上一个假设版本：

- 新版本必须通过 `supersedes` 指向上一个已知假设；
- `version` 必须递增；
- supporting/disconfirming Evidence 与 EvidenceLink 必须完全一致；
- 悬空 evidence_id、hypothesis_id、related_evidence_id 或 supersedes 会触发一次付费修复，仍失败则安全 Abstain；
- `other_hypotheses_possible` 始终保持为真，避免把有限候选误写成穷举证明。

## 4. 充分性门槛

程序消费冻结的 `powershell-v1` rubric。核心规则如下：

- **G0**：验证 Alert 原文 hash、ToolRecord hash、Registry fact_key 与产生该事实的 call_id。未登记结果不能成为证据。
- **G1**：进程与全部相关网络记录必须在十分钟活动窗内，通过 host、PID 和稳定 process GUID 关联到同一实例。
- **G2**：只有来源记录的未授权凭证读取与同实例发送效果等实际攻击行为链可成立；告警标签、编码元数据、TI 或 ATT&CK 映射不能单独成立。
- **G3**：用完整批准登记检查最强良性解释。完整 asset 或等价完整 history 可用；partial/unavailable 保持 unknown。
- **G4**：检查所有采用记录的可靠性、覆盖范围和去重后的事实来源，不按工具数量授予充分性。
- **B1**：实际 host、账号、时间、job、script hash 和参数全部存在且与某个批准任务匹配。
- **B2**：当前行为必须严格匹配版本化的 mock 备份行为词表，全部网络目标必须落在批准范围内。
- **B3**：相关范围完整，且没有未解决的高质量恶意反证；关闭建议仅适用于本次告警活动。

检查会消费去重后的全部相关进程和网络记录，包括 `destination_ip`、`observed_destinations` 和 `destinations`。任何后续反证都可以阻断 FP。模型充分性解释必须逐项复制程序 outcome 和 evidence_ids；格式正确但擅自把 unknown/unmet 改为 met 仍会被拒绝。

## 5. 调查策略

本版是有限、版本化的证据响应策略，不宣称通用最优规划：

- 活动窗口固定为 `[as_of-10m, as_of)`；历史窗口固定为 `[as_of-1d, as_of)`。
- 候选目录包括 process tree、network events、asset approval 和 host history。
- 冻结优先级为 `3*discrimination + 2*critical_gap + counterevidence + availability - cost - redundancy`。
- 初始状态优先获取实际进程行为；发现未授权行为线索后优先检查同实例网络效果；发现明确 job/hash 或正文缺失时优先检查批准记录。
- 候选预测引用当前真实 Hypothesis ID，并分别记录支持、推翻和无法验证的结果。
- 完整 ToolCall 相等才视为已经尝试；不同实体、窗口或参数不会因工具名相同而被误删。
- 当前 seed policy 不查询 TI 或 ATT&CK，因为它们不能关闭本批案例的关键行为与授权门槛。

## 6. 停止和最终结论

- TP/FP 只由确定性门槛组全部成立产生。
- `approval_execution_mismatch` 只有在同 host/account/time 的积极批准记录与实际 job/hash/参数存在已知差异时成立。
- Suspicious 只允许在没有硬预算停止，且合法有用动作已耗尽或不可用时输出。
- tool budget 的最后一次合法 ToolResult 返回后不再调用模型；如果程序门槛已经充分，可确定性输出 TP/FP，否则 Abstain。
- token、step、deadline 等硬停止不能产生新的确定结论；已有 grounded risk flags 会保留在 Abstain 中。
- 协议或模型失败生成可重放的 Abstain，而不是异常退出或强制二分类。

## 7. 可审计记录

Trace 保存：初始及修订假设、EvidenceLink、每轮 SufficiencyResult、带真实 usage 和四态缺口状态的 InvestigationState、选中和未选候选、公共动作、工具返回、预算对账和最终结论。`unqueried`、`partial`、`unavailable` 与 `resolved` 不互相替代。
