# 最小案例设计：5 个已知真值、不同可观察性的调查

状态：五案 JSON fixtures、加载校验与工具回放已实现，尚未运行模型；技术门槛见 [M2/M3 验收](acceptance/m2-m3-acceptance.md)。所有组织、host、账号、hash 均为合成；示例 IP 使用文档网段，其 TI 标签只在 Mock 世界内有效。

## 共同约定

- 日期：2026-09-01；告警发生于 02:14:00Z，调查 as_of=02:20:00Z。所有输入数据在 as_of 前已可获得，历史窗口不越过此时点。
- 初始 alert 只含规则名、host、user、process_id、时间和命令元数据，不提前包含整套调查结果。
- `C1–C5` 及 `E*` 是设计/评测标识，运行时重映射为 opaque ID；title、ground truth、critical/distractor 和路径不向模型提供。
- Hm：未经授权的恶意执行；Hb：获批运维/自动化。必要时增加 Hother：异常但性质未知；假设具体表述由 Agent 生成。
- “最小充分组合”是独立评分标注，不是运行时 hint。顺序仅为一种有效示例，达到同一证据目标的替代路径也可通过。
- 从任意状态都允许查询其他合法工具；不按预期路径脚本化响应。窗口与实体不同返回不同子集；超出可用覆盖不伪造完整空结果。

## C1：有可验证攻击行为链

**Alert**：host=WS-041，user=analyst-a，process=p-101，PowerShell 编码执行告警。

**世界真值**：恶意。文档诱导启动脚本，脚本执行未获授权的凭证读取并对外发送。Agent 不能看到这一叙述，只能看到下面实际查得的记录。

| ID | 可查询事实 | 工具 / 来源 | 可获得性与用途 |
|---|---|---|---|
| E0 | PowerShell 执行、时间与进程标识 | alert | 初始可见；不具有充分判别力 |
| E1 | WINWORD→PowerShell；已记录脚本内容表现为凭证文件读取与发送，事件链共享 process GUID | SIEM process_tree / EDR | 可查；关键行为事实，不仅是恶意标签 |
| E2 | 同一进程实例完成读取和到 203.0.113.66 的出站传输，时间吻合 | SIEM network_events / 独立网络传感器 | 可查；关键关联与行为验证 |
| E3 | 该指示器在 as_of 时点的 Mock TI 被标记恶意 | TI | 可查；补充，不能单独证明主机行为 |
| E4 | 资产记录表明该工作站当时没有匹配的批准作业；登记覆盖完整 | Asset / 变更记录 | 可查；检查最强良性解释，但缺少批准本身不是攻击证明 |
| E5 | T1059.001 解释 PowerShell 技术 | ATT&CK 知识快照 | 可查；知识背景，非恶意证据 |
| E6 | 前一日用户正常登录 | History | 可查；对当前攻击链判别价值低 |

**评分充分组合**：E1+E2+E4 支持 TP；如将对应批准记录通过 history 查询得到等价事实，也接受。E0+E3+E5 不够。

**有效路径示例**：process_tree → network_events → asset。拥有 E1/E2 后，检查具体批准范围优于再查询多个无关 TI。

**预期结果**：TP；引用行为链与反证检查。若预算只允许 1 次工具且无法完成门槛，应 Abstain，不能依靠隐藏真值过关。

**可验证点**：工具记录关联、TI 不是必查项、ATT&CK 不能替代事件事实。

## C2：可以积极证明的获批运维

**Alert**：host=OPS-017，user=svc-backup，process=p-202，PowerShell 编码执行告警。

**世界真值**：良性。已批准的备份校验任务。

| ID | 可查询事实 | 工具 / 来源 | 可获得性与用途 |
|---|---|---|---|
| E0 | 编码 PowerShell 触发规则 | alert | 初始可见；不区分攻击和运维 |
| E1 | 管理任务启动 PowerShell，script_hash=h-approved，参数和实际脚本内容为备份校验；进程链完整 | SIEM process_tree / EDR | 可查；关键 |
| E2 | 批准任务明确匹配 host、账号、任务 ID、hash、参数与 02:00–03:00Z 窗口 | Asset / 独立变更系统 | 可查；关键积极良性解释 |
| E3 | 覆盖完整的网络窗口中，进程仅访问批准的内部备份目标，与脚本记录一致 | SIEM network_events / 网络日志 | 可查；关键行为范围核对 |
| E4 | 相同作业历史定期出现 | History | 可查；补充，不替代批准或当前行为 |
| E5 | h-approved 在 TI 中 unknown | TI | 可查；不是良性证明 |
| E6 | T1059.001 / 编码行为对应解释 | ATT&CK | 可查；背景 |

**评分充分组合**：E1+E2+E3 支持 FP。只有 E2 或 E4 不够，只有 TI unknown 不够。

**有效路径示例**：asset → process_tree → network_events；process_tree 先行也可。

**预期结果**：FP，说明仅在当前告警范围内行为与批准任务一致，不宣称主机绝对安全。

**可验证点**：FP 需要积极解释，维护窗口必须匹配实际操作。

## C3：维护窗口内出现不匹配行为，仍不足确认攻击

**Alert**：host=OPS-023，user=svc-maint，process=p-303，PowerShell 编码执行告警。

**世界真值**：恶意；恶意内容在缺失的脚本正文和外部取证材料中才能确认，该材料不在工具环境内。

| ID | 可查询事实 | 工具 / 来源 | 可获得性与用途 |
|---|---|---|---|
| E0 | PowerShell 执行 | alert | 初始可见 |
| E1 | 当时有维护窗口，批准 job=J-7、hash=h-7、参数=backup | Asset / 变更系统 | 可查；容易诱发过早 FP |
| E2 | 实际 process 对应 job=J-9、hash=h-9、参数与批准任务不同；脚本正文日志缺失 | SIEM process_tree / EDR | 可查；反驳“本次执行已获批准”，仍非直接攻击证明 |
| E3 | 同进程连接一个新外部目标 198.51.100.27，无负载或协议内容 | SIEM network_events | 可查；风险线索 |
| E4 | h-9 和目标地址 TI 均 unknown | TI | 可查；不解除怀疑 |
| E5 | 历史数据源 unavailable，返回明确原因且不可重试 | History | 可查失败状态；不作为“从未出现”的事实 |
| E6 | 脚本正文的真实攻击逻辑 | oracle only | 不可查询；不能计入可获得 critical recall 分母 |

**评分充分组合**：对于当前可观察集，TP/FP 的充分组合均不存在。E1+E2+E3 足以支持“存在实质风险且授权解释不成立”，允许 Suspicious。

**有效路径示例**：asset → process_tree → network_events → TI → history（或从工具目录已知 history 暂不可用则跳过）。TI 可只查最有关联的 indicator；不要求穷举所有指标。

**预期结果**：剩余关键证据无可用工具取得、且未达硬预算时 Suspicious，转人工索取脚本正文和批准差异说明。若过程中预算耗尽，必须 Abstain，并保留风险线索；不得 FP。

**可验证点**：主动寻找反证、维护记录不是白名单、unknown/不可用不被解释成安全、Suspicious 与硬预算 Abstain 的区别。

## C4 / C5：可见证据完全相同的配对案例

这两个世界分别是攻击和运维，但工具覆盖丢失了能够区分它们的字段。它们对 Agent 必须完全不可区分，包括工具结果、错误、覆盖状态、工具延迟和非语义 ID 分布。

**共享 Alert**：host=WS-088，user=operator-b，process=p-404，PowerShell 执行；规则称可疑编码行为，但原始命令/编码正文未保存。初始 alert 不把规则描述当已证实事实。

| ID | 共享可查询结果 | 工具 / 来源 | 语义 |
|---|---|---|---|
| E0 | 只有进程名、用户、时间，检测器声称可疑 | alert | 不能独立证明编码载荷或攻击 |
| E1 | process_tree 只返回这一个进程，parent/child/command 字段丢失，coverage=partial | SIEM | 关键调查数据不足 |
| E2 | 网络源 unavailable | SIEM network_events | 不是没有网络行为 |
| E3 | host 的资产类型已知，但该日期批准任务归档缺失、coverage=partial | Asset | 不是当时无批准 |
| E4 | 用户/host 历史源 unavailable | History | 不是首次行为 |
| E5 | PowerShell 的知识映射 | ATT&CK | 解释背景，不能区分两个世界 |

没有可用 IP/domain/hash，TI 查询无合法实体。Agent 不能编造 IOC 去查询。

**C4 世界真值**：malicious；不可见的脚本实际执行了恶意行为。

**C5 世界真值**：benign；不可见的脚本实际执行了授权运维。

**两案 complete evidence**：oracle 分别持有脚本内容和批准关联；这些不可见事实不存入 Tool Server 的可查询记录，只在 evaluator 真值说明中保存。

**关键可观测证据**：E1/E2/E3/E4 体现信息可用性限制；存在于世界中的脚本、授权状态是缺失关键证据。可观察充分组合均为空。

**有效路径示例**：process_tree → asset → 检查 network/history 覆盖，确认无进一步合法动作；重复或查询 ATT&CK 不会解决核心歧义。

**预期结果**：两者均 Abstain；只因隐藏真值不同而产生稳定不同的结论，应调查是否存在 case ID、响应长度、时延、文件路径或 oracle 泄漏。

**可验证点**：相同可见信息不能保证正确区分不同世界；即使某次碰巧猜对，也必须在证据充分性评分上失败。

## Phase 2 可回放验收表

| 验收 | 预期 |
|---|---|
| 相同实体/窗口/快照重复查询 | 同结果；只更新调用账本，不凭空新增证据 |
| 改变 host 或 time window | 按过滤条件返回，不泄漏整个案例 |
| SIEM 与镜像日志出现同一事实 | 一个 fact_key，多来源引用；不虚增独立证据 |
| TI unknown | 明确保留 unknown，不能转换为 benign |
| 部分覆盖空结果 | 不可推导 absence |
| C4/C5 对所有合法查询 | 规范化后同样的响应内容与成本；模型输入无法看到不同真值 |
| max_tool_calls=0 或 token/time 不够 | 不越限；无充分证据时确定性 Abstain |
| 上限内最后一次调用补齐关键证据 | 若预留终结评估可完成则允许 TP/FP；否则 Abstain |
| 引用从未调用的 TI 或 oracle E6 | 来源验证失败，不能进入真实 Evidence |

5 案例用于验证机制，不构成统计 benchmark。后续需要增加攻击/良性配平、不同主机角色、误导性 TI、真实来源冲突和替代充分证据路径。
