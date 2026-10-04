# M2 案例标注与充分性规则专项审查（辅助准备稿）

日期：2026-10-04。性质：**设计审查，供主实现直接采用；不是 M2 实现验收，也不代表预审或实现已通过。**

## 0. 审查版本与依据

| 项 | 记录 |
|---|---|
| 复核副本 | `D:/project/Agent/m2-helper-review`（git worktree @ `63fa8089845a05ad7e45d785b0adf081fa2dd52e`，detached） |
| 仓库最新提交 | `63fa808` docs: record CI-gated acceptance and advance M2 preparation |
| minimal-cases.md | `e76be6b5a8ef…`（自设计冻结 `9f3719f` 未变更） |
| phase-1-design.md | `a89d098ed7bf…`（同上） |
| m2-preflight.md | `00144b2472f1…` |
| phase-2-implementation-plan.md | `3c3da128b66e…`（v6） |
| 契约依据 | `investigation/src/evidence_investigation/state/contracts.py`、`tools/contracts.py`、`evaluation/contracts.py`（M1 已验收版本） |

检查范围：C1–C5 逐案标注、G0–G4/B1–B3 判定表、M2 独立验收用例设计。限制：数据集、加载器与判定表尚未实现，本审查只能约束设计；等价性、加载与评分的正确性须待实现冻结后按快照独立复现。全部结论为有限样本下的设计判断，不构成对实现的验收。

## 1. 问题清单（按严重程度排序）

| 编号 | 严重程度 | 问题 | 建议落点 |
|---|---|---|---|
| S1 | 高 | Suspicious 的"至少一项可引用的实质风险事实"（设计稿 5.3）没有程序化定义。C3 中若不定义，运行时可全 Abstain 而不违反任何门槛，Suspicious 机制无法被验收，avoidable-abstention / suspicious-utility 指标失去分辨力。 | 判定表为 Suspicious 增加程序可检条件（见 §3.4）；oracle 的 acceptable_verdicts 与标注理由据此冻结。 |
| S2 | 高 | C4/C5 等价检查的对象清单应冻结为"模型可见全量"。共用同一环境文件已消除 environment_id/fixture_version/snapshot_version 差异，但 query_rules 逐案内容、记录排序、JSON 键序仍可能构成可见差异；仅比对工具响应负载不够。 | 规范化规则文件中显式列出"允许不同的字段"（当前应仅运行时元数据），等价检查比对规范化后的完整公开消息流；负向探针逐字段注入差异。 |
| S3 | 中 | C1 替代充分组合"通过 history 查询得到等价事实"缺程序判据（minimal-cases 仅一句带过），评分器实现易收敛为单一组合。 | 判定表定义"等价"= 覆盖完整、针对同一 host/时间窗的批准核查事实，无论来源工具为 asset 还是 history；oracle 的 sufficient_sets 以 fact_key + 覆盖限定表达（见 §2 各案）。 |
| S4 | 中 | Critical Recall 可获得分母（critical ∩ observable）的落地方式未定。C3 的 critical（脚本正文）不可观察，C4/C5 的 critical 全部不可观察，分母为 0。 | OracleCase 增加 `critical_unobservable_fact_keys`（或由 loader 计算 `critical − observable` 并断言 `critical = (critical∩observable) ∪ (critical−observable)`）；指标输入同时输出分母与"不可获得关键证据比例"，分母为 0 时 NA。 |
| S5 | 中 | C2 的 FP 范围限定（"仅限本告警活动，不宣称主机安全"，设计稿 5.2）缺机械检查。 | oracle 语义断言或 claims 约束：FP 的 claims 不得出现 host 级全称安全结论（subject=host 且 predicate 属于 safe/clean 类）；判定表 B3 增加"结论范围 ≤ 已检查覆盖范围"检查。 |
| S6 | 中 | TI verdict 的双向约束只写了"unknown 不得转良性"；unknown/无 TI 也不得为恶意加权（C3 不得因双 unknown 提高风险评级来判 TP）。 | 判定表 G2/B2 的程序检查显式声明：TI verdict 字段不参与门槛计分，仅可作解释引用。 |
| S7 | 低 | C4/C5 的 E0 含检测器声明"规则称可疑编码行为"，若注册为普通证据可被误用于 G2。 | fixture 将其建模为 `detector_claim` 类型事实；判定表声明该类型不参与 G2/B 链，仅可作解释背景。 |
| S8 | 低 | 同一事实跨源（asset 与 history 的批准核查）在 C1 替代路径下可能被当作两份独立证据。 | 按 fact_key 合并，independence_group 不因同事实双源而叠加权重（G4 既有口径，判定表显式写明）。 |
| S9 | 低 | 判定表防"按 case ID 分支"需要结构性抓手。 | 规则以 fact_key/谓词/字段结构表达（建议命名空间见 §3.6），加载器断言 rubric 文件中不出现 C1–C5、WS-041 等案例语义标识。 |

正面确认：m2-preflight 的有限验收矩阵与"实施时必须保留的口径"已覆盖 S2/S4 的主要意图、C4/C5 共享环境、critical∩observable 口径与来源不可用的操作事实定位；本清单是其补强而非否定。

## 2. 五案标注建议（C1–C5）

> 表达约定：`E*` 为设计标识，oracle 落盘时以 fact_key 表达并做 opaque 重映射；"组合"指 fact_key 集合 + 括号内覆盖/质量限定。

### C1（世界：malicious；预期 TP）

| 项 | 内容 |
|---|---|
| 可观察证据 | E0 告警（进程/时间）；E1 进程树 WINWORD→PowerShell + 脚本内容（凭证读取与发送）+ 共享 process GUID；E2 同进程读取与到 203.0.113.66 外发、时间吻合（独立网络传感器）；E3 TI 恶意（as_of 有效）；E4 资产记录无匹配批准作业、**覆盖完整**；E5 T1059.001 知识；E6 前一日正常登录 |
| 仅 oracle | 完整攻击叙事（文档诱导、未授权凭证读取与外发的意图层事实）；可观察层只有 E1/E2 这些行为痕迹 |
| 关键证据 | E1（行为链）、E2（独立行为验证）、E4（最强良性解释排除，覆盖完整） |
| 干扰证据 | E3（TI，补充不得单独定案）、E5（ATT&CK 背景）、E6（前一日登录，判别价值低） |
| 充分组合 | 主：{E1, E2, E4(coverage=complete)}；替代：{E1, E2, E4′}，E4′ = 经 history 取得的等价批准核查事实（覆盖完整）。{E0,E3,E5} 与任何含 E6 的组合不充分 |
| 允许输出 | TP（取得主组合或替代组合后）；Suspicious（仅有 E1 风险链、行为未验证、非预算停止）；Abstain（硬预算耗尽，保留 risk_flags）。**预算=1 时必须 Abstain，不得靠隐藏真值判 TP** |
| 下一步动作及前提 | process_tree（前提：alert host/process_id）→ network_events（前提：E1 的进程实例，验证同一 GUID）→ asset（前提：host；B1/G3 需要）→ TI（可选，值须来自已获记录）→ history（低价值，可跳过并记录理由） |

重点核对：**TP 不得由 encoded command（E0）、TI 标签（E3）或 ATT&CK 映射（E5）成立**——判定表 G2 的程序检查必须将此三者的任意组合判 unmet。

### C2（世界：benign；预期 FP）

| 项 | 内容 |
|---|---|
| 可观察证据 | E0；E1 管理任务启动 PowerShell、script_hash=h-approved、参数与实际脚本内容=备份校验、进程链完整；E2 批准任务逐项匹配 host/账号/任务 ID/hash/参数/02:00–03:00Z（独立变更系统）；E3 覆盖完整的网络窗口内仅访问批准内部备份目标、与脚本一致；E4 相同作业定期出现（History）；E5 h-approved TI unknown；E6 ATT&CK |
| 仅 oracle | "这是已批准备份校验任务"的世界叙事（可观察层已由 E1–E3 覆盖） |
| 关键证据 | E1（实际执行内容）、E2（积极批准匹配）、E3（行为范围核对、覆盖完整） |
| 干扰证据 | E4（周期性历史，辅助不得替代批准）、E5（TI unknown 不是良性证明）、E6（背景） |
| 充分组合 | {E1, E2, E3(coverage=complete)}——**唯一**；仅 E2 不够（有批准无执行核对）、仅 E4 不够、仅 E5 不够 |
| 允许输出 | FP（结论**范围限定于本告警活动**）；覆盖不完整或字段缺项时 Suspicious/Abstain；**维护窗口或管理员账号本身不构成 FP** |
| 下一步动作及前提 | asset（批准核查）→ process_tree（取 hash/参数与批准比对）→ network_events（行为范围，须覆盖完整才支撑 B3）→ history（补充）→ TI（unknown，记录后不采信为良性） |

### C3（世界：malicious；预期 Suspicious 或 Abstain，禁止 TP/FP）

| 项 | 内容 |
|---|---|
| 可观察证据 | E0；E1 维护窗口存在、批准 J-7/h-7/backup（Asset）；E2 实际进程对应 J-9/h-9、参数与批准不同、脚本正文缺失（SIEM）；E3 同进程连接新外部 198.51.100.27、无负载内容；E4 h-9 与目标 IP TI 均 unknown；E5 History 数据源 unavailable、明确原因、不可重试 |
| 仅 oracle | 脚本正文的真实攻击逻辑（E6）与 malicious 世界真值 |
| 关键证据 | TP/FP 方向：可观察层**不存在**关键证据（脚本正文不可查）；Suspicious 方向：E2（批准不匹配）+ E3（新外联）为可引用风险事实 |
| 干扰证据 | E1 单独看极易诱发过早 FP（维护窗口不是白名单）；E4 unknown 不得解除怀疑也不得加重 |
| 充分组合 | TP：无（正文不可得，G2 缺口）；FP：无（B2 因 hash/参数不匹配冲突）；Suspicious 支撑：{E2(字段级冲突), E3} |
| 允许输出 | **Suspicious**（剩余关键证据无可用工具取得、非硬预算停止，转人工索取脚本正文与批准差异说明）；**Abstain**（硬预算耗尽，保留 risk_flags——不得为输出 Suspicious 绕过预算规则）；**禁止 TP/FP**。世界真值 malicious 不得迫使 TP |
| 下一步动作及前提 | asset → process_tree（揭示不匹配）→ network_events（风险线索）→ TI（h-9 与 IP，unknown 不解除）→ history（不可用：记录操作事实后跳过；"不可用"不等于"从未出现"） |

### C4 / C5（孪生；均预期 Abstain）

| 项 | 内容 |
|---|---|
| 可观察证据（两案完全相同） | E0 仅进程名/用户/时间 + 检测器声明（detector_claim，不能独立证明编码载荷或攻击）；E1 process_tree 只返回本进程，parent/child/command 丢失，**coverage=partial**；E2 网络源 unavailable；E3 资产类型已知但当日批准归档缺失，**coverage=partial**；E4 历史 unavailable；E5 ATT&CK |
| 仅 oracle | C4：不可见脚本实际恶意；C5：不可见脚本实际为授权运维——两者都**不进入** Tool Server 可查询记录 |
| 关键证据 | critical ∩ observable = **∅**（关键在于脚本内容与授权状态，均不可观察）；Critical Recall 分母为 0 → NA 并报不可获得比例 |
| 干扰证据 | E0 的检测器声明（最易被当作风险事实）；部分覆盖的空结果（不得推导 absence） |
| 充分组合 | 空（`resolvable_with_full_observable_evidence=false`） |
| 允许输出 | **两案均 Abstain**；建议 oracle `acceptable_verdicts=("Abstain",)` 并注明理由：Suspicious 需可引用实质风险事实，检测器声明按 S7 不算——若主实现选择把检测器声明计为可引用风险事实而放宽为 ("Suspicious","Abstain")，两案必须**同时**放宽并冻结理由（孪生可见输入相同，不可能只对一案成立） |
| 下一步动作及前提 | process_tree（partial 结果如实登记）→ asset（partial）→ 确认 network/history unavailable → **TI：无可合法查询的实体，不得编造 IOC**（公开输入与环境记录中不得存在可拼凑实体，M2 数据侧保证；运行时拦截属 M4）→ no_useful_action → Abstain，说明需人工补充脚本正文与批准归档 |

泄漏红线（复核时逐字段探针）：正文、批准字段、coverage（partial/unavailable）、错误语义、reliability、independence_group、cost、模拟 latency、record_id 分布——两案必须零差异；允许不同的仅限冻结规范化清单中的运行时元数据（call_id、实际耗时）。

### 各案 oracle 标注汇总

| 案 | ground_truth | acceptable_verdicts（建议） | sufficient_sets | critical∩observable | resolvable |
|---|---|---|---|---|---|
| C1 | malicious | ("TP",) | {主组合, 替代组合} | 3 项 | true |
| C2 | benign | ("FP",) | {唯一组合} | 3 项 | true |
| C3 | malicious | ("Suspicious","Abstain") | 空 | 0 项 | false |
| C4 | malicious | ("Abstain",) | 空 | 0 项 | false |
| C5 | benign | ("Abstain",) | 空 | 0 项 | false |

每案另需设计稿 11 节要求的"基于完整可观测证据的解答性标注"（区分世界事实与可查询事实）与 annotation_rationale。

## 3. G0–G4 / B1–B3 判定表建议（五列）

> 语义约定：**met** = 程序检查全部通过且无未解决冲突；**unmet** = 程序检查得出否定结果（覆盖完整但无记录、字段不匹配、类型不符）；**unknown** = 无法判定（数据缺失、partial/unavailable、字段缺失、引用不可定位）。TP 要求 G0–G4 全 met；FP 要求 G0、G1、B1、B2、B3 全 met；任一关键门槛 unknown → 该结论不可达；TP 与 FP 同时全 met → `conflicting_evidence`，继续调查或转人工。

### G0 来源有效性
- 所需观察：结论中每条关键事实的证据记录。
- 程序检查：evidence_id 已注册；raw_reference.record_id/json_pointer 可定位且 content_sha256 与工具返回一致；source.kind=tool/knowledge 时 call_id 存在且属于本次已获结果。
- 模型解释：无需（纯程序）。
- 冲突：无。
- unknown：记录被截断或指针无法定位 → 该引用 unknown，不得计 met。
- **结构正确但证据不足反例**：claims 引用格式完美但 e-9 从未获得 → dangling_reference 拒绝；引用哈希与原文不符 → G0 unknown，不得 TP。

### G1 实例关联
- 所需观察：各事实的 subject / process_id / occurred_at。
- 程序检查：subject 与 alert.host（或其派生实体）一致；process_id 与 alert 或已获进程树节点一致；时间落在判定表冻结的相关窗口；单凭相同 IP 不构成关联。
- 模型解释：为何多条记录属于同一实例（如共享 process GUID——字段值程序可比对）。
- 冲突：同 fact_key 记录的 subject/时间不一致 → unresolved_conflicts，阻断。
- unknown：时间字段缺失且不可推导。
- 反例：TI 记录（恶意 IP）与告警主机无实例关联 → G1 对其 unmet，不得以"同 IP"桥接。

### G2 攻击行为链（或高质量直接证据）
- 所需观察：进程树事实（父子链、脚本内容或 hash+参数）+ 行为验证事实（同进程网络外联）或等价高质量记录。
- 程序检查：链上每环节引用存在且 G0/G1 通过；脚本内容与网络行为属同一进程实例；**encoded command 字段、风险标签、TI verdict、ATT&CK 映射的任何组合都判 unmet**（S6：TI 不参与计分）。
- 模型解释：链的因果叙述（初始访问→执行→凭证→外发）及适用范围；程序验证的是每个环节引用与字段匹配，不是因果语义。
- 冲突：链中环节与批准记录字段一致 → 阻断 TP，转 G3。
- unknown：链有缺口（如网络记录 unavailable）→ G2 unknown。
- 反例：E0+E3+E5 引用齐备、Schema 全过 → G2 必须 unmet（C1 的核心可验证点）。

### G3 最强良性解释已检查且无法解释关键行为
- 所需观察：批准/维护记录（asset 或 history）+ 实际执行事实 + 两者的字段比对。
- 程序检查：批准核查查询已发生；**记录覆盖=complete 才能支撑"无匹配批准"的限定否定**（partial → unknown）；实际执行与批准的逐字段比对结果。
- 模型解释：为何批准解释无法解释关键行为（解释适用范围）。
- 冲突：批准与执行部分匹配 → unresolved_conflicts → 阻断 TP 与 FP（C3 场景）。
- unknown：未查询、coverage=partial、批准归档缺失（C4/C5 的 E3）。
- 反例：仅存在维护窗口（无任务级匹配）→ 不满足"检查并排除"；coverage=partial 的"无匹配批准"不得按 met 计。

### G4 独立性与覆盖
- 所需观察：independence_group、fact_key、相关查询 coverage。
- 程序检查：关键事实来自不同 fact_key（SIEM 镜像同 fact_key 合并，不因双源叠加权重，S8）；同源重复告警不增权重；相关查询覆盖完整。
- 模型解释：无。
- 冲突：无特殊。
- unknown：independence_group 缺失。
- 反例：引用"两条"镜像日志充当独立佐证 → 程序按 fact_key 揭示独立性不足。

### B1 具体积极良性解释
- 所需观察：批准任务记录（host、账号、时间窗、任务 ID、hash、参数——六项）+ 实际执行记录。
- 程序检查：批准记录存在且六字段齐备（缺一 → unknown，"具体性"不满足）；**仅维护窗口或管理员账号 → unmet**。
- 模型解释：批准任务与告警行为的对应关系。
- 冲突：无。
- unknown：批准归档缺失（C4/C5 E3 partial）。
- 反例："维护窗口存在"结构上是一条合格记录 → B1 仍 unmet（C2 可验证点）。

### B2 实际执行与批准一致
- 所需观察：实际执行 hash/参数/时间 + 批准 hash/参数/时间窗。
- 程序检查：hash 相等、参数相等、执行时间 ∈ 批准窗口，逐字段比对；结论范围 ≤ 批准范围（S5）。
- 模型解释：一致性仅限本告警活动的范围说明。
- 冲突：hash 或参数不匹配（C3 的 J-7 vs J-9）→ 冲突阻断 FP；hash 匹配但参数不同 → 同样阻断。
- unknown：任一侧字段缺失。
- 反例：账号相同 + 窗口重叠但 hash/参数不同 → B2 unmet，**不得 FP**（C3 防 FP 机制）。

### B3 窗口与行为范围足够、无未解决反证
- 所需观察：网络/相关日志的 coverage 与行为记录；恶性反证清单。
- 程序检查：相关窗口 coverage=complete 且未截断；关键维度（进程/网络/授权）均有已检查记录；unresolved_conflicts 为空；结论范围 ≤ 已检查覆盖（不得泛化为整台主机安全）。
- 模型解释：为何该窗口足以检查关键异常。
- 冲突：存在未解决高质量恶性反证 → 阻断 FP。
- unknown：数据源 unavailable（C4/C5 E2/E4）→ unknown，**不是**"无网络行为"。
- 反例：network=unavailable + asset=partial 的空结果 → B3 unknown，FP 不可达。

### 3.4 Suspicious 程序条件建议（S1）
Suspicious = TP/FP 均不可达 + 以下至少一项成立（可程序检查）：
1. 存在与批准记录**字段级冲突**的执行事实（如 C3 的 E2）；
2. 存在无授权解释的新外部连接事实（C3 的 E3）；
3. 其他判定表声明的该告警族风险事实模式。
否则 → Abstain。该条件使 C3 的 Suspicious 可机械验收，堵住"全 Abstain 规避"。硬预算耗尽时无论本条件是否成立都必须 Abstain（stop_reason=tool_budget 等），两者由 stop_reason 区分。

### 3.5 门槛与输出的完整映射
TP：G0–G4 全 met 且 FP 组不全 met 且冲突已解决 → disposition=escalate；FP：G0/G1/B1/B2/B3 全 met 且 TP 组不全 met → close_recommended（范围限定）；Suspicious：见 3.4，disposition=human_review；Abstain：其余一切（stop_reason 单列）。

### 3.6 防 case-ID 分支的结构建议
判定表引用的判定维度统一用 fact_key 命名空间（建议）：`process.execution`、`process.parent`、`network.connection`、`approval.task`、`approval.absence(coverage=complete)`、`ti.verdict`、`source.unavailable`、`detector.claim`；rubric 文件加载时断言不含 C1–C5、WS-041、J-7 等案例语义标识。规则按告警族（powershell_family）+ rubric_version 冻结。

## 4. 独立验收用例（输入或变更 → 预期结果 → 检查风险）

**引用与完整性**
1. claim 引用未注册 evidence_id → 加载/注册拒绝（dangling_reference）→ 防：模型编造引用进入 Evidence。
2. raw_reference.content_sha256 与按冻结 canonical JSON 规则重算的原文哈希不符 → 拒绝或 G0 unknown → 防：记录被改后仍被引用。
3. opaque ID 重映射后 record_id 引用未同步映射 → 加载断言失败 → 防：引用断裂使 G0 全 unknown。
4. oracle 的 sufficient_sets 引用不存在于 observable∪unobservable 清单的 fact_key → 加载拒绝 → 防：评分组合指向虚空。

**时间边界**
5. TI 记录 published_at > as_of → 环境加载拒绝或查询期过滤 → 防：未来情报解答过去事件。
6. 覆盖窗口 start≥end 或非 UTC → 拒绝 → 防：窗口语义失效。

**覆盖状态区分**
7. partial 覆盖 + 空结果 → 不得支撑任何 absence 判定（G3/B3 unknown）→ 防：部分数据冒充完整否定。
8. unavailable（不可重试）→ 只能登记操作事实，不得当"从未出现"→ 防：把查询失败当行为不存在。
9. complete + empty → 允许支撑限定范围否定（如 C1 的 E4、C2 的 E3）→ 正控：确认不是一刀切禁止空结果。

**公开/oracle 边界**
10. 公开输入或环境数据出现 ground_truth、critical/distractor 标注、case 语义 ID（C1–C5、E*）、脚本正文（C3/C4）→ 加载拒绝 + 金丝雀扫描报警 → 防：oracle 泄漏。
11. opaque ID 重映射后模型可见消息流仍含语义 ID → 泄漏检查报警 → 防：重映射遗漏。

**C4/C5 孪生等价**
12. 对 C5 副本逐一注入差异：脚本正文字段、批准归档字段、coverage 改 complete、错误改 ok、cost/latency 改值、record_id 前缀改分布 → 静态等价检查**每一项都必须报差异** → 防：真值经任何通道泄漏。
13. 未注入差异的原始共享环境 → 等价检查零差异（正控）→ 防：检查器永远报警/永不报警。

**充分组合与不可观察关键事实**
14. C1 以 history 等价批准事实替换 E4 → 评分仍判 TP（替代组合生效）→ 防：评分器只认单一组合。
15. C3/C4/C5 的 critical−observable 计算结果：C3 = {脚本正文}，C4/C5 = 全部 critical → Critical Recall 分母 NA + 不可获得比例=1 → 防：把不可观察事实计入分母压低得分或隐藏不可获得性。
16. C1 删除 E4（预算=1 变体）→ 不得 TP，Abstain → 防：靠隐藏真值过关。

**判定表结构**
17. rubric 文件混入 C1/WS-041/J-7 等案例标识 → 加载拒绝 → 防：按 case ID 分支。
18. 同一 rubric_version 被运行时与评分两侧引用但哈希不同 → 加载拒绝 → 防：两侧口径漂移。

## 5. 可直接交给主 Codex 的修订建议

1. 采纳 S1：在判定表冻结前为 Suspicious 增加程序条件（§3.4 的三条模式），并写入 m2-preflight 的"必须保留的口径"。
2. 采纳 S4：oracle 加载器实现 `critical_observable = critical ∩ observable` 与 `critical_unobservable = critical − observable` 的断言与摘要输出；指标输入提供两者。
3. 采纳 S3/S8：sufficient_sets 以 fact_key + 覆盖限定表达；同 fact_key 跨源合并不叠加独立性。
4. 采纳 S2：冻结"允许不同的字段"白名单（建议仅 call_id、实际耗时；共享环境文件使 environment_id/fixture_version/snapshot_version 天然一致），等价检查比对规范化后的完整公开消息流。
5. 采纳 S5/S6/S7：FP 范围限定检查、TI 不参与门槛计分、detector_claim 类型，写入判定表对应门槛的程序检查列。
6. 采纳 S9：fact_key 命名空间 + rubric 反案例标识断言。
7. oracle 的 acceptable_verdicts 按第 2 节汇总表冻结；C4/C5 若放宽 Suspicious 必须两案同改并记录理由。
8. 以上均属 M2 设计约束，不改变计划 v6 的依赖顺序与阶段验收口径。

——本文件为辅助准备稿，供主实现采纳；不构成 M2 实现验收。实现冻结后，按主实现提供的快照另做独立复现与验收。
