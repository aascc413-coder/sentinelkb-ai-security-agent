# Evidence-Aware Security Alert Investigation Agent — Phase 1 设计

状态：可评审的设计草案；尚未实现 Agent、工具环境或实验。日期：2026-10-01。

## 0. 阅读入口与交付边界

- 本文：问题审查、系统架构、决策机制、工具契约、实验与依赖任务。
- `contracts.py`：仅 Python 数据结构和 Protocol，无工具、Agent 或模型调用实现。
- `minimal-cases.md`：5 个可转为 fixture 的设计案例，包含隐藏真值与可见证据边界。
- `architecture.drawio`：可编辑架构图。

本阶段只完成用户要求的 Phase 1。下一阶段才把案例做成可执行的 Mock Environment。

## 1. 结论与必须修正的问题

项目可做，但应定位为“带调查预算和拒判机制的证据获取策略实验”。以下修正是进入编码的前提。

| 原需求中的风险 | 设计决定 |
|---|---|
| TP/FP 与 Suspicious/Abstain 被混作四类真值 | 真值为 malicious / benign；四种输出是决策。Suspicious 和 Abstain 均转人工，不能计作正确的二分类。 |
| TP/FP 在 SOC 也可能指检测规则是否正确触发 | 本项目明确 TP=有充分证据确认恶意活动，FP=有充分证据确认该告警对应活动良性。获批的运维即使触发规则，也按本项目约定计 FP。 |
| LLM 自报 0.95 就意味着证据充分 | 概率估计、事实落地、充分性分别记录；LLM 自报置信度不是充分性的通行证。 |
| 支持两种假设就等于避免确认偏误 | 每个调查目标必须列出能支持或推翻不同假设的可能观察；决策前显式检查最强替代解释。仍需反证消融验证效果。 |
| 至少两个假设导致强行穷举二分世界 | 初始至少一个恶意解释、一个良性解释；保留 other/unknown 通道，允许假设被否定、修订。初期最多 4 个具体假设。 |
| 没查到恶意记录就关闭 | 空结果、查询失败、日志缺失、窗口未覆盖要区分；只有覆盖完整的相关查询才能支撑限定范围的否定事实。 |
| 声称下一步最大化信息增益 | 没有可靠的观察概率模型，MVP 只能使用可审计的行动价值启发式，不能宣称真实信息增益或最优策略。 |
| 充分性规则与数据集由同一机制定义 | 运行时只看通用告警族 rubric；离线评分使用独立标注的充分证据组合和断言。不得将案例答案或最短路径传给 Agent。 |
| 一条预期路径成为唯一正确路径 | 以状态相关的可接受动作集合、证据目标和替代充分证据集合评分，允许不同顺序。 |
| 更少调用就代表效率更高 | 同时记录工具成本、结果大小、模型 tokens、运行时间，并在相近判断覆盖率/错误关闭率下比较。 |
| 全部 Abstain 也能实现零错误关闭 | 必须报告覆盖率、人工负担、可解案例上的拒判率及风险—覆盖曲线。 |
| 5 个合成案例能证明创新 | 5 个仅用于设计和功能验收；30–100 个也主要是探索性证据，不足以宣称生产性能。 |

研究边界：主动获取信息与选择性分类已有研究。本项目可能的贡献是把这些思想落实为可复现的安全调查策略，并展示其相对基线的实测收益；目前不能声称首创或证明超过已有 SOC Agent。

参考：[Active Feature Acquisition, ICML 2021](https://proceedings.mlr.press/v139/li21p.html)、[Selective Classification 与风险—覆盖权衡, JMLR 2010](https://www.jmlr.org/papers/v11/el-yaniv10a.html)。这里只借鉴问题定义，不套用论文的性能保证。

## 2. MVP 范围与可证伪的假设

初期限定告警族：Windows 可疑 PowerShell 执行。它可以对应运维、攻击或证据不完整，适合构造竞争性假设。

输入：单条告警、可见工具目录、统一预算、固定版本的知识快照。

输出：TP / FP / Suspicious / Abstain，事实引用、未解决问题、停止原因、人工复核所需材料、完整可重放 Trace。

H1：相同自动判断覆盖率下，Proposed 降低 False Close Rate。

H2：相近错误关闭率和覆盖率下，Proposed 降低工具成本；不能仅比较调用次数。

H3：对可见证据无法区分真值的案例，Proposed 更少输出确定结论；同时不会在所有可解案例上拒判。

H4：Proposed 更经常取得关键判别证据，且最终事实更少超出证据内容。

结果不支持时保留失败 trace；不得通过删困难样本、改测试标签或降低覆盖率来包装提升。

## 3. 最终系统架构

采用一个顺序调查循环和 5 类本地工具。MVP 不依赖 LangGraph、Neo4j、向量库或外部 SOC 服务。这样每轮行为和成本容易测试；未来需要持久任务时再接工作流框架。

### 3.1 三个数据边界

| 边界 | 可以访问 | 不可以访问 |
|---|---|---|
| Agent Runtime | 原始 alert、实际已返回的 ToolResult、公开工具规格、通用 rubric、剩余预算 | Ground truth、未调用工具的完整结果、critical/distractor 标注、expected verdict/path |
| Mock Tool Server | 当前案例的可查询观测记录、查询覆盖范围、不可用状态、冻结的 as_of 时间 | Agent 的最终标签预测；无需读取 ground truth |
| Offline Evaluator | 冻结真值、全部可观测与隐藏世界标注、Trace、独立评分标准 | 不能在运行中给 Agent 答案或补证据 |

Phase 2 用独立环境服务或受限子进程持有 fixtures；Agent 只得到只读工具客户端。Agent 输入不含案例语义 ID、文件路径或隐藏标签。随机 opaque ID 仅用于 harness 关联，counterfactual 双胞胎拥有相同模型可见输入。

### 3.2 一轮调查

1. Context Builder 只规范化告警，登记原始来源；没有隐式免费查资产或历史。
2. Hypothesis Generator 提出竞争假设、预期观察和可推翻条件；这些是解释，不是事实证据。
3. Evidence Registry 接受来自告警或已执行工具的事实；Evidence State 维护事实与解释的关联。
4. Sufficiency Evaluator 判断当前证据支持哪个决策、还缺什么，并检查竞争解释与关键矛盾。
5. 若 TP/FP 的门槛满足，保存结果并终止。否则在预算内进入 Planner。
6. Planner 从合法候选动作中选择最有判别价值且可负担的一个，记录理由及放弃的候选。
7. Budget Guard 检查调用、tokens、steps、deadline；Dispatcher 执行工具并记录费用、错误、覆盖范围。
8. Evidence Registry 记录新事实、去重并保留来源关联；返回第 3 步。
9. 无可行调查或预期收益不足时，按 Suspicious/Abstain 规则结束；硬预算耗尽且尚不充分必须 Abstain。

所有方法都经过相同的 Dispatcher、预算与 Trace 层。只有 Proposed 在线运行假设/充分性机制。Evaluator 在运行结束后独立给四种方法评分。

### 3.3 与当前 SentinelKB 的关系

当前 `code/python/agents/security_analysis_agent.py` 的风险分数主要由 IOC 数量、关键词和 ATT&CK 命中累加，不能作为概率、事实可靠度或充分性评分。

当前 `code/python/orchestrator/graph.py` 的入库、QA 和更新流程不是调查策略基线，也不能改个名字作为 ReAct。

后续在仓库中新增独立 `investigation/` 实验模块，保留明确的模型适配接口；Phase 6 才把 SentinelKB 检索变成一个可计费、可溯源工具。复用解析/配置思路，但不继承其启发式风险评分或默认“规则映射=恶意”假设。

建议后续结构：

```text
investigation/
  pyproject.toml
  src/evidence_investigation/
    agents/          # hypothesis / planner / sufficiency / investigator
    state/           # contracts，带运行时验证
    tools/           # schema / dispatcher / local adapters
    baselines/       # direct / fixed / react
    runtime/         # model adapter / budget / trace
    prompts/         # 模板和版本
  evaluation/        # evaluator / metrics / benchmark，不被 Agent 导入
  datasets/
    public/          # alert 输入
    environment/     # Tool Server 持有的可查询记录
    oracle/          # 仅 Evaluator 使用的真值和评分标准
  tests/
  runs/              # 按 run_id 保存 trace、manifest、汇总；默认不入库
```

现在不创建这些空目录，只保留 Phase 1 设计产物。

## 4. 数据契约与事实边界

完整 Python 设计见 `contracts.py`。这是标准库 dataclass/Protocol 草案；类型注解不是运行时验证。Phase 2 必须加入边界校验及 JSON 编解码，之后才可接收模型输出。

### 4.1 Evidence

Evidence 是来源中可定位的原子观察。必须包含 evidence_id、fact_key、subject、predicate、value、occurred_at、observed_at、reliability、source、raw_reference、independence_group。

- `source` 区分 alert、tool、knowledge；tool 证据必须有可追溯的 call_id。
- `raw_reference` 包含 record ID、JSON Pointer 和原始记录内容哈希。离线复核可以定位值并检查是否被修改；哈希证明内容一致，不证明传感器没有撒谎。
- `reliability` 为来源/覆盖约定下的 high/medium/low/unknown 等级及理由，由适配器配置；不是由模型猜一个“证据为真的概率”。
- `fact_key` 去重同一事件事实；`independence_group` 防止 SIEM 与 TI 镜像记录被当作两份独立证明。
- `value` 可承载 IP/domain/hash、command_line、parent/child process、网络连接、资产属性、历史行为、维护授权、已知运维工具、ATT&CK technique 等结构化字段。
- 出现在不可信日志中的“管理员已批准”只是一条日志声称；批准事实必须来自对应权威记录。
- TI 的“未收录”不能变成“良性”；ATT&CK 映射属于知识解释，不能成为恶意性的独立证明。

支持/反驳关系由 `EvidenceLink` 维护，包含 evidence_id、hypothesis_id、stance、理由、适用实体/时间。关系是解释，可以修订，原始事实只追加不覆盖。

假设只能引用已存在的 evidence ID。LLM 生成的摘要、风险分数、自由文本“事实”、自身判断均不得写入 Evidence Registry。

工具返回的 coverage/error 也要保存为原始响应 envelope，允许引用“某数据源不可用”这一操作事实；它不是“目标行为不存在”的事件事实。原始注册器和确定性字段提取器为四种方法共用，基线也获得相同的 evidence ID 以便引用；仅 Proposed 维护假设、证据关联、缺口与在线充分性状态。这样证据评分不会因为基线没有专用 ID 而天然偏低。

### 4.2 Grounding / Sufficiency / Discrimination

**Grounding** 分两层：

1. Provenance validity：ID 存在、属于本次已取得结果、原文定位和值一致。
2. Semantic support：引用是否真的支持断言、是否超出原文范围。MVP 优先使用 subject/predicate/value 的结构化断言；未能机械验证的自然语言断言须独立人工评分，不能仅用同一个模型自证。

**Sufficiency** 是特定结论的门槛检查，不是证据条数。返回每个门槛 `met / unmet / unknown`、证据 ID、阻断矛盾和缺口。

**Discrimination** 是相对于假设对的判别作用。比如“执行 PowerShell”同时符合攻击与运维；“调用参数与批准任务不同”可以推翻某个运维解释，但单独仍未必证明攻击。

`p_attack` 仅为对二元真值的模型估计，允许为空；完整案例评测 Brier/ECE 时需各方法在所有案例均输出该估计，并报告缺失率。未经校准不得称为可靠概率。对假设的支持程度也不强行相加为 1。

### 4.3 运行时约束

ID 唯一、引用存在、UTC 时间带时区、start<end、数据发布时间<=as_of、概率在 [0,1]、成本非负、来源与调用一致、最终证据必须是已获得事实的子集。

非法模型输出最多修复一次，修复也计入预算。仍非法或无预算时记录 protocol_error 并 Abstain；不能静默修成一个 TP/FP。

## 5. Evidence Sufficiency 的 MVP 实现

采用“通用告警族 rubric + 结构化模型解释 + 确定性约束”的混合方案。

这些是待验证的操作性标准，不是真实世界的形式证明。rubric 在 dev 上冻结；不能根据 test 案例 ID 分支。新增证据可能产生矛盾，因此充分性不要求单调增加。

### 5.1 TP 门槛（PowerShell 告警族）

- G0：结论中的关键事实均有有效来源。
- G1：证据关联到同一主机、进程实例和相关时间窗口；单凭相同 IP 不够。
- G2：存在经验证的攻击行为链，或足以直接表明未经授权恶意行为的高质量证据；不能只凭 encoded command、风险标签或 ATT&CK 映射。
- G3：最强良性解释已被检查，无法解释关键行为；反证和来源冲突已解决或明确不足以推翻结论。
- G4：独立性与覆盖充分；同源重复告警不提升证据权重。

不硬性要求固定的两份工具结果：一个含完整可验证行为的高质量记录可能足够；多个弱线索也可能仍不够。

### 5.2 FP 门槛（关闭更谨慎）

- G0/G1 同上。
- B1：存在具体、积极的良性解释，匹配用户、host、时间、进程/任务、脚本内容或 hash 与参数。
- B2：观察到的执行行为与获批行为一致；不能仅因在维护窗口或由管理员账号执行就关闭。
- B3：相关日志窗口与行为范围足以检查关键异常，且无未解决的高质量恶意反证。

结论范围只能覆盖此条活动，不能说“整台主机安全”。对检测范围外的行为保持未知。

### 5.3 四种输出与停止优先级

| 输出 | 条件 | 后续动作 |
|---|---|---|
| TP | TP 门槛满足、FP 不满足且关键冲突解决 | 标记需要安全人员后续处置，不自动隔离 |
| FP | FP 门槛满足、TP 不满足且关键冲突解决 | 允许建议关闭，不在 MVP 写入真实 SOC |
| Suspicious | TP/FP 均不满足；至少一项可引用的实质风险事实，关键解释未定；合法且可负担的剩余动作已评估为无帮助或不可用；尚未触发硬预算停止 | 带风险线索优先转人工 |
| Abstain | 不足以支持确定结论；硬预算触发、关键来源冲突不可解、只有模糊触发事实或协议失败等 | 说明为何无法判定及需要人工补充的证据 |

若预算耗尽且此前未有有效的充分性结论，最终必须 Abstain；可保留 risk_flags，不能为了输出 Suspicious 绕过预算规则。若最后一次合法工具返回后仍有评估预算，先做预留的终结评估：已足够可以 TP/FP，否则 Abstain。

同时满足 TP/FP 是冲突，不选择分数较高者；继续查冲突来源或转人工。

停止原因与 verdict 分字段：sufficient / no_useful_action / no_available_tool / tool_budget / token_budget / step_budget / deadline / conflicting_evidence / protocol_error / model_error。

## 6. Investigation Planner

模型每轮提出最多 3 个候选动作。每个动作包括：

- 要解决的证据缺口，以及针对的假设对。
- 查询结果的不同可能取值；各取值分别支持/推翻什么。
- 为什么可能改变结论，而非仅补充背景。
- 工具名、已知实体、时间窗、预计结果量和成本。
- 选中与未选中理由，以简短、可核查的决策记录保存；不要求输出模型隐藏思维链。

MVP 排序使用预先固定的序数启发式，禁止包装为校准信息增益：

`priority = 3*discrimination + 2*critical_gap + counterevidence + availability - normalized_cost - redundancy`

各收益分量取 0/1/2，由明确定义的 rubric 约束；成本由工具目录给定，redundancy 由 Dispatcher 的查询签名与返回记录计算。系数只是初始假设，dev 调整后冻结；没有证据证明这些系数最优。

discrimination=0 表示不区分假设，1 表示可改变排序但不能解决核心歧义，2 表示至少一种可能结果能排除强竞争解释。关键缺口不能由 oracle 告知，由当前假设的可检验预期与运行时 rubric 推导。

实际步骤不固定：拥有进程链却不知道是否运维时先查授权；只有编码命令时可能先查 process tree；进程已关联出站 IP 时可能查 reputation。

对完全重复且环境未变的查询阻止再次后端执行；缓存结果仍记决策与工具请求。瞬态错误最多一次重试，计费；永久不可用不重复查询。

当前剩余行动均得分<=0不自动等于无证据价值：终止前检查是否遗漏有可用工具覆盖的关键缺口，并记录为什么不选。此启发式可能漏掉先低收益、后高收益的多步路径，列为 MVP 已知局限。

## 7. Tool Interface

5 类工具实现见 `contracts.py` 的参数类型和 Protocol。最终外露为有闭合字段的 JSON Schema，禁止任意 SQL、任意脚本、全表下载和返回整个 case。

| 工具 | 参数与能力 | 返回记录 | 默认模拟成本单位 / 延迟 |
|---|---|---|---|
| SIEM | view=host_events/user_events/process_tree/network_events；host 或 user；可选 process_id；start/end；limit | 进程实例与父子关系、命令、网络事件；实际过滤范围、覆盖和截断状态 | 2 / 0.20s |
| Threat Intelligence | indicator_type=ip/domain/hash；value；as_of | provider、verdict=malicious/benign/unknown、valid_at/published_at、适用说明 | 3 / 0.30s |
| Asset Context | host；as_of | 资产用途、系统、重要性、部门、owner、覆盖指定时间的批准任务及维护范围 | 1 / 0.05s |
| Historical Behavior | entity_type=host/user/command；entity；start/end；可选关联 host/user/command；limit | 匹配行为计数、样本、时间分布、日志覆盖；不能把历史频繁等同正常 | 2 / 0.15s |
| ATT&CK Knowledge | behavior_terms；technique_ids；snapshot_version | Technique 信息与来源；只解释行为，不提供恶意 verdict | 1 / 0.02s |

Asset 工具在 Mock 中聚合有限的批准任务信息，是为了可测试，不建设 CMDB 后台；真实接入时须区分 CMDB 与变更系统来源。

统一 `ToolResult` 含 call_id、tool、status、records、coverage、error、cost、duration、snapshot_version。status 为 ok/empty/partial/unavailable/timeout/error。只有 `ok` 和 `empty` 且 coverage=complete、未截断，才能论证该查询范围内的 absence。覆盖由环境报告，模型不能修改。

ToolContext 的 run_id/as_of/remaining_timeout 由执行器注入，不由模型构造。调用实体必须来自 alert 或已获记录；最大时间窗 24h（SIEM）/30d（history），结果上限 50。Phase 2 统一强制执行。

## 8. 预算与成本

初始 smoke 配置：max_tool_calls=6，max_investigation_steps=8，max_tokens=16000，max_time=90s；这是起始配置，不是调好的最优参数。

- 一 step 定义为一次策略轮次，可输出一项工具请求或结束。Hypothesis 初始化单独计模型调用；充分性评估等模型调用全部记账，不藏进 step。
- max_tool_calls 计所有工具尝试，包括错误、重试、缓存请求和非法请求；另报真正执行的 backend_calls、cache_hits。
- max_tokens 计所有输入/输出与服务商计费的 reasoning tokens（如果输出口径已经包含，不重复相加）；工具返回被送入模型时计输入，初始提示、修复、Planner、Evaluator 和最终答复都计费。
- 调用前核算输入并预留最大输出；预留终结评估 token 空间。无法准确预估时注明估算方式；缺少 usage 的运行不参与精确 token 等预算结论，不能用 0 填充。
- max_time 用 monotonic deadline，工具和模型超时取剩余时长；终止后的迟到响应不写 Evidence。已经发出的费用仍记录为实际或 unknown。
- 结束时若无模型预算，程序从最后一个已验证状态生成结构化 Abstain，禁止用额外免费 LLM 总结。
- 同时报真实 wall time 与 mock simulated latency；网络模型时间和模拟工具时间不混称生产延迟。
- 模型单价在 run manifest 中保存版本，拿不到费用只报告 tokens 和工具成本，不编造金额。

所有方法使用相同硬预算控制器。预算到达并且尚未完成有效最终输出的运行由控制器记 Abstain；此前过早且无据的模型 TP/FP 不被事后改好，留给评测暴露。

## 9. Baseline 与 Proposed 的公平对照

| 方法 | 模型可见输入/动作 | 在线显式假设 | 在线充分性门槛 | 结束策略 |
|---|---|---|---|---|
| Direct LLM | alert；一次模型判断 | 无 | 无 | 直接输出同一四选一 schema，无工具 |
| Fixed Workflow | 固定 SIEM 查询→TI→ATT&CK，结果统一输入 LLM | 无 | 无 | 按预定步骤后输出 |
| ReAct | alert + 同一 5 类工具 + 可见预算；逐轮工具/结束 | 不要求显式结构 | 无 | 模型自行决定结束 |
| Proposed | 同样输入与工具；显式证据状态和假设 | 有 | 有 | 充分结束、价值停止或拒判 |

四种方法都有权输出 Suspicious/Abstain；不能故意让基线强制二分来放大优势。Direct 没有工具导致信息受限，这是有意基线，不能把它落后单独解释成策略贡献。

Fixed 的 SIEM view、时间窗、TI 选择和 ATT&CK query 全部由 alert 和预定解析规则生成；查不到 indicator 时记录 stage_skipped，不能从隐藏 fixture 免费取得。多指标按冻结排序逐个取到上限，每项调用计费。主实验 Fixed 采用用户指定 3 类工具；增加 Fixed-All（同 5 类工具，顺序冻结）辅助控制，区分“有额外数据源”和“会选择动作”的收益。

ReAct 给予合理任务说明、证据引用要求和四种决策定义，不刻意使用弱提示。只是不注入独立充分性模块、竞争假设模板和我们的行动价值排序。

统一模型快照、temperature、输出上限、工具版本、as_of、case split、预算上限、最终 schema、重试规则与系统事实约束。方法提示不同是实验变量；所有额外提示成本计账。

Tool Environment 不因方法而变化。每个 run 重置缓存和状态；测试时屏蔽其他 case 记忆。工具回放使用请求规范化签名，而非第几个请求，避免固定路径才有正确答案。

对照轨道：

1. 相同预算上限的主实验，输出质量/覆盖/成本全套结果。
2. tool budget=2/4/6/8 的预算扫描；按真实总 tokens 分层，防止 Proposed 用更多模型思考换少量 tool call 却被宣称总成本更低。
3. ReAct+Sufficiency Gate、Proposed 去掉反证检查、Proposed 去掉价值排序的消融（完整 MVP 后再做），区分保守门槛与规划贡献。
4. 规则启发式的简单基线可作为 sanity check；不代替三个必需基线。

## 10. Evaluation Schema 与指标

数据拆成 PublicCase、EnvironmentFixture、OracleCase，运行记录为 RunManifest + TraceEvent + FinalAssessment，评分为 CaseScore + AggregateMetrics。具体 Python 契约见 `contracts.py`。

OracleCase 存世界真值、可观察性、可接受决策、替代最小充分证据集合、关键证据、干扰证据、状态相关可接受动作、语义断言标注。expected_verdict 是评测策略目标，不能从 ground_truth 直接推导：世界是恶意，但不可观察时仍应 Abstain。

### 10.1 分类与安全

记 N 为已知真值案例数，D 为输出 TP 或 FP 的案例；a=恶意→TP，b=良性→TP，c=恶意→FP，d=良性→FP，u_m=恶意→Suspicious/Abstain。

| 指标 | 定义与注意事项 |
|---|---|
| Verdict confusion table | 世界真值 2 行 × 决策 4 列，加 failed/invalid 一列；失败不能被丢弃 |
| Decision coverage | (a+b+c+d)/N |
| Selective accuracy | (a+d)/(a+b+c+d)，无确定决策时 NA |
| Overall resolved accuracy | (a+d)/N；拒判不当作正确判断 |
| Attack precision | a/(a+b) |
| End-to-end attack recall | a/(a+c+u_m)；攻击上的拒判计未识别，避免虚高 |
| Attack F1 | 上述 precision 与 end-to-end recall 的调和均值；另对良性报告对称指标 |
| False Close Rate | c / 全部恶意案例；分母是恶意案例数 |
| False Closure Proportion | c/(c+d)；回答“已关闭的里面有多少攻击” |
| Human review rate | (Suspicious+Abstain)/N；单独报告二者占比 |
| Suspicious utility | Suspicious 子集的真实攻击比例、可引用风险线索比例；不纳入 TP 正确数 |

基础指标分母为 0 则 NA 并展示分子/分母。benchmark 运行故障不静默丢弃：attempted N 始终保留，失败另列；安全决策指标展示有效样本分母和失败数，不把失败冒充正确拒判。

### 10.2 证据质量

- Provenance validity：有效可溯源事实引用数 / 全部事实引用数。
- Evidence Grounding Rate：具有有效来源且语义得到支持的原子事实断言数 / 全部最终事实断言数。有效 ID 本身不等于语义正确；无引用的事实计失败。
- Evidence Precision：最终提交的 unique evidence 中，来源有效且被独立标注为与当前结论/不确定性相关的数量 / 最终提交数量。干扰证据即使真实也可能无关。
- Critical Evidence Recall：已获得关键证据 / 环境中可获得关键证据；分母排除隐藏世界中无法查询的证据，另报不可获得比例。
- Sufficiency pass rate：输出 TP/FP 且实际取得、引用的证据满足离线独立充分组合并无未解决矛盾的数量 / TP/FP 数量。
- Discriminating evidence recall：已获得 oracle 标注的可区分假设的证据 / 可获得判别证据。

充分证据集合允许替代组合。例如 E1+E2 或 E1+E3 均可成立；“Critical” 不强制等于唯一一条固定证据。模型碰巧猜对真值但无充分证据，要在证据评分上失败。

初期结构化 fixture 机械比对；Phase 5 对自由文本按冻结 rubric 盲评。仅有一名标注者时明确局限，不把 LLM judge 当权威真值。运行时 sufficiency 与离线 oracle 由不同模块实现，离线评判不调用 Proposed 的自评分。

### 10.3 行为与效率

- Tool Selection Accuracy：正确地选择某个状态下可接受的工具+关键参数的决策数 / 有 oracle 动作标注的决策数；同时报动作标注覆盖率。不是只比工具名字。
- Tool Call Success Rate：ok+empty+partial 的工具尝试数 / 全部尝试；另报 complete-result rate、缓存命中、超时、不可用、参数错误。空结果技术成功但可能无信息。
- Unnecessary Tool Call Rate：重复未变化的查询、明知永久不可用仍查询、或已知对任何剩余假设都无区分作用的调用 / 全部调用。不能因为事后返回空就认为浪费。
- Average/P50/P95 工具尝试数、backend calls、steps、模型调用数、总输入/输出 tokens、工具成本、wall time、模拟 latency。
- 全部案例与成功确定判断案例分别报告成本；低质量或全部拒判的低成本不能作为胜利。

### 10.4 拒判与校准

“Abstention Accuracy”名称不清，拆成：

- Appropriate Abstention Precision：oracle 在当前已获证据下判为不足的 Abstain / 全部 Abstain。
- Required Abstention Recall：环境和给定预算无法支持可靠结论的案例中输出 Abstain 的比例；是否允许 Suspicious 由冻结标注区分，另外报告任何人工升级的召回。
- Avoidable Abstention Rate：在可解且预算足够的案例中 Abstain 的比例，暴露没查到本来可取得证据的问题。
- Risk-Coverage：在同样自动判断覆盖率下比较确定判断错误率和 False Close；选择阈值只用 dev，曲线为描述性分析，不能在 test 上挑最漂亮的阈值。
- Brier：所有已知真值且有 p_attack 的案例均方误差 mean((p_attack-y)^2)，必须报告 p 缺失率；ECE 等分箱指标在样本充足后给出，5 个案例不作校准结论。

p_attack 不是 confidence_of_verdict；不对 Suspicious/Abstain 强求一个“它正确的概率”。

## 11. 数据集与实验规程

5 个公开设计案例用于调试，不计作未来盲测。Phase 2 扩到 5–10 个可回放案例，其中含工具故障、截断、同源重复和预算不足变体。

Phase 5 冻结 30–100 个高质量案例（建议目标 60：dev=20、test=40），按场景模板/组织/来源分组切分。counterfactual 双胞胎和同模板改写必须同组，不能一半训练一半测试。提示、rubric、权重只用 dev 调整。

每个 case 至少提供一个基于完整可观测证据的解答性标注；区分世界事实和可查询事实，并保存当时可用的 TI/知识快照。禁止用未来更新的 TI 解答过去时点的事件。

模型输出即使 temperature=0 也不保证一致；初步每方法每 case 跑 3 次，按 case/场景 family 做配对统计，不把重复采样当新的独立案例。记录种子是否被 provider 支持。

bootstrap 区间以独立 case/family 为单位，报告样本数、失败数和零事件情形的单侧上界；5 案例不做显著性结论。合成集类别比例不是生产基率，不能直接外推生产 precision。

真正的公开安全数据集接入必须审查许可、标签来源、缺失上下文与可观察性。本阶段没有选定或下载公开数据，不把 README 中“真实数据”当已验证来源。

## 12. Trace 契约

每 run 保存 manifest.json、events.jsonl、final.json；以 ID 关联原始记录。每 event 有递增 sequence、UTC 时间、elapsed_ms、step、event_type、payload、usage 累计、前后 state_version。

事件至少涵盖 alert_received、hypotheses_created/revised、state_snapshot、sufficiency_checked、plan_selected、tool_requested、tool_returned、evidence_registered、budget_checked、finalized、error。

保存结构化计划、候选及选择理由，不要求或假称保存模型内部推理。raw model response 可保存供解析复核，但凭证和秘密不进入 trace。

每轮快照包含 Evidence State、Hypothesis、缺口、预算、判定门槛；模型消息/prompt 版本、provider request ID、模型版本、工具参数/返回及费用单独记录。重放不再调用模型或外部工具；重跑才计新成本。

## 13. 按依赖排序的开发任务

| 编号 | 阶段 / 任务 | 依赖 | 验收标准 |
|---|---|---|---|
| P1.1 | 冻结问题范围与四种输出语义 | 无 | 读者能区分真值、决策、停止原因和人工动作 |
| P1.2 | 审查契约、来源边界和充分性 rubric | P1.1 | 空结果/冲突/TI unknown/双门槛满足都有定义 |
| P1.3 | 审查 5 个案例与独立 oracle | P1.2 | 各案证据来源、可获得性、替代路径、预期结果明确 |
| P1.4 | 冻结主指标、基线和实验 manifest | P1.3 | 全拒判、猜对、工具故障均不会被算作胜利 |
| P2.1 | 建轻量 Python 包与 JSON schema 验证 | P1.4 | 错误引用、时区、非法参数能被拒绝 |
| P2.2 | 实现本地工具服务与 fixture 隔离 | P2.1 | 5 案例工具可回放；不同调用顺序同查询同结果 |
| P2.3 | Budget、Dispatcher、Trace、模型适配接口 | P2.2 | 所有调用计费；超时/重复/迟到结果被正确处理 |
| P2.4 | 指标单元样例与手工 oracle 回放 | P2.3 | 手算结果等于报告；标签不进入模型消息 |
| P3.1 | Direct 与 Fixed | P2.4 | 同一输出 schema 与预算；Fixed 顺序真实冻结 |
| P3.2 | ReAct | P3.1 | 合理自主调用同 5 类工具，允许拒判 |
| P4.1 | 竞争假设和 EvidenceLink | P3.2 | 支持/反驳分离，事实不来自模型生成 |
| P4.2 | Sufficiency 门槛与确定性检查 | P4.1 | 仅 PowerShell/白名单/unknown TI 不导致 TP/FP |
| P4.3 | 价值排序与调查循环 | P4.2 | 不同可见状态选不同工具；反证、停止和拒判可追踪 |
| P5.1 | 统一 benchmark 与预算扫描 | P4.3 | 全方法同环境；完整报告成本、覆盖、错误关闭 |
| P5.2 | 扩充盲测、消融和失败分析 | P5.1 | 冻结测试；可重复报告支持或不支持哪些假设 |
| P6 | 真实工具、其他告警族与 SentinelKB 接入 | P5.2 | 只有实验支持且数据边界明确后推进 |

本次完成的是 P1.1–P1.4 的设计稿，不等于已获独立安全专家审定；进入实现时以这组契约验收，不扩大到 SOC 平台。

## 14. 明确延后

MCP、多 Agent、图谱增强、Web UI、RBAC、工单、自动响应、真实 SIEM 和 Prompt Injection 专项 V2 延后。MVP 仍坚持日志是数据、工具只读且参数受限的基础边界；不实现专项攻防测试套件。

前沿价值将由证据获取、拒判和成本控制的实验结果体现。不能用框架数量或“自主”字样替代实验。
