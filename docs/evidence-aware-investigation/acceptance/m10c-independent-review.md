# M10c 独立技术复核（`974283d` 之上已暂存变更）

日期：2026-10-26。复核对象：`main` @ **`974283d`** 之上的 `git diff --cached`（72 文件，+11384/−8）及主验收说明 [m10c-dev-freeze-acceptance.md](m10c-dev-freeze-acceptance.md)。

性质：独立只读复核——冻结元数据重算、四条命令复现、20 案逐案语义审查、跨案结构差异量化、端到端行为轨迹分析与自建负向探针。未修改实现、测试、数据或暂存内容；未提交、未推送；未调用任何真实模型或付费 API（全程 `EngineeringFakeModel`）。

## 一、结论

**不通过。** 1 项 P0 阻断 + 2 项 P1 + 4 项 P2。

阻断项：M10c 首次把「成功空结果」作为**无记录可观察事实**写入 `observable_fact_keys`、`critical_fact_keys` 与 `sufficient_sets`，但评测层无法把 runtime 产生的 `absence:` 事实映射回 Oracle（`investigation/evaluation/evaluator.py:104` 硬编码 `fact.fact_key.startswith('source:')`），且 C20 的冻结 TP 充分集合要求引用该事实，而确定性 gate 在 TP 终结时并不引用它。后果可复现且已实测：**C20 的 TP 结论 `evidence_sufficient=False`（冻结充分集合永不可满足）、`C16` 的 `critical_evidence_recall` 永久封顶 2/3、`C20` 的 `discriminating_evidence_recall` 永久封顶 2/3**。这直接违反作者指南第 5 节「TP/FP 案例必须给出至少一个充分集合，并由确定性 gate 实际复现」，并会让 M11 的 `sufficiency_pass_rate` / 召回类指标系统性失真。

其余重点方向全部通过：10 个 Git blob SHA1 与 3 个内容 SHA256 逐一匹配；冻结清单内 9 个文件哈希真实；`.gitattributes` 对 9 个按字节绑定资产全部生效 `text=set / eol=lf`，工作区内容无 CR；构建器逐字节复现且不动暂存；C1–C12 与 v2 逐字节一致；三组 counterfactual 静态等价、同 family、同 split、真值相反；Public/Environment 无作者标签泄漏；Planner user/host history 选择正确且为 load-bearing；C15 恰好一次自动重试且 `tool_selection_accuracy=1`；11 项伪造 status/retryable 负向探针中 9 项被拒。

## 二、冻结元数据核验（全部通过）

### 2.1 Git blob SHA1（暂存区实测）

| 文件 | 实测 blob | 验收说明 | 一致 |
|---|---|---|---|
| `.gitattributes` | `158c16178e1f8da6f73bad845292c5cbeec353ac` | 同 | ✓ |
| `investigation/src/evidence_investigation/agents/planner.py` | `2e4dbc0faff4aafc389bc6b0e235ea68ded326ac` | 同 | ✓ |
| `investigation/scripts/dataset_split_audit.py` | `4e09d28056079400f970acc60ad2bf0935767959` | 同 | ✓ |
| `investigation/scripts/build_dev_dataset_v3.py` | `e03ee214c7efadeef36bd471a13fd97124325970` | 同 | ✓ |
| `investigation/tests/test_agents.py` | `75903c5c5068dd482f4736277441e0b6e3646a1a` | 同 | ✓ |
| `investigation/tests/test_dev_dataset_v3.py` | `4ae765e02638157c0f5a9d177190e005aa66a03d` | 同 | ✓ |
| `docs/evidence-aware-investigation/m10c-authoring-guide.md` | `08e2f5e1db6340a57a42a1773e527df2f2c4700d` | 同 | ✓ |
| `investigation/evaluation/freeze/powershell-dev-v3.json` | `9def3669aae81ba7038780462f7ed4850969c4df` | 同 | ✓ |
| `investigation/datasets/powershell-dev-v3/manifest.json` | `3295ad89a944226bb000333d933d7036a46b4aab` | 同 | ✓ |
| `investigation/evaluation/annotations/powershell-dev-v3.json` | `cc21dfde8682ffc249f3e3230f6dfa20e4c85f4d` | 同 | ✓ |

### 2.2 内容 SHA256（独立重算）

| 文件 | 实测 SHA256 | 验收说明 | 一致 |
|---|---|---|---|
| manifest | `82e77ee36ce125b41996575536691038a5896170a9fc672d5c3433f675378a0e` | 同 | ✓ |
| annotations | `f0a4f471eeaf19b7ffc9779540798fe12b7933d58a98f7bb33d70f30e4a3cce1` | 同 | ✓ |
| freeze | `b453e3d0a793fa64e77a3a00ce2884f52cdeb14e878eb125372cf48e16e94be7` | 同 | ✓ |

冻结文件 `file_sha256` 内 9 个绑定项独立重算全部命中：作者指南 `8d1a1e70…`、manifest `82e77ee3…`、annotations `f0a4f471…`、rubric `bb139cb0…`、direct `bfeaeb58…`、fixed-final `5028f9ac…`、hypothesis-v2 `85ef01c0…`、react `610a5134…`、sufficiency `36f40dd0…`。`budget_profile` 与 `Budget()` 默认值逐字段相同（6/16000/8/90.0/2500）。

### 2.3 跨平台 LF

`git check-attr` 对冻结清单直接绑定的 8 个文件（rubric、5 个 Prompt、freeze、作者指南、manifest）全部返回 `text: set` / `eol: lf`；annotations 由既有规则 `investigation/evaluation/annotations/*.json` 覆盖，同样为 `eol: lf`。字节层面：9 个绑定文件的工作区内容均**不含** `0d0a`；其中 rubric 与 5 个 Prompt 属既有文件，其 `HEAD` blob 与工作区 SHA256 完全相同且不含 CR，可证「Prompt/rubric 文字内容未改变」。新增的 4 条属性规则覆盖 freeze、rubric、prompts、作者指南，此前只覆盖 datasets 与 annotations，修复方向正确。

## 三、实际命令与结果

均在 `D:\project\Agent\sentinelkb\investigation` 下、`.\.venv\Scripts\python.exe`（Python 3.12.10，Windows）。

| 命令 | 退出码 | 实测结果 | 与验收说明对比 |
|---|---|---|---|
| `scripts\build_dev_dataset_v3.py` | 0 | `Wrote powershell-dev-v3: 20 dev cases, 17 physical environments, 20 oracle cases.` | 一致 |
| `scripts\dataset_split_audit.py --dataset datasets\powershell-dev-v3` | 0 | 20 cases / 14 families / dev=20；VG001={C4,C5}、VG002={C10,C11}、VG003={C17,C18}；5 项 checks 全 `passed` | 一致 |
| `pytest tests\test_agents.py tests\test_dev_dataset_v2.py tests\test_dev_dataset_v3.py tests\test_dataset_split_audit.py -q` | 0 | **65 passed in 42.24s** | 一致（65） |
| `pytest -q` | 0 | **738 passed in 87.36s** | 计数一致（738）；耗时 87.36s vs 18.00s 为机器差异 |
| `git diff --cached --check` | 0 | 无输出 | 一致 |

构建器副作用检查：执行前后 `git status --porcelain` 排序后 SHA256 均为 `984a60f3ee346891460c4f578ea540edd3134d9bf9696d7a4f0512b2fda15732`，`git diff` 为空——构建逐字节复现且未污染工作区/暂存区。数据结构规模独立统计：`environment/` 17 个、`public/` 20 个、`oracle/` 20 个。

## 四、逐项检查结论

| 检查项 | 结论 | 关键依据 |
|---|---|---|
| C1–C12 与 v2 逐字节一致 | **通过** | 12 案逐一比对 public/environment/oracle，覆盖 v2 全部 34 个 JSON 文件（12 public + 10 environment + 12 oracle，C4/C5 与 C10/C11 共享环境文件）`read_bytes()` 全等；manifest 映射行也完全相等 |
| C13–C20 真值 / 充分集合 / 可接受结论 / 评测标注一致 | **不通过** | C20 充分集合含不可映射的 E2（见 P0-1）；其余 7 案一致 |
| C4/C5、C10/C11、C17/C18 静态等价、同 family、同 split、真值相反 | **通过** | 三组 public 字节相同、共享同一 environment 文件且字节相同、family/split 相同、`ground_truth` 相反、`acceptable_verdicts` 均为 `("Abstain",)` |
| 新案例真实语义差异 | **部分不通过** | 无结构完全等价对，但 C13≈C6（对象/动词/TI 声誉替换）、C20 = C12（encrypt→delete，网络记录→absence）；第三组 counterfactual 相对 C10/C11 仅失败码替换（P2-1/P2-2） |
| Public/Environment 泄漏 case/family/split/truth/oracle | **通过** | 20×2 文件扫描 `case_id/family_id/split/ground_truth/oracle/critical_fact_keys/sufficient_sets/acceptable_verdicts/expected_actions/...` 均为 CLEAN；仅出现 `malicious`/`benign` 作为 TI `reputation` 数据值（C1/C6/C13/C19），且与真值不构成单一映射（C13 恶意↔benign、C19 良性↔malicious），不构成捷径 |
| Planner 有 user 查 user history、无 user 回退 host history | **通过** | 单元探针 + C15 轨迹双重确认（见 5.1） |
| C15 retryable timeout 仅一次自动重试且 TSA=1 | **通过** | 5 attempts / 4 decisions / 1 retry，`tool_selection_accuracy=1.0`、`action_annotation_coverage=1.0` |
| recordless status/reason/retryable 与 fixture rule 对齐 | **部分不通过** | 11 项负向探针 9 拒 2 收（见 5.2）；`retryable` 缺失不校验、同工具多 envelope 下 status 混淆不校验 |
| Prompt/rubric/指南/freeze 跨平台 LF、哈希真实 | **通过** | 见 2.3；9/9 哈希命中，无 CR |
| 成功空结果 / 部分覆盖 / 重复记录 / TI 干扰不误产 TP/FP | **不通过（空结果）** | 空结果事实在现有实现中**无法进入任何 Oracle 事实匹配类指标**（acquired / cited / 召回 / 充分性），因此既不能误产 TP，也使以其为前提的 TP 不可复现（P0-1）；部分覆盖、重复记录、TI 干扰三项通过 |

## 五、独立探针

### 5.1 Planner 历史实体（load-bearing 验证）

| 场景 | 结果 |
|---|---|
| `user=analyst-a, host=WS-1` | `entity_type=user, entity=analyst-a` |
| `user=None, host=WS-1` | `entity_type=host, entity=WS-1` |
| `user=analyst-a, host=None` | 不产生 history 候选（`history_call` 仍以 `alert.host` 为前提，见 P2-4） |
| C15 实际轨迹 | `{"entity_type":"user","entity":"svc-ops","host":"OPS-115","user":"svc-ops",...}` |

用 C15 的 action 标注 `{"entity_type":"user","entity":"svc-ops"}` 反事实比对：修复前的 host 实体请求 **不匹配**（`False`），修复后的 user 实体请求 **匹配**（`True`）。故该修复确实改变 `tool_selection_accuracy`，不是无效改动。

### 5.2 recordless operational fact 负向探针（自建，数据集副本 + 重算 manifest 哈希）

| 探针 | 期望 | 实测 |
|---|---|---|
| C15/E4 `retryable` True→False | 拒绝 | **拒绝** `ungrounded_annotation` |
| C15/E4 `status` timeout→error | 拒绝 | **拒绝** |
| C15/E4 `reason` 改为 `history_backend_error` | 拒绝 | **拒绝** |
| C15/E4 `status` timeout→partial | 拒绝 | **拒绝** |
| C17/E4 `retryable` False→True | 拒绝 | **拒绝** |
| C17/E2 `retryable` True→False | 拒绝 | **拒绝** |
| C19/E2 empty→unavailable + `no_matching_rule` | 拒绝 | **拒绝** |
| C20/E2 empty→ok | 拒绝 | **拒绝**（`ok` 不在允许集合） |
| C16/E4 借用其它案件的 reason | 拒绝 | **拒绝** |
| C15/E4 **删除** `retryable` 字段 | 拒绝 | **接受（缺口 P1-2）** |
| C16/E2 empty→partial | 拒绝 | **接受（缺口 P1-1）** |

C16/E2 被接受的原因：C16 的 siem 同时存在 `partial`（process）与 `empty`（network）两条规则，审计只按 `tool + status` 聚合，因而把"网络空结果"错标为 `partial` 仍能匹配到 process 的 partial 规则。

### 5.3 空结果事实的映射能力（P0 复现）

C20/C19/C16 的 runtime 轨迹中均存在 `absence:siem:<hash>` 事实，`absence_provable=true`、`status='empty'`、`error_code=null`，`_provenance_valid=True`，但 `matched_fact_keys` 返回**空集**。把同一事实的 key 前缀改为 `source:`（其余字节不动）后立即映射为 `['E2']` —— 证明失配原因就是 `evaluator.py:104` 的 `startswith('source:')`。

### 5.4 端到端行为覆盖（20 案，Proposed + 假模型）

| 案件 | 结论 | 可接受集合 | `evidence_sufficient` | 关键召回 | 已获关键事实 |
|---|---|---|---|---|---|
| C1 | TP | TP | True | 3/3 | E1,E2,E4 |
| C2 | FP | FP | True | 3/3 | E1,E2,E3 |
| C6/C7/C8/C12/C13/C14 | TP/FP/FP/TP/TP/FP | 各自单一 | True | 3/3 | 齐全 |
| C3/C9/C15 | Suspicious | Suspicious/Abstain | None | 3/3, 4/4, 3/3 | — |
| C4/C5, C10/C11, C17/C18 | Abstain | Abstain | None | 0/0 | — |
| C16 | Abstain | Abstain | None | **2/3** | 缺 E2（映射缺口） |
| C19 | Abstain | Abstain | None | 0/0 | 缺 E2（非关键，仅 observable 不可达） |
| C20 | **TP** | TP | **False** | **2/3** | 缺 E2（映射缺口 + 未引用） |

v2 同法复跑 C1–C12：`evidence_sufficient` 与 v3 完全一致（v2 无 `empty` 事实），说明失真并非继承而来，而是 M10c 引入的空结果形态新触发。

### 5.5 部分覆盖 / 重复记录 / TI 干扰

- **部分覆盖（C16）**：process 返回 `status=partial`、`missing_sources=["process_start"]`，确定性基线转 Abstain，未因"看似有害的加密记录"误产 TP；`sufficient_sets` 两向皆空。
- **重复同源记录（C14）**：siem 有两条 `content_sha256` 相同、`independence_group` 同为 `network-01` 的记录，同一 query rule 同时返回；`acquired` 以 Oracle 事实键为单位，重复记录不增加支撑，FP 仍只由 `[E1,E2,E3]` 一次成立，`evidence_sufficient=True` 且未产生额外 TP 支撑。（C1 在 v2 中已有同类镜像记录，属既有设计。）
- **TI 干扰（C19）**：`203.0.113.119` 仅存在于 threat_intel，未出现在任何网络记录的 `destination_ip`/`observed_destinations`；`critical_fact_keys=[]`，故不可能进入任何充分集合；基线 Abstain。TI 声誉与真值非单调（C13 恶意案配 benign、C19 良性案配 malicious），未形成捷径。

## 六、发现

### P0-1（阻断）成功空结果事实无法进入评测，导致冻结充分集合不可满足

**位置**：`investigation/evaluation/evaluator.py:103-108`（本提交未修改）与 M10c 新增数据（`oracle/c16.json`、`c19.json`、`c20.json`）。

**机制**：runtime 对 complete-empty 结果按 `absence:<tool>:<hash>` 记账且带 `absence_provable=true`；而 `matched_fact_keys` 的 operational 分支只接受 `fact_key.startswith('source:')`。因此任何 `operational_status="empty"` 的 Oracle 事实**永远**无法被 `acquired`/`cited` 命中。

**实测后果**：
1. C20（`ground_truth=malicious`，`sufficient_sets.TP=[["E1","E2","E3"]]`）的 TP 结论 `evidence_sufficient=False`。轨迹显示 agent 先查 process（ok）、asset（ok）、network（**empty**），随后以 E1+E3 终结 TP，`final_evidence_ids=[ev-0001..ev-0003]` 未引用 absence 事实 `ev-0004`。即使引用，第 5.3 节的映射缺陷也会使其无效——**该充分集合在现有实现下恒不可满足**。
2. C16 `critical_fact_keys=[E1,E2,E3]`，其中 E2 为 empty，`critical_evidence_recall` 永久 2/3。
3. C20 `discriminating_fact_keys=[E1,E2,E3]`，`discriminating_evidence_recall` 永久 2/3。

**与冻结文档的冲突**：作者指南第 5 节要求「TP/FP 案例必须给出至少一个充分集合，并由确定性 gate 实际复现」；验收说明第 5 节自述「成功空结果……本身不支持 TP」，而 C20 的 TP 充分集合恰好以该空结果为必要前提。

**为何现有测试未发现**：`test_proposed_expected_behavior_on_m10c_cases` 只断言 `final.verdict`，未断言 `evidence_sufficient`、`sufficiency_pass_rate`、`critical_evidence_recall`；`test_v3_audit_annotations_and_three_counterfactual_groups` 只校验标注能加载。

**修复建议（二者需同时做，或明确降级冻结断言）**：
- (a) `matched_fact_keys` 的 operational 分支接受 `absence:` 前缀，并在 `operational_status=="empty"` 时要求 `value.get("absence_provable") is True`；
- (b) 令 C20 的 TP 充分集合与确定性 gate 的实际终结依据一致（如 `[["E1","E3"]]`），或让 runtime 在 TP 终结时把 absence 事实纳入 `final_evidence_ids`；同时把 C16 的 E2 从 `critical_fact_keys` 移除或改为可映射形态；
- (c) 增加断言 `C20.evidence_sufficient is True` 与 `C16.critical_evidence_recall == 1` 的回归测试，否则同类问题在 M10d 会静默复发。

### P1-1 审计的 recordless status 校验只到工具粒度

`scripts/dataset_split_audit.py:158-173` 仅按 `rule.tool == source and rule.status == operational_status` 聚合。当一个事实的 source 工具同时存在多种 envelope（C16 的 siem 同时有 `partial` 与 `empty`）时，把 empty 错标为 partial 仍能匹配到另一条规则并通过审计（第 5.2 节实测 ACCEPTED）。这不影响当前 20 案的既有标签（已逐案核对无误），但 M10d 的 40 案由独立作者编写，同类错标会静默通过并直接压低可复现性。建议按 `argument_constraints` 或 coverage scope 进一步限定匹配。

### P1-2 `retryable` 字段可省略而不被校验

验收说明 2.3 声称「可选 retryable 字段也必须一致」，但实现为 `if "retryable" in fact:`（`dataset_split_audit.py:167`）。删除 C15/E4 的 `retryable` 后审计通过（实测 ACCEPTED），等价于放弃对可重试性的断言。建议对 `timeout`/`error` 状态强制要求该字段存在。

### P2-1 三组 counterfactual 属同一「全源失败」模板

C4/C5、C10/C11、C17/C18 的可见结构完全同构：process 部分覆盖 → network 失败 → approval 不完整 → history 失败 → attack 映射。C17/C18 相对 C10/C11 的差异按字段展开后基本是 `status`（unavailable→timeout/error）、`error_code`、`missing_sources`、`retryable` 的替换（`query_rules[1]` 与 `[3]` 的全部差异项均为此类）。这满足「静态等价 + 真值相反」的硬要求，但第三组提供的是**失败模式覆盖**，而非新的 counterfactual 推理结构。作者指南第 4 节要求「同一模板……必须使用同一 family_id」，三组却分属三个 family；若 M11 以 family 为单位做重采样，独立 family 数会被高估。建议在验收文档中显式声明该口径，或改述为「三组静态等价的失败模式变体」。

### P2-2 C13 与 C20 属模板级变体，连带 family 计数口径

C6↔C13 的差异集中在 host/process/对象名/`job_id`/TI 声誉/操作动词（public 7 项、environment 33 项，均为值替换，无键集变化）；C20↔C12 为 `encrypt→delete`、`affected_count 250→75`，并把「有记录的空网络」改为「无记录的 absence」（`query_rules[1].status` 与 `record_ids` 变化）。C1/C6/C13 在作者指南第 6 节覆盖矩阵中被列为**同一行同一条件**（敏感对象读取+同对象外传），却分属 `powershell-seed-v1`、`powershell-office-exfil-v1`、`powershell-private-key-exfil-v1` 三个 family。验收说明「14 family」作为 `family_id` 去重计数成立，但不宜解读为 14 个独立条件。建议在 M11 报告口径中说明。

### P2-3 C19 的 TI 指标与主机编号同源

干扰指标 `203.0.113.119` 与主机 `WS-119`、进程 `p-1919` 共享案例序号，形成数据里并不存在的「编号暗示关联」。语义标签正确（未关联、不可判别），但该命名习惯给模型提供了人工关联线索，可能诱发非预期的 TP。建议干扰项使用与案例序号无关的地址（如 `203.0.113.250`）。

### P2-4 Planner 的 history 调用仍以 `alert.host` 为前提

`planner.py:91-93`：`history_call` 的构造条件仍是 `if alert.host else None`，只有实体类型/实体做了 user 回退。若告警带 user 而无 host，则既不查 user history 也不查 host history。当前 20 案均有 host，未触发；M10d 若引入纯用户维度告警会静默丢失 action 标注（`action_annotation_coverage` 下降）。建议把条件改为 `if alert.host or alert.user`。

## 七、未覆盖范围

1. 未运行任何真实模型或付费 API；不涉及 blind 泛化、统计优势或生产性能结论。
2. 未运行远端 CI（按要求不提交、不推送），验收说明所述 run `40014244342` / `40014619250` 未独立核验。
3. 未审查 M10d 的 40 个盲测案例（尚不存在）。
4. 未在 Linux/macOS 实际 checkout 复验 LF 结论；仅依据 `.gitattributes` 生效状态、工作区与 HEAD blob 的字节检查推断。
5. 未覆盖与 M10c 无关的既有模块；全量 738 项测试仅作为回归绿灯依据，未逐项审阅。
6. 语义改写检测仍不可自动化；「是否参数替换」结论基于键集/差异字段量化与人工判读，不构成形式化证明。
7. 单机单解释器（Windows，Python 3.12.10）；耗时数据不可与他机直接比较。

## 八、结论状态分立

| 维度 | 状态 |
|---|---|
| 辅助独立技术复核（本报告） | **不通过**（P0-1 阻断；P1-1、P1-2 需修） |
| 主实现自检（验收说明） | 与本复核在命令结果上一致（65 / 738 / 审计 5 项 / 构建字节复现），但未覆盖充分集合可复现性 |
| 冻结元数据 | 通过：blob、SHA256、LF 属性、预算值全部真实一致 |
| 提交 / 推送 / 远端双 CI | 未执行（按要求） |

修复 P0-1 与 P1-1、P1-2 后建议复验项：C20 `evidence_sufficient=True`、C16 `critical_evidence_recall=1`、C15/C17 `retryable` 缺失与 C16/E2 错标各自被拒、全量测试与数据审计重跑无回归。
