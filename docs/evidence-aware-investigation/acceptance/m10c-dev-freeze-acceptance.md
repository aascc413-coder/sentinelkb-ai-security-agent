# M10c 二十案开发集与协议冻结验收记录

里程碑 / 状态：M10c；首次独立复核未通过，所提 P0/P1/P2 已修复；辅助 AI 独立复验通过，待提交和同一提交双 CI。

提验日期：2026-10-26。

父依赖：M10b 已完成；实现与跨平台修复验收 head 为 `2b1aaca`，远端 run `40014244342` 双 job 通过；状态文档 `974283d` 的 run `40014619250` 也双 job 通过。

## 1. 交付内容

- `powershell-dev-v3`：20 个 dev 案例、12 个 family、17 个物理环境。
- C1–C12 的 Public、Environment、Oracle 与 v2 对应 JSON 逐字节一致。
- C13–C20 预期结果：`TP / FP / Suspicious / Abstain / Abstain / Abstain / Abstain / TP`。
- 三组静态等价 counterfactual：C4/C5、C10/C11、C17/C18；组内隐藏真值相反且均要求 Abstain。
- 新覆盖：私钥外传、批准的软件盘点、重复同源记录、批准不匹配伴随 retryable timeout、部分进程覆盖、批准源冲突双胞胎、永久 history error、成功空网络结果、未关联恶意 TI 干扰、未授权批量删除。
- 确定性构建器：`scripts/build_dev_dataset_v3.py`。
- 作者指南：`docs/evidence-aware-investigation/m10c-authoring-guide.md`。
- 机器冻结协议：`evaluation/freeze/powershell-dev-v3.json`，绑定五个实际 Prompt、rubric、默认 Budget、数据 manifest、评测标注和作者指南的 SHA256。

## 2. 冻结前发现并修复的问题

### 2.1 Planner 历史实体不一致

Oracle expected action 和 fixture rule 使用 user history，但 DeterministicPlanner 固定请求 host history。旧结论测试仍可能通过，却会造成正确的历史查询规则未匹配，并降低 M11 的 Tool Selection Accuracy。

修复后：告警有 user 时查询 user history；没有 user 时回退 host history。C3 集成回归验证实际请求实体，C15 端到端行为评分验证 `tool_selection_accuracy=1`、`action_annotation_coverage=1`，retryable timeout 的一次自动重试不计作新的 Agent 决策。

### 2.2 冻结哈希随平台换行变化

Prompt、rubric 和作者指南属于按字节绑定的协议资产。此前 Windows checkout 可能把文本改为 CRLF，使相同提交在不同平台得到不同 Prompt 哈希。

`.gitattributes` 现在将 Prompt、rubric、作者指南、冻结 JSON、数据 JSON 和评测标注统一为 LF。Prompt/rubric 文字内容未改变；M10c 冻结文件绑定 LF 字节。

### 2.3 无记录 ToolResult 的 Oracle 引用

原数据审计只允许 recordless `unavailable` 事实。M10c 需要表示成功空结果、partial、retryable timeout 和 permanent error。

审计现在要求 recordless 可观察事实的 `operational_status` 必须匹配同工具 fixture rule 的真实 status；新增非 `unavailable` 事实必须保存与 rule 完全一致的 arguments；失败 envelope 的 reason 必须匹配 error code，timeout/error 必须显式保存布尔 retryable。伪造 status、删除 arguments/retryable 的负向测试都会被 `ungrounded_annotation` 拒绝。

### 2.4 首次独立复核后的修复

辅助 AI 的首次报告 `m10c-independent-review.md` 判定不通过，发现成功空结果未被评测映射、最终结论未引用空范围操作证据、审计可能错配同工具不同查询范围，以及数据 family 独立性与 Planner user-only 边界问题。

修复后：Evaluator 将 complete `empty` 的 `absence:*` 事实映射到对应 Oracle 操作事实；Sufficiency 将 network 空范围的 operational evidence 纳入最终 criterion 引用；审计以 arguments 精确匹配 rule 并强制失败重试字段；Planner 支持没有 host 的 user history；C17/C18 改为独立批准源冲突双胞胎，C13/C20 合并回同源 family，C19 使用无编号联想的 TI 地址并承接 permanent history error。新增端到端评分与四项负向审计回归锁定这些修复。

### 2.5 修复后独立复验

辅助 AI 的修复后报告 `m10c-independent-rereview.md` 判定通过：P0/P1 全部关闭，P2 已关闭或降级为不影响当前冻结标签的兼容性遗留；独立复现 102 项重点测试、745 项全量测试、13 项负向探针、20 案端到端评分以及全部冻结哈希。

复验新增两项非阻断建议，登记为 M10d 数据编写前置改进：禁止同一 Oracle fact 同时混用非空 `record_ids` 与 operational 字段；M10d 新增 `unavailable` 事实必须携带并校验 arguments。M10c 为保持 C1–C12 与 v2 逐字节一致，不回写旧 unavailable 标注。

## 3. 提验实现快照

| 文件 | Git blob SHA1 |
|---|---|
| `.gitattributes` | `158c16178e1f8da6f73bad845292c5cbeec353ac` |
| `investigation/src/evidence_investigation/agents/planner.py` | `8fe1c9be0f46235990f87c36df5d932f538ff788` |
| `investigation/src/evidence_investigation/agents/sufficiency.py` | `aad2de4cba0b643674b2b1f5d0abbfd6d5121ec2` |
| `investigation/evaluation/evaluator.py` | `6e1b0b21e470825c272468403471df64d766b20c` |
| `investigation/scripts/dataset_split_audit.py` | `d02038e6eca5054387aa4f920ef6a61ee74305ce` |
| `investigation/scripts/build_dev_dataset_v3.py` | `82b5bb2351b7b46218a0221276135beaad3b9f60` |
| `investigation/tests/test_agents.py` | `4db21f8aa89a2f7276a23e57589774808b2d3925` |
| `investigation/tests/test_dev_dataset_v3.py` | `d55d5a91237c6ae7be8734f41802d7f44c730f1b` |
| `docs/evidence-aware-investigation/m10c-authoring-guide.md` | `ea9966dd3ee7f0258f8fece6ee62ea43b770b65e` |
| `investigation/evaluation/freeze/powershell-dev-v3.json` | `1e04445997b1ce1f4cd7e6c5be6d6f162bde1eca` |
| `investigation/datasets/powershell-dev-v3/manifest.json` | `1f6dc35964b5aa2c482fbd295fe8c67d48a22e24` |
| `investigation/evaluation/annotations/powershell-dev-v3.json` | `857609b42c11b61d7be7546b78483381afc3c385` |

内容 SHA256：

- manifest：`44db35439e017146ba044bcb2e7a221cfcc20fe9ac13f7757e65eacd44fc2844`；
- annotations：`af037928eccea9467bcecf711f5843947815959f1f4ed25366c4b8272a331764`；
- freeze：`edb11f2c6e84dfa4a403e699a3dfe76410a4b25a3558b5dc4bdefdfc722565bc`。

## 4. 主实现自检

在 `investigation/` 执行：

```powershell
.\.venv\Scripts\python.exe scripts\build_dev_dataset_v3.py
.\.venv\Scripts\python.exe scripts\dataset_split_audit.py --dataset datasets\powershell-dev-v3
.\.venv\Scripts\python.exe -m pytest tests\test_agents.py tests\test_dev_dataset_v2.py tests\test_dev_dataset_v3.py tests\test_dataset_split_audit.py -q
.\.venv\Scripts\python.exe -m pytest -q
```

实测：

- 构建器输出 20 案、17 个物理环境、20 个 Oracle，并逐字节复现冻结数据与标注。
- 数据审计：20 cases、12 families、dev=20；三组静态等价输入；五项 checks 全 passed。
- 重点测试（agents、v2/v3 dataset、split audit、evaluator）：102 passed in 16.67s。
- `investigation/` 全量测试：745 passed in 30.96s。
- C1–C12 与 v2 对应 JSON 逐字节一致。
- C13–C20 全部得到冻结预期结论。
- Public/Environment 无作者标签；冻结文件能检测 Prompt、rubric、Budget、manifest、annotation 和作者指南漂移。
- `git diff --check`：通过，仅显示现有非冻结 Markdown/脚本将按 Windows checkout 策略转换的提示。

## 5. 结论边界

- 20 案全部为公开 synthetic dev 数据；没有运行真实模型，不能声称 blind 泛化、统计优势或生产性能。
- 第三组 counterfactual 通过相互冲突的独立批准源建立，不再重复 C10/C11 的遥测故障；M10d test 仍需独立作者另写，不能复制参数变体充数。
- retryable timeout 在本地 Mock 中每次都失败，用于验证重试记账和证据不足处理，不代表真实服务可靠性。
- 成功空结果只有在 coverage complete 时才有否定信息；它本身不支持 TP。
- Prompt/rubric LF 统一会改变 Windows 工作区的原始字节哈希，但不改变文字语义；旧验收文档记录的是当时快照，M10c 冻结从 `powershell-dev-protocol-v1` 起采用跨平台 LF 哈希。

## 6. 待完成门槛

1. 提交、推送并核对同一提交的 `test` 与 `investigation-tests`。
2. 双 CI 通过后更新里程碑状态；M10d 开始前落实复验报告中的两项非阻断审计加固。

门槛完成后才将 M10c 标记为完成并开始 M10d 的独立 blind test 编写。
