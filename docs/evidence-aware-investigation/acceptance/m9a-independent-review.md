# M9a 独立技术复核（239584f）

日期：2026-10-24。复核对象：main 分支提交 **`239584f`**（M9a 效率修订：实现范围 `cec4f0d..186b7cc`，文档收尾 `186b7cc..239584f`）。
被审文档：[m9a-efficiency-acceptance.md](m9a-efficiency-acceptance.md)、[m9-efficiency-contract.md](../m9-efficiency-contract.md)。

## 一、结论

**建议通过。** 七项重点检查全部通过；未发现需要修复的缺陷。五案 Verdict、工具路径与证据边界经双归档独立重放确认不变；预算硬停止后无模型调用的结构性保证与测试锁定一致；M9b compare 的缺失 usage 处理符合"未知成本不当零"的契约口径。两项观察（O1/O2）不阻断。

## 二、被审版本与依据

| 项 | 记录 |
|---|---|
| 验收 head | `186b7cce0d508da06ecffc97bafa6523f479cf66` |
| 审查 head | `239584f`（= 186b7cc + 2 个 docs 文件：m9a-efficiency-acceptance.md 状态更新、plan 状态行） |
| 实现差异 | `cec4f0d..186b7cc`：14 文件，+571/−52（hypothesis.py、investigator.py、hypothesis-v2.txt、hypothesis_proposal_v2.schema.json、schema_loader.py、benchmark/m8b.py、tests×3、docs×3） |
| 测试基线 | 186b7cc 内容 **695 passed**（主工作区 704 = 695 + 9 个 M10a 未提交审计测试，已分解核对）；双 CI 在 `186b7cc` 通过（run 40002378447 经 API 独立核实：test ✓ / investigation-tests ✓） |

## 三、逐项检查结果

### 1. cec4f0d..186b7cc 实现差异 ✅
差异与契约声明一致：v2 Schema+Prompt 新增；links 成为唯一关联来源；调查循环重构；M9b compare 新增；v1 Schema/Prompt 保留（`HYPOTHESIS_PROPOSAL_V1`）。`schema_loader.py` 将 `HYPOTHESIS_PROPOSAL` 别名指向 v2 并纳入 Registry 注册，`state/__init__.py` 导出同步更新。239584f 相对 186b7cc 仅改 2 个文档文件，无代码。

### 2. hypothesis-v2 消除重复证据关联 ✅
- v2 Schema 的 hypotheses 条目**删除** `supporting_evidence`/`disconfirming_evidence` 字段（`additionalProperties: false` 拒绝夹带）；仅 `links` 承载关联。
- 运行时 `validate_hypothesis_output` 确定性投影：support/contradict 链接按 hypothesis 聚合后 `dataclasses.replace` 生成内部数组的兼容投影（v1 消费方兼容）。
- 传给模型的 `previous_hypotheses` 剥离两个数组字段，避免模型回抄。
- 新增防御：`duplicate_link`（同一 hypothesis×evidence×stance 重复拒绝）与 `conflicting_link`（同一 evidence 不得既支持又反驳同一假设）。
- 测试锁定：`test_hypothesis_links_are_projected_once_and_conflicts_are_rejected`；假模型测试断言 previous 中不含两个数组字段。

### 3. hypothesis_id、kind、版本关系稳定 ✅
修订约束收紧为：`supersedes == 自身 hypothesis_id`、`hypothesis_id ∈ previous`、`kind` 与前一版相同、`version` 严格递增、**修订必须保持假设集合不变**（`set(by_id) != set(previous)` 拒绝新增/删除）。`test_hypothesis_revision_preserves_ids_and_kinds` 锁定 kind 漂移被拒。

### 4. 假设只在初始阶段和正常停止前修订 ✅
循环重构：初始 `propose_hypotheses`（revision=1）→ 循环内仅在 `plan.action == "finalize"` 且 ledger 非空时做一次"最终证据整合修订"（`reason: final_evidence_consolidation`）→ `_explain_sufficiency` → 确定性终结。逐工具修订已删除。M9a 归档五案 trace 实测：每案 model_phases = `hypothesis-1 / hypothesis-2 / final`，`hypotheses_revised` 事件恰好 1 次（与锁定测试断言一致）。整合修订发生在 `last_evaluation` 计算之后且不重算充分性——假设是解释不是事实，评估只依赖 registry+ledger，语义一致。

### 5. 硬预算停止后不继续调用模型 ✅
结构性保证：循环顶部 `hard_stop = controller.stopped_reason` → 直接 `return self._finalize(...)`（`_finalize`/`_assessment` 均确定性，无模型调用）；最后一次工具准入关闭后 `continue` 回到同一分支。异常路径（BudgetExceeded/ProtocolViolation/ModelError）同样确定性终结。若整合修订或解释调用本身耗尽预算 → BudgetExceeded → except → 确定性 Abstain。测试锁定：`test_last_tool_budget_forces_abstain_without_post_tool_model` 断言硬停时 `model.calls == 1`（仅初始提案）。

### 6. M9b compare 处理 ✅
- **修复次数**：`_repair_count` 从 trace 的 `model_output_recorded` 事件统计 `repaired_output` 非空的**去重 call_id**（V4-3A 四态留存），计入 `all_case_totals`（不依赖 usage 完整性）。
- **token**：仅当**两侧** `usage_complete` 时计算差值与配对累计；否则 `None`。配对合计附带 `complete_usage_case_count`。
- **费用**：仅当两侧 currency 均为 USD（且 usage 完整）时计算；`priced_case_count` 单列；缺失为 `None` 不填零。
- **口径分离**（97222c8）：`model_calls`/`repair_count` 为全案例口径（本地计数器，缺失 usage 也可知），`input/output_tokens`/`model_cost_usd` 为配对完整口径——两者不再混在一个合计里。
- **管道完整性**：`compare_artifacts` 先做 checksum 校验 + 逐 run 重放（重放结果与 inventory 不符即报错）+ 重算报告与持久报告逐字节比对 + 实验条件（模型/参数/预算/数据/Rubric/标注/价格快照）校验，然后才比较。
- **实测**：M8b v5 归档自对比 → 5 个 Proposed 配对、`complete_usage_case_count=4`、`priced_case_count=4`、model_calls=18、repair_count=3、token/费用差值全 0，与验收说明一致。

### 7. 五案 Verdict、工具路径、证据边界不变 ✅
- 双归档独立重放：`m8a-fake-d3b8341`（v1，175 runs）与 `m9a-fake-5d59ecf`（v2，25 runs）checksum+重放全过（751/131 文件验证）。两归档五案 **run_id 后缀逐案相同**（e2f1e861/8b762c8e/da7cd1c7/37174b42/e397f04a），Verdict 均为 `TP / FP / Suspicious / Abstain / Abstain`。
- M9a 归档 trace 实测工具路径：C1 `siem(process_tree)→siem(network_events)→asset`，C2 `siem(process_tree)→asset→siem(network_events)`，C3/C4/C5 各 4 次调用（含 history）——与契约"不修改工具候选、优先级、调用参数或停止条件"一致。
- 预算扫描行为（v1 归档 budget-2/4/6/8 的 C1→Abstain、C3 低预算→Abstain 等）为 M8a 既有结果，M9a 未改动扫描逻辑。
- 证据边界：假模型模型名 `fake-engineering-visible-input-v1` 未变；泄漏策略与标注应用逻辑未在差异范围内。

## 四、发现与风险

| 编号 | 类型 | 内容 |
|---|---|---|
| O1 | 观察 | 整合修订后不重算充分性，最终评估基于修订前 evaluation——与契约语义一致（假设为解释层），但 trace 中修订后的 links 与最终评估引用的证据集合可能不完全对应。无需修改；M9b 解读时注意。 |
| O2 | 观察 | `HYPOTHESIS_PROPOSAL` 公共别名从 v1 改指 v2：包内导入方自动获得 v2。历史 Artifact 重放不受影响（重放不重新校验模型输出 Schema，v1 归档重放已实测通过）。若未来出现需要按 v1 校验新输出的场景，须显式用 `HYPOTHESIS_PROPOSAL_V1`。 |
| O3 | 低风险（M9b 范畴） | v2 假设调用 `max_output_tokens` 由 1400 降至 1000：v2 输出确实更小（去两个字段），但真实模型加 `related_evidence_ids` 后是否仍充裕，留待 M9b 修复率数据验证；修复一次的机制可兜底。 |
| O4 | 提示 | 验收说明第 3 节表格的"输入预估/输出预留"是预算控制器口径（chars/4 与最大预留），非供应商实测——文档已明确声明，复述风险为零；仅提醒 M9b 报告继续维持该区分。 |

## 五、实际命令与结果

| 命令（investigation/ 下） | 结果 |
|---|---|
| `pytest tests -q --ignore=tests/test_dataset_split_audit.py` | **695 passed**（186b7cc 内容基线） |
| `pytest tests -q`（含 M10a 未提交 9 项） | 704 passed |
| `python -c "from benchmark.m8a import replay_artifact; replay_artifact('../evals/reports/m8a-fake-d3b8341')"` | 751 文件校验、175 runs 重放、25 报告一致 |
| 同上（m9a-fake-5d59ecf） | 131 文件校验、25 runs 重放、5 报告一致 |
| `python -m benchmark.m8b compare --baseline ../evals/reports/m8b-deepseek-20261024-v5 --candidate 同` | 5 配对、4 完整 usage、差值全 0 |
| trace 提取（read_trace 五案） | 工具路径 3/3/4/4/4、model_phases 各 3 次、revised 事件各 1 次 |
| GitHub API run 40002378447 | head=186b7cc，test ✓ / investigation-tests ✓ |

## 六、复核版本哈希（Git blob，`git ls-tree`）

```
186b7cc: investigation/src/evidence_investigation/agents/hypothesis.py
         investigation/src/evidence_investigation/agents/investigator.py
         investigation/src/evidence_investigation/state/schemas/hypothesis_proposal_v2.schema.json
         investigation/src/evidence_investigation/prompts/hypothesis-v2.txt
         investigation/benchmark/m8b.py
```
（完整哈希可由上述 head 一步复得；本复核在主工作区检出 `239584f` 上进行，未修改任何源文件。）

## 七、建议

**建议通过 M9a。** 剩余验收按文档执行：M9b 需新的付费额度授权后运行，compare 管道已就绪；五个公开开发案例结论仍不外推。
