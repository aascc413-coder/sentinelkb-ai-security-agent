# M10c 数据作者指南与开发集冻结规则

状态：M10c 作者侧冻结候选。适用于 `powershell-dev-v3` 的 20 个公开开发案例，以及 M10d 独立编写的 40 个盲测案例。

## 1. 冻结边界

M10c 完成后，以下内容共同构成实验协议：

- 五个实际使用的 Prompt：Direct、Fixed、ReAct、Proposed Hypothesis、Proposed Sufficiency；
- `powershell-v1` rubric；
- 默认预算：6 次工具调用、16000 token、8 个调查步骤、90 秒、2500 token 最终化预留；
- `powershell-dev-v3` 数据、`powershell-dev-eval-v3` 评测标注；
- 本作者指南；
- `evaluation/freeze/powershell-dev-v3.json` 中保存的文件哈希和预算值。

任何冻结项变化都必须创建新的数据或协议版本，并说明变化原因。M10d 的 test 40 只能复用这套协议，不能依据盲测结果修改 Prompt、rubric、预算或充分性规则。

## 2. 单案例交付物

每个案例必须同时包含：

1. `PublicCase`：仅含告警输入；
2. `EnvironmentFixture`：仅由工具服务持有的可查询世界；
3. `OracleCase`：完整世界、可观察事实、隐藏事实、充分集合和可接受结论；
4. 预算绑定的评测标注：判别事实、风险线索、拒判要求和人工复核要求。

Public 与 Environment 禁止包含 `case_id`、`family_id`、split、ground truth、oracle 提示或作者答案。环境中的 host、user、process、记录 ID 只是合成世界字段，不能被实现代码作为判定捷径。

## 3. 事实和证据写法

- Alert 事实必须引用 `raw_reference.record_id`。
- Tool 事实必须引用真实 `ToolRecord.record_id`；记录哈希必须匹配 payload。
- 成功空结果、部分覆盖、不可用、超时或错误可以没有 record，但必须以 `operational_status` 对应同工具的 fixture rule。M10c 新增的非 `unavailable` 操作事实还必须保存与 rule 完全一致的 `arguments`；失败 envelope 的 `reason` 必须等于 `error_code`，`timeout/error` 必须显式保存布尔型 `retryable`。
- `oracle_only` 事实不得带 record 引用，也不得出现在 `observable_fact_keys`。
- `critical_fact_keys` 表示决定完整世界真值所必需的事实；`discriminating_fact_keys` 表示当前预算内能区分竞争假设的可见事实；两者不能混用。
- `distractor_fact_keys` 应真实可见但不应决定结论，例如未关联 TI、ATT&CK 映射、重复同源记录或仅有 detector claim。
- `sufficient_sets` 只能引用可观察事实。若当前可见信息不足，TP 和 FP 均为空。

## 4. Family 与 counterfactual

同一模板、同源改写、组织语境变体和 counterfactual 双胞胎必须使用同一 `family_id` 且位于同一 split。模型可见 Public 与 Environment 完全相同的双胞胎必须共享环境文件，隐藏真值只能存在于各自 Oracle。

静态规范化审计只能发现字节结构等价，不能识别语义改写。作者必须主动声明同源 family，独立复核者必须逐案检查。

## 5. 结论与停止条件

- TP/FP 案例必须给出至少一个充分集合，并由确定性 gate 实际复现。
- 风险明确但不可定论案例需要可引用的风险模式，例如字段级批准不匹配；仅删除证据通常只能支持 Abstain。
- 信息不可区分、关键覆盖缺失、冲突未解或材料来源故障时允许或要求 Abstain。
- TI reputation、ATT&CK、PowerShell 标签、编码元数据、管理员身份和缺少批准均不能单独支持 TP。
- FP 只表示当前告警活动在已检查范围内建议关闭，不代表主机安全。
- 工具预算耗尽但证据不足时必须 Abstain。

## 6. 20 案覆盖矩阵

| 案例 | 主要条件 | 预期 | 作用 |
|---|---|---|---|
| C1/C6/C13 | 敏感对象读取与同对象外传 | TP | 三种敏感对象与外传表达 |
| C12/C20 | 未授权批量加密/删除 | TP | 直接破坏效果与提前停止 |
| C2/C7/C8/C14 | 行为、参数、目标与批准完整匹配 | FP | legacy 与结构化批准、零网络、远程运维、重复记录 |
| C3/C9/C15 | 当前执行与批准字段不匹配 | Suspicious 或 Abstain | 风险升级、历史正常/新目标/重试失败 |
| C4/C5 | 原始静态等价双胞胎 | Abstain | 隐藏脚本真值 |
| C10/C11 | 遥测缺口静态等价双胞胎 | Abstain | 多来源不可用 |
| C17/C18 | 批准源冲突静态等价双胞胎 | Abstain | 两个独立批准台账分别给出匹配与无批准，隐藏意图相反 |
| C16 | 有害记录但进程覆盖 partial | Abstain | 不把部分覆盖当完整证据 |
| C19 | 成功空网络、永久 history error、未关联恶意 TI | Abstain | 空结果可追溯，故障不伪装成证据，TI 保持干扰项 |

当前共有 20 案、12 family、17 个物理环境、3 个 counterfactual family。C13 与 C6、C20 与 C12 分别属于同源语义 family，不以对象名或动作名变化虚增 family。比例是合成实验设计，不代表生产基率。

## 7. 作者自检

在 `investigation/` 执行：

```powershell
python scripts/build_dev_dataset_v3.py
python scripts/dataset_split_audit.py --dataset datasets/powershell-dev-v3
python -m pytest tests/test_dev_dataset_v3.py -q
python -m pytest -q
```

提交前必须确认：

- C1–C12 与 v2 对应 JSON 逐字节一致；
- 构建器能逐字节重建 v3 数据与标注；
- 三组 counterfactual 均同 family、同 split、真值相反；C17/C18 的公开证据源冲突不同于 C10/C11 的遥测不可用；
- Public/Environment 不含作者标签；
- 冻结协议测试能检测 Prompt、rubric、预算和作者指南漂移；
- 数据审计、完整测试和远端两个 CI job 全部通过。

## 8. 独立复核要求

独立复核者至少检查：逐案真值与充分集合、故障 envelope 与 Oracle 对齐、重复记录是否被去重、TI/ATT&CK 是否误入攻击依据、三组双胞胎是否真正静态等价，以及新增案例是否只是旧案例参数替换。复核不得读取并修改运行时判定来迎合标签。
