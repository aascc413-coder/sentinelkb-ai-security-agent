# M10 数据集扩展与盲测分组契约

状态：M10a 已完成；M10b 已形成 12 案开发集和案例通用化充分性实现，本地验收与独立复核通过，待远端 CI。

适用范围：P5.2 的 30–100 个高质量案例扩展。

目标规模：60 案例，其中 dev 20、test 40。

## 1. 这一阶段要回答什么

五个公开开发案例足以验证工程流程，不能证明策略具有泛化能力。M10 要建立一个冻结、可复现、不会把同源变体拆到开发集和测试集的实验数据集，使后续消融和统计比较有可信输入。

本阶段不改变 Agent、Prompt、充分性规则或 M8/M9 历史产物。先冻结数据协议，再分批编写和复核案例。

## 2. 分组与切分规则

`OracleCase.family_id` 是不可拆分的最小分组单位，必须同时覆盖以下关系：

- 同一场景模板的参数变体；
- 同一原始事件的改写或组织语境变体；
- counterfactual 双胞胎；
- 模型可见输入完全相同、仅隐藏世界真值不同的案例。

一个 `family_id` 只能属于 `dev` 或 `test`。按冻结 `visible-metadata-v1` 规则规范化后静态等价的 PublicCase 与 EnvironmentFixture 必须具有相同 `family_id` 和 `split`。审计报告同时保存规范化版本与哈希；语义相近但静态内容不同的模板改写仍需作者与独立复核者在编写时归入同一 family。

`dev` 可用于调整 Prompt、rubric 和决策权重。`test` 在冻结前可以做结构、引用和标签质量检查；冻结后不得依据测试结果调参。任何修复都创建新 dataset version，并保留旧版本及变更原因。

## 3. 目标覆盖矩阵

60 案例按 family 分组后切分为 dev 20、test 40。案例总数服从以下覆盖目标，family 是统计推断与 bootstrap 的独立单位：

| 维度 | 最低覆盖要求 |
|---|---|
| 最终证据状态 | 可充分 TP、可充分 FP、风险明确但不可定论、信息不可区分 |
| 证据条件 | 关键证据完整、关键证据缺失、冲突证据、空结果、数据源不可用 |
| 调查行为 | 单工具即可解决、多工具交叉验证、应提前停止、应转人工 |
| 干扰项 | 高风险但低判别线索、重复同源记录、无关 ATT&CK/TI 线索 |
| 工具故障 | 非重试错误、可重试错误、部分覆盖、成功但零结果 |
| counterfactual | 至少三个 family；双胞胎必须同 split |

类别比例是合成实验设计，不代表生产基率。报告必须同时给逐 family 结果和总体原始计数。

## 4. 单案例作者清单

每个案例必须同时交付 PublicCase、EnvironmentFixture、OracleCase 和预算绑定的评测标注，并完成：

1. Ground Truth 与完整世界证据一致；
2. observable、critical、distractor 和 discriminating fact 明确分开；
3. 每个可观测事实可回溯到 Alert、ToolRecord 或可验证的故障 envelope；
4. sufficient set 只包含可观测事实，且能支持对应 TP/FP；
5. expected action 按当前已获/缺失事实定义可接受集合，不规定唯一脚本；
6. 不可定论案例明确允许 Suspicious 或要求 Abstain；
7. family、split、rubric、预算和数据版本均冻结；
8. Public/Environment 中无 oracle 字段、语义 case ID 或作者提示。

## 5. 自动审计

在 `investigation/` 目录执行：

```powershell
python scripts/dataset_split_audit.py
```

命令验证：

- manifest 为封闭结构，所有数据文件均被 SHA256 覆盖且没有孤儿文件；
- public/environment/oracle 使用各自的类型加载器且映射一致；
- case ID 唯一，每个 oracle 文件只映射一次；
- family 不跨 dev/test；
- 按冻结规则规范化后静态等价的模型可见输入不会跨 family 或 split；
- 输出 case、family、split 计数和重复可见输入组，供复核留档。

该命令是作者侧审计，会读取 oracle，禁止由 Agent 运行时导入。它不能自动识别语义改写，因此不能替代独立内容复核。

## 6. 分批实施顺序

1. M10a：冻结本契约和自动审计规则；对现有五案执行回归。
2. M10b：新增 7 个案例，将开发集扩到 12 案；覆盖至少三个新 family，并在写案例前消除只识别固定 credential/backup 字符串的实现耦合。新增结构化批准行为精确匹配、有限的直接有害行为词表和完整零网络范围处理，同时保留五案回归。
3. M10c：扩到 dev 20；冻结 Prompt、rubric、预算和数据作者指南。
4. M10d：独立编写并冻结 test 40；测试案例只做结构和标签质量复核。
5. M11：四方法多次运行、消融和以 case/family 为单位的统计分析。

每一批都必须先通过数据审计、加载器测试、人工内容复核和 CI，再进入下一批。新增案例不能修改 M8/M9 的历史 artifact。
