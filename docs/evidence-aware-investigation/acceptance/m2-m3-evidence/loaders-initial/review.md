# M2 加载器、Schema 与实际数据独立审查

日期：2026-10-04，复核代理 m3_diff。审查其他代理编写的加载器与主实现的数据，不审查自己的 diff_report.py。

## 冻结与执行方式

源目录 `D:/project/Agent/m3-independent-foundations/investigation` 整体复制为本目录下 `investigation/`，排除虚拟环境、pycache、运行结果。79 个文件字节指纹保存在 `snapshot.json`，冻结时源 HEAD 为通用组件 72e808f。M2 文件为该 HEAD 后的待提交工作。

复核使用现有锁定虚拟环境作为 Python/依赖解释器，通过 PYTHONPATH 明确优先导入冻结 src 和 evaluation；不读取作者运行时源码。独立探针在 `test_review_probes.py`；未修改作者源码、测试或数据。

执行作者 `test_dataset_loaders.py` 和独立探针：**77 检查，68 通过，9 失败**。完整记录在 `review-tests.log` 与 `review-tests.xml`。以下两项须修复后复验。

## F1 / P1：专用 oracle 标注可进入模型可见字段

位置：`state/content.py::_HIDDEN_KEYS` 及两个可见加载器调用点。

嵌套 `expected_actions`、`resolvable_with_full_observable_evidence` 在 public raw 和 ToolRecord payload 中都被接受，共四个独立失败探针。它们属于 OracleCase 的调查路径标注和可解性答案，进入 Agent 输入会泄露评测信息，即使没有 ground_truth 字段也会影响实验。

最小修复：封闭隐藏字段清单应包括这两个 oracle 专用字段，递归拒绝；继续允许 legitimate TI reputation 等业务字段，不使用 malicious/benign 词汇过滤。添加四种边界回归测试。

## F2 / P1：预期动作约束未校验，工具选择评分标准可失效

位置：`evaluation/oracle_loader.py::validate_oracle` expected_actions 循环。

当前仅检查工具枚举、事实引用和 evidence_goal，未检查 `argument_constraints` 是否属于声明 acceptable_tools 的查询字段及类型。asset 的 host=True、host=17、unknown_filter、非时间 as_of、非法 limit 均通过，共五个独立失败探针。

后续 Tool Selection Accuracy 使用这些约束作为评分标准，错误标注会导致正常请求被判错、全部请求不能匹配或隐含放宽评分。最小修复应从公共 state Query 类型验证约束，避免导入工具环境实现破坏 oracle 边界。多 acceptable_tools 时明确共享约束的合法性规则并冻结。至少拒绝对任何可接受工具都无意义的字段和非法类型，缺失的查询字段允许作为部分匹配约束。

## 已通过的检查

- 5 public、4 物理 environment、5 oracle 全部通过作者加载器。
- manifest 中每份数据文件的原始 SHA256 与实际字节一致。
- C4/C5 共用同一物理 environment，公开输入完全一致。
- public 原文 hash 与实际 raw 一致；opaque remap 保留业务 payload/hash、来源、可靠性，并一致重映射规则引用。
- 环境中的 host 布尔/整数、未知约束、非法 limit/window 被拒绝。
- top-level occurrence/publication/observation 未来时间被拒绝。
- oracle 的悬空事实、不可观察充分组合、世界真值/确定判定冲突、可解性不一致被拒绝。
- 实际 oracle observable record_ids 在对应 public/environment 中全部可解析；manifest 的 dataset/rubric 版本与各文件一致。
- environment Schema 与公共契约派生结果一致；public/oracle 模块导入边界正确。

## 验收结论与范围

本轮不通过，原因是 F1/F2；当前真实 fixtures 未观察到这两种恶意/错误元数据，但加载器边界应在冻结 M2 前能拒绝它们。新增工具响应与实际模型请求仍需分别在 M3/M5 验收，五个 dev 样例不支持统计效果结论。未进行大范围任意 JSON 或所有字段组合穷举。
