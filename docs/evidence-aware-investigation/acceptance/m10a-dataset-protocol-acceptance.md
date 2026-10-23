# M10a 数据扩展协议与切分审计验收记录

里程碑 / 状态：M10a；主实现自检与辅助 AI 独立复核通过，待提交与同一提交 CI。

提验日期：2026-10-24。

父依赖：M2 数据契约与 M5 评测边界均已完成；本阶段不依赖 M9b 收费复验。

## 本次完成的能力

- 冻结 M10 的目标规模、family 分组语义、dev/test 使用边界、覆盖矩阵、单案作者清单与分批实施顺序。
- 新增作者侧 `dataset_split_audit.py`，检查 manifest 封闭结构、全量 SHA256、类型加载、路径分区、case/oracle 映射、孤儿文件、family 跨 split 和按冻结规则规范化后静态等价的模型可见输入跨组。
- 保持五个种子案例和 M8/M9 Artifact 字节不变；未调用模型。
- 明确精确输入重复可自动检查，语义改写仍需独立内容复核，避免夸大自动审计能力。

## 提验文件与 Git blob 哈希

| 文件 | Git blob SHA1 |
|---|---|
| `investigation/scripts/dataset_split_audit.py` | `c1df4c8b403adf5f482887f8ad8e297048c87cbf` |
| `investigation/tests/test_dataset_split_audit.py` | `e2174875dc53227b14bb8ee7f8e7c26d88eeaaa2` |
| `investigation/datasets/README.md` | `72cdec4d14fa891b3c2cd5e519079d791581e30d` |
| `docs/evidence-aware-investigation/m10-dataset-expansion-contract.md` | `842bd5bb524772b5ab5a90c541162f26b26a70cd` |
| `docs/evidence-aware-investigation/m9-efficiency-contract.md` | `ea5d620dbe5fb852c7030a9c50a8c6b61a0475ec` |
| `docs/evidence-aware-investigation/phase-2-implementation-plan.md` | `1c267422f2c3f98c15a091269e99b4133b361f2d` |

上表是辅助 AI 独立复核使用的提验快照。复核通过后只更新了本验收记录、M9a 验收状态和实施计划状态行；因此实施计划在最终提交中的 blob 会变化，审计实现、测试和契约的受审字节保持不变。

## 主实现自检

环境：`D:\project\Agent\sentinelkb\investigation\.venv`，Python 3.12 项目环境。

```powershell
cd D:\project\Agent\sentinelkb\investigation
.\.venv\Scripts\python.exe scripts\dataset_split_audit.py
.\.venv\Scripts\python.exe -m pytest tests\test_dataset_split_audit.py -q
.\.venv\Scripts\python.exe -m pytest -q
```

实测结果：

- 当前数据集：5 cases、2 families、dev=5；C4/C5 是唯一静态等价的模型可见输入组，二者同 family、同 split；报告绑定 `visible-metadata-v1` 及其哈希。
- 审计专项：9 passed（包含在全量结果中）。
- investigation 全量：704 passed in 12.30s。
- `git diff --check`：通过。

负向测试覆盖：family 跨 dev/test；等价可见输入跨 family；等价可见输入同时跨 family 与 split；哈希正确但未映射的孤儿文件；映射指向错误分区；映射路径不是字符串。正向补充覆盖仅 environment envelope ID 不同仍被规范化为同一可见组。

## 主实现复核结论

实现符合 M10a 范围，没有修改运行时决策、数据内容、Prompt、Rubric 或既有实验产物。审计工具明确位于 `scripts/`，会读取 oracle，不能作为 Agent 运行时依赖。主实现结论为可进入独立复核与提交门槛。

## 辅助 AI 独立复核

辅助 AI 对冻结 blob、规范化绑定、family/split 规则、九项专项测试、全量回归和独立哈希篡改探针完成复核，结论为**建议通过并进入提交/CI 门槛**；见 [M10a 独立技术复核](m10a-independent-review.md)。

复核提出的低风险建议是在 M10b 固化一个 `dataset_hash_mismatch` 专项测试；该路径已经由独立探针验证，不阻断 M10a。O(n²) 静态比较在目标 60 案例下约 1770 次，当前无需优化。

## 已知限制

- 冻结静态规范化不能识别自然语言改写、参数替换或同模板不同值；这些关系依赖作者正确设置 `family_id` 和独立内容复核。
- 当前五案全在 dev，尚无 blind test 数据；本里程碑不形成泛化或策略优越性结论。
- 60 案例的类别比例是实验设计，不代表生产环境基率。

## 待完成门槛

1. 提交、推送已复核实现与验收记录。
2. 核对同一提交的 `test` 与 `investigation-tests` 两个 CI job。

只有两项完成后才将 M10a 标为已完成并开始 M10b 案例扩写。
