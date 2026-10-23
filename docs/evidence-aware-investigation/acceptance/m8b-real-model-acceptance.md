# M8b 真实模型探索验收

日期：2026-10-24

正式运行代码：`36e6c8c`

正式 Artifact：`evals/reports/m8b-deepseek-20261024-v5/`

## 1. 验收结论

M8b **工程验收通过**，真实模型探索已完成。

- 五种方法在相同模型、参数、数据集、工具快照和默认预算下各运行 5 个案例，共 25 个 run。
- 25 个 run 均形成完整 Trace；131 个归档文件校验通过，离线重放重算 25 个 run 和 5 份方法报告，结果一致。
- 48 次获得响应的模型调用均记录 token 与计算费用；模型输入泄漏发现为 0。
- Proposed/C3 的首次模型请求发生一次上游连接中断。系统按预定策略输出 `Abstain / model_error`，完整失败 Trace 已保留，没有删除或用有利结果覆盖。
- 实验结果未证明 Proposed 优于基线。工程验收与实验结论分开判断。

## 2. 冻结实验条件

| 项目 | 值 |
|---|---|
| Provider | DeepSeek 官方 API |
| Base URL | `https://api.deepseek.com` |
| Model | `deepseek-flash` |
| 参数 | temperature=0；thinking=disabled；JSON object |
| Dataset / rubric | `synthetic-v1` / `powershell-v1` |
| 方法 | direct、fixed、fixed_all、react、proposed |
| 案例 | C1–C5，每种方法各一次 |
| 单 run 预算 | 6 tool calls；16000 tokens；8 steps；90 seconds |
| 价格快照 | DeepSeek 官方 2026-10-24 off-peak 价格；缺失缓存拆分时按全部 cache miss 计价 |
| 密钥处理 | `.env` 本地加载；密钥不进入配置、Trace、报告或 Git |
| seed | Provider 不支持冻结 seed；`seed_supported=false` |

正式 Artifact 的 `config.json`、各 run `manifest.json`、冻结输入和 SHA-256 清单共同绑定上述条件。真实 `.env` 不进入归档。

## 3. 原始结果

| 方法 | TP | FP | Suspicious | Abstain | 决策覆盖 | 选择性准确率 | False Close |
|---|---:|---:|---:|---:|---:|---:|---:|
| Direct | 0 | 0 | 5 | 0 | 0/5 | NA | 0/3 |
| Fixed | 0 | 0 | 5 | 0 | 0/5 | NA | 0/3 |
| Fixed-all | 0 | 0 | 5 | 0 | 0/5 | NA | 0/3 |
| ReAct | 1 | 0 | 2 | 2 | 1/5 | 1/1 | 0/3 |
| Proposed | 1 | 0 | 0 | 4 | 1/5 | 1/1 | 0/3 |

这是五个公开开发案例的原始计数，不做置信区间、显著性或泛化推断。

Proposed 的逐案结果：

| Case | Ground truth | Verdict | Stop reason |
|---|---|---|---|
| C1 | malicious | TP | sufficient |
| C2 | benign | Abstain | token_budget |
| C3 | malicious | Abstain | model_error |
| C4 | malicious | Abstain | token_budget |
| C5 | benign / required abstention | Abstain | token_budget |

## 4. 行为与效率发现

- Proposed 在 C1 收集到全部 3 项关键及判别证据，证据精度为 4/4，工具选择为 3/3，并形成有充分证据的 TP。
- Proposed 对要求拒判的案例保持安全：required abstention recall 为 2/2，False Close 为 0/3。
- Proposed 的 appropriate abstention precision 为 3/4；C2 属于可避免拒判，说明默认 token 预算下仍未可靠完成良性关闭。
- Proposed 的工具选择 12/12 命中冻结可接受动作，已知无用调用为 0/12；工具调用策略本身表现正常。
- Proposed 的已测运行平均约 9913 input tokens、3177 output tokens；ReAct 约 9651 input、503 output。Proposed 的假设生成和修订带来明显输出开销，并在 C2/C4/C5 触发 token budget。
- Direct、Fixed 和 Fixed-all 全部选择 Suspicious，没有错误关闭，也没有形成确定结论。
- 不同真实批次在个别案例上出现 Verdict 波动。Provider 不支持冻结 seed，五案单次运行不能用于稳定性结论。

因此，本轮只支持以下有限结论：Evidence-Aware 路径能够在证据充分的 C1 形成可追溯 TP，并在不充分或运行失败时安全拒判；当前实现尚未证明比 ReAct 有更高覆盖率，也未证明更低成本。下一轮应优先压缩假设状态与修订输出，再扩展盲测数据。

## 5. 费用与授权边界

正式 v5 批次计算费用为 `$0.024532 USD`，按 8 CNY/USD 的保守核算为 `0.1963 CNY`。所有有完整 inventory 的预检、修复验证和正式批次合计 `0.9887 CNY`；加上一次极小连通性检查及中止预检的未完整计量请求，项目侧保守估计仍低于 `1.1 CNY`，远低于用户授权的 7 CNY。

费用由 Provider 返回的 token 计数和冻结价格快照计算，最终账单以 DeepSeek 控制台为准。

## 6. 运行中发现并修复的问题

1. 首轮费用响应偶尔缺少缓存拆分。修复为按全部 cache miss 保守计价，避免预算保护失效。
2. ReAct 曾把 process 作为 History 的 entity type。提示词补充合法枚举与 SIEM process tree 路径。
3. Proposed 假设修订曾遗漏 `supersedes`、输出截断或新增未允许的假设 ID。提示词补充修订契约，输出上限调整为 1400 tokens，修复提示要求完整、简洁且不得重复非法输出。
4. Registry 曾只采集顶层 IOC，导致模型可见的嵌套目标 IP 被 Dispatcher 拒绝。现已递归采集工具记录中的嵌套 IOC，并增加回归测试。

早期 Artifact（v2–v4、candidate 和单案检查）保留在 `evals/reports/`，用于追溯上述问题，不作为正式 M8b 结论。

## 7. 验证证据

- `python -m pytest investigation/tests -q`：`690 passed`。
- `python -m benchmark.m8b replay --artifact evals/reports/m8b-deepseek-20261024-v5`：131 个文件校验通过，25 个 run 与 5 份报告重放一致。
- 正式批次：25 runs，48 priced calls，0 unpriced calls，0 leakage findings。
- 失败 Trace：`evals/reports/m8b-deepseek-20261024-v5/runs/main/run-0023-212a4d34fc60/`。

## 8. 结论边界

本报告验证真实模型调用、预算、Trace、费用、重放和失败保存链路。五个公开设计案例既不是盲测，也没有重复采样；不能据此声称策略优越、生产可用或统计显著。M8b 完成后，后续研究应使用 30–100 个盲测案例、冻结模型版本或多次重复，并将稳定性和 token 效率列为主要指标。
