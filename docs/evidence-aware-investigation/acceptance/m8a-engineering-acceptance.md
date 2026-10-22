# M8a 假模型工程验收记录

## 1. 结论

M8a 工程验收通过。冻结实现提交为
`d3b8341f8feac4d3c1884d52d77d7342adb3093a`，远端工作流
[run 39823511219](https://github.com/aascc413-coder/sentinelkb-ai-security-agent/actions/runs/39823511219)
的 `test` 与 `investigation-tests` 均成功。

本结论只表示假模型下的运行、预算、Trace、请求捕获、评分、归档和离线重放链路
成立。它不证明 Proposed 优于任何基线，不表示真实模型有效，也不表示系统可以接入
真实 SOC 或执行安全处置。M8b 真实模型探索尚未执行。

## 2. 实现范围

- `benchmark/m8a.py`：五方法统一编排、确定性假模型、75-run 主矩阵、100-run
  预算冒烟、不可覆盖归档、SHA-256 清单与离线重放。
- `evaluation/evaluator.py`：按输出意图区分 Proposed 的终局充分性解释和真正的
  `FinalAssessment` 提案，避免合法解释被误计为模型提案错误。
- `test_m8a_benchmark.py`：25-run 最小集成矩阵、全归档重放、非默认预算不误用
  默认标注。
- [M8a 工程契约](../m8a-engineering-contract.md)：结论边界、运行矩阵、归档结构、
  重跑/重放差异与标注口径。

## 3. 正式批次

完整本地归档保存在 `evals/reports/m8a-fake-d3b8341/`。该目录属于运行产物，
默认不提交 Git；代码、输入快照、配置、清单、报告和每个 Trace 均由归档自身的
`checksums.sha256` 绑定。

| 项目 | 结果 |
|---|---:|
| 主矩阵 | 5 方法 × 5 案例 × 3 重复 = 75 runs |
| 预算冒烟 | 5 方法 × 5 案例 × 4 档预算 = 100 runs |
| 总运行 | 175 |
| valid | 175 |
| failed | 0 |
| 模型输入泄漏命中 | 0 |
| 归档文件 | 752 |
| 归档大小 | 14,536,362 bytes |
| 离线重放检查 | 751 个有校验和文件、175 runs、25 reports 全部一致 |

关键归档哈希：

| 文件 | SHA-256 |
|---|---|
| `checksums.sha256` | `efb514c1646e22b6126f140f293e434c9480337b4c7145d715234f1aa5dc9145` |
| `inventory.json` | `1701dad6e67ed12df18602734bf0dc9a456cb468c8c760417a10c0dbd5797ade` |
| `config.json` | `d4582b58dbe5398bcd33ddd64615fc4c7c4c45993a19f1464f8b8890ea164b1c` |
| `reports/summary.md` | `d6d4be713cbcd18d539dae126cd6760e5dbf961c03101ed6fb131f0699dc2c85` |

## 4. 原始结果边界

主矩阵原始运行计数如下。重复只用于稳定性检查，独立案例数仍为五。

| 方法 | attempted | valid | TP | FP | Suspicious | Abstain | failed |
|---|---:|---:|---:|---:|---:|---:|---:|
| direct | 15 | 15 | 0 | 0 | 0 | 15 | 0 |
| fixed | 15 | 15 | 0 | 0 | 0 | 15 | 0 |
| fixed_all | 15 | 15 | 0 | 0 | 0 | 15 | 0 |
| react | 15 | 15 | 0 | 0 | 0 | 15 | 0 |
| proposed | 15 | 15 | 3 | 3 | 3 | 6 | 0 |

Direct、Fixed、Fixed-all 和 ReAct 的确定性假模型采用保守拒判策略；这四组全拒判
不是胜利指标。Proposed 结果来自 M7 的确定性门槛与同一假模型解释器，只验证预设
工程路径。上述数字不能用于比较方法效果。

预算冒烟中，tool budget=2 的 Proposed 全部 Abstain；budget=4 时 C1/C2 可以在
最后一个已接纳工具结果上分别得到 TP/FP，其余 Abstain；budget=6/8 恢复五案预设
的 TP/FP/Suspicious/Abstain。这里同样只验证预算停止与既有确定性门槛。

## 5. 重跑与重放验证

正式执行：

```powershell
cd investigation
python -m benchmark.m8a run `
  --output ..\evals\reports\m8a-fake-d3b8341 `
  --repeats 3 --budget-scan 2,4,6,8
```

只读重放：

```powershell
cd investigation
python -m benchmark.m8a replay `
  --artifact ..\evals\reports\m8a-fake-d3b8341
```

重放返回 `verified_files=751`、`replayed_runs=175`、`reports=25`。重放没有构造模型
或工具服务；重新运行必须使用不存在的新目录，因此不会覆盖旧批次。

代表性 Proposed Trace：

- C1：`runs/main/run-0061-e2f1e861eb80`，TP / sufficient。
- C2：`runs/main/run-0064-8b762c8ed87f`，FP / sufficient。
- C3、C4、C5 和其余全部运行可从 `inventory.json` 按 case/method/repeat 定位。
- 本批失败数为零；失败保留与协议失败汇总机制由 M5/M8a 自动测试覆盖，没有伪造
  失败运行混入正式矩阵。

## 6. 发现并修复的问题

辅助只读预审发现两个评测口径风险：

1. Proposed 使用 final token reserve 生成结构化充分性解释，旧评测器只按
   `phase=final` 判断，可能把它误作 `FinalAssessment` 并计为 proposal error。
2. 冻结 annotation 绑定完整默认 Budget，不能复用到 tool budget=2/4/8。

实现改为按实际输出意图区分充分性解释，增加回归测试；Runner 仅在完整 Budget
逐字段一致时应用冻结标注，其他预算组相关指标保持 NA 并单独汇总。正式 Proposed
报告的 `model_proposal_error_rate` 为 `0/0 = NA`，没有把解释误计为错误提案。

## 7. 验证证据

- 本地全量：`683 passed in 11.27s`。
- M8a 专项与 evaluator：`32 passed in 5.07s`。
- 编译检查：`python -m compileall -q investigation/benchmark investigation/evaluation investigation/src/evidence_investigation` 成功。
- `git diff --check` 成功。
- 正式批次：175/175 valid，0 leakage finding，离线重放逐字段一致。
- 远端 CI：冻结实现 SHA 的 `test` 与 `investigation-tests` 均成功。
- 机器可读摘要：[m8a-engineering-evidence.json](m8a-engineering-evidence.json)。

## 8. 后续入口

M8b 需要调用真实模型，属于付费资源，必须先获得单独费用上限授权。在此之前保持
“未完成”，不使用 M8a 假模型结果替代真实模型探索。无需付费即可继续准备 M8b 的
只读配置校验、真实模型批次格式和失败保留测试，但不能发出真实 API 请求。
