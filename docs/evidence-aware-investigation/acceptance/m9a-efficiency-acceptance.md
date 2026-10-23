# M9a 调查循环效率修订工程记录

日期：2026-10-24
状态：实现、本地自检与分支/主分支双 CI 通过；待辅助 AI 独立复核

实现 commit：`5d59ecf5ace3a84dbe965dc62e84582aa604c29a`

验收 head：`186b7cce0d508da06ecffc97bafa6523f479cf66`

## 1. 交付内容

- 新增 `hypothesis-v2.txt` 与 `hypothesis_proposal_v2.schema.json`。
- Evidence Link 成为模型输出的唯一关联来源，内部假设证据数组由运行时确定性投影。
- 调查循环从每次工具调用后修订，改为开始生成一次、正常停止前集中修订一次。
- v1 Prompt 与 Schema 保留，供历史版本和 Artifact 追溯。
- 更新 M8a 假模型适配器和相关单元测试。
- 增加 M9b Artifact 离线对比命令；对比前强制重放两侧归档并校验实验条件。

设计理由及不变量见 [M9 效率修订契约](../m9-efficiency-contract.md)。

## 2. 本地验证

### 全量测试

```text
.venv/Scripts/python.exe -m pytest investigation/tests -q
695 passed
```

### 统一假模型基准

执行一次五方法 × 五案例离线批次，共 25 runs；随后校验不可变归档并重放：

```text
verified_files=131
replayed_runs=25
reports=5
```

归档位置：`evals/reports/m9a-fake-5d59ecf`（本地忽略目录，不提交 Git）。归档配置绑定上述实现 commit。

Proposed 五案均为有效 run，Verdict 仍为 `TP / FP / Suspicious / Abstain / Abstain`，工具调用仍为 `3 / 3 / 4 / 4 / 4`。该假模型每阶段首轮输出均合法，因此每案为 3 个实际模型请求；真实模型若触发修复，会额外计费并进入 M9b 对比。

### 真实模型归档对比预检

使用 M8b v5 正式 Artifact 同自身执行离线 compare，得到 5 个 Proposed 配对 Case；其中 4 个 Case 两侧 usage 完整，模型调用和 input token 差值均为 0。该检查验证 compare 管道，不产生新模型或工具调用。

## 3. 调用数量与预算预留对比

| Case | M8a 已归档 v1 调用数 | M9a v2 调用数 | v1 输入预估合计 | v2 输入预估合计 | v1 输出预留合计 | v2 输出预留合计 |
|---|---:|---:|---:|---:|---:|---:|
| C1 | 5 | 3 | 7611 | 4300 | 4900 | 2900 |
| C2 | 5 | 3 | 7732 | 4371 | 4900 | 2900 |
| C3 | 6 | 3 | 11280 | 4897 | 5900 | 2900 |
| C4 | 6 | 3 | 11731 | 5010 | 5900 | 2900 |
| C5 | 6 | 3 | 11731 | 5010 | 5900 | 2900 |

输入数字是预算控制器的 `chars/4` 预估，输出数字是最大 token 预留；它们不是供应商实际计费 token。假模型实测 token 是固定合成值，不能作为真实模型效率证据。

## 4. 结论边界与剩余验收

M9a 已验证调用拓扑缩减且五案确定性行为不变。真实模型是否减少格式修复、预算耗尽、实际 token 和费用仍需 M9b 同条件复验。

剩余步骤：

1. 独立技术复核受影响的 Hypothesis Schema、预算硬停和五案 Trace。
2. 获得新的付费额度授权后才执行 M9b。

## 5. 远端 CI

- 开发分支 head `186b7cc`：`test` 与 `investigation-tests` 均通过，[run 40002144661](https://github.com/aascc413-coder/sentinelkb-ai-security-agent/actions/runs/40002144661)。
- `main` 同一 head：`test` 与 `investigation-tests` 均通过，[run 40002378447](https://github.com/aascc413-coder/sentinelkb-ai-security-agent/actions/runs/40002378447)。
