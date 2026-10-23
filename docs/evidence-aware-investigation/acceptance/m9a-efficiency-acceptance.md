# M9a 调查循环效率修订工程记录

日期：2026-10-24
状态：本地实现与自检通过；待提交、独立复核和远端 CI

## 1. 交付内容

- 新增 `hypothesis-v2.txt` 与 `hypothesis_proposal_v2.schema.json`。
- Evidence Link 成为模型输出的唯一关联来源，内部假设证据数组由运行时确定性投影。
- 调查循环从每次工具调用后修订，改为开始生成一次、正常停止前集中修订一次。
- v1 Prompt 与 Schema 保留，供历史版本和 Artifact 追溯。
- 更新 M8a 假模型适配器和相关单元测试。

设计理由及不变量见 [M9 效率修订契约](../m9-efficiency-contract.md)。

## 2. 本地验证

### 全量测试

```text
.venv/Scripts/python.exe -m pytest investigation/tests -q
692 passed
```

### 统一假模型基准

执行一次五方法 × 五案例离线批次，共 25 runs；随后校验不可变归档并重放：

```text
verified_files=131
replayed_runs=25
reports=5
```

Proposed 五案均为有效 run，Verdict 仍为 `TP / FP / Suspicious / Abstain / Abstain`，工具调用仍为 `3 / 3 / 4 / 4 / 4`。

## 3. 调用数量与预算预留对比

| Case | M8a 已归档 v1 调用数 | M9a v2 调用数 | v1 输入预估合计 | v2 输入预估合计 | v1 输出预留合计 | v2 输出预留合计 |
|---|---:|---:|---:|---:|---:|---:|
| C1 | 5 | 3 | 7611 | 4336 | 4900 | 2900 |
| C2 | 5 | 3 | 7732 | 4407 | 4900 | 2900 |
| C3 | 6 | 3 | 11280 | 4933 | 5900 | 2900 |
| C4 | 6 | 3 | 11731 | 5047 | 5900 | 2900 |
| C5 | 6 | 3 | 11731 | 5047 | 5900 | 2900 |

输入数字是预算控制器的 `chars/4` 预估，输出数字是最大 token 预留；它们不是供应商实际计费 token。假模型实测 token 是固定合成值，不能作为真实模型效率证据。

## 4. 结论边界与剩余验收

M9a 已验证调用拓扑缩减且五案确定性行为不变。真实模型是否减少格式修复、预算耗尽、实际 token 和费用仍需 M9b 同条件复验。

提交后还需完成：

1. 独立技术复核受影响的 Hypothesis Schema、预算硬停和五案 Trace。
2. 推送并核对同一 commit 的 `test` 与 `investigation-tests`。
3. 获得新的付费额度授权后才执行 M9b。
