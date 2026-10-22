# M7 Proposed 层验收记录

## 1. 结论

M7 工程验收通过。实现提交为 `ea5d1f0003db911144dbec4eefef00c491d5b973`，远端工作流 [run 39821412776](https://github.com/aascc413-coder/sentinelkb-ai-security-agent/actions/runs/39821412776) 的 `test` 与 `investigation-tests` 均成功。

本结论只表示 Proposed 调查闭环、确定性门槛、预算停止、Trace 与反例处理符合当前 `powershell-v1` 工程契约。它不证明真实模型优于基线，也不代表可以连接真实 SOC 后执行处置。

## 2. 交付范围

- `agents/hypothesis.py`：2–4 个竞争假设、恶意/良性最小集合、EvidenceLink 一致性、引用闭包与 supersedes 版本修订。
- `agents/sufficiency.py`：G0–G4、B1–B3 三值程序检查；多记录、多目标、多批准来源冲突处理；Suspicious 风险模式输入。
- `agents/planner.py`：最多 3 个候选、冻结优先级、真实 hypothesis ID、动作特定预测、完整 ToolCall 去重与证据响应排序。
- `agents/investigator.py`：Hypothesis → Sufficiency → Plan → Budget → Dispatcher 主循环，以及 TP/FP/Suspicious/Abstain 停止规则。
- `runtime/prompts.py` 与两个版本化 prompt：精确字节 SHA-256 写入 manifest；原基线改为复用公共 prompt 读取器。
- `runtime/registry.py`：同一 fact/envelope 的完整来源 call_id 台账，支持缓存重查的可追溯验证。
- [M7 运行契约](../m7-proposed-contract.md)：边界、门槛、有限策略与限制。

## 3. 五案例行为

| 案例 | 调查顺序 | 最终结论 | 关键原因 |
|---|---|---|---|
| C1 | process → network → asset | TP | 同实例未授权凭证读取与发送，完整批准登记无匹配 |
| C2 | process → asset → network | FP | 实际作业六字段匹配批准记录，行为与全部目标均在批准范围内 |
| C3 | process → asset → network → history | Suspicious | 当前执行与积极批准记录的 job/hash/参数不匹配，替代历史不可用 |
| C4 | process → asset → network → history | Abstain | 正文、批准归档和网络/历史覆盖不足，无已验证实质风险模式 |
| C5 | process → asset → network → history | Abstain | 与 C4 的公开输入、动作、评分和停止行为完全相同 |

不同可见状态产生不同顺序：C1 的未授权行为线索使 network 优先；C2/C3 的明确作业字段使 asset 优先。因此该策略不是 Fixed Workflow 的改名实现。

## 4. 预算与安全停止

- tool budget=3：C1/C2 的最后一个合法工具结果已使全部程序门槛成立，因此无需模型调用即可分别得到 TP/FP；C3 仍不充分，得到 `Abstain/tool_budget`。
- step budget 在 C3 风险已登记后耗尽：输出 Abstain，同时保留 `approval_execution_mismatch`。
- deadline、token、step 等硬停止不能新增确定结论；最后一个工具调用后不再调用模型。
- 格式正确但擅自把程序门槛升级为 `met` 的充分性解释，在一次付费修复后仍非法时得到 `Abstain/protocol_error`。

## 5. 负向与冲突验证

专项测试和独立探针覆盖：

1. 未登记 ToolResult 不能通过 G0；合法缓存重查仍保持已登记来源关系。
2. 旧时间、不同 GUID/host/PID、partial/unavailable 覆盖不能升级为充分证据。
3. 缺 job/hash/parameters、畸形 job、布尔 parameters、无时区批准窗口保持 unknown，运行不会崩溃。
4. 后续进程记录中的恶意行为、额外网络记录、`observed_destinations`/`destinations` 中的额外目标都会阻断 FP。
5. 多个完整批准来源的 match/none/mismatch/unknown、目标范围冲突，以及 asset/history 冲突都会阻断确定结论。
6. partial asset 可以由等价完整 history 批准查询替代；不可用 history 不会被解释为无批准。
7. C4/C5 的完整 planner 投影一致，不读取 case ID、host 特例或 oracle。

## 6. 独立复核过程

两路只读复核分别覆盖 sufficiency/Registry 与 planner/investigator。首轮复核发现固定排序、首条记录偏见、批准字段缺失误匹配、未登记证据可通过、deadline 仍可定论、畸形 payload 崩溃、partial 批准升级、history 替代路径缺失、错误去重和缺口状态失真等问题。

这些问题逐项修复并由复核者使用反例重测。最终结论：规划与停止侧无剩余阻塞；充分性与 Registry 侧已报告的 P1/P2 全部关闭。最终专项范围为 agents + registry 30 tests passed，并额外验证批准记录顺序反转、独立完整来源冲突、asset/history 冲突和批准目标范围冲突。

独立复核结论没有被解释为真实模型效果证明。

## 7. 验证证据

- 本地全量：`680 passed in 7.82s`。
- 编译检查：`python -m compileall -q investigation/src/evidence_investigation` 成功。
- diff 检查：`git diff --check` 无错误，仅 Windows 行尾提示。
- 远端提交：`ea5d1f0003db911144dbec4eefef00c491d5b973`。
- 远端 CI：`test=success`，`investigation-tests=success`。
- 机器可读快照：`m7-proposed-evidence/source-snapshot.json` 与 `ci-final.json`。

## 8. 后续入口

M8a 可以开始：用假模型运行四方法（另含 fixed_all）× 5 案例 × 3 重复，以及 tool budget=2/4/6/8 冒烟；报告必须标注工程验收性质并保留原始计数、运行配置、Trace 清单和哈希，不得声称算法优越性。
