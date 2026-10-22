# M6 基线层技术验收

里程碑 / 状态：M6 / 已完成  
日期：2026-10-23

## 提验版本与父依赖

- 实现提交：`7cd8887a468cfe581386b0a55db223bed4467516`
- 分支：`codex/m6-baselines`
- 完整变更文件及 Git blob：[`m6-baseline-evidence/source-snapshot.json`](m6-baseline-evidence/source-snapshot.json)
- M5 父依赖：主分支 `e62fd855d796a9b672c24338bfafe0884fed349a`，M5 双 CI 已通过。

## 完成能力

1. 实现 Direct、Fixed、Fixed-all、ReAct 四种比较方法。
2. 四种方法共用 Registry、Budget、Dispatcher、Trace、模型修复和 FinalAssessment 引用校验。
3. Fixed 顺序冻结为 SIEM → TI → ATT&CK；Fixed-all 冻结五类工具。无可用指标时记录 `stage_skipped`。
4. ReAct 只使用公共 ToolAction / FinishAction，不接收 Proposed 的 Hypothesis、缺口、充分性或判别分数字段。
5. Prompt 文件版本化，原始 UTF-8 字节 SHA-256 强制写入 manifest；不匹配时在创建 trace 前拒绝。
6. 自包含输出 Schema 进入实际 provider messages，评测捕获与 HTTP wire 保持一致，Schema token 纳入预算估算。
7. 工具协议错误、模型超时和预算耗尽均输出可重放的安全 Abstain。
8. ReAct 嵌套或畸形 Finish 与其他方法使用同一模型提案错误指标口径。

详细方法边界见 [`m6-baseline-contract.md`](../m6-baseline-contract.md)。

## 主实现自检

环境：Python 3.12；源码来自本 worktree；依赖复用审查虚拟环境的只读 site-packages。

```powershell
$env:PYTHONPATH='D:/project/Agent/m4-implementation/investigation/src;D:/project/Agent/m4-helper-review/.review-venv/Lib/site-packages'
& 'C:/Users/scc/.local/markitdown/Scripts/python.exe' -m pytest investigation/tests -q
```

实测：**660 passed in 6.75s**。覆盖 C1 四方法 trace、Fixed 顺序、TI 跳过、ReAct 自主动作、相同 final 结构、离线重放、prompt hash、Schema wire、模型修复、工具协议拒绝、预算停止、超时和 M5 评分兼容。

本机产品测试环境缺少 FastAPI、LangChain 等产品依赖，因此未将本地产品测试作为验收证据；远端 `test` job 在干净依赖环境完成并通过。

## 辅助独立复核

独立报告：[`m6-baseline-evidence/independent-review.md`](m6-baseline-evidence/independent-review.md)。复核者先发现五个边界问题，修复后对受影响六组 **102 tests** 和独立探针复验，最终结论为通过。

## 远端 CI

- Run：[`39817946163`](https://github.com/aascc413-coder/sentinelkb-ai-security-agent/actions/runs/39817946163)
- 实际 head SHA：`7cd8887a468cfe581386b0a55db223bed4467516`
- `test`：success
- `investigation-tests`：success
- 结构化记录：[`m6-baseline-evidence/ci-final.json`](m6-baseline-evidence/ci-final.json)

## 限制与结论边界

- 当前 Fixed 选择一个冻结的 `network_events` SIEM 查询，以便在默认六次工具预算内保留最终模型调用并形成 SIEM → TI 链路；它是比较控制，不是生产 playbook。
- 本地隔离环境缺少 setuptools，未单独完成 wheel 构建；远端干净环境已成功执行项目安装和完整 investigation 测试，prompt 资源也由运行测试加载。
- 本里程碑证明工程路径、比较边界和记录口径成立，不证明任何方法优于其他方法。

## 授权与下一步

依据用户对本项目开发提交、推送与 CI 通过后自动推进的持续授权完成。发布、付费模型调用和真实安全处置仍需单独授权。M7 可开始实现 Proposed 的 Hypothesis、Sufficiency、Planner 与主调查循环。
