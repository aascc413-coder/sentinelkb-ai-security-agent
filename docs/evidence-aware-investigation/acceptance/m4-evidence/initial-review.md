# M4 独立审查报告

审查日期：2026-10-21。结论：**暂不通过验收，需要修复后复验**。

审查对象为 `codex/m4-runtime-layer` 的 `126f0be19b8208cd6e423e7910a9fdf6a720a162`；恢复审查时该分支仍为此提交，工作区干净。未修改实现分支或主分支。所有探针、快照和测试结果均在本审查目录。

## 证据与环境

- 从 Git archive 导出提交快照，导入路径明确指向 `source/investigation/src`。
- 原分支全套测试：**311 passed**，见 `source-tests.xml`。本次 Python 为 3.12.14，使用已有辅助复核环境中的依赖，通过 PYTHONPATH 指定；不是新建干净依赖环境。历史 3.12.10 复现记录不作为本次环境声明。
- 集成副本：以 main `579c09d5e3495c6b83dd52e1d3a11ea853b09c7b` 为底，将 M4 提交相对其父提交的 11 个变更文件覆盖至独立副本。**484 passed**，见 `integration-tests-retest.xml`。这是文件级集成验证，未执行正式合并或远端 CI。
- 第一次集成测试出现 42 个临时目录权限错误、442 passed。改用审查目录下的 pytest basetemp 后全部通过；保留 `integration-tests.xml`，这些环境错误不计作实现缺陷。
- 原分支复测有一条 pytest cache 写权限警告，不影响 311 项断言。
- 9 个定向探针的观察结果见 `probe-results.json`，脚本为 `probe_review.py`。这些是故障复现观察，不应宣称为“新增测试全部通过”。
- 修正过探针自身的预算用量：原来 12000 tokens 不足以阻止修复调用，改为 13000 后实际触发 token_budget；报告仅使用修正后的结果。
- 所有模型调用使用 FakeScriptedModel 或 httpx.MockTransport，没有真实模型调用。

## 必须修复的问题

### R1 / P1：不同时间窗的空查询被合并成同一条否定证据

位置：`runtime/registry.py:234–246`。

操作事实 key 只使用 `coverage.scope`，还主动排除了 window；真正的 `coverage.window`、覆盖完整性等也未参与去重。相同主机与视图在两天分别查询，第二次返回的 operational ID 指向第一次的时间窗。探针 `absence_window_collision` 已复现，两次均返回 ev-0002，但第二次证据仍记录第一天的范围。

影响：Agent 无法可靠区分“这个时间段没查到”与“另一个时间段没查到”。这会污染项目最重要的证据充分性判断。先 partial 后 complete 等覆盖状态变化也必须纳入回归验证。

修复要求：操作事实身份包含完整查询范围、时间窗、快照及影响可证明性的覆盖属性；只有真正等价的查询结果才能合并，并保留各次来源。

### R2 / P1：模型修复调用失败后，预算一直处于 pending

位置：`runtime/model.py:201–212`；非法 Schema 入口另见 `:182`。

首次调用有 ModelError 对账处理，但第二次修复调用没有。探针 `repair_service_error`：非法输出触发修复，修复服务报错，之后正常 reserve_model 报 `another operation is pending`，该 run 无法继续工具或模型操作。非法 Schema 同样泄漏 pending，与辅助报告 H1 一致。

修复要求：Schema 在预留前校验；每个已预留调用的成功、服务失败、解析失败等路径都恰好对账一次，费用未知时保守记录，不能留下 pending。增加“修复失败后账本可以继续使用”的测试。

### R3 / P2：失败路径没有保存原始模型输出，无法核查模型错误

位置：`runtime/model.py:200–212, 240–258`。

`model_output_recorded` 仅在修复已返回并校验后才落盘。探针 `repair_budget_exhausted` 确认：第一次模型输出非法，实际用量 13000，下一次修复因预算拒绝，Trace 只有 budget_checked，没有原始输出、校验失败原因或首次对账事件。修复服务报错也一样。

修复要求：拿到原始输出即保存；校验错误和每次对账及时追加；修复未开始、失败和成功均有明确记录。不能为了保留四态而等整个修复过程完成后一次性写入。

### R4 / P2：非 JSON 模型输出丢失原文和已知 usage

位置：`runtime/model.py:137`。

适配器先解析 content，再读取 usage。服务返回非 JSON 内容时，解析抛 ModelError，已返回的原文与 usage 均丢失，也不会进入一次格式修复。探针 `nonjson` 返回明确的 12 输入 + 34 输出 tokens，结果被登记为 usage 未知、保守计费 900，Trace 没有模型原文。

修复要求：保留原始响应与可解析的 usage，再处理格式校验。区分服务失败与模型输出格式失败，后者按预算控制的修复策略处理。

### R5 / P2：工具重试漏记第一次返回

位置：`runtime/dispatcher.py:109–123`。

首次 tool_timeout 会登记操作事实，但进入重试分支后只发出第二次 tool_returned。探针 `retry_trace`：两次 tool_requested、两次费用，但只有一次 tool_returned。第一次错误 envelope 无完整返回事件供重放。

修复要求：每个已开始的 call_id 恰好有一个结果或明确异常事件，再决定是否重试；避免现有 ProtocolViolation 分支内外重复 emit。测试应按 call_id 校验完整生命周期，不能只检查重试次数及费用。

### R6 / P2：已登记证据可被外部修改，哈希与事实脱节

位置：`runtime/registry.py:207–215`，以及 get/facts 查询接口。

Evidence.value 直接引用 ToolRecord.payload；冻结 dataclass 不会冻结其内部 dict。探针 `mutable_evidence`：登记后修改原记录 remote_ip，Registry 中的事实跟着变化，RawReference 哈希却不变，实体台账也仍是旧值。

修复要求：登记时做隔离副本，读取时返回不可变视图或副本，验证原始哈希。回归测试应同时覆盖修改输入记录和修改查询结果。

### R7 / P2：模型超时结果仍被标成 accepted

位置：`runtime/model.py:183, 228–230`。

模型请求超时至少设为 1 秒，即使调查只剩不到 1 秒；对账发现 deadline 后仍返回 ModelCallResult 并填写 accepted_output。探针 `late_model` 中调查期限 0.5 秒，响应在逻辑时钟 2 秒到达，预算已 deadline，输出仍被接受。

修复要求：使用真实剩余时间上限；迟到输出可留存和计费，但不能标作可消费的有效决策，应明确返回超时状态。探针使用 Abstain 输出，验证的是错误接受边界，尚未证明下游已经发生误关闭。

### R8 / P2：重复 run_id 混合两次 Trace

位置：`runtime/trace.py:55–62`。

构造器允许已有目录，覆盖 manifest、保留旧 events 和 final，同时从 sequence=1 重新计数。探针 `duplicate_trace_run`：两次 recorder 使用同一 run_id 后，序列为 [1,1]，新 run 尚未 finalize 就读到了旧 final。

修复要求：新 run 拒绝已存在的运行目录，或实现显式、校验完整的恢复流程。增加重复 run_id 测试。该问题不依赖并发或断电场景。

## 对原测试和辅助报告的评价

36 项 M4 新增测试覆盖了基础成功路径、部分协议错误、正常重试、工具迟到和正常修复，是有效起点；311 passed 本身可复现。

但以下验收声明超出了测试实际证明范围：

1. `test_runtime_integration.py:95` 的 A4 正控把普通 PowerShell 告警称为“初始证据充分”，直接让 Fake 输出 TP，claims 和 final_evidence_ids 均为空。它证明零工具预算不阻止模型调用，没有证明无工具结论有充分证据。应增加真实充分初始证据及对应引用，并配对不足证据的负控。
2. `test_full_chain_dispatch_trace_model` 没有实际调用模型，final 是手工构造的。不能据此声称 Registry、Dispatcher、Model、Trace 全链路已验证。
3. 四态测试使用非法枚举等 Schema 错误，没有展示“Schema 合法但引用虚构 evidence_id”的原始错误、拦截原因和最终接受结果。Grounding 负控仍需补齐；不要求格式适配器独自完成语义充分性判断。
4. Trace 测试主要验证读写往返和事件类型存在，没有核对每次调用都有结果、每个证据可重建、原始告警完整、版本前后衔接。不能等同于完整离线重放验收。
5. 缺少修复服务失败、修复预算拒绝、空查询跨时间窗、输入可变性和重复 run_id 等边界测试，导致上述问题在全部测试通过时仍存在。

辅助报告关于 H1 的发现成立；H2 的换行哈希口径问题应按 Git blob 哈希修订。其“其余全部通过”和“仅复验 H1/H2 即可关闭”的范围过宽，不能据此关闭 M4。

## 集成与验收安排

M4 的父提交是较早的 72e808f，尚未包含已验收 M2/M3。分支差异中的 M2/M3 缺失是基线落后，不应描述成作者删除了这些功能。独立组合副本 484 项测试通过，说明现有测试层面兼容；仍须在修复分支正式整合当前 main 后复验。

建议依赖顺序：

1. 修复 R1、R6 的证据身份和不可变性。
2. 修复 R2、R3、R4、R7 的模型生命周期与预算/日志。
3. 修复 R5、R8 的 Trace 完整性。
4. 补齐上述故障回归，以及 A4、虚构引用、完整链路验收测试。
5. 整合当前 main，运行完整测试和可重放演示，更新验收证据。
6. 对正式提交运行远端 test + investigation-tests，核对实际提交后关闭 M4。

本次审查未推送、未运行远端 CI，也没有替实现者修改生产代码。后续评测设计与独立数据标注可以继续；依赖该 runtime 正确性的阶段不能以 M4 已验收为前提。
