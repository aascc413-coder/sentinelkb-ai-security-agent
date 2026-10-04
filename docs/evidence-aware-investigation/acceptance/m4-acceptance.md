# M4 提验说明：运行时层与公共 Evidence Registry

日期：2026-10-04。实现分支：`codex/m4-runtime-layer`（基于 `72e808fefb1ef29726991a9d8d4199e31ee8a9a8`）。
状态：**主实现自检通过，待辅助独立复核；未提交推送，远端 CI 未运行。** 本文件按计划 v6 §7.2 记录。

## 交付范围（计划 M4 [P2.3 + R2]）

| 模块 | 职责 |
|---|---|
| `runtime/registry.py` | 公共 Evidence Registry：来源登记、确定性字段提取、ID 分配、fact_key 去重（镜像日志合并佐证不虚增独立性）、RawReference+原文哈希、call_id 关联、coverage/error envelope 保存为操作事实（unavailable/timeout/error、partial 覆盖上限、complete-empty 的限定否定 absence）、实体台账（host/user/process/command/indicator，IOC 形态与 signatures 规范化一致）。无自由文本登记入口；不访问 oracle；迟到响应按 call_id 防重复登记。 |
| `runtime/dispatcher.py` | 唯一合法工具调用通道：预算准入先行（非法/缓存/重试全计费）、tool/参数关联校验与 M1 参数校验、ToolContext 注入（run_id/call_id/as_of=告警冻结 as_of/剩余超时）、实体授权（调用实体必须来自 alert 或 Registry 台账）、瞬态超时重试一次（计费）、永久不可用不再查询（短路返回缓存语义结果）、迟到响应照记费用但不登记 Evidence、冗余签名台账。自动经公共 Registry 登记，保证四方法等价引用能力（R2）。 |
| `runtime/trace.py` | 三件套 `runs/<run_id>/manifest.json + events.jsonl + final.json`；事件含 sequence/UTC 时间/elapsed/step/state_version 前后/payload/usage 快照；事件类型校验（EventType.ALL）；`read_trace` 离线重放入口。 |
| `runtime/model.py` | `FakeScriptedModel`（脚本化、usage 可覆盖、耗尽抛错）；`OpenAICompatAdapter`（httpx + 注入 transport，JSON 解析、usage 映射、缺失 → None）；`run_model_call` 规定入口：预算预留 → 调用 → Schema 校验 → 非法输出修复一次（计费，顺序预算先对账再预留）→ `ModelOutputRecord` 四态留存（V4-3A）→ `budget_reconciled` 事件（V4-3B 预估/实测/未知三态）。ModelError 时对账为 usage=None（保守预留保留，不填零）。 |
| `runtime/budget.py` | M3 已交付组件（经独立复核），本轮仅消费：`begin_tool_attempt/record_tool_result/reserve_model/reconcile_model`。 |

依赖方向：runtime → state（+ `tools.signatures` 查询规范化）；不导入 tools 包根/环境契约与 evaluation（M1 守卫 10/10 通过）。

## 文件快照（工作区字节 SHA-256，前 12 位）

| 文件 | 哈希 |
|---|---|
| `runtime/__init__.py` | `2ecbcc16fdf1` |
| `runtime/registry.py` | `03372644f7ab` |
| `runtime/dispatcher.py` | `5a773e9adacd` |
| `runtime/trace.py` | `e94ff3d91a2d` |
| `runtime/model.py` | `e57430cdbcf1` |
| `tests/test_registry.py` | `258435f4f1c8` |
| `tests/test_dispatcher.py` | `d16693b656ae` |
| `tests/test_trace.py` | `c7a342b6293b` |
| `tests/test_model_adapter.py` | `16899ca5cd4c` |
| `tests/test_runtime_integration.py` | `c5a4e6ae909d` |

## 主实现自检结果

| 检查 | 结果 |
|---|---|
| 全量测试（基线 275 + M4 新增 36） | ✅ **311 passed**（0.89s） |
| 干净环境（lock + --no-deps 安装）全量测试 | ✅ 311 passed |
| 产品依赖存在性（fastapi/langchain/chromadb/neo4j） | ✅ 均不存在 |
| 导入边界守卫（含 runtime 新模块） | ✅ 10 passed |
| P2.3 验收：相同响应经 Registry 等价事实与引用 | ✅ test_registry::test_equivalent_responses_yield_equivalent_references |
| P2.3 验收：全部调用计费（含非法/缓存/重试/迟到） | ✅ dispatcher 六项计费断言 |
| P2.3 验收：超时/重复/迟到结果正确处理 | ✅ retry/short-circuit/late 三项 |
| P2.3 验收：trace 足以离线重放 | ✅ test_trace + 集成测试 read_trace 往返 |
| A4 正控：max_tool_calls=0 不禁止无工具结论 | ✅ test_runtime_integration（模型调用成功；工具被拒后按 M3 语义锁存，最终输出确定性构造） |
| V4-3A：原始输出/校验错误/修复/接受四态留存 | ✅ 修复路径与双失败路径测试 |
| V4-3B：预估/实测/未知三态对账 | ✅ reconcile 事件与 usage_complete 语义测试 |

## 自检中发现并已修复的问题

| 问题 | 修复 |
|---|---|
| registry 操作事实以 fact_key 为键，`get`/`require_known` 误用 evidence_id 查找 | 查找改为遍历 evidence_id（测试暴露） |
| 修复调用预留与顺序预算冲突（一次仅允许一个待定模型操作） | 先对账第一次调用，再预留修复（设计稿 §8 顺序语义） |
| ModelError 路径未对账，usage 未知丢失 | except ModelError → reconcile(plan, None) → 上抛 |
| 永久不可用短路返回旧 call_id 结果 | `replace(result, call_id=新 call_id)` 保持一致 |

## 已知限制与后续承接

1. fact_key 采用"工具+payload 精确哈希"合并：镜像日志同负载合并生效；措辞不同的语义级合并延后至 M2 fixture 适配评估（已在模块 docstring 声明）。
2. Registry 未实现 EvidenceState/假设关联（M7 Proposed 专有）；实体授权的 TI 指标采集为确定性形态识别（IP/域/摘要），不做语义抽取。
3. Dispatcher 的冗余台账与 server 缓存对齐依赖"同 run 单 server"假设（组合根保证）。
4. `run_model_call` 的修复提示为中文固定文案，进入 prompts/ 版本化管理属 M6/M7 范畴。
5. M5 泄漏检查、M7 充分性与调查循环、M8a/M8b 报告未实现。

## 验收记录（计划 §7.2）

| 字段 | 记录 |
|---|---|
| 提验版本 | 本文件快照表（工作区字节）；分支 `codex/m4-runtime-layer` |
| 主实现自检 | 通过（上表） |
| 辅助独立复核 | **待进行**（建议复核点：Registry 去重/操作事实语义、dispatcher 计费与迟到防护、顺序预算下的修复计费、A4 语义） |
| 提交 | 本分支本地 commit（见 git log）；推送待复核通过后按 CI 门禁流程 |
| 远端 CI | 未运行 |
| 阶段状态 | 待复验 |
