# M1 v3 辅助独立复核报告

日期：2026-10-04。复核人：辅助 AI（依据 [并行开发交接](../parallel-development.md)）。
被复核对象：[M1 验收说明 v3](m1-acceptance.md) 及其 [文件快照](m1-current-evidence/snapshot.json)（30 项文件，完整 SHA-256）。

## 一、结论

**M1 v3 技术复核通过。**

- 干净 Python 3.12.10 环境、独立副本中：正式测试 **89 passed**、既有独立检查 **20 passed**、演示 **7 项全部 REJECTED**，与验收说明预期完全一致。
- 两项历史遗留修复（M1-A2-R 守卫解析 from-import 名称、M1-A4-R 适配入口经 decode 拒绝 NaN）实现方式与复核建议一致，且被 89 项正式测试（含 6 项新回归）与 20 项独立用例覆盖。
- 59 项补充探针 **58 项通过**；唯一未通过项（ToolCall 解码不关联工具名与参数）属复核报告 M1-A8 **已明确由 M4 承接**的范围，Schema 层关联已生效（20/20 错配组合全部拒绝），不构成 M1 缺陷。
- 未发现 oracle 数据泄漏、守卫误报合法同区导入或 NaN 进入规定入口的缺陷。

本结论仅为技术复核。**用户人工验收与远端 CI 状态分别独立**：截至本报告，用户尚未作出 M1 人工结论，远端 CI 尚未运行（M1 未提交、未推送）。本地与副本的通过结果不等于远端 CI 已通过。

## 二、被复核版本与环境

| 项 | 记录 |
|---|---|
| 基础提交 | `2a31d90bbe1d1ec4754bbf7d115d474c04557630`（git worktree detached HEAD） |
| M1 内容 | 未提交文件，按 snapshot.json **30 项逐文件复制**至独立副本 |
| 哈希核对 | **30/30 与 snapshot.json 完整 SHA-256 一致**（`m1-helper-evidence/snapshot-verification.json`） |
| 独立副本 | `D:/project/Agent/m1-helper-review`（worktree + 覆盖复制，未改动主工作区实现） |
| 复核环境 | 新建 `.helper-venv`，Python 3.12.10（tags/v3.12.10:0cc8128） |
| 安装方式 | `pip install -r investigation/requirements-lock.txt`（21 项，版本与快照记录逐一一致）+ `pip install --no-deps -e investigation` |
| 导入路径确认 | `evidence_investigation.__file__` 指向 `D:\project\Agent\m1-helper-review\investigation\src\...`（非主工作区） |
| pip check | No broken requirements found. |
| 产品依赖 | fastapi/langchain/chromadb/neo4j/uvicorn/pydantic 均不存在（pip freeze 见证据目录） |

快照完整性交叉核对：主工作区未提交的 investigation 文件与快照 30 项**一一对应，无遗漏**；`docs/evidence-aware-investigation/phase-2-implementation-plan.md` 有未提交修改但不在快照内（属计划文档，非代码，提验时建议纳入版本管理即可）。复核结束后主工作区 30 项文件**零漂移**（`snapshot-verification.json`）。

## 三、实际命令与结果

均在独立副本目录、使用副本虚拟环境执行（输出存于 `m1-helper-evidence/`）：

| 检查 | 命令要点 | 实测 | 预期 |
|---|---|---|---|
| 正式测试 | `python -m pytest investigation/tests -q` | **89 passed**（tests-official.log） | 89 |
| 既有独立检查 | `M1_AUDIT_ROOT=D:/project/Agent/m1-helper-review python -m pytest <m1-audit-evidence>/test_m1_independent.py -q` | **20 passed**（tests-independent.log） | 20 |
| 非法输入演示 | `python investigation/scripts/demo_validate.py` | **7 项全部 REJECTED**，无意外 ACCEPTED（demo.log） | 7 项拒绝 |
| 补充探针 | `python probe_m1.py` | **58/59 通过**，1 项属 M4 承接（probe-results.json） | — |

## 四、重点核查结果

### 1. 嵌套 JSON 编解码
既有测试覆盖三种形态 + Alert 深层 raw；补充探针新增六层嵌套、Unicode 键、空容器、顶层列表、Alert 中文深层 raw 往返，全部一致（P5.1–P5.5）。`bool/int/float/null` 区别保持，`decode(float, 1)` 接受整数字面量。

### 2. 导入边界守卫（完整模块名、相对导入、from-import 名称）
对 v3 守卫注入 11 种旁路变体（P1.1–P1.11）：普通 `import` 形式、`from evidence_investigation import tools`、`from .. import tools`、`from tools import contracts as c`、括号多名导入、as 别名、evaluation 导入环境契约——**全部被发现**；合法同区相对导入（`from .contracts import`、`from . import tools as state_tools`）、evaluation→state、state→第三方库**均不误报**。单一违规无重复报告（P1.12）。语义确认：`from . import tools` 在 state 内解析为 `evidence_investigation.state.tools`（state 子模块），守卫不拦截是**正确**行为。

### 3. NaN / Infinity 在规定入口
`adapters.final_assessment_from_output`（p_attack=nan/inf、claims 内 NaN）与 `validation.validate_final_assessment`（p_attack=nan）全部拒绝（P2.1–P2.3、P2.6）；正控 `p_attack=1` 整数被接受并归一为 1.0（P2.4）；模型声明的 `confidence_status="dev_calibrated"` 被强制覆写为 `uncalibrated`（P2.5）。codec encode/decode 双向亦拒绝非有限数值（既有测试）。

### 4. 工具名与参数类型匹配
公共动作 Schema：5 种工具**全部正确组合接受**、**20 种错配组合全部拒绝**（P3）；`common.tool_call`（plan 路径）同样生效。`codec.decode(ToolCall, …)` 解码层不做关联——属 [首次复核 M1-A8](m1-independent-review.md) **已约定 M4 承接**项（Dispatcher 用完整映射表校验并覆盖 candidate.call），非 M1 缺陷。

### 5. 最终证据引用与字段约束
悬空 `final_evidence_ids`、悬空/空串 claim 引用、protocol_error+TP 组合、p_attack=-0.1/1.01 全部拒绝；`p_attack=None` 与确定性结论并存被正确允许（P4.1–P4.7）。最终证据重复 ID 未做去重约束——设计上由 M4 Registry 去重（fact_key），记录为观察项，非缺陷。

### 6. 布局与转换约定
三区布局（state / tools.contracts / 包外 evaluation）关键文件齐备；公共动作 Schema 不含 hypothesis、target_gap_ids 等 Proposed 专有定义（P6.2、P6.3）；`FinalAssessment` 与 Schema 统一结构成立：最小输出可直接 decode、完整对象 encode 后过 Schema（既有测试 + 适配器入口强制 confidence_status）。包根不预载 tools 属性（P6.1）。

### 7. 历史报告标注
[首次复核](m1-independent-review.md)与 [v2 复验](m1-independent-retest.md)均已标注"历史记录，对应当时快照，不代表 v3 状态"。

## 五、问题清单

| 编号 | 严重程度 | 描述 | 处理 |
|---|---|---|---|
| H1 | 信息（非 M1 缺陷） | `codec.decode(ToolCall, …)` 不关联工具名与参数联合分支（探针 P3 唯一未过项）；最小复现：`codec.decode(ToolCall, {"tool":"siem","arguments":{"host":"h","as_of":"2026-09-01T02:14:00Z"}})` 成功 | 首次复核 A8 已约定 M4 Dispatcher 承接；建议 M4 用完整 tool→参数类型映射表实现，并覆盖 Proposed 的 candidate.call。无需 M1 修改 |
| H2 | 信息（文档） | `phase-2-implementation-plan.md` 有未提交修改但不在 v3 快照内 | 建议主实现提交时一并纳入版本管理 |
| H3 | 信息（观察） | 最终证据允许重复 evidence_id | 由 M4 Registry 的 fact_key 去重承接，与设计一致 |

## 六、检查范围与未覆盖项

**已覆盖**：30 项快照哈希一致性；干净环境安装与导入路径；89+20 项测试与演示复现；守卫 11 种旁路/4 种合法变体；NaN 全规定入口；工具名-参数 25 种组合；最终证据引用与字段约束 7 项；嵌套 JSON 5 种额外形态；三区布局与统一结构约定；历史报告标注。

**未覆盖 / 有限性声明**：
- 静态守卫不覆盖动态导入（importlib、`sys.path` 注入、字符串拼接模块名）——验收说明已声明为逻辑隔离边界，进程/文件系统隔离本就不在 M1。
- 预算控制、实体归属（alert/已获记录）、Trace、模型请求留存属 M4；FixtureRule.status 收窄属 M3；数据集与判定表属 M2；指标实现属 M5——均未复核实现（尚未存在）。
- 全部用例（89+20+59）为有限样本，不构成对所有可能输入的穷尽证明；本报告不宣称产品准确率。
- 未验证远端 CI（未运行）；未替代用户人工验收。

## 七、结论状态分立记录

| 维度 | 状态 |
|---|---|
| 辅助 AI 技术复核（本报告） | **通过** |
| 用户人工验收 | 待用户决定 |
| 远端 CI | 未运行（M1 未提交未推送；提交推送由主实现按计划第 7.1 节流程处理） |
