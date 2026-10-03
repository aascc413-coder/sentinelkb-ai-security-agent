# M1 人工验收说明

版本：**v3（2026-10-04）**。本会话已按用户要求接手主要实现。

状态：**本地自检及辅助 AI 独立复核通过，本地已提交，已获持续开发推送授权，待远端验证。** 所测提交的必需 CI 通过后按实施计划 v6 自动进入 M2。

## 里程碑与用户可见结果

M1 契约分区与公共动作 Schema，父依赖 M0。

这一步建立告警、证据、工具请求与结论的数据规则，拒绝非法字段、时间、引用和数值，为后续数据集及 Agent 运行提供基础。当前交付不包含告警研判策略或对照实验结论。

## 提验版本与文件快照

基础提交为 `2a31d90`；当前 M1 内容尚未提交，不能仅用这个提交号复现 M1。

完整快照见 [snapshot.json](m1-current-evidence/snapshot.json)：采集时间、30 项文件完整 SHA-256、环境、21 项锁定依赖与测试汇总。哈希按文件原始字节计算；本验收说明排除在快照之外，以避免自引用。

提交字节另见 [Git blob 快照](m1-current-evidence/git-index-snapshot.json)：30 项已复核文件与暂存内容一致；其中四项由 Git 将 CRLF 规范化为 LF。该记录同时保留复核工作区哈希与 Git blob 哈希，并仅允许 CRLF→LF 比较，不隐藏业务内容差异。复核原始快照保留，不覆盖历史值。

| 文件 | SHA-256 |
|---|---|
| `docs/evidence-aware-investigation/interface-changelog.md` | `9bee20682d9121c93865b5407e118b2373507cae76eb35ed1093c1727de8a810` |
| `docs/evidence-aware-investigation/parallel-development.md` | `0a71df1f0a168310d5a3eee0c070d0ec20b65f29cef33a5abba70f2ff3f21569` |
| `investigation/conftest.py` | `179296da5c771b0ff9177fffcd3f38a6c5fabe5839d6946ff0ee10adb2620a6d` |
| `investigation/evaluation/__init__.py` | `4ae6472550547e19bffe6fe9e5ec74ae09fdee9890636f317c07f447824fed70` |
| `investigation/evaluation/contracts.py` | `399400d9d9d1cc7906fe889710630ff381627003eeb8935235290635abba0322` |
| `investigation/pyproject.toml` | `ed1c63bf4041dda74ab69e191bcda3429d0a8d32306c561ffde7eedb2ee0a612` |
| `investigation/requirements-lock.txt` | `6163760cfff7ff66d4e663da6281f9a45ec6272b09f1deecefb29563b07ee77c` |
| `investigation/scripts/demo_validate.py` | `8d9a2b07ef2924044028c9b6fc6e5226cfeef6cbab415ef45bfccd84ddc8c6a7` |
| `investigation/src/evidence_investigation/state/__init__.py` | `75b700865e46a88e97f6f1159d9967e92884b903fe47d274ff73471183512b2e` |
| `investigation/src/evidence_investigation/state/adapters.py` | `26cbf931bba2fdb68d2a92cf1cf62e97fd9ff44fd04ac0649b141373ee68cf55` |
| `investigation/src/evidence_investigation/state/codec.py` | `b6f14fdbf42e4068c7a86d0f7de09302c419d5f5b2e19b5b6dc549f124015cb1` |
| `investigation/src/evidence_investigation/state/contracts.py` | `381329f7cbfbd7f4014147299c8037a6b2f4d17424ca7918e8a0d5325c9a7b1f` |
| `investigation/src/evidence_investigation/state/errors.py` | `63bb6fa47932e5dcc9fae6239f86895cda4b3201efb006031397da72ba6fd0bb` |
| `investigation/src/evidence_investigation/state/schema_loader.py` | `297c0aa65d4fc91beb72e61f9dffaa1fb8514a891fface78ae24a02db2833fbc` |
| `investigation/src/evidence_investigation/state/schemas/action.schema.json` | `63f9cf914cee55092ab078bda8b25f87b990d45aafa3ac9aec69ce3d18b1ea0b` |
| `investigation/src/evidence_investigation/state/schemas/common.schema.json` | `c3b04866d4fbea062ab724fa0c62b9212b38d0c13a9b394961a9a3ebe7996d0c` |
| `investigation/src/evidence_investigation/state/schemas/final_assessment.schema.json` | `f85336ea3280cf7899860803867e4716e0ce4bfa216db31de9a8e60090470daf` |
| `investigation/src/evidence_investigation/state/schemas/hypothesis_proposal.schema.json` | `9b5a359ff47e388d381a465b5dab2d0d64a056e4432f725d3ce8976d09ded20b` |
| `investigation/src/evidence_investigation/state/schemas/plan.schema.json` | `9ae141f8514968c6a94804b03a68bcee1ba79f714480cbdc68701248da028b0f` |
| `investigation/src/evidence_investigation/state/schemas/sufficiency_explanation.schema.json` | `208da63ce392105bd5360917fab8217371c890eb483c1410e4e556913d248920` |
| `investigation/src/evidence_investigation/state/validation.py` | `26b6356948f6fea53edf005e029b6b932c07876933c95262a2b0ad8b18da9822` |
| `investigation/src/evidence_investigation/tools/__init__.py` | `3236108a418176bef8631795fe3d1ef33d70d47a41a74dde840a2784232f6d44` |
| `investigation/src/evidence_investigation/tools/contracts.py` | `cb0e6d711f6fd1af01c1ef9ba7d176b895e5c44463ff4569bfcfb15eb11bcf41` |
| `investigation/tests/test_adapters.py` | `97c621a875b71190532e9ccb40301406b51490fb19bb36f8da0fa42143ff0ed1` |
| `investigation/tests/test_codec.py` | `5808bc077e9a53df2c0e5fae29e86ad5b676e6d192dadb0962a7d691fe0c34c8` |
| `investigation/tests/test_import_boundaries.py` | `a34ec489e5d7c5e50c968c23044016b2ee5335f251c4e92892c8e5812fb0c840` |
| `investigation/tests/test_m1_review_regressions.py` | `d5928b67ed0eac3895561fae2dff17789ecd00ddc701f1365bfa4681994895ba` |
| `investigation/tests/test_model_schemas.py` | `e08121cda96e0e354cec6863fd6a203dea95bee72263b4dc8c84d36bdf15fc8b` |
| `investigation/tests/test_package.py` | `cba496095ed990787593233691ece1265f26577480f3d4a742c1283d6751ee17` |
| `investigation/tests/test_validation.py` | `f39524fca781e17afb06f244ab1b92952e0d0cd99ccd961f1509143887428854` |

## 本次完成的能力

1. 三区契约：state 为运行时可见契约；tools/contracts.py 为工具环境契约；包外 evaluation/contracts.py 为 oracle/评测契约。
2. 确定性校验：UTC、时间窗、概率、非负有限成本、引用存在、ID 唯一、来源 call_id、最终证据子集，以及按 Query 类型检查实体、limit、时间窗跨度。
3. 编解码：嵌套 JsonValue、dataclass、联合类型、时间、字典键；float 接受合法整数，bool 不冒充数字，NaN/Infinity 被拒绝。
4. 四方法公共动作与最终结论 Schema，工具名与参数类型关联；Proposed 专有输出独立存放。
5. FinalAssessment 与最终输出 Schema 的统一结构；适配入口复用严格 decode，再强制 confidence_status=uncalibrated。
6. 静态导入守卫覆盖完整模块名、相对导入和 from-import 名称；正式回归覆盖此前漏检写法及合法同区导入。
7. ModelOutputRecord、TokenPlan 和事件类型预留，供 M4 的原始输出留存与 token 对账使用。

## v3 修复与复验范围

| 问题 | 已合入主工作区的修复 |
|---|---|
| M1-A2-R | 导入解析同时检查父模块与导入名称；按文件和类别汇总，避免重复报告 |
| M1-A4-R | 模型适配入口通过 decode 校验 p_attack 等字段，拒绝 NaN |
| 回归 | 新增 test_m1_review_regressions.py，6 项正式测试 |

修复影响导入守卫和最终模型输出入口；已复跑全部正式测试和此前独立用例，而非只测试补丁。

## 人工操作与预期结果

命令使用已安装主工作区包的 investigation/.venv，均可从任意目录执行。

### 1. 正式测试

```powershell
& 'D:/project/Agent/sentinelkb/investigation/.venv/Scripts/python.exe' -m pytest 'D:/project/Agent/sentinelkb/investigation/tests' -q
```

预期 **89 passed**。其中：package 2、validation 30、codec 20、schemas 16、boundaries 10、adapters 5、review_regressions 6。

### 2. 此前独立边界检查

```powershell
$env:M1_AUDIT_ROOT = 'D:/project/Agent/sentinelkb'
$env:PYTHONIOENCODING = 'utf-8'
& 'D:/project/Agent/sentinelkb/investigation/.venv/Scripts/python.exe' -m pytest 'D:/project/Agent/sentinelkb/docs/evidence-aware-investigation/acceptance/m1-audit-evidence/test_m1_independent.py' -q
```

预期 **20 passed**。正式测试与本组用例合计 **109 passed**。

### 3. 非法输入演示

```powershell
& 'D:/project/Agent/sentinelkb/investigation/.venv/Scripts/python.exe' 'D:/project/Agent/sentinelkb/investigation/scripts/demo_validate.py'
```

预期七项全部 REJECTED，显示错误码及中文原因，没有意外 ACCEPTED。

### 4. 布局与边界抽查

查看 state、tools、包外 evaluation 的布局与公共动作 Schema。辅助 AI 可按 [并行开发交接](../parallel-development.md) 在独立副本复现，并给出绑定快照的复核结论。

## 自动验证证据

| 检查 | 实测结果 |
|---|---|
| 主工作区正式测试 + 此前独立检查 | 109 passed in 0.34s |
| 演示 | 七项非法输入全部 REJECTED |
| 依赖版本 | 21 项均与 lock 一致 |
| pip check | No broken requirements found. |
| 产品依赖 | fastapi/langchain/chromadb/neo4j/uvicorn/pydantic 均不存在 |
| 产品代码 | code/python 工作区 diff 为空 |
| 干净环境候选修复 | 相同修复此前在独立 worktree 的新环境中 109 passed；见历史 v2 复验报告 |

本轮主工作区使用已有 Python 3.12.10 虚拟环境，确认 editable 安装指向本仓库；不将其表述为本轮重新创建的环境。

当前证据：

- [文件快照与机器汇总](m1-current-evidence/snapshot.json)
- [测试输出](m1-current-evidence/tests.log)及 [JUnit](m1-current-evidence/tests.xml)
- [演示输出](m1-current-evidence/demo.log)
- [依赖检查](m1-current-evidence/pip-check.log)

历史问题记录：[首次复核](m1-independent-review.md)、[v2 复验与候选补丁验证](m1-independent-retest.md)。旧报告的失败对应当时快照，不能用来判断当前 v3 的状态。

## 已知限制与后续承接

- 采用逻辑隔离与常规静态导入检查；没有实现进程 / 文件系统隔离或动态导入沙箱。
- FixtureRule.status 暂为 str，M3 收窄并与 ToolResult.status 对齐。
- 实体属于 alert / 已获记录、预算执行、Trace 和模型请求留存由 M4 承接；当前预留类型不代表这些功能已实现。
- M2 数据集、充分性判定表、M5 指标实现和真实 Agent 实验尚未交付。
- 辅助 AI 已在独立副本和干净环境复核通过，见 [辅助复核报告](m1-helper-review.md)；远端 CI 尚未运行。
- `codec.decode(ToolCall, ...)` 的工具名与参数类型关联由 M4 Dispatcher 承接（H1）；最终 evidence_id 列表的重复处理应单独验证，不把 fact_key 去重等同于列表 ID 唯一（H3）。

## 验收记录

| 字段 | 当前记录 |
|---|---|
| 里程碑 | M1 契约分区与公共动作 Schema |
| 提验版本 | v3；本说明及 snapshot.json 完整文件快照 |
| 实现负责人 | 本会话 Codex（主实现） |
| 技术自检 | 通过，109 项测试与七项演示均符合预期 |
| 辅助独立复核 | 通过；m1-helper-review.md，干净环境 89 + 20 项通过，补充探针 58/59，唯一未过项为 M4 承接项 |
| 用户人工结论 | 用户于 2026-10-04 指示“另外一个AI已经完成工作，你根据结果继续推进”；本次依据通过的辅助复核执行本地提交，未声明用户亲自执行测试 |
| 通过后 commit | `d95592608f1131d693ece1007c211662862ba037`（M1 实现与复核证据） |
| 远端 CI | 待推送验证，核对 test 与 investigation-tests 的实际 head SHA |
| 当前授权 | 2026-10-04：技术验收由主实现与辅助 AI 完成，CI 通过后自动推进，授权本项目开发提交与推送；发布、付费资源、真实安全处置另行征求同意 |
| 阶段状态 | 待远端验证；本地验收依据和复核证据已齐备 |
| 实验结论 | 不适用，本阶段不评估研判策略 |

验收通过后的提交及推送仍按既有计划执行。原有未跟踪的 evals/reports/ 不属于 M1 交付。
