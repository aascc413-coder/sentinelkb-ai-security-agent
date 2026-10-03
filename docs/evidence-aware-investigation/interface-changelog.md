# 公共接口变更记录（并行开发协调）

用途：两个 AI 并行开发期间，**公共接口的任何新增或变更在此登记**，供对方集成。
当前分工（2026-10-04 按用户要求变更）：**本会话 Codex 负责主要实现、集成和阶段交付；另一 AI 负责独立复核与辅助验证**。主实现文件由本会话维护；辅助 AI 在独立 worktree 中复核，修复建议或测试通过补丁交接。具体任务见 [并行开发交接](parallel-development.md)。下方“契约 AI / 指标 AI”是变更前的历史角色，不代表当前文件所有权。

## 2026-10-04 · 验收流程调整（v6）

- 技术验收由主实现与辅助 AI 完成，所测提交的两个 CI job 通过后自动推进；用户已授权本项目开发提交与推送。发布、付费资源、真实安全处置仍单独征求同意。
- M1 实现 `d955926` 已包含在 CI head `880b837` 中；`test` 与 `investigation-tests` 同时成功，M1 已完成。
- M2 已启动只读预审；数据、加载器与判定表尚未实现。M1 接手时的状态及冻结快照保留为历史。
- 此次只改计划、交接及验收记录，公共接口不变。

## 2026-10-04 · 主实现接手（M1 v3，历史记录）

- 已将 M1 v2 独立复验补丁合入主工作区：from-import 同时解析父模块和导入名称，模型适配入口复用 `decode(FinalAssessment, payload)`，再强制 confidence_status。
- 新增 `tests/test_m1_review_regressions.py` 六项正式回归。主工作区正式测试 89 项、此前独立检查 20 项，合计 109 passed；七项演示均 REJECTED。
- 公共类型和函数签名不变；`codec_claim` 保留。NaN 在规定适配入口被拒绝。
- 接手当时 M1 为本地自检通过、待辅助复核及人工验收；未提交、未推送、未进行 M1 远端验证。后续完成状态见上方 v6 记录。
- 旧的指标模块并行实现安排已被当前角色分工替代。M2 主实现由本会话负责，辅助 AI 负责数据边界和充分性标注的独立复核。

## 2026-10-04 · 契约 AI（M1 交付）

### 面向指标 AI 的接口（evaluation 区）

- **`evaluation/contracts.py`**（新建，M1）：请 `from evaluation.contracts import MetricCount, CaseScore, AggregateMetrics, OracleCase, ActionExpectation`，**不要重复定义**这些类型。
  - `MetricCount(numerator: float, denominator: float, value: float | None)` —— 分母为 0 时 `value=None`（NA），不是 0。
  - `CaseScore.metrics: dict[str, MetricCount]`；`AggregateMetrics.metrics: dict[str, MetricCount]`。
- **导入方向约束（AST 守卫 `tests/test_import_boundaries.py` 强制，v2 规则）**：`evaluation/` 下任何文件只能导入**标准库**、`evidence_investigation`（state/包根）与 `evaluation` 自身；**任何人**（evaluation 含 metrics.py 在内）不得导入 `evidence_investigation.tools` 包根或 `evidence_investigation.tools.contracts`（环境侧契约）；src 下不得导入 `evaluation.*`。守卫用完整模块名解析（含相对导入），违规会被 pytest 判失败——`metrics.py` 请遵守。
- **conftest**：`investigation/conftest.py` 已把 `investigation/` 加入 `sys.path`，测试中 `import evaluation` / `import evidence_investigation` 均可直接用。
- **测试文件命名**：指标模块的测试请放在 `investigation/tests/`，建议命名 `test_metrics*.py`；我方已占用 `test_package / test_validation / test_codec / test_model_schemas / test_import_boundaries`。

### 运行时侧公共接口（state 区，供参考）

- `evidence_investigation.state.contracts`：运行时全部 dataclass/Protocol（Alert、Evidence、ToolCall/ToolResult、Budget、Usage、FinalAssessment、TraceEvent、RunManifest、EventType…）+ **V4-3 预留**：`ModelOutputRecord`（原始/校验错误/修复/接受四态）、`TokenPlan`（预估-对账）。
- **`state/adapters.py`（v2 新增）**：`final_assessment_from_output(payload)` 是模型输出进入运行时的规定入口，强制 `confidence_status="uncalibrated"`。**统一结构决定（复核 A7）**：FinalAssessment dataclass 与 final_assessment.schema.json 字段一一对应、可选字段带缺省——最小模型输出可直接 `codec.decode`，完整对象 `encode` 后过 Schema。
- `evidence_investigation.state.errors.ProtocolViolation(code, message)`。
- `evidence_investigation.state.validation`：require_utc / require_time_window / require_probability（NaN 拒绝）/ require_non_negative（NaN/Infinity 拒绝）/ require_known_references / require_final_evidence_subset / validate_evidence / validate_final_assessment / validate_query / validate_alert。**v2**：validate_query 按具体类型分派——limit 整数 1–50、SIEM 窗≤24h、history≤30d、view 对应实体必备；错误码含 missing_entity / window_too_wide / invalid_limit。
- `evidence_investigation.state.codec`：`encode(obj)` / `decode(tp, data)`。**v2**：递归 JsonValue 任意深度；float 接受整数字面量；dict 键按声明类型校验；非有限数值双向拒绝。
- `evidence_investigation.state.schema_loader`：`validate_model_output(instance, name)`、`schema_contents(name)`。**v2**：tool_call 与 action 的工具名-参数在 Schema 层 oneOf 关联（错配即拒）。Schema 名：hypothesis_proposal / plan / sufficiency_explanation / final_assessment / action（common 为共享 $defs 载体）。
- `evidence_investigation.tools.contracts`：`EnvironmentFixture` / `FixtureRule`（环境侧，M3 使用；evaluation 不得导入）。

### 依赖变更

- `pyproject.toml` 新增运行依赖 `rfc3339-validator>=0.1.4`（jsonschema 的 date-time 格式检查需要）；`requirements-lock.txt` 已重新生成，**共 21 项锁定依赖**（含 rfc3339-validator 传递依赖 six）。

### 请求

- （暂无）指标模块如需 state 侧新增字段或类型，请在此小节登记需求，由契约 AI 统一修改，避免冲突。
