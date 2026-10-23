# M10a 独立技术复核（未提交工作区变更）

日期：2026-10-24。复核对象：main @ `239584f` 之上的 **M10a 未提交工作区变更**及 [m10a-dataset-protocol-acceptance.md](m10a-dataset-protocol-acceptance.md)。
性质：协议与审计工具的静态审查 + 命令复现 + 独立负向探针；**不是 M10b 案例扩写的验收，也不代表盲测数据已存在。**

## 一、结论

**建议通过（进入提交/CI 门槛）。** 七项重点检查全部通过；审计工具正确复用 M2 冻结的 `visible-metadata-v1` 规范化机制，family 单 split 强制与静态等价跨组拒绝均有实现与测试双重保证；独立哈希篡改探针被正确拒绝；审计代码严格位于作者/评测侧；文档对"无法自动识别语义改写"的局限表述诚实。两项观察（O1/O2）与一项补充建议（R1）不阻断。

## 二、被审版本与文件哈希

基线 main `239584f`；被审变更未提交。实测 Git blob 哈希（`git hash-object`）与验收说明对照表**逐一匹配**：

| 文件 | blob（前 12 位） | 状态 |
|---|---|---|
| `investigation/scripts/dataset_split_audit.py` | `c1df4c8b403a` | 新增 |
| `investigation/tests/test_dataset_split_audit.py` | `e2174875dc53` | 新增 |
| `investigation/datasets/README.md` | `72cdec4d14fa` | 修改（+6：审计命令说明） |
| `docs/.../m10-dataset-expansion-contract.md` | `842bd5bb5247` | 新增 |
| `docs/.../m9-efficiency-contract.md` | `ea5d620dbe5f` | 修改（1 行口径澄清） |
| `docs/.../phase-2-implementation-plan.md` | `1c267422f2c3` | 修改（v7→v8，M10a 范围） |

验收说明中"验收记录本身不纳入快照"的自排除口径已注明。变更范围核对：`investigation/src/`、`investigation/rubrics/`、`investigation/prompts/`、五个种子数据 JSON **零改动**（git status 仅上述文件）；`evals/reports/` 下 M8/M9 归档为未跟踪目录，本会话早前已在其存在状态下通过 751+131 文件 checksum 重放，未受影响。

## 三、逐项检查结果

### 1. family_id 强制单一 dev/test split ✅
`audit_dataset` 按 `oracle.family_id → {splits}` 聚合，任一 family 出现多个 split 即抛 `family_split_leakage` 并列出泄漏明细。测试 `test_family_cannot_cross_dev_and_test` 锁定。

### 2. compare_static 复用冻结规范化 ✅
审计脚本从 `evidence_investigation.state.normalization` 导入 `compare_static` 与 `NORMALIZATION_VERSION/NORMALIZATION_SHA256`——该模块系 M2 种子数据集交付（`751c77d`）的冻结实现，本变更**未重新定义规则**。审计输出绑定 `visible-metadata-v1` 与 SHA256 `94be1577…`，与模块常量逐字节一致（独立核对）。C4/C5 是当前数据集唯一等价可见组，报告如实输出。

### 3. 静态等价跨 family/split 拒绝 ✅
对全部案例两两做 `compare_static`，等价者并查集合并；多成员组必须单 family 单 split，否则 `visible_input_split_leakage`。单测覆盖跨 family、同时跨 family+split 两个方向；正控 `test_envelope_identity_difference_still_forms_one_visible_group` 证明 envelope ID 差异被规范化吸收而不误报。

### 4. 孤儿/路径分区/非字符串/哈希异常拒绝 ✅
- **孤儿**：manifest `file_sha256` 必须与 public/environment/oracle 下全部 JSON **恰好相等**（all and only）；映射后 `unused_paths` 非空 → `orphaned_dataset_file`。
- **路径分区**：`checked_file` 要求路径以 `public/`、`environment/`、`oracle/` 各自前缀开始，反斜杠写法拒绝；`resolve()` 后必须仍在 root 内（防 `../` 逃逸）且已在哈希清单中。
- **非字符串**：`type(relative) is not str` → 拒绝。
- **哈希异常**：64 位小写十六进制格式校验 + 文件字节重算比对 → `dataset_hash_mismatch`。
- **独立探针**（超出既有测试）：复制数据集到临时目录、篡改 `oracle/c1.json` 一个字段 → 审计以 `dataset_hash_mismatch` 拒绝，探针后临时目录清理。该场景无专属单测（见 R1）。

### 5. 审计代码边界 ✅
脚本位于 `investigation/scripts/`（作者/评测侧），导入 `evaluation.oracle_loader`（评测侧）与 state/tools 类型化加载器；docstring 与 README、契约均声明"会读取 oracle，禁止 Agent 运行时导入"。`investigation/src`、`evaluation/`、`benchmark/` 中**无任何**对 `dataset_split_audit` 的引用（grep 验证）；src 侧导入守卫（M1）不涉脚本目录，704 项测试含守卫全绿。与 M5 评测代码同侧的既有边界一致。

### 6. 文档诚实性 ✅
验收说明"已知限制"与 M10 契约 §2/§5 均明确：冻结静态规范化**不能**识别自然语言改写、参数替换或同模板不同值，这些关系依赖作者设置 `family_id` 与独立内容复核；"精确输入重复可自动检查，语义改写仍需独立内容复核，避免夸大自动审计能力"。无能力夸大表述。

### 7. 五案/Prompt/Rubric/历史 Artifact 不变 ✅
- 数据 JSON、rubrics、prompts、src 零改动（git status 证实）；
- 两个已修改文档均为澄清/范围扩展（README 增审计说明；M9 契约澄清"假模型首轮合法时每案 3 次调用，真实模型修复额外计一次"——与 M9a 复核实测一致；plan v8 增量记录 M10a 范围）；
- 五案审计输出：5 cases / 2 families / dev=5 / 唯一等价组 C4+C5（同 family 同 split）；
- M8/M9 归档未在变更清单，且本会话在其存在状态下完成过 checksum 重放。

## 四、实际命令与结果

| 命令（investigation/ 下） | 结果 |
|---|---|
| `.venv\Scripts\python.exe scripts\dataset_split_audit.py` | 5 cases、2 families、dev=5；VG001={C4,C5}；绑定 visible-metadata-v1 + SHA256；4 项 checks 全 passed |
| `.venv\Scripts\python.exe -m pytest tests\test_dataset_split_audit.py -q` | **9 passed** |
| `.venv\Scripts\python.exe -m pytest -q` | **704 passed**（695 基线 + 9 审计） |
| 独立探针：篡改 oracle 副本文件 | `dataset_hash_mismatch` 拒绝 ✅ |
| 独立核对：NORMALIZATION_SHA256 常量 vs 审计输出 | 逐字节一致 ✅ |
| 独立核对：六个 blob 哈希 vs 验收说明 | 逐一匹配 ✅ |

## 五、发现与风险

| 编号 | 程度 | 内容 | 建议 |
|---|---|---|---|
| R1 | 低（补测试建议） | `dataset_hash_mismatch`（格式非法与重算不符）已实现并经独立探针验证，但无专属单测；验收说明的负向覆盖清单也未声称包含它。 | M10b 扩写数据时顺手补一条哈希篡改负向测试（可将本复核探针固化为测试）。不阻断。 |
| O1 | 观察 | 两两 `compare_static` 为 O(n²)：60 案例约 1770 次比较，当前耗时无虞；若未来扩到数百案例可先按规范化哈希分组再组内比较。现阶段无需修改。 |
| O2 | 观察 | 审计对 `manifest["cases"]` 中 public/environment 文件未做"一个数据文件只被一个 case 引用"的去重检查（oracle 有 `duplicate_oracle_mapping`）。共享 environment 文件（如未来 C4/C5 式 twins 复用同一份物理文件）可能正是合法需求，当前靠孤儿检查 + 等价组检查兜底。M10b 出现文件级复用需求时再明确语义。 |
| O3 | 提示 | 契约目标"dev 20 / test 40"与当前 5 dev 的差距全部在后续批次；M10a 未引入任何 test 数据，盲测有效性取决于 M10d 的独立编写纪律——文档已正确将该纪律列为流程要求。 |

## 六、检查范围与未覆盖项

已覆盖：七个重点检查项、六文件 blob 哈希对照、三条指定命令复现、独立哈希篡改探针、规范化常量绑定核对、运行时无审计引用的 grep 验证、数据/Prompt/Rubric/src 零改动核对。
未覆盖：语义改写检测（明示不可自动）、M10b–M10d 尚未编写的案例质量、审计脚本在畸形 manifest 之外的全部对抗输入空间（有限样本）、CI 运行（未提交未推送）。

## 七、结论状态分立

| 维度 | 状态 |
|---|---|
| 辅助技术复核（本报告） | **通过（建议进入提交/CI 门槛）** |
| 主实现自检 | 通过（验收说明记录：704 passed、git diff --check 通过） |
| 提交/推送 | 未执行（待本复核后按流程） |
| 远端 CI | 未运行 |
