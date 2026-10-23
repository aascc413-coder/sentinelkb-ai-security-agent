# M10b 独立技术复核（63fc9f8 之上未提交工作区变更）

日期：2026-10-24。复核对象：main @ **`63fc9f8`** 之上的 M10b 未提交变更及 [m10b-dev-dataset-acceptance.md](m10b-dev-dataset-acceptance.md)。
性质：充分性通用化的语义审查 + 数据集结构/泄漏/差异核查 + 命令复现 + **端到端独立负向探针**；不是 M10c（dev 20）的验收。

## 一、结论

**通过（建议提交并进入 CI）。** 七个重点方向全部通过：期望观察比较为封闭、顺序无关的多重集比较且全路径 fail-closed；七项独立负向探针（10 个子变体）在端到端 Proposed 运行中全部阻止错误 TP/FP；数据集 12 案/7 family/10 环境属实，C1–C5 与 synthetic-v1 逐字节一致，两组双胞胎静态等价且真值相反；构建器确定性重建逐字节复现且不动种子数据；审计新增 Oracle 引用校验正确且与种子数据集兼容。发现两项观察与一项低风险提示，均不阻断。

## 二、被测文件与哈希

实现范围：8 个修改文件 + 6 个新增路径（详见验收说明）。实测 Git blob SHA1 与验收说明快照表**逐一匹配**：

| 文件 | blob（前 12 位） | 状态 |
|---|---|---|
| `agents/sufficiency.py` | `b30ff9aa046a` | 修改（+113/−32 主体） |
| `scripts/dataset_split_audit.py` | `d98ef17bc5f0` | 修改（+46：Oracle 引用校验） |
| `scripts/build_dev_dataset.py` | `b504ad93d097` | 新增 |
| `tests/test_agents.py` / `test_dataset_split_audit.py` / `test_dev_dataset_v2.py` / `test_seed_dataset.py` | `14df3c270f1a` / `b645b5ac73bf` / `b39390f0734b` / `29d467d13a0a` | 见左 |
| `datasets/powershell-dev-v2/README.md` / `manifest.json` | `046f370c6451` / `0fd88db91391` | 新增 |
| `evaluation/annotations/powershell-dev-v2.json` | `3f63df0fadbc` | 新增 |

内容哈希声明核对：manifest SHA256 `859ea24b…`、标注 SHA256 `084587fc…` 均**匹配**。

## 三、实际命令与结果

| 命令（investigation/ 下） | 结果 |
|---|---|
| `python scripts/dataset_split_audit.py --dataset datasets/powershell-dev-v2` | **12 cases、7 families、dev=12**；等价可见组 VG001={C4,C5}、VG002={C10,C11}；5 项 checks（含新增 `oracle_fact_references`）全 passed |
| `pytest tests/test_dev_dataset_v2.py tests/test_dataset_split_audit.py tests/test_agents.py -q` | **48 passed** |
| `pytest -q` | **721 passed** |
| `python scripts/build_dev_dataset.py`（本复核执行） | 重建后 35 个 v2 JSON **逐字节一致**，synthetic-v1 的 15 个文件**零改动** |
| `python scripts/dataset_split_audit.py`（默认种子数据集） | 5/2/dev=5，`oracle_fact_references: passed`——新校验与旧标注格式兼容 |
| 独立负向探针 `probe_m10b.py` | **10/10 通过**（见第五节） |

## 四、重点审查结果

### 1. sufficiency.py 期望观察匹配语义 ✅
- **封闭、顺序无关**：`_observation_signatures` 对每项做 canonical JSON 哈希后排序比较——多重集相等要求"无缺失、无额外、无替换"；顺序无关（sort_keys 哈希也消除键序）。
- **fail-closed**：非 list、含非 str/dict 项、expected 非法 → 签名 `None` → 不匹配；空行为或 `expected_observations: []` → 显式 False（`test_structured_behavior_matching_fails_closed…` 与我的 P1/P2 探针双重确认）。
- **空行为不 FP**：`_behavior_matches_approval` 首行 `if not observations or not isinstance(matching_job, dict): return False`；行为字段缺失时 `observations_known=False` 同样阻断 B2。
- **凭据读取↔外传对象关联**：通用路径要求 `read.produces == sent.object`（双向具体值匹配）；C1 兼容路径为冻结固定配对（`credential-store`→`credential-bytes`）。P5b 证明该兼容路径**不**外溢到 `browser-credential-store` 等新对象。外传还要求 destination ∈ 同实例网络记录的目的地集合。
- **批量 encrypt/delete**：`authorized is False` + `affected_count` 为 int 且**显式排除 bool** + `>= 10`。P3（=9）与 P4（=true）均被阻止；小数量与自由文本（非结构化 dict）不进入判定。
- **零网络结果**：G1 允许"进程一致 + 网络 complete-empty"成立（`network_consistent or complete_empty_network`）；`times_ok` 同样接受 complete-empty；B2 的 `network_complete` 允许无记录但 coverage complete；G4 的 `coverage_ok` 仍要求 `network_acq` complete。完整零网络在 B2 参与关闭，但 G2 链仍需 same_instance 成立——语义自洽。
- **partial/unavailable/truncated 网络**：`network_consistent` 为 False → G1 unknown；`coverage_ok` False → G4 unknown；`network_complete` False → B2 不可 met；B3 依赖 coverage_ok → unknown。**TP 与 FP 均不可达**（P6a/P6b/P6c 探针确认转为 Abstain）。
- **C1/C2 兼容与行为不变**：C1 走冻结配对外传链、C2 走 legacy 三元组精确匹配（expected 缺失时）；`test_agents.py` 五案参数化测试全绿（含 C1=TP、C2=FP、C3=Suspicious、C4/C5=Abstain），721 项中既有回归未破。

### 2. powershell-dev-v2 数据集 ✅
- **结构**：12 cases、7 families、10 物理 environment（world-1/2/3、shared-pair、world-6/7/8/9、shared-10-11、world-12）；manifest 覆盖 34 个 JSON。
- **C1–C5 字节一致**：public/c1–c5、oracle/c1–c5、environment/world-1/2/3 + shared-pair 与 synthetic-v1 对应文件 SHA256 逐一相同（独立计算）。
- **双胞胎**：C4/C5、C10/C11 各共享同一环境文件，`ground_truth` 相反、`acceptable_verdicts=("Abstain",)` 相同、同 family 同 split。
- **C6–C12 标注一致性**：ground_truth（malicious/benign/benign/malicious/malicious/benign/malicious）与场景结构相符；sufficient_sets 全部仅含可观察事实（audit 的 oracle 引用校验强制 record_ids 可解析且 source 匹配）；C9 的脚本正文为 `oracle_only` 且不在 observable；expected_actions 按已获/缺失事实给可接受集合。逐案预期 `TP/FP/FP/Suspicious/Abstain/Abstain/TP` 与端到端测试一致。
- **无泄漏**：17 个 public/environment 文件对 case_id/family_id/split/ground_truth/critical/distractor/oracle 等标记扫描 **CLEAN**（测试另以 JSON 键名扫描双保险）。
- **真实差异**：C6 browser-credential-store 读取+上传、C7 批准 Office 报表（REPORT-7 带 2 项结构化期望）、C8 远程运维精确匹配（RMM-88）、C9 导出+上传但批准不匹配、C10/C11 无结构化观察的遥测缺口、C12 未授权加密 250 个文档——操作/对象/授权位/数量各不相同，非参数替换。

### 3. build_dev_dataset.py ✅
本复核实际执行：重建输出与冻结 JSON 及标注**逐字节相同**（35 文件），synthetic-v1 零改动；测试内另有 tmp_path 重建比对。manifest 由构建器生成，审计的 all-and-only 哈希检查保证覆盖恰好全部实际文件。

### 4. dataset_split_audit.py 新增校验 ✅
- record_id → tool 台账（含 alert 自身引用）；`complete_world_evidence` 每条必须为结构化 dict。
- 悬空引用 → `dangling_annotation`；`oracle_only` 带引用或出现在 observable → `hidden_fact_leak`；`source_tools` 与实际引用工具集合不一致 → `annotation_source_mismatch`；可观察事实无引用时必须是匹配的 unavailable 操作事实（工具+error_code 对应 query_rules）→ 否则 `ungrounded_annotation`。
- 单测覆盖字节篡改（顺带闭环 M10a 复核的 R1 建议）与悬空引用；种子数据集在新校验下审计通过（兼容性）。

## 五、独立负向探针（端到端，EngineeringFakeModel + Proposed 全流程）

方法：复制数据集到临时目录 → JSON 手术（重算受影响记录 content_sha256）→ 同一 runner 运行 → 每族先跑正控再断言手术后结论。

| 探针 | 案例 | 基线 | 手术后 | 断言 |
|---|---|---|---|---|
| P1 expected_observations=[] | C8 | FP | **Abstain** | 非 FP ✓ |
| P2 实际行为多一项 | C8 | FP | **Abstain** | 非 FP ✓ |
| P3 affected_count=9 | C12 | TP | **Abstain** | 非 TP ✓ |
| P4 affected_count=true | C12 | TP | **Abstain** | 非 TP ✓ |
| P5a upload 缺 object | C6 | TP | **Abstain** | 非 TP ✓ |
| P5b produces 与 send.object 不一致 | C6 | TP | **Abstain** | 非 TP ✓（兼证兼容配对不外溢） |
| P6a 网络 partial | C6 | TP | **Abstain** | 非 TP ✓ |
| P6b 网络 partial | C8 | FP | **Abstain** | 非 FP ✓ |
| P6c 网络 unavailable | C6 | TP | **Abstain** | 非 TP ✓ |
| P7 批准仅 host/user 同、job_id 不匹配 | C8 | FP | **Suspicious** | 非 FP ✓（正确触发批准不匹配风险旗标，符合 C3 族语义） |

探针脚本留存于 `investigation/probe_m10b.py`（复核工作产物，未纳入提验快照；主实现可择机固化为测试）。

## 六、发现及严重程度

| 编号 | 程度 | 内容 |
|---|---|---|
| O1 | 观察 | C1 兼容路径的固定配对（credential-store→credential-bytes）不校验 `produces` 字段——同一实例内"读取凭据库 + 发送 credential-bytes"即成立，即使产物字段写别的值。这是有意的冻结词表（保 C1 不变），且范围被 same_instance + 网络目的地关联合理约束；但新增"凭据库读+字节发"类案例时需意识到该配对是词表级等价而非产物级证明。 |
| O2 | 观察 | legacy 三元组匹配（expected 缺失时）是**顺序相关**的精确元组比较，与 v2 结构化路径的顺序无关语义不同。仅影响未提供 expected_observations 的旧式批准记录（现数据集中仅 C2 路径）；顺序差异会 fail-closed 不误 FP，方向安全。 |
| R1 | 低（提示） | 探针显示手术后多转为 Abstain 而非 Suspicious：风险旗标仅在"批准记录与执行字段级不匹配"（C9/P7 情形）时触发，其余缺口走 Abstain。与 rubric 现行定义一致，但 M10c 扩写"风险明确但不可定论"覆盖项时，需按覆盖矩阵为相应案例构造 mismatch 类事实而非仅删除证据。 |

## 七、检查范围与未覆盖项

已覆盖：任务列出的全部七个方向、四条命令复现、构建确定性、双归档一致性、泄漏双扫描、10 个端到端负向探针、哈希与 blob 快照对照、种子数据集向后兼容。
未覆盖：真实模型行为（本复核全程假模型，未调用付费 API）；M10c 案例质量；语义改写检测（M10a 已明示不可自动）；`EngineeringFakeModel` 对手术后的输出适应性（假模型输出通用合法，未模拟格式修复路径与手术组合）；CI（未提交未推送）。

## 八、结论状态分立

| 维度 | 状态 |
|---|---|
| 辅助技术复核（本报告） | **通过** |
| 主实现自检 | 通过（验收说明：721 passed、重建逐字节、审计通过） |
| 提交/推送 | 建议提交并进入 CI（由主实现按流程执行） |
| 远端 CI | 未运行（待提交后核对同一提交双 job） |
