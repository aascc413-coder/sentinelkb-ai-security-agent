# M10c 修复后独立复验（`974283d` 之上已暂存变更）

日期：2026-10-26。复验对象：`main` @ **`974283d`** 之上的 `git diff --cached`（75 文件，+11949/−19），即首次复核 [m10c-independent-review.md](m10c-independent-review.md) 判定不通过后的修复版本。

性质：独立只读复验——关闭状态逐项验证、冻结元数据重算、四条命令复现、20 案端到端评分、自建审计负向探针与 Planner 边界探针。未修改、未重新暂存、未提交、未推送任何现有文件；**未调用任何真实模型或付费 API**（全程 `EngineeringFakeModel`，工具服务为 `MockToolServer`）。

## 一、结论

**通过。** 首次报告中 1 项 P0、2 项 P1 全部关闭且证据可复现；4 项 P2 中 3 项完全关闭、1 项在 M10c 范围内关闭并留下一项受 v2 冻结约束的遗留口径；M10c 固定快照未引入新的阻断项。

关键关闭证据：C20 的 TP 现引用 `absence:siem:*` 空范围证据（`ev-0004`）且 `sufficiency_pass_rate=1`、`discriminating_evidence_recall=1`、`critical_evidence_recall=1`；C16 `critical_evidence_recall=3/3`；9 个确定性判定案（C1/C2/C6/C7/C8/C12/C13/C14/C20）`sufficiency_pass_rate` 全部为 1；13 项自建审计负向探针全部按预期拒绝；family 由 14 更正为 12，C13↔C6、C20↔C12 已同 family；C17/C18 改为独立批准源冲突双胞胎且不再复用遥测故障场景。

## 二、首次发现关闭状态

| 首次编号 | 内容 | 状态 | 复验证据 |
|---|---|---|---|
| **P0-1** | complete-empty 的 `absence:` 事实无法映射回 Oracle，C20 冻结 TP 充分集合恒不可满足 | **已关闭** | `evaluation/evaluator.py:103-118` 现接受 `absence:` 且要求 `absence_provable is True`；C20 `final_evidence_ids=[ev-0001,ev-0002,ev-0003,ev-0004]`，其中 `ev-0004` 键为 `absence:siem:f8b500c0…`、`absence_provable=True`、映射为 `['E2']`；C20 `evidence_sufficient=True`、`sufficiency_pass_rate=1/1`、`discriminating_evidence_recall=1/1`；C16 `critical_evidence_recall=3/3`；C19 空网络事实映射为 `['E2']` |
| **P1-1** | 审计的 recordless status 只按 `tool+status` 聚合，同工具多 envelope 可错配 | **已关闭** | `scripts/dataset_split_audit.py:163-168` 对非 `unavailable` 事实强制 `arguments` 与 rule 的 `argument_constraints` 精确相等；探针「C16/E2 empty→partial」「C16/E2 交换 view」「C20/E2 empty→partial」均被 `ungrounded_annotation` 拒绝 |
| **P1-2** | `retryable` 可省略即绕过校验 | **已关闭** | `dataset_split_audit.py:175-177` 对 `timeout/error` 强制布尔 `retryable`；探针「C15/E4 删除 retryable」「C15/E4 retryable 翻转」「C19/E4 retryable 翻转」均被拒绝 |
| **P2-1** | 三组 counterfactual 同属「全源失败」模板 | **已关闭（M10c 新增部分）** | C17/C18 重建为 `powershell-approval-conflict-pair-v1`：5 条规则全为 `ok`，asset 返回 2 条记录（`change-register`/`change-01` 含匹配批准、`secondary-change-register`/`change-02` 的 `approved_jobs=[]`），history 携带 `approval_feed_conflict=true`。C10 仍是 partial/unavailable 全失败形态，两者结构已不同 |
| **P2-2** | C13≈C6、C20≈C12 却分属不同 family，虚增 family 数 | **已关闭（新增部分）/ 遗留观察** | C13 现属 `powershell-office-exfil-v1`（与 C6 同）、C20 现属 `powershell-direct-destructive-v1`（与 C12 同），`family_count=12`。遗留：C1 仍属 `powershell-seed-v1`，与 C6/C13 属同一敏感对象外传原型，但因 C1–C12 必须与 v2 逐字节一致，`family_id` 无法改动（见观察 O4） |
| **P2-3** | C19 干扰 TI 地址与主机编号同源 | **已关闭** | TI 值改为 `203.0.113.250`，全环境仅出现在 threat_intel 记录及其自身 query rule，不出现在任何 siem/asset/history payload；主机仍为 `WS-119`，无编号联想 |
| **P2-4** | Planner 的 history 调用以 `alert.host` 为前提，纯 user 告警丢查询 | **已关闭** | `planner.py:89-93` 改为 `if history_entity`，`core_attempted` 改为只统计存在的 core calls；实测 `user=analyst-z, host=None` → `selected=query:history, entity_type=user, entity=analyst-z, host=None` |

## 三、十项重点验证逐项结论

| # | 要求 | 结论 | 证据 |
|---|---|---|---|
| 1 | complete empty 的 absence evidence 可映射回 Oracle | **通过** | C16/C19/C20 的 `absence:siem:*` 均为 `absence_provable=True`、`status='empty'`、`error_code=null`，分别映射为 E2；反向验证：把同一事实键前缀改为 `source:` 不再必要（新逻辑按 `absence:` 分支直接命中） |
| 2 | C20：真实引用空网络证据、`sufficiency_pass_rate=1`、`discriminating_evidence_recall=1` | **通过** | 轨迹：process(ok) → asset(ok) → network(**empty, complete**)，`operational_ids=['ev-0004']`；`final_evidence_ids` 含 `ev-0004`；三项指标均为 1.0 |
| 3 | C16：`critical_evidence_recall=1`；E2 empty→partial 必须被拒 | **通过** | C16 实得 `3/3`；篡改探针返回 `rejected(ungrounded_annotation)` |
| 4 | C15：删除 timeout 事实的 `retryable` 必须被拒 | **通过** | `rejected(ungrounded_annotation)` |
| 5 | recordless fact 的 `arguments` 必须精确匹配；删除必须被拒 | **通过** | C15/C19/C20/C16 四类删除均被拒；`arguments.entity` 改错、`view` 改错、改用不存在规则的 constraints 亦被拒 |
| 6 | 仅 user 无 host 时仍生成 user history 查询 | **通过** | 单元探针：`query:history`，`entity_type=user`、`entity=analyst-z`、`host=None` |
| 7 | C17/C18 静态等价、真值相反、体现独立批准源冲突、不复用 C10/C11 故障、均 Abstain | **通过** | public 字节相同；共享 `shared-17-18.json` 且字节相同；同 family/同 split；truth `malicious/benign`；accept 均 `('Abstain',)`；两条 asset 记录来自不同 `source_system`/`independence_group` 且 `approval_register_complete` 均为 true 而 `approved_jobs` 分别为 1/0；全部 query rule 为 `ok`（C10 为 partial+unavailable）；端到端两次运行轨迹逐事件相同且均为 Abstain |
| 8 | family 总数 12；C13 与 C6 同 family；C20 与 C12 同 family | **通过** | 审计输出 `family_count=12`；两两 family_id 相同 |
| 9 | C19 TI 与编号无关联且保持未关联；permanent history error 可追溯 | **通过** | TI=`203.0.113.250`（主机 `WS-119`）；occurrence 仅限 threat_intel payload 与自身 rule；`critical=[]`、`distractor=[E5,E7]`；history 返回 `status=error, error_code=history_backend_error, retryable=False`，事实含 `arguments={entity_type:user, entity:analyst-i}` 并可映射 E4 |
| 10 | freeze 哈希、C1–C12 字节、构建器复现、标签隔离 | **通过** | 9/9 绑定 SHA256 命中；manifest/annotations/freeze 三个内容 SHA256 与验收说明逐一相同；C1–C12 共 34 个 JSON 与 v2 逐字节相同；构建前后 `git status` 指纹不变；20×2 可见分区泄漏扫描 0 命中 |

## 四、实际命令与结果

在 `D:\project\Agent\sentinelkb\investigation` 下，`.\.venv\Scripts\python.exe`（Python 3.12.10，Windows）。

| 命令 | 退出码 | 结果 | 与验收说明对比 |
|---|---|---|---|
| `scripts\build_dev_dataset_v3.py` | 0 | `Wrote powershell-dev-v3: 20 dev cases, 17 physical environments, 20 oracle cases.`；执行前后 `git status --porcelain` 排序 SHA256 均为 `0f11c97e…`，`git diff` 为空 | 一致 |
| `scripts\dataset_split_audit.py --dataset datasets\powershell-dev-v3` | 0 | 20 cases / **12 families** / dev=20；VG001={C4,C5}、VG002={C10,C11}、VG003={C17,C18}；5 项 checks 全 `passed` | 一致 |
| `pytest tests\test_agents.py tests\test_dev_dataset_v2.py tests\test_dev_dataset_v3.py tests\test_dataset_split_audit.py tests\test_evaluator.py -q` | 0 | **102 passed in 31.89s** | 计数一致（验收记 102 passed） |
| `pytest -q` | 0 | **745 passed in 87.20s** | 计数一致（验收记 745 passed） |
| `git diff --cached --check` | 0 | 无输出 | 一致 |

快照核对（12 个 blob 全部命中验收说明表）：`planner.py` `8fe1c9be…`、`sufficiency.py` `aad2de4c…`、`evaluator.py` `6e1b0b21…`、`dataset_split_audit.py` `d02038e6…`、`build_dev_dataset_v3.py` `82b5bb23…`、`test_agents.py` `4db21f8a…`、`test_dev_dataset_v3.py` `d55d5a91…`、作者指南 `ea9966dd…`、freeze `1e044459…`、manifest `1f6dc359…`、annotations `857609b4…`、`.gitattributes` `158c1617…`。内容 SHA256：manifest `44db3543…`、annotations `af037928…`、freeze `edb11f2c…`，与验收说明第 3 节完全一致；freeze 内 9 个绑定哈希（含作者指南 `1dd3628b…`）逐项重算命中，全部无 CR，`git check-attr` 均为 `text: set / eol: lf`。

## 五、独立负向探针（数据集副本 + 重算 manifest 哈希）

| 探针 | 期望 | 实测 |
|---|---|---|
| C16/E2 `empty`→`partial` | 拒绝 | `rejected(ungrounded_annotation)` |
| C16/E2 删除 `arguments` | 拒绝 | 拒绝 |
| C16/E2 `arguments.view` 改为 `host_events` | 拒绝 | 拒绝 |
| C20/E2 `empty`→`partial` | 拒绝 | 拒绝 |
| C20/E2 删除 `arguments` | 拒绝 | 拒绝 |
| C15/E4 删除 `retryable`（timeout） | 拒绝 | 拒绝 |
| C15/E4 `retryable` 翻转 | 拒绝 | 拒绝 |
| C15/E4 删除 `arguments` | 拒绝 | 拒绝 |
| C15/E4 `arguments.entity` 改错 | 拒绝 | 拒绝 |
| C15/E4 改为不存在的 host 规则 constraints | 拒绝 | 拒绝 |
| C19/E4 删除 `arguments`（error） | 拒绝 | 拒绝 |
| C19/E4 `retryable` 翻转 | 拒绝 | 拒绝 |
| C16/E4（`unavailable`）填入错误 `arguments` | 接受（文档化的豁免） | 接受，与作者指南第 3 节「新增**非 unavailable** 事实」一致 |
| C16/E1（有 record 引用）追加 `operational_status=partial` | 拒绝 | **接受**（见 P2-1） |

评分侧复核（Proposed + 假模型，20 案全跑）：全部 20 案 `verdict ∈ acceptable_verdicts`；`final_evidence_error_rate=0`；9 个判定案 `sufficiency_pass_rate=1`；全部 Abstain 案 `required_abstention_recall=1`、`required_human_review_recall=1`、`appropriate_abstention_precision=1`；C15 轨迹为 5 attempts / 4 decisions / 1 次自动重试（`retry_of` 指向前一次调用）、`tool_selection_accuracy=1`。

## 六、本轮新发现（均非阻断）

### P2-1 审计不拒绝「有 record 引用又带 operational_status」的混合标注

`scripts/dataset_split_audit.py:152` 的校验分支以 `not references` 为前提，因此带 `record_ids` 的事实若额外携带 `operational_status`（或 `arguments`），既不进入 envelope 校验，也不会被拒绝。而 `evaluation/evaluator.py:103` 的 `matched_fact_keys` 对含 `operational_status` 的标注走 operational 分支并 `continue`，**不再校验 record 身份**，该事实的身份依据会从「具体记录」退化为「工具+状态+reason+retryable」。

实测：给 `C16/E1`（本应指向 process 记录）追加 `operational_status="partial"` 后审计**接受**；随后运行仍 `critical_evidence_recall=3/3`，但 E1 是由 `source:siem:partial:*` envelope 而非其记录命中的——即标注语义已被静默改写。当前 20 案无此形态（全量扫描：不存在同时带 `record_ids` 与 `operational_status`/`arguments` 的事实），故不影响已冻结标签。建议补一条规则：`record_ids` 非空时禁止出现 `operational_status`/`arguments`，避免 M10d 独立作者写出混合标注后静默改变 grounding 语义。

### P2-2 `unavailable` 事实的 `arguments` 豁免仍可错配同工具多规则

`dataset_split_audit.py:163` 明确豁免 `unavailable`（否则 C1–C12 无法与 v2 逐字节一致，因为 v2 的 unavailable 事实不带 arguments）。残余影响：同一工具存在两条 unavailable 规则时（如 C3 的 host/user 两条 history 规则），unavailable 事实可被归到任一条。由于 unavailable 事实不能支持 TP/FP，当前不影响标签与指标；M10d 新增 unavailable 案例时建议同步保存 `arguments`。

### 观察项

- **O1** C20 的充分集合现在经由 `sufficiency.py:238-240` 把 network 的 operational evidence id 纳入 G1/G2/G4 引用；Proposed 由引擎自动引用，而 Direct/Fixed/ReAct 由模型自选证据。若这些基线不引用 operational id，其 `sufficiency_pass_rate` 会系统性低于 Proposed——这是方法差异而非标签缺陷，但 M11 报告需说明该口径，避免被读成能力差异之外的东西。
- **O2** C17/C18 的 `critical_fact_keys=[E3,E6]` 中 E6 为 `oracle_only`，故 `unobservable_critical_fraction=0.5`，与 C4/C5/C10/C11 的 1.0 同属「部分关键事实不可观察」的既有设计，非新问题。
- **O3** C1（`powershell-seed-v1`）与 C6/C13 仍属同一「敏感对象读取+同对象外传」原型却分属两个 family，受 C1–C12 冻结字节约束无法合并；`family_count=12` 仍应理解为「family_id 去重」而非「12 个互不相同的行为原型」。
- **O4** 构建器与评测层均未引入新依赖；本复验未发现暂存内容与工作区不一致（`git diff` 为空）。

## 七、未覆盖范围

1. 未调用任何真实模型或付费 API；不涉及 blind 泛化、统计优势、跨模型稳定性或生产性能结论。
2. 未运行远端 CI（按要求未提交、未推送）；验收说明所述历史 run 未独立核验。
3. 未覆盖 M10d 的 40 个盲测案例（尚不存在）。
4. 未在 Linux/macOS 实际 checkout 复验 LF 结论；仅依据 `git check-attr` 生效状态与绑定文件字节检查推断。
5. 语义改写检测仍不可自动化；「是否参数替换」类判断基于结构差异与人工判读。
6. 全量 745 项测试仅作为回归绿灯依据，未逐项审阅新增的 `test_evaluator.py` 用例实现质量。
7. 单机单解释器（Windows，Python 3.12.10）；耗时数据不可与他机直接比较。

## 八、结论状态分立

| 维度 | 状态 |
|---|---|
| 辅助独立复验（本报告） | **通过**：P0/P1 全部关闭，P2 关闭或降级为遗留口径，无新增阻断 |
| 首次 P0/P1/P2 关闭情况 | P0-1、P1-1、P1-2 已关闭；P2-1/P2-2 在 M10c 范围内关闭；P2-3、P2-4 已关闭 |
| 冻结元数据与快照 | 通过：12 个 blob SHA1、3 个内容 SHA256、9 个绑定哈希、LF 属性全部一致 |
| 提交 / 推送 / 远端双 CI | 未执行（按要求） |

建议后续（不阻断 M10c 完成）：补 P2-1 的混合标注拒绝规则与一条对应用例；M10d 编写时对 `unavailable` 事实一并保存 `arguments`。
