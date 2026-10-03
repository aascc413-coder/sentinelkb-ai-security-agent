# M1 v2 独立复验与修复交接

版本说明：本报告记录 v2 的历史检查及候选修复。补丁现已由主实现合入 v3；当前状态与证据见 [M1 验收说明](m1-acceptance.md)。

日期：2026-10-04。承接 [首次复核](m1-independent-review.md)。

## 验收结论

**主工作区 M1 v2 暂不通过技术验收，剩余两项边界问题。** 原有问题的多数修复已验证：正式测试 83 passed、首次独立检查 20 passed、演示 7 项全部拒绝非法输入。

针对重写的守卫和新增适配器，补充检查发现两项缺口，共 5 次失败。已在独立 worktree 准备修复补丁和 6 项正式回归测试，修复副本 **109 passed**；补丁可应用到当前主工作区。该结果证明候选修复通过了本轮测试，**不代表主工作区已修复或远端 CI 已通过**。

未修改另一 AI 的源文件，未代填人工通过、提交或推送；主工作区新增内容仅为本报告、证据及候选补丁。

## 被检查版本

- 基础提交：`2a31d90`；M1 v2 仍为未提交文件。
- 原始 v2 快照：29 项文件、完整 SHA-256 与采集时间，见 `m1-retest-evidence/source-snapshot.json`。
- 独立目录：`D:/project/Agent/m1-contract-retest`，新建 Python 3.12.10 虚拟环境。
- 仅安装 21 项锁定依赖和 `--no-deps` editable 包；21 项版本全部匹配，`pip check` 无冲突，六类产品依赖均不存在。
- 提验说明中的 27 项文件哈希前缀全部匹配，文件与哈希逐一对应。
- 主工作区被检查的 29 项文件在复验后未改变，见 `source-drift.json`。候选补丁仅应用于独立副本，原始两项代码另保存在该副本的 `audit-artifacts/before/`。

## 实测结果

| 阶段 | 检查 | 结果 |
|---|---|---|
| 主工作区 v2 的冻结副本 | 正式测试 | 83 passed |
| 同上 | 首次独立用例 | 20 passed |
| 同上 | 修复入口补充检查 | 5 failed / 1 passed |
| 同上 | 校验演示、依赖检查 | 7 项 REJECTED；无依赖冲突 |
| 独立候选修复 | 正式测试含新增回归 + 首次独立用例 | 89 + 20 = 109 passed |
| 当前主工作区 | `git apply --check` | 补丁可应用，未实际合入 |

5 次失败来自导入写法的 4 个场景和 NaN 概率的 1 个场景，对应两项问题，不是五个独立缺陷。有限测试不代表穷举所有输入。

## 剩余问题与候选修复

### M1-A2-R：守卫没有解析 from-import 的名称

位置：`investigation/tests/test_import_boundaries.py` 的 `_full_imports`。

这些正常 Python 写法仍返回零违规：

```python
from evidence_investigation import tools
from .. import tools
from evidence_investigation import tools as environment
```

守卫解析了 `node.module`，但没有解析 `node.names`，所以只看到允许的父包，遗漏了被导入的 tools 子包。state、agents 和 evaluation 均可出现这种漏检。这属于声明的静态导入边界，未涉及动态导入或进程沙箱。

候选修复：同时解析父模块与被导入名称；按文件和违规类别汇总目标，避免同一条导入产生重复报告。新增四类违规与一个合法同区导入的回归测试。没有证据表明当前项目已实际泄漏 oracle 数据；本项验证守卫的发现能力。

### M1-A4-R：模型适配器绕过有限数值解码

位置：`investigation/src/evidence_investigation/state/adapters.py`。

```python
final_assessment_from_output({
    "verdict": "Abstain", "disposition": "human_review",
    "stop_reason": "tool_budget", "claims": [],
    "final_evidence_ids": [], "p_attack": float("nan"),
})
```

实际：成功构造含 NaN 的 FinalAssessment。适配器直接复制 p_attack；JSON Schema 的数值边界未阻止该 Python 非标准数值。codec 与最终校验函数虽已拒绝 NaN，但这个规定入口没有复用它们。

候选修复：通过 `decode(FinalAssessment, payload)` 统一执行缺省和数值检查，再用 `dataclasses.replace` 强制 confidence_status 为 uncalibrated。保留现有 `codec_claim` 接口，避免未经协调删除公共函数。新增适配入口的 NaN 拒绝测试。

本项不证明 NaN 已被最终控制器接受；M4 尚未实现。验收关注的是 M1 新交付入口自身的有效性。

## 交接补丁

文件：`m1-retest-evidence/m1-v2-followup.patch`，修改两项代码并新增一项正式测试文件：

- `investigation/tests/test_import_boundaries.py`
- `investigation/src/evidence_investigation/state/adapters.py`
- `investigation/tests/test_m1_review_regressions.py`（6 项回归）

契约实现 AI 可在仓库根目录执行：

```powershell
git apply --check docs/evidence-aware-investigation/acceptance/m1-retest-evidence/m1-v2-followup.patch
git apply docs/evidence-aware-investigation/acceptance/m1-retest-evidence/m1-v2-followup.patch
$env:M1_AUDIT_ROOT = 'D:/project/Agent/sentinelkb'
$env:PYTHONIOENCODING = 'utf-8'
& 'D:/project/Agent/sentinelkb/investigation/.venv/Scripts/python.exe' -m pytest investigation/tests docs/evidence-aware-investigation/acceptance/m1-audit-evidence/test_m1_independent.py -q
```

前提：该环境安装的是当前主工作区的包。预期为 **109 passed**；补丁后正式测试单独运行预期为 **89 passed**。若目标文件在交接后改变，应先核对差异，不能强行套用补丁。

完整证据见 `m1-retest-evidence/`：原始 v2 安装和测试日志、JUnit、首次检查回放、补充用例、补丁后结果、文件哈希和机器汇总。旧版报告与失败证据保留为历史记录。

## 另一 AI 现在适合做什么

### 立即：收口 M1

1. 合入候选补丁或实现等价修复，保留新增回归。
2. 复跑 109 项检查与演示，刷新逐文件完整哈希、测试计数和验收说明，登记这两项修复与影响范围。
3. 完成人工验收、提交和按授权推送；核对远端两个 CI job 的实际 commit。M1 的远端验证目前未发生。

### M1 完成后：负责 M2 数据集与充分性判定表

按计划交付：

- 5 个案例的 PublicCase、工具环境数据和 OracleCase，公开输入与 oracle 标注分开。
- C4 / C5 共享同一环境；建立冻结规范化规则和静态输入等价检查。
- PowerShell 的 G0–G4、B1–B3 五列充分性判定表：所需观察、程序检查、模型解释、冲突处理、无法验证。
- 数据加载校验、opaque ID 重映射、fixture 摘要演示，以及 M2 验收说明。

并行建议：契约实现 AI 负责 M2 的数据、判定表和加载实现；复核方负责静态输入边界、关键证据与替代充分组合的独立检查。评测指标口径和手算样例可同步准备，正式 M5 集成仍遵循依赖顺序。
