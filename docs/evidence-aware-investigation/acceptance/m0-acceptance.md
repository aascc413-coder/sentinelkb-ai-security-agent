# M0 人工验收说明

按 [实施计划（v5）](../phase-2-implementation-plan.md) 第 7.4 节模板编制。
状态：**已完成**（本地人工验收通过 2026-10-04；远端 CI 双 job 通过于 commit `e6c4473`）。

## 里程碑

M0 脚手架与独立环境（父依赖：无）

## 提验版本 / 文件快照

提交前快照，SHA-256（2026-10-01 生成，验收以此版本为准）：

| 文件 | SHA-256（前 12 位） |
|---|---|
| `.python-version` | `7b55f8e67b56` |
| `investigation/pyproject.toml` | `8170810d5256` |
| `investigation/requirements-lock.txt` | `b4119c6a599b` |
| `investigation/README.md` | `da59a139e747` |
| `investigation/.gitignore` | `266d463a19a8` |
| `investigation/src/evidence_investigation/__init__.py` | `1cd2ecf49bf5` |
| `investigation/tests/test_package.py` | `cba496095ed9` |
| `.github/workflows/python-tests.yml` | `0ff9f90a5021` |
| `docs/evidence-aware-investigation/phase-1-design.md` | `1946996f4b68` |
| `docs/evidence-aware-investigation/contracts.py` | `4ab2babef7a6` |
| `docs/evidence-aware-investigation/minimal-cases.md` | `b7d3a61c6edd` |
| `docs/evidence-aware-investigation/architecture.drawio` | `12deed48e40a` |
| `docs/evidence-aware-investigation/implementation-plan-review.md` | `d79f8b2580b4` |
| `docs/evidence-aware-investigation/manual-acceptance-review.md` | `5e9bb5b3ec49` |
| `docs/evidence-aware-investigation/implementation-plan-v4-review.md` | `665853ee7266` |
| `docs/evidence-aware-investigation/phase-2-implementation-plan.md` | `211d53416c00` |

完整哈希可向开发方索取或复核上表前缀。

## 这一步解决什么问题

为调查实验建立独立、可复现的工程基线：独立包、锁定依赖、独立 CI job，并把 Phase 1 设计产物固化为版本基线（后续所有里程碑的"父依赖"）。

## 本次完成的能力

1. `investigation/` 独立包：`pyproject.toml`（requires-python≥3.12；运行依赖仅 jsonschema+httpx；dev 含 pytest+pytest-asyncio）、`src/evidence_investigation/` 包（`__version__ = "0.1.0"`）、2 项冒烟测试、README（含边界与目录规划）、`.gitignore`（runs/ 与 venv 不入库）。
2. 依赖锁定：`requirements-lock.txt`（19 个包，全部锁定精确版本，含生成说明头）。
3. 独立 venv：`investigation/.venv`（不入库），可编辑安装，测试全绿。
4. CI 独立 job：`investigation-tests`（windows-latest，工作目录 `investigation/`，干净环境仅装 lock 依赖 + `--no-deps` 可编辑安装），与产品 `test` job 互不影响、结果分开显示。
5. 设计产物冻结基线就绪（Phase 1 设计 + 计划 v5 + 三份评审意见 + `.python-version`）。

## 操作步骤（请逐项执行核对）

1. **干净环境安装与测试**
   - 操作或命令（已全部使用绝对路径，在任意目录执行均可）：
     ```powershell
     py -3.12 -m venv D:\temp\m0check
     D:\temp\m0check\Scripts\python.exe -m pip install -r D:\project\Agent\sentinelkb\investigation\requirements-lock.txt
     D:\temp\m0check\Scripts\python.exe -m pip install --no-deps -e D:\project\Agent\sentinelkb\investigation
     D:\temp\m0check\Scripts\python.exe -m pytest D:\project\Agent\sentinelkb\investigation\tests -q
     ```
     注意：不要在命令中使用相对路径（如 `investigation\requirements-lock.txt`），除非已先 `cd D:\project\Agent\sentinelkb`。验证后可 `Remove-Item -Recurse -Force D:\temp\m0check` 删除。
   - 应看到的结果：`2 passed`，无失败、无产品依赖报错。
   - 如何核对：输出末行为 `2 passed`；可另执行
     `D:\temp\m0check\Scripts\python.exe -m pip list` 确认清单中**没有** fastapi/langchain/chromadb/neo4j 等产品依赖。
2. **产品代码零改动**
   - 操作或命令：`git status --porcelain -- code/python`（在仓库根目录）
   - 应看到的结果：无任何输出（0 项变更）。
   - 如何核对：开发方已执行，结果为空；`git diff --stat .github/` 应只显示 `python-tests.yml | 28 ++++++` 一行。
3. **workflow 配置审阅**
   - 操作或命令：打开 `.github/workflows/python-tests.yml`
   - 应看到的结果：原 `test` job 原样保留（工作目录 `code/python`）；新增 `investigation-tests` job（工作目录 `investigation/`，独立安装与测试步骤）。
   - 如何核对：两个 job 的 `working-directory` 各自正确、互不引用。
4. **gitignore 生效**
   - 操作或命令：`git status --porcelain -- investigation/`
   - 应看到的结果：只列出 pyproject/lock/README/.gitignore/src/tests，**不包含** `.venv/`。

## 自动测试与技术自检结果

| 检查 | 结果 |
|---|---|
| investigation venv 安装 + `pytest investigation/tests -q` | ✅ 2 passed（无警告） |
| 全新 venv 仅从 lock 安装（模拟 CI）+ 测试 | ✅ 2 passed |
| 干净环境产品依赖存在性检查（fastapi/langchain/chromadb/neo4j/uvicorn/pydantic） | ✅ 均不存在 |
| `git status -- code/python` | ✅ 0 项变更 |
| 产品测试套件本地执行 | ⚠️ 未执行：根目录 `.venv` 当前为 uv 创建的空环境（无 pip、无包，见"已知限制"）；产品回归由提交后触发的 CI `test` job 执行 |

## 报告 / Trace / 差异记录路径

- 本验收说明：`docs/evidence-aware-investigation/acceptance/m0-acceptance.md`
- 变更清单：`git status` 输出见上方操作步骤 2–4；无 Trace 产物（本里程碑无运行记录）。

## 已知限制及未完成项

1. **产品测试套件未在本地重跑**：根目录 `.venv` 是 uv 创建的空环境（`pyvenv.cfg` 标记 uv 0.12.5，无 pip、site-packages 为空），无法执行产品 pytest。M0 变更对产品的隔离性由 `git status`（code/python 0 项变更）保证；产品回归在提交后由 CI `test` job 重跑确认（对应 README "27 项"为历史基线，按计划 R7 待重新验证）。如需本地恢复产品环境：`.venv` 为空环境，可用 `uv pip install -r code/python/requirements-dev.txt -p .venv` 或按 README 重建。
2. **远端 CI 未运行**：按 A1 流程，CI 属提交后确认步骤；本里程碑在推送并核对 commit 前标记"待远端验证"。
3. `evals/reports/offline_baseline.json` 为既有未跟踪文件（8 月 12 日的离线基线报告），**不在 M0 交付范围**，本次不提交。
4. CI 的 `cache-dependency-path` 指向 `requirements-lock.txt`，锁更新后缓存自动失效，无需手工清理。

## 需要用户判断的事项

1. 是否通过本里程碑验收（通过 / 不通过）。
2. 通过后的提交拆分：建议 commit 1 = 设计产物（docs/evidence-aware-investigation/ + `.python-version`，docs-only），commit 2 = investigation 脚手架 + CI 修改；也可合并为一个 commit。
3. 是否授权**推送到远端**触发 CI（A1 要求推送须在明确授权范围内；不推送则本里程碑停在"待远端验证"）。
4. `evals/reports/offline_baseline.json` 是否随本次一并入库（默认不提交）。

## 复验时补充

（首次提验，无复验记录）

## 验收记录（实施计划 7.2 字段，A7）

| 字段 | 记录内容 |
|---|---|
| 里程碑 | M0 脚手架与独立环境 |
| 提验版本 | 本文件上方 SHA-256 快照（2026-10-01） |
| 验收说明 | `docs/evidence-aware-investigation/acceptance/m0-acceptance.md`（本文件） |
| 测试与演示证据 | 用户执行：干净环境安装+测试（`2 passed`）、pip list 无产品依赖、`git status -- code/python` 无输出、三个文件目视核对；开发方自检结果见上方表格 |
| 验收人及日期 | 用户，2026-10-04 |
| 人工结论 | **通过** |
| 问题及修复 | 问题 1：验收说明步骤 1 使用相对路径，用户在 `C:\Windows\system32` 下首次执行失败（pip 找不到 requirements 文件）；修复：命令全部改为绝对路径并加提示（仅文档修正，不涉及工程成果，复验范围=无） |
| 通过后 commit | `9f3719f`（docs: freeze evidence-aware investigation design and plan baseline）+ `9ac5b0c`（feat: scaffold evidence-investigation package with independent CI job）+ `0bde2a9`（验收记录）；推送时远端已有用户单独添加的 LICENSE 提交（`0d2c7e8`，v1.0.0 标签），经合并提交 `e6c4473` 集成，LICENSE 采用**远端已发布版本**（署名 `413`，替换本地未推送草稿版署名 `aascc413-coder`——如需改回请告知，一行即可） |
| 远端 CI | **通过**：`investigation-tests` success（32s）+ `test` success（91s），所测 commit `e6c4473dcff4f30553dad68e5f3fab88955c60ed`（合并提交，含 `9f3719f`/`9ac5b0c`/`0bde2a9` 全部 M0 内容），[run 37136875969](https://github.com/aascc413-coder/sentinelkb-ai-security-agent/actions/runs/37136875969) |
| 阶段状态 | **已完成** |
| 实验结论 | 不适用（本里程碑无实验） |

用户决策记录：提交拆分为两个 commit（采纳建议方案）；推送未授权（待定）；`evals/reports/` 不入库（默认）。
