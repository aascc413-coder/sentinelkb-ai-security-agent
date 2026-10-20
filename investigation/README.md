# Evidence-Aware 调查实验包（investigation/）

SentinelKB 的独立实验包：实现"带调查预算和拒判机制"的安全告警调查策略实验
（证据感知调查 Agent、Mock 工具环境、四方法对照基准）。

设计、契约与实施计划见 [`docs/evidence-aware-investigation/`](../docs/evidence-aware-investigation/)：

- [Phase 1 设计](../docs/evidence-aware-investigation/phase-1-design.md)
- [实施计划（v6）](../docs/evidence-aware-investigation/phase-2-implementation-plan.md)

## 边界

- 与产品代码 `code/python/` **零依赖**：不导入 LangGraph、Neo4j、ChromaDB 或任何产品模块。
- 运行依赖为 `jsonschema`、`httpx`、`rfc3339-validator`，版本以 `requirements-lock.txt` 锁定。
- 评测代码在包外 `evaluation/`，已含契约与 oracle loader；指标/evaluator 待 M5，实现包不导入它（逻辑隔离）。
- CI 使用独立 job（`investigation-tests`），干净环境只安装本包自身依赖。

## 本地开发

通用工具和预算组件的历史交付见 [组件记录](../docs/evidence-aware-investigation/acceptance/m3-foundations-acceptance.md)。本次新增 M2 数据与 M3 五案联调见 [验收记录](../docs/evidence-aware-investigation/acceptance/m2-m3-acceptance.md)；M4 仍仅完成预算组件。通用离线演示：

```powershell
investigation\.venv\Scripts\python.exe investigation\scripts\demo_tools.py
```

使用本包自己的虚拟环境（不入库）：

```powershell
py -3.12 -m venv investigation\.venv
investigation\.venv\Scripts\python.exe -m pip install -r investigation\requirements-lock.txt
investigation\.venv\Scripts\python.exe -m pip install -e "investigation[dev]"
investigation\.venv\Scripts\python.exe -m pytest investigation\tests -q
```

依赖变更后重新生成锁定文件（在装有包的 venv 中执行）：

```powershell
investigation\.venv\Scripts\python.exe -m pip freeze `
  | Select-String -NotMatch "evidence-investigation", "^-e" `
  | Set-Content investigation\requirements-lock.txt
```

## 目录（随里程碑逐步创建）

```
investigation/
  pyproject.toml            # 包定义，依赖锁定见 requirements-lock.txt
  src/evidence_investigation/
    state/                  # M1：运行时侧契约与校验
    tools/                  # M3：Mock 工具环境
    runtime/                # M4：公共 Registry、预算、Dispatcher、Trace、模型适配
    agents/                 # M7：Proposed 方法
    baselines/              # M6：Direct / Fixed / ReAct
    prompts/                # M6：提示模板与版本
  evaluation/               # M5：指标、独立评分、回放（包外，不被 Agent 导入）
  datasets/                 # M2：public / environment / oracle，manifest 仅开发/评测侧
  rubrics/                  # M2：冻结的告警族门槛，M5/M7 后续共同引用
  tests/                    # 各里程碑测试
  runs/                     # 运行产物（trace、manifest），默认不入库
```

## 五案数据与工具回放

```powershell
investigation/.venv/Scripts/python.exe investigation/scripts/dataset_summary.py
investigation/.venv/Scripts/python.exe investigation/scripts/replay_seed_tools.py
```

第一条验证数据、哈希、oracle 引用和双胞胎静态输入；第二条保存五案实际工具
响应及27组代表查询的差异报告到 `investigation/runs/`。它们没有调用模型或
生成研判结论，不是算法比较。数据边界见 [datasets/README.md](datasets/README.md)。
