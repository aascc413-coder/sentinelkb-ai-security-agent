# Evidence-Aware 调查实验包（investigation/）

SentinelKB 的独立实验包：实现"带调查预算和拒判机制"的安全告警调查策略实验
（证据感知调查 Agent、Mock 工具环境、四方法对照基准）。

设计、契约与实施计划见 [`docs/evidence-aware-investigation/`](../docs/evidence-aware-investigation/)：

- [Phase 1 设计](../docs/evidence-aware-investigation/phase-1-design.md)
- [实施计划（v6）](../docs/evidence-aware-investigation/phase-2-implementation-plan.md)

## 边界

- 与产品代码 `code/python/` **零依赖**：不导入 LangGraph、Neo4j、ChromaDB 或任何产品模块。
- 运行依赖仅 `jsonschema` + `httpx`，版本以 `requirements-lock.txt` 锁定。
- 评测代码在包外 `evaluation/`（Phase 2.4 起创建），物理上不被本包导入（逻辑隔离）。
- CI 使用独立 job（`investigation-tests`），干净环境只安装本包自身依赖。

## 本地开发

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
  datasets/                 # M2：public / environment / oracle / rubrics
  tests/                    # 各里程碑测试
  runs/                     # 运行产物（trace、manifest），默认不入库
```
