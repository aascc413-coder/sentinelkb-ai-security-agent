# M8a 假模型工程验收契约

## 1. 目的与结论边界

M8a 验证五种方法能在同一公开数据、工具、预算和评分接口下完成运行、记录、
离线重放与汇总。模型是确定性假模型，token 数是固定合成值。五个案例都是开发
案例，因此 M8a 不产生算法优越性、真实模型质量、泛化能力或生产可用性结论。

M8b 真实模型探索仍未完成。真实模型调用涉及付费资源，继续遵守单独授权边界。

## 2. 运行矩阵

- 主矩阵：`direct / fixed / fixed_all / react / proposed × C1–C5 × 3`，75 runs。
- 预算冒烟：上述五方法和五案例在 `max_tool_calls=2/4/6/8` 各运行一次，100 runs。
- 每个 run 使用新的模型适配器、工具服务器、Registry、预算控制器和 opaque run ID。
- 重复只检查执行稳定性，不增加独立案例数。

假模型使用公共输出 Schema 响应实际请求。Direct、Fixed、Fixed-all 和 ReAct 采用
保守拒判策略；ReAct 的动作只读取公开 alert、Evidence 与预算使用量；Proposed 的
假设和充分性解释只读取传入的公开上下文及程序判定结果。Oracle、标注与语义案例
ID 只在 run 结束后的评测侧加载。

## 3. 归档结构

每批输出目录不可预先存在，旧批次不会被覆盖：

```text
artifact/
  config.json                 # 运行配置、版本和输入哈希
  inputs/                     # 数据、环境、oracle、rubric、标注、prompt、runner 快照
  runs/<cohort>/<run-id>/
    manifest.json
    events.jsonl
    final.json
    model-requests.json       # 实际 ModelAdapter 请求及完整性摘要
  reports/<cohort>/<method>.json
  reports/summary.md          # 仅原始计数和边界说明
  inventory.json              # 逐案例结果、Trace 定位、文件哈希
  checksums.sha256            # 全归档校验和
```

`inventory.json` 记录全部运行，包括失败运行；没有失败时显式记录失败数为零。
代表性 Trace 是完整归档中的索引，不复制或筛选运行来改变统计结果。

## 4. 重跑与重放

```powershell
# 在 investigation/ 下执行；output 必须是新目录
python -m benchmark.m8a run --output <new-artifact> --repeats 3

# 不调用模型或工具
python -m benchmark.m8a replay --artifact <existing-artifact>
```

重跑创建新目录和新批次，不覆盖旧运行。重放先验证所有 SHA-256，再从归档的
Trace、请求捕获、Oracle 和适用标注重新计算每个 run 与逐方法报告；重算结果必须
与已保存报告逐字段一致。

## 5. 标注与评分口径

- 冻结标注绑定完整默认 `Budget`，只在预算对象逐字段一致时应用。
- 非默认预算组不复用默认预算标签，相关指标保持 NA；不同预算分别汇总。
- Proposed 结束前的结构化充分性解释虽然使用 final token reserve，但不是
  `FinalAssessment` 提案，不能计入 final proposal error 指标。
- 全拒判、猜对但无充分证据、协议失败和工具失败都不能成为方法胜利指标。
- 报告保存原始分子、分母、逐案 verdict、失败状态和实际 Trace；不做统计推断。

## 6. 安全与限制

实际模型请求由 `CapturingModelAdapter` 深拷贝保存并在评测侧检查 Oracle 字段、
语义案例 ID、禁用来源与 canary。该机制验证当前结构化逻辑边界，不是操作系统
沙箱，也不覆盖自然语言中的所有潜在间接泄漏。

假模型的稳定表现只说明工程路径可复现。真实模型提示遵循、证据选择、费用、延迟
与校准均需在 M8b 或后续扩展数据实验中单独评估。
