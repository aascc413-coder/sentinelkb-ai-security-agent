# M1 独立技术复核

版本说明：本报告记录 v1 的历史检查。相关修复已由主实现合入 v3；当前状态与证据见 [M1 验收说明](m1-acceptance.md)。

日期：2026-10-04。范围：M1 契约分区、编解码、确定性校验、模型输出 Schema、导入边界守卫。

## 结论

**当前版本不建议通过 M1 技术验收。** 独立安装、已有测试和演示均通过，但新增检查复现了嵌套 JSON 解码失败和导入边界漏检，直接影响 M2 数据集加载与后续 Agent 的数据边界。应先修复这两类问题，再处理数值、查询参数和字典键的校验缺口。

这是一份技术复核意见，未替用户作出人工验收结论，没有修改阶段状态、提交或推送。

## 版本与复现结果

- 基础提交：`2a31d90`；M1 尚未提交，不能将该提交号单独当作 M1 版本。
- 独立副本：`D:/project/Agent/m1-contract-audit`。从主工作区逐文件复制 M1 内容，保存 26 项文件的完整 SHA-256 和采集时间，见 `m1-audit-evidence/source-snapshot.json`。
- 复核结束时，这 26 项主工作区文件与被测快照一致，见 `source-drift.json`。之后新增的 `m1-acceptance.md` 已阅读，但不在被测代码快照内。
- 新建 Python 3.12.10 环境，使用 PyPI 安装锁定依赖，再执行 `--no-deps` editable 安装；安装成功，`pip check` 无冲突。

| 检查 | 实际结果 |
|---|---|
| 现有 M1 测试 | 54 passed |
| 校验演示 | 7 项非法输入全部 REJECTED |
| 独立边界检查 | 20 项：2 passed / 18 failed |

18 次失败对应下表八类问题，其中包括参数化的重复场景及后续阶段接口检查；不能表述为 18 个独立缺陷，也不能据此计算产品准确率。测试专门覆盖已发现的边界风险，不代表全部可能输入。

## 问题清单

| 编号 | 优先级与处理阶段 | 问题 | 独立检查失败数 |
|---|---|---|---:|
| M1-A1 | P1，M1 修复 | 嵌套 JsonValue / Alert 无法解码 | 4 |
| M1-A2 | P1，M1 修复 | 导入守卫漏掉完整模块名、相对导入与 Agent 环境契约引用 | 4 |
| M1-A3 | P2，M1 修复 | float 解码拒绝合法 JSON 整数 | 1 |
| M1-A4 | P2，M1 修复 | 非负成本检查接受 NaN / Infinity | 2 |
| M1-A5 | P2，M1 修复 | 查询接受非法 limit 与无实体范围 | 3 |
| M1-A6 | P2，M1 修复 | typed dict 忽略键类型 | 1 |
| M1-A7 | M1 明确接口；转换可由 M4 实现 | 最终模型输出和运行时对象结构不一致，缺少明确转换约定 | 2 |
| M1-A8 | 已约定 M4 承接 | Schema 允许工具名与参数类型错配 | 1 |

### M1-A1：嵌套 JSON 无法解码

位置：`state/codec.py` 的联合、容器分支和 `state/contracts.py` 的递归 JsonValue 定义。

最小复现：

```python
codec.decode(JsonValue, {"process": {"pid": 123}})
```

实际：抛出 `decode_type_mismatch`。真实契约的 `Alert.raw` 中放入嵌套事件和列表后，`decode(Alert, encode(alert))` 同样失败。现有测试只使用浅层对象和标量。

原因：递归类型中的字符串 / ForwardRef 没有被递归解析。影响范围包括 Alert.raw、ToolRecord.payload、Trace payload 和 oracle 的世界证据。

建议：对递归 JsonValue 使用专门的递归 JSON 校验 / 还原分支，或正确解析受控 ForwardRef；保持 bool、int、float、null 的区别。新增真实契约的深层对象 / 列表往返测试。

### M1-A2：导入守卫不能兑现声明的边界

位置：`tests/test_import_boundaries.py:23` 起。

守卫仅保留顶层模块名，`evidence_investigation.tools.contracts` 被压缩为 `evidence_investigation`；所有相对导入被压缩为 `<relative>`。在独立临时目录中注入以下违规，现有守卫均未报错：

- state 模块：`from evidence_investigation.tools.contracts import EnvironmentFixture`。
- state 模块：`from ..tools.contracts import EnvironmentFixture`。
- agents 模块：导入上述环境契约。
- evaluation 模块：导入上述环境契约。

当前的 `import evaluation` 演示只能证明一种写法被发现。没有证据表明现有源码已发生标签泄漏；这里证明的是守卫发现能力不足。

建议：保留完整模块名，结合当前模块路径解析相对导入，再按目录和目标模块判断。对 agents 与 baselines 明确禁止环境契约，同时允许未来按设计引用运行时工具协议；不要简单禁止所有 tools 导入。将违规样本放入测试的临时目录，无需让用户临时修改正在开发的源码。

### M1-A3：合法整数不能解码为 float

位置：`state/codec.py:86` 起。

`decode(float, 1)` 被拒绝。JSON Schema 的 number 包含整数，模型可以合法输出 `p_attack=1`，日志也可能将零成本序列化为 `0`；这些数据不能因 Python 字面量类型不同而失败。

建议：float 字段接受 int / float 并转换为 float，继续拒绝 bool；int 字段保持严格整数规则。

### M1-A4：成本检查接受非有限数

位置：`state/validation.py:53` 起。

`require_non_negative(float("nan"), "cost")` 和 Infinity 均被接受。NaN 可让大小比较失效，并且不能作为标准 JSON 数值稳定保存。

建议：非负数同时要求 `math.isfinite`；明确 encode / decode 和模型 JSON 解析如何拒绝非标准数值。这里没有要求提前实现 M4 的预算控制器。

### M1-A5：查询校验范围不足

位置：`state/validation.py:103` 起。

实际被接受：SIEM 的 `limit=51`、`limit=1.5`、host / user 均缺失的 host_events 查询。设计稿第 7 节要求限定实体和结果上限 50，公共 Schema 自身也把 limit 限定为整数 1–50，当前 Python 校验与其不一致。

建议：按具体 Query 类型校验 limit 类型、范围和实体条件。SIEM / history 的最大窗口、实体是否属于 alert / 已获事实等也要明确最终检查入口；后者由 M4 Dispatcher 承接，不要求 M1 访问尚未实现的 Registry。

### M1-A6：字典键类型没有检查

位置：`state/codec.py:137` 起。

`decode(dict[ToolName, int], {"hidden_tool": 1})` 成功。实现丢弃 `_key_tp` 并把所有键转换成字符串，因而 EnvironmentFixture.records_by_tool 的工具枚举键没有得到校验。

建议：按声明的键类型解码 / 验证；禁止通过字符串化静默接受未知键或合并不同原始键。

### M1-A7：模型 DTO 与运行时对象需要显式转换

位置：`state/schemas/final_assessment.schema.json` 与 `state/contracts.py:381` 起。

- Schema 允许仅含 verdict、disposition、stop_reason、claims、final_evidence_ids 的输出，但 `decode(FinalAssessment, output)` 因缺少 p_attack 等字段失败。
- 完整 FinalAssessment 经 encode 后，Schema 又因额外的 `confidence_status` 字段拒绝。

模型输出与运行时对象可以使用不同结构，这本身不构成错误。当前问题是没有明确 DTO、缺省值和转换接口，验收材料容易让后续开发误以为二者可直接共用。

建议：M1 固化 ModelFinal / FinalAssessment 的映射说明，明确哪些字段由程序补充；M4 如负责转换，就增加对应任务。若选择统一结构，则同步 Schema 和 dataclass。上述两项探针的直接转换预期只适用于统一结构方案，选择显式适配方案时应改为验证适配器。

### M1-A8：工具名与参数错配是已登记的后续检查

公共动作 Schema 接受 `tool="siem"` 配 Asset 参数，公共 ToolCall 的解码也不会自动关联工具名与参数联合分支。

`m1-acceptance.md` 已明确 M4 Dispatcher 会补类型匹配检查，因此**本项不单独阻断 M1**。建议 M4 用完整工具映射表验证，并同时覆盖 Proposed 的 candidate.call。若提前加强 Schema，也必须四方法共用同一规则。

## 交给契约实现方的修复顺序

1. 先修 M1-A1 的递归 JSON 和 M1-A2 的守卫，避免 M2 数据加载和边界检查建立在错误前提上。
2. 修 M1-A3 / A6 的类型解码，M1-A4 / A5 的数值与参数校验。
3. 固化 M1-A7 的模型 DTO 转换约定；保持 M1-A8 的 M4 检查任务。
4. 把相关独立用例移入正式测试，避免只增加单函数的正例。
5. 在干净环境复跑原有测试、新增回归和演示；更新完整文件快照及验收说明，明确修复影响的验收项。
6. 再由用户人工验收，通过并完成规定的远端验证后进入 M2。

`m1-acceptance.md` 尚有两处材料问题：Schema 六个哈希未逐一绑定文件名；54 项测试的分项数字相加不足 54。锁文件实际有 21 项依赖，而接口变更记录写 20 项。建议用机器生成清单修正，避免手写计数。

## 测试材料与执行

证据位于本报告旁的 `m1-audit-evidence/`：文件快照、安装与测试日志、JUnit XML、演示日志、测试汇总，以及可交接的 `test_m1_independent.py`。

对本次被冻结的副本运行：

```powershell
$env:M1_AUDIT_ROOT = 'D:/project/Agent/m1-contract-audit'
$env:PYTHONIOENCODING = 'utf-8'
& 'D:/project/Agent/m1-contract-audit/.audit-venv/Scripts/python.exe' -m pytest 'D:/project/Agent/sentinelkb/docs/evidence-aware-investigation/acceptance/m1-audit-evidence/test_m1_independent.py' -q
```

此命令预期在当前快照上显示 18 failed / 2 passed；失败正是待修复问题的复现证据。修复后应在安装了修复版本的环境中测试，并将 M1_AUDIT_ROOT 指向该版本的仓库。不要使用仍安装冻结旧版本的环境证明新版本已修复。

本次没有修改另一个 AI 的契约、指标、测试或验收文件；只新增独立报告与证据。未实现 M2 数据集、M4 运行时或 M5 指标，也未进行 Agent 策略实验。
