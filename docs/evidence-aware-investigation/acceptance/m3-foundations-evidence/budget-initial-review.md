# M3 通用预算组件独立审查

这是准备组件的独立审查，不替代外部 AI 的 M2/M3 正式验收。

基础提交：`63fa8089845a05ad7e45d785b0adf081fa2dd52e`。审查源文件先复制冻结，再运行探针；未修改任何预算源文件。`git diff 63fa808 -- investigation/src/evidence_investigation/state/contracts.py` 无输出，预算组件引用已验收 M1 契约。

## 冻结 SHA-256

| 文件 | SHA-256 |
| --- | --- |
| budget.py | `9c1819392d4910edacb5cd5751eb7f5fad308f1b02266c503f8b553e84615f5f` |
| runtime-init.py | `aa62f2c64a306fd6d67527bdb3706a442facf1083622eb20ade11a1bb030470a` |
| test_budget.py | `819738c54dd8d53b0875402ccb8b364ac8a271b1c4e233456d5cd49da42a805c` |
| M1 state/contracts.py | `062fc6647467e7f533242b6cb347f6d5f6b58813796320e002b46486a7152a19` |

正式组件测试 16/16 通过；新增独立探针 11 项，6 失败、5 通过。独立探针通过 importlib 装载本目录的冻结 budget.py，避免后续修改改变结果。正式测试引用工作区版本，运行后确认 hash 仍与冻结版本一致。

## 问题

### B1 / P2：有限费用累加后可变成 Infinity

两次 backend ToolResult 的 simulated_cost_units 各为 `1e308`，分别通过 finite 检查，累积账本却为 Infinity。两个 model Usage 的 model_cost 各为 `1e308` 也会使 model_cost=Infinity。随后 M1 codec.encode(snapshot) 拒绝结果，Trace 无法保存。这是极端数值边界，正常模拟费用不会触发，但协议目前允许这些输入。

复现：`test_tool_aggregate_cost_stays_finite`、`test_model_aggregate_cost_stays_json_encodable`。

建议：对累计结果也校验有限性；异常路径必须保证 pending 调用可以保守结算，不能先污染账本再抛异常。

### B2 / P2：未消费的 Usage 字段可以破坏 Trace 契约

reconcile_model 仅检查 input/output tokens、usage_complete、model_cost、currency，然后 `replace(actual_usage)` 整体保存在 TokenPlan.actual_usage。因此 `Usage(model_calls=True)` 被接受，但 M1 decode 不接受布尔整数；`Usage(tool_cost_units=NaN)` 被接受，M1 encode 失败；`Usage(elapsed_ms=-1)` 被接受，Trace 带非法负计量。

复现：`test_accepted_provider_usage_remains_m1_decodable[bad0/bad2]`、`test_negative_unconsumed_usage_fields_are_rejected`。

这些额外字段没有修改主账本计数，但会损坏对账结果的序列化或语义。建议对完整 Usage 做严格类型及非负有限检查，或定义明确的 provider usage 投影并记录拒绝字段；不要保留未经验证的完整对象。

### B3 / P2：伪 ToolResult 可进入工具对账

record_tool_result 接受 `SimpleNamespace(simulated_cost_units=1.0, simulated_latency_ms=1)`，账本将其计为一次真实 backend 调用。类型注解不会进行校验。上层 server 若严格验证可以挡住，但组件独立使用时无该保证。

复现：`test_fake_tool_result_rejected`。

建议：至少检查完整 ToolResult dataclass 类型及 M1 编解码类型；错误结果应允许调用者以 None 保守收尾。

## 已证实正常

- 缓存命中收取 tool attempt，计入 cache_hits，不计 backend_calls、工具模拟费用或模拟延迟。
- 非法 input_tokens=True 被拒绝后，同一个 plan 可通过 reconcile_model(plan,None) 恢复；保留 reservation 且 usage_complete=False，没有永久死锁。
- deadline 后仍能结算迟到结果，记录 after deadline，保持终止；不重新开放下一步。
- max_investigation_steps=0 时 begin_step 被拒绝。
- max_tool_calls=0 不阻止 tool-free 模型调用。
- 缺失 usage 保留 None 和预算 reservation，而非把测得 tokens 写成 0。
- 额外调用方责任：必须调用 begin_step 才能受 step limit 约束；必须在异常后执行保守结算。组件不主动中断 backend，调用者需使用 remaining_timeout_ms。

## 未列为确定缺陷的观察

backend_called=True 但 result=None 时，计数真实增加而工具费用/延迟保持现有已知合计；组件没有单独的工具费用完整性字段。后续报告应把这称为“已知模拟费用合计”，不能宣称失败后端必然免费。是否增加完整性字段需要结合 M4/M7 的统一计量协议决定。

## 命令与证据

```powershell
& D:/project/Agent/m3-independent-foundations/investigation/.venv/Scripts/python.exe -m pytest D:/project/Agent/m3-budget-independent-audit/test_budget.py -q
& D:/project/Agent/m3-independent-foundations/investigation/.venv/Scripts/python.exe -m pytest D:/project/Agent/m3-budget-independent-audit/test_independent_budget.py -q
```

本目录保存 snapshot.json、official.log/xml、probes.log/xml 和独立探针源码。探针失败反映冻结版本风险，不作为 M2/M3 已通过验收的证据。
