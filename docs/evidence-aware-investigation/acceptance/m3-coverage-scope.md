# M3 工具响应比较与测试范围

## 比较规则冻结

本规则在 C4/C5 实际响应比较前冻结。经独立审查修正引用与键序问题后，版本为 `tool-result-envelope-v2`，规范 JSON SHA256 为 `81d983ec1efd254c4098ec75321b80d7d4f4a71129321e123102cf0afb68c136`。运行时可通过 `normalization_policy()` 取得同一规则及指纹；保留初版失败记录，不扩充可忽略路径。

| 路径 | 处理 | 原因 |
|---|---|---|
| `/call_id` | 仅在任一侧业务键或值均未引用任一调用 ID 时使用相同占位值；否则保留并报告引用路径 | 不掩盖 envelope 与业务内容之间的身份关联变化 |
| `/actual_duration_ms` | 使用相同占位值 | 本机调度和实际测量时长可变化 |

这是一份封闭白名单；嵌套 payload/scope 中同名字段不受上述规则影响。报告保存原始值、处理原因和是否变化，不在看到响应差异后增加忽略项。

记录 ID、记录顺序、payload、hash、来源、独立性分组、可靠性、快照、时间、覆盖状态和范围、错误、重试、模拟费用与模拟延迟全部逐字段比较。尤其缓存命中造成的模拟费用与延迟变化必须报告差异。物理共享环境中不需要为记录 ID 建立重映射；将不同记录 ID 视为等价可能掩盖身份关系变化，因此本版本保留它们。若将来比较多响应 trace，需另立版本检查调用身份之间的引用关系，不能直接以本函数证明 trace 等价。

`compare_responses(left, right)` 只接受 ToolResult。输出 `equal`、`differences`、`difference_count`、`normalization_version`、`normalization_sha256`、`normalized_fields`、`normalization_exclusions` 和 `reasons`，差异使用转义后的 JSON Pointer。对象键序列和数组顺序均影响结果；缺失值与 null 不混同。非法类型、未知 envelope 字段和非法计量不被静默忽略。

## 代表性覆盖表

这是有限代表性测试，不能证明所有参数组合。下表描述通用模块的已有测试；五案实际回放及 C4/C5 响应报告由主集成验收另行归档。

| 范围 | 测试文件和代表性检查 |
|---|---|
| 五工具协议操作 | `test_tool_server.py::test_all_five_protocol_operations`：SIEM / TI / asset / history / ATT&CK |
| SIEM 筛选 | `test_tool_selection.py`：view、host、user、process、事件窗口、发布时间；`test_tool_server.py`：limit 截断及镜像记录来源分组保留 |
| History 筛选 | `test_tool_selection.py::test_history_combines_entity_optional_selectors_and_event_window` |
| TI 筛选 | `test_tool_selection.py`：IP/domain/hash 规范化、indicator 类型、发布时间；`test_tool_signatures.py`：IDNA、IP、hash 边界 |
| Asset 筛选 | `test_tool_selection.py::test_asset_selector_and_missing_publication`；server 中旧 as_of 无法证明当前完整缺席 |
| ATT&CK 筛选 | `test_tool_selection.py`：快照、technique/term 集合匹配、空条件快照查询及缺失匹配元数据 |
| 时间与未知字段 | `[start,end)`、未来记录不可见、发布早于发生为 unknown；缺失筛选字段降 partial；未知 constraint 拒绝 |
| 覆盖状态 | server 的 complete empty、partial、unavailable 区分；狭窄源范围不能声明宽查询完整缺席；完整源约束保留 |
| 错误状态 | error / timeout 可重试响应不缓存；永久 unavailable 可缓存但不能变成行为不存在；deadline 包括等锁时间 |
| 缓存和调用顺序 | `test_tool_server.py`：隔离变更、并发重复一次后端、缓存费用零；`test_tool_selection.py`：选择无状态 |
| 比较器防掩盖 | `test_tool_diff_report.py`：内容、记录身份/顺序/hash、source/reliability、coverage/as_of、cost/模拟 latency 篡改都报告；只有 envelope call_id/实际时长可归一 |
| 五案工具联调 | `test_seed_tool_integration.py`：实际过程/网络/批准记录及覆盖、C3 永久 history unavailable、C1 备用批准与镜像身份、混合 IP/hash TI 规则；`replay_seed_tools.py` 归档全部返回 |
| 双胞胎实际响应 | 同一共享物理环境，两台独立 server；27 组代表查询覆盖五工具、四 SIEM view、limit、事件边界、未知实体、history 实体种类、TI 种类、ATT&CK ID/term；正序与逆序/缓存重复比较 |

未覆盖全部 IOC 输入、任意 JSON 内容、所有规则交叠、操作系统调度序列、所有合法查询组合；不声称性质穷举或真实 SOC 集成。工具级等价不会替代 M5 实际模型请求边界验收，工程通过不会证明 Agent 研判效果更优。
