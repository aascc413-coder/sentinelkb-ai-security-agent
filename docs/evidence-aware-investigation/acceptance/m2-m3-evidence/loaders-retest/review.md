# M2 加载器独立复验

日期：2026-10-04（Asia/Shanghai），代理 m3_diff。复验他人修复 F1/F2，不包含自身 diff_report.py。

## 冻结与证据

重新复制源 investigation 到本目录下 investigation，84 文件指纹记录 `snapshot.json`；初审目录的快照、失败探针和日志未覆盖。复制原始 `test_review_probes.py` 不改断言，新添 `test_retest_probes.py`。PYTHONPATH 优先指向本次固定 src/evaluation，解释器及依赖使用既有锁定虚拟环境。

执行作者 loader 测试、导入守卫、原始全部独立探针、新增 6 检查，结果：**110 passed**，零失败、零错误。见 `retest-tests.log` 与 `retest-tests.xml`。

| 文件 | SHA256 |
|---|---|
| state/content.py | aa0a5b36130c390d6a43071ccb1cb58951dc4b4d20aa8c76f668c9b7f803a84e |
| evaluation/oracle_loader.py | 259180705a5ebca834ec730538da496ecd0dd893837fef154aa1db93a5854755 |
| tests/test_dataset_loaders.py | b464b8c5b35c99bbc683ea42efdc9941ac225e6b395413368a3205a28d71a9b6 |
| snapshot.json | cd34d9b264455a85e2c529f15f292094852e2df8affb8f841a01f6a4744b0a16 |
| test_retest_probes.py | 556f199310022366bf6b0dca93ce3000f7a3b94c8953a26372d63edcb5eebe72 |

## F1 关闭

原来四个 oracle 字段边界失败探针均通过。修复是在递归隐藏键集合中增加 expected_actions 和 resolvable_with_full_observable_evidence，public/raw 与 tool/payload 都拒绝它们。已有 TI 业务事实不受 malicious/benign 关键词过滤影响。

## F2 关闭

原来五个错误 ActionExpectation 约束探针均通过。修复依据公共 Query 契约做部分约束字段与类型校验，不导入 tools：整份约束须能被至少一个 acceptable tool 支持，不能逐字段拼接不同工具造出不可执行的标准。

新增独立检查通过：
- asset/history 的 host + entity + as_of 混合约束被拒绝。
- 真实 C1 的 asset/history、host=WS-041 替代授权检查继续被接受。
- 只适用于 history 的完整部分约束可被一个候选工具支持；交换工具次序不改变结果。
- 列表 host、无时区 as_of、含额外字段的 window 均拒绝。

## 实际数据与结论

原始独立正向检查继续通过：五公开告警、四物理环境、五 oracle 可加载；manifest 文件 SHA、一份共享 C4/C5 环境、公开双胞胎等价、原文/hash/opaque 引用保持、可见事实记录映射、schema 和导入边界均一致。

复验结论：F1/F2 已关闭，本轮 M2 加载器与数据边界范围通过。未声称完整 Agent/evaluator 已实现，未用五个 dev 样例推导性能结论；M3 响应及 M5 实际模型请求仍需要各自验收。
