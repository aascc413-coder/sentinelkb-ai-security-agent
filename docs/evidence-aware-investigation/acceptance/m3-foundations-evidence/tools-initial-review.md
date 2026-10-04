# M3 通用工具组件独立审查

此审查只验证通用实现，不替代外部 AI 的 M3 正式五案验收。M2 fixtures 尚未实现或接入本审查，不对 C4/C5 的实际案例等价性作结论。

基础提交：`63fa8089845a05ad7e45d785b0adf081fa2dd52e`。在独立目录复制完整 src 支撑包和三份专项测试，记录 snapshot.json；通过 PYTHONPATH 强制加载副本，新增 test_explicitly_frozen_source_is_loaded 断言实际 server 路径属于副本。未修改实现源文件。

## 结果

- 官方工具专项测试：144 passed。
- 独立探针：17 项，6 failed / 11 passed。
- 6 个失败属于以下两组问题。

## T1 / P1：可选过滤与查询时间的覆盖范围被扩大

位置：server.py 的 _response，当前 covered 仅检查 anchors。SIEM anchors 不包括 process_id/user；Asset 不包括 as_of。然后响应 scope 被重写为请求参数，原先局部覆盖消失。

可复现的失真：

1. 原 scope 为 host=H, view=network_events, process_id=p1；请求 p2，结果却是 complete empty。
2. 同一原 scope，请求 process_id=None（整台主机），结果仍 complete empty。
3. 原 scope 增加 user=u1；请求 u2 或未指定 user，结果均 complete empty。
4. 资产档案 scope.as_of 比请求 as_of 早一天，结果仍 complete empty。

这会让只覆盖其他进程、其他用户或较早快照的空结果被解释为当前调查范围没有相关行为，影响安全研判的阴性证据可靠性。

对应探针：test_restricted_optional_scope_cannot_assert_complete_absence 的四个参数，test_asset_older_coverage_cannot_assert_complete_current_absence。

修复建议：证明原 scope 覆盖请求的全部语义维度，再允许 complete。未指定/None 的原 scope 可视为宽过滤；原 scope 的非空限制不能支持不同限制或未限制的请求。按 UTC 时间语义验证 as_of 覆盖。不能证明覆盖时返回 partial/unknown，保留原因；可以返回有效正证据，但不能推导完整阴性。不要简单强制所有scope键逐字相等，因为宽覆盖应支持更窄请求，时间表示也可能等价。

## T2 / P2：等待共享锁没有请求超时上限

位置：server.py 的 _invoke，使用 async with self._lock，只有取得锁后检查 remaining。

第一个调用持有锁等待 sleeper；第二个调用 remaining_timeout_ms=10，但等待 80 ms 仍未返回工具 timeout，被外层 wait_for 超时取消。取得锁后检查 deadline 可以避免迟到证据，却不能约束锁等待耗时，单次调用可能阻碍总预算的及时终止。

对应探针：test_lock_wait_respects_shorter_call_timeout。

修复建议：acquire 使用请求剩余 deadline 的 asyncio timeout/wait_for。锁等待超时返回 ToolResult(timeout, deadline_exhausted)，不增加 backend_calls、不产生 backend 模拟费用，必须防止取消路径错误释放别人的锁。缓存重复请求仍应只执行一次 backend。

## 已通过的独立检查

- 宽 host/view 覆盖允许更窄 process 查询。
- 缺失可用性时间的潜在匹配记录被排除时保持 partial，不变成 complete empty。
- 布尔 timeout、空 run_id、非 UTC as_of、不同冻结 as_of、伪上下文在 backend 前拒绝。
- 请求未来窗口在 backend 前拒绝。
- 同等具体度规则歧义连续两次拒绝，不缓存猜测。
- 并发重复查询只执行一次 backend；两个返回记录副本隔离、未修改副本的 hash 与正文一致。
- 官方专项测试还覆盖规范化签名、limit 截断、失败/timeout 不缓存、永久 unavailable 区别、timeout=0 阻止缓存返回、原 fixture/hash 防篡改等。

## 冻结文件

| 文件 | SHA-256 |
| --- | --- |
| src/evidence_investigation/tools/signatures.py | `059e0c1acd560e429b91b156cbf5ba1ddbfa41a434a42a25d9ddd1d2b3d64332` |
| src/evidence_investigation/tools/selection.py | `016651842cc44ac8fd3b933180aed69d2732b41502f5b5a57766d343ad62b8e1` |
| src/evidence_investigation/tools/server.py | `09e90ebe490c72d190f57a14f7df67c2a3f6283341a73a4da9e2bcf9c545f33a` |
| tests/test_tool_signatures.py | `1b1d6f4bd47dac3c22bb1eb99ebc73dedeb9bd0d6cb2dee3bf8a63e6c2c6e625` |
| tests/test_tool_selection.py | `f966d91f833aaa5d214218ba95f461e9dfe620098806cef6bae74343478dbc6a` |
| tests/test_tool_server.py | `6dfa141c0921793ef12e487803d4119cc57c30de094fa75e56a1567c95a26f4a` |

完整支撑包的 hashes 见 snapshot.json。源 freeze 不包括后续修复。

## 可复现命令

```powershell
$env:PYTHONPATH = 'D:/project/Agent/m3-tools-independent-audit/src'
& 'D:/project/Agent/m3-independent-foundations/investigation/.venv/Scripts/python.exe' -m pytest tests -q --junitxml=official.xml
& 'D:/project/Agent/m3-independent-foundations/investigation/.venv/Scripts/python.exe' -m pytest test_independent_tools.py -q --junitxml=probes.xml
```

工作目录 D:/project/Agent/m3-tools-independent-audit。保存 official.log/xml、probes.log/xml、独立探针源码与原始冻结源码。没有付费模型调用或真实安全处置。
