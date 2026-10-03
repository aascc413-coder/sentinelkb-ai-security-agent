# M3 通用工具组件独立复验

范围：通用工具实现，不替代正式 M3 五个 M2 案例的集成验收。未使用真实外部SOC系统或付费模型。

基础提交：`63fa8089845a05ad7e45d785b0adf081fa2dd52e`，修复工作区文件独立复制冻结至本目录，具体实现版本由下方 SHA-256 标识。旧目录 D:/project/Agent/m3-tools-independent-audit 的原失败源码、报告与日志保持不变。

## 结果

1. 原17项独立探针 + 当前32项 server 专项：49 passed。
2. 全部当前工具专项 + 原17项独立探针 + 4项补充探针：171 passed。
3. 冻结副本全部原始 hashes 复核一致，实际 import 路径由探针确认属于此副本。

## 缺陷关闭

- T1 / P1：原scope的process_id/user不同或更窄限制不能支持更宽/不同请求的complete empty，4项原失败均通过。资产coverage.as_of早于请求时降为partial，原失败通过。宽覆盖支持窄查询的原通过项仍通过。结果保留 source_scope，便于追溯覆盖依据。
- T2 / P2：等待共享锁使用调用剩余timeout，短时限调用及时返回timeout且无backend计费，原失败通过。

## 修复针对性检查

- EXAMPLE.TEST. 源scope与 example.test 查询规范化语义一致，合法TI响应仍为complete，并保留原source_scope。
- 资产source_scope声明未来as_of时降为partial，记录coverage_scope缺口。
- 被取消的锁等待不错误释放/永久拿走锁；首个backend完成后第三次请求正常命中缓存。
- 锁等待timeout不增加backend_calls或模拟费用，不妨碍后续缓存访问。
- 非法ctx、未来查询、歧义规则、partial empty、并发副本和内容hash保留的原独立通过检查全部仍通过。

## 冻结版本

| 文件 | SHA-256 |
| --- | --- |
| src/evidence_investigation/tools/signatures.py | `059e0c1acd560e429b91b156cbf5ba1ddbfa41a434a42a25d9ddd1d2b3d64332` |
| src/evidence_investigation/tools/selection.py | `016651842cc44ac8fd3b933180aed69d2732b41502f5b5a57766d343ad62b8e1` |
| src/evidence_investigation/tools/server.py | `19af72dee7792475888f6b187d1b08b85accabb568f3d0e05c86ebf143064034` |
| tests/test_tool_signatures.py | `1b1d6f4bd47dac3c22bb1eb99ebc73dedeb9bd0d6cb2dee3bf8a63e6c2c6e625` |
| tests/test_tool_selection.py | `f966d91f833aaa5d214218ba95f461e9dfe620098806cef6bae74343478dbc6a` |
| tests/test_tool_server.py | `55be88814fe1a0f50142ddb4e17e164cb717b4a589c8766c9daac12c254ba7b5` |

完整支撑包与原17项探针的hash见 snapshot.json；新增探针与复验日志/XML的hash见 evidence-hashes.json。基础SHA不包含未提交工作区修复，不将它误称为已远端验证代码。

## 命令

工作目录 D:/project/Agent/m3-tools-independent-retest：

```powershell
$env:PYTHONPATH = 'D:/project/Agent/m3-tools-independent-retest/src'
& 'D:/project/Agent/m3-independent-foundations/investigation/.venv/Scripts/python.exe' -m pytest test_independent_tools.py tests/test_tool_server.py -q --junitxml=retest.xml
& 'D:/project/Agent/m3-independent-foundations/investigation/.venv/Scripts/python.exe' -m pytest tests test_independent_tools.py test_followup_tools.py -q --junitxml=all-retest.xml
```

## 限制

这是人工构造的通用契约fixtures审查，不能证明正式C4/C5的模型可见输入与实际工具响应等价，也不能证明Agent研判效果或token成本改善。后续正式数据集适配需要单独验收。未修改实现源码、未提交或推送。
