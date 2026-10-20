# Rubric / normalization / ToolResult diff 独立复验

结论：**通过本次复核范围**。初版失败记录未删除或覆盖；R1–R4 均已修复并由原始/新增探针验证。

## 被测版本

- 副本：`D:/project/Agent/m2-rubric-diff-independent-review/retest/snapshot/investigation`。
- 来源：`D:/project/Agent/m3-independent-foundations/investigation`，复制时 Git HEAD `8f01f1fa22d7c0242793878a294176de425a283a`，新增代码待提交。以 `snapshot.json` 的 79 文件字节清单为准。
- `snapshot.json` SHA256：`e7bb8d9faf8ac0563cc40bf66120d44fd6b7faf5c6f3381fe499ea0d3de268d3`。
- rubric.py SHA256：`98ef4196e4dc9307b66d8b0e55bbd79642ab71bfb27f5f144ab58a442a733ead`，规则未改变。
- normalization.py SHA256：`11c47ab4c09218c91c03e492f9e66b5ffa549f7634b78d1f1829b1e780e8bca7`。
- diff_report.py SHA256：`acd7b47c8075e0f8b88730ae05423c15081004dae8ee9c4c506844da766ad736`。
- powershell-v1.json SHA256：`c40ec12911ab27a79c17d28ab0bc38bb4eeb136b009b41737632a6c1ddd75248`，规范不变。
- `import-provenance.json` 核实运行时实际导入独立副本，未使用作者最新工作区源码。

## 命令与结果

```powershell
$env:PYTHONPATH='D:/project/Agent/m2-rubric-diff-independent-review/retest/snapshot/investigation/src;D:/project/Agent/m2-rubric-diff-independent-review/retest/snapshot/investigation'
& 'D:/project/Agent/m3-independent-foundations/investigation/.venv/Scripts/python.exe' -m pytest tests/test_rubric.py tests/test_normalization.py tests/test_tool_diff_report.py 'D:/project/Agent/m2-rubric-diff-independent-review/probes.py' 'D:/project/Agent/m2-rubric-diff-independent-review/retest/extra_probes.py' -q --junitxml='D:/project/Agent/m2-rubric-diff-independent-review/retest/tests.xml'
```

**117 passed / 0 failed**：作者 rubric 14、normalization 33、tool diff 38，共 85；初版独立探针原样重跑 24；新增独立复验探针 8。

完整证据：`tests.log`、`tests.xml`、原 `../probes.py`、`extra_probes.py`。

## 修复核对

- R1：工具 call_id 存在业务值或业务键引用时保留；报告记录未应用规范化的原因和精确参考路径。左右任一侧有引用都锚定两侧。
- R2：工具响应检查对象键顺序，精确报告嵌套 payload 的 order 差异；仍保留数组、内容、覆盖、模拟成本/延迟的差异。
- R3：静态规范化在 encode 前递归拒绝非字符串键与循环引用；普通共享对象、合法 dataclass 输入仍可处理。
- R4：静态业务字典键参与锚定；跨文档 alert ID、raw record ID 的索引关系断裂可以发现；非引用的 envelope 动态 ID 仍允许按名单规范化。

rubric 为冻结、闭合的告警族规范，其加载不是运行时或评分 evaluator 的实现。源码版本和工具规范化规则 v2 均需随主实现验收快照记录；不能将旧 policy 指纹冒充新版本。

## 边界

不审查本人实现的 M2 loaders，其复验由另一代理承担。本复核不替代五案工具集成验收、M5 实际模型请求检查、M7 判定程序或真实模型实验。初始 94 pass / 3 fail 和补充 R4 的失败复现保留在上一级目录，不能写成首次即通过。
