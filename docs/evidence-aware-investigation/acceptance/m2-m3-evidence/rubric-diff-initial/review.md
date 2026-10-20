# M2 rubric / normalization 与 M3 ToolResult 差异报告独立复核

结论：**不通过，需修复后复验**。未修改作者源码或作者测试。

## 被测快照

- 来源：`D:/project/Agent/m3-independent-foundations/investigation`。
- 独立副本：`D:/project/Agent/m2-rubric-diff-independent-review/snapshot/investigation`。
- 来源 Git HEAD：`8f01f1fa22d7c0242793878a294176de425a283a`；本次新增内容尚未提交，实际被测文件以 `snapshot.json` 的 76 文件 SHA256 为准。
- `snapshot.json` SHA256：`455220603937fa0648ac715e3dff1d2b8602c6020b48ee4d22abdb39294a8cff`。
- 实際导入位置见 `import-provenance.json`，PYTHONPATH 指向独立副本。
- rubric.py：`98ef4196e4dc9307b66d8b0e55bbd79642ab71bfb27f5f144ab58a442a733ead`。
- normalization.py：`1f033af2d912bc0f22127bffe9fdcd84df3ba995cbea8d161888a87740137c52`。
- diff_report.py：`99f72f64d96c051dc76fa53ee6e60c36098da74b018df88aafa53ead1ce9d89c`。
- powershell-v1.json：`c40ec12911ab27a79c17d28ab0bc38bb4eeb136b009b41737632a6c1ddd75248`。

## 命令与实测

使用作者已有 Python 3.12 环境的依赖，源码从独立副本导入：

```powershell
$env:PYTHONPATH='D:/project/Agent/m2-rubric-diff-independent-review/snapshot/investigation/src;D:/project/Agent/m2-rubric-diff-independent-review/snapshot/investigation'
& 'D:/project/Agent/m3-independent-foundations/investigation/.venv/Scripts/python.exe' -m pytest tests/test_rubric.py tests/test_normalization.py tests/test_tool_diff_report.py 'D:/project/Agent/m2-rubric-diff-independent-review/probes.py' -q --junitxml='D:/project/Agent/m2-rubric-diff-independent-review/tests.xml'
```

- 作者测试：rubric 14 + normalization 25 + tool diff 34 = **73 passed**。
- 独立对抗探针：24 项，**21 passed / 3 failed**。
- 合计：**94 passed / 3 failed**。
- 原始结果：`tests.log`、`tests.xml`；探针完整源码：`probes.py`。

## 发现

### R1 [P1] call_id 规范化可隐藏真实引用关系变化

`tools/diff_report.py` 的 compare_responses 无条件清除顶层 call_id。探针构造左响应 call_id=`call-a`，payload 中 call_reference=`call-a`；右响应仅将顶层 call_id 改为 `call-b`。左侧引用与 envelope 对应，右侧不对应，checker 仍然返回 equal=True。

影响：工具响应等价检查可能掩盖字段关联变化；“只规范化动态 ID”不能授权破坏其与实际数据的引用关系。

建议：冻结明确的锚定规则，顶层 call_id 若出现在保留的业务字段中，必须保留原值参与比较；应用/未应用规范化的路径和原因应体现在报告中。勿递归删除业务字段。

### R2 [P2] ToolResult 比较遗漏 JSON 对象键顺序

`tools/diff_report.py` 的 _differences 对键集合排序后逐值比较，payload `{first:1,second:2}` 与 `{second:2,first:1}` 被判为相同。两者规范内容哈希相同，序列化顺序可能进入实际模型输入，state 的静态比较已明确检查对象键顺序，工具级检查却没有承接。

建议：报告对象键/顺序差异，继续保留详细字段差异。若未来模型输入明确采用统一规范序列化，另行冻结该序列化契约与验证，不能在当前未定义条件下直接忽略顺序。

### R3 [P2] 静态规范化静默转换非法 JSON 键

`state/normalization.py` 先调用 codec.encode，后者将字典键字符串化。环境 payload `{1:'value'}` 的非法键没有被拒绝，compare_static 可报告相同；非法输入被默默转换成另一份有效输入。

建议：在 encode 前递归拒绝非字符串字典键；不能借规范化掩盖输入类型错误。原始合法 JSON fixtures 的键均为字符串，本项为边界健壮性缺口。

## 已确认项

- 判定表为闭合、冻结的告警族规范，G0–G4、B1–B3 五列齐全。单独提供新文件哈希不能覆盖冻结语义摘要。
- 文件名带 case ID 不影响规则；未发现按特定案例、host、job 的判定分支。
- TP/FP gate 分组、三值门槛、硬预算 stop、冲突处理与实质风险模式有明确约定。
- 判定表加载不等于已经实现 sufficiency evaluator，作者代码与 scope 已正确声明这一边界。
- 静态比较保留 host、时间、原始 hash、业务内容、类型和对象/数组顺序；同一文档内 ID 相等与不等关系得到保留。
- compare_static 的跨文档业务锚定能发现 alert ID / raw record ID 与环境 payload/record 的链接断裂；未找到可绕过该锚定的合法业务引用样例。
- environment_id 与 alert_id 属于不同 envelope 名称空间，仅裸字符串相等本身不构成业务引用；未据此提出额外缺陷。
- 工具差异报告保留模拟成本、模拟延迟、覆盖范围、独立性组、状态、快照与嵌套业务 ID 差异；实测时长差异可按事先名单忽略。

## 复验与限制

复验准备另发现 R4 [P1]：静态 _business_strings 仅收集字典值，不收集业务字典键。public.alert_id=`a`，环境 record payload=`{a:'event'}`；右侧仅将 alert_id 改为 `b`，compare_static 仍报告 equal=True，隐藏了合法 JSON 索引键的引用关系变化。用初始冻结副本复现结果保存在 `extra-key-reference-initial.log`，此补充探针不混入前述 97 项的原始计数。已通知作者将非白名单业务字典键纳入锚定，并补回归。

修复 R1–R3 后应冻结新副本，重跑原始探针和作者回归，保存旧失败记录。此复核不验证 M2 加载器（由本人实现，交由另一复核者），不验收 M5 实际模型输入，也不代表算法效果或 M7 程序门槛已实现。
