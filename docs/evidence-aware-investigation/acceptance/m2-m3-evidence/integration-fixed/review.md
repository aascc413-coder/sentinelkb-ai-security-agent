# M2 数据摘要与 M3 五案联调独立复验

日期：2026-10-04（Asia/Shanghai）。m3_diff 接续原独立代理审查；审查主实现的 scripts、selection、合成数据和五案集成，不承担自身 diff_report.py 的实现审查（该模块另由 m2_loaders 独立复核）。

## 冻结与执行

原目录的初始 snapshot、官方 68 项通过日志、原始 18 探针（15 通过、3 失败）保留。中间复验存于 `../retest/`，最终再复制工作树 investigation 到本目录下 investigation，84 文件 SHA256 见 snapshot.json。

所有检查使用固定副本中的 src/evaluation/scripts/data，既有锁定虚拟环境仅提供解释器及依赖；通过 PYTHONPATH 与探针导入路径确认 source 来自本副本。复制原代理 probes.py 保持原始断言；新增独立 new_probes.py。

执行当前官方 seed、tool integration、selection 检查，原始 18 探针和新增检查：**99 passed**，零错误、零失败、零跳过。证据：`final-tests.log`、`final-tests.xml`。

## 原三项问题关闭

1. 隐藏世界事实被声明为 observable：summary 现在禁止 oracle_only 有公开 record 引用或进入 observable 集合，原 C4/E6 探针通过。
2. Annotation 标记 asset 却引用 SIEM 记录：summary 现在核对来源工具与 record 所属工具，原篡改探针通过；未知来源也被拒绝。
3. 未被 case mapping 使用的声明文件未核 hash：现在在映射前遍历所有声明文件校验原始字节，原 unused file 错 hash 探针通过。

并确认非结构化 annotation、非字符串 record 引用、虚构 unavailable reason、public/environment as_of 配对不一致都被拒绝。合法 unavailable envelope 仍作为可观察操作事实保留，不能当作攻击行为缺席。

## 接续审查发现的 selection 问题关闭

中间复验发现合法部分 TI 规则 `indicator_type=ip` 对 hash 请求 h-9 错误地重新解释请求值，抛 invalid_indicator。作者修复后原独立负例返回 False，当前同类规则与完整 type/value 规则检查通过；无关规则不再中断当前查询。非法时间条件不能借类型不匹配被跳过。

## 独立探针的一项断言修正

中间日志为 98 检查、96 通过、2 失败：一项为上述真实 TI 问题；另一项是审查者将“不同 process 查询”预期写成 partial。原 fixture source_scope 明确 process_id=None，表示完整 host 来源无进程限制，故返回 complete empty 正确。

未将该失败归咎于源码。中间 new_probes.py 与失败日志保留；最终副本中将该探针改为要求 empty/complete，并断言原 source_scope.process_id is None。这是修正不成立的测试假设，没有改变产品行为或隐藏初始结果。

## 已验证的联调行为

- 五案实际 SIEM/asset/history 状态符合设计，C3 history 明确 nonretryable unavailable。
- C1 六种查询顺序、镜像记录同事实/hash/group、独立网络 sensor、进程实例关联通过。
- C1 asset/history 替代授权检查共用完整时间范围和独立性来源，不伪造第二独立证据。
- `[start,end)`、截断、未知实体、缓存成本/延迟、短 deadline 及缓存后恢复通过。
- C4/C5 相同查询、反向顺序、缓存回放的业务响应、coverage 和模拟成本一致；回放报告 27 组代表查询全部相等。
- replay 不读取 oracle，不生成 verdict/ground_truth，不是模型基准。
- 作者构造器重建数据的字节与冻结版本完全一致。

## 包资源与说明

pyproject package-data 分别包含 state 和 tools 的 schemas/*.schema.json。rubric、datasets、evaluation 位于运行时包外，当前脚本显式读取仓库资源，未声称 wheel 自带完整 benchmark。

README 已修正实际三项直接运行依赖和 M2/M3 新增联调状态；M4 仍明确仅预算组件。`evaluation/（Phase 2.4 起创建）` 是遗留阶段描述，现已存在契约与 oracle loader，建议后续改为“指标与 evaluator 后续在此实现”；不影响工程验收。

## 关键指纹

| 文件 | SHA256 |
|---|---|
| scripts/dataset_summary.py | 08bca3e57bfb700873ab9bba216ab23f41061274154113fc6a34f6162894ec3f |
| scripts/replay_seed_tools.py | b746e1b5c7009734bfe1a104622792ec01351ea704b5e9bd011637555bb0f622 |
| scripts/build_seed_dataset.py | 8312f81fa88cb535c52a8941ebdc23f0324c28d4746e6286288a889ebafaf873 |
| tools/selection.py | 29b859bca92722cb4990a6b9fc57ae8d2ec75eee901e821486d7abe92e75d0b5 |
| datasets/manifest.json | 41de366715ada625f22fe136873fc43e66b20d386d973e9cf6d922d32b771a67 |
| pyproject.toml | 033176d37564be74dcf92e012a649f39abdee265a2facdf8be2c188ceb6607ce |
| README.md | 908e34714ba592f0f52f468ddf14416d6e16f90d2358d4e2065a229e865733f9 |
| snapshot.json | 6d741b5b774d4d8ecce02032be7fc855c6759804100f9b221ee9d1427e90bfcd |
| probes.py（原始） | f680173b0907d48f1911e011524eaee2d51dd8af2a7af1ea1e38b3d7a3edf91a |
| new_probes.py（最终） | e02ec2562543f20463337917a77800df091721de52bf1869b8c226572ed7be9b |

结论：本轮数据摘要/五案工具联调范围通过，无代码阻塞。测试是有限代表查询，不声称穷举；最终提交仍须同 SHA 双 CI。M5 实际模型请求边界检查和 Agent/evaluator 实现未由本轮代替。
