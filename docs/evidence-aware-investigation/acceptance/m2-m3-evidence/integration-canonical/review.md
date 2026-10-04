# M2/M3 主实现最终独立验收：canonical E4 版本

日期：2026-10-04（Asia/Shanghai）。辅助代理 m3_diff 审查主实现的合成数据、作者重建器、摘要器、TI 规则选择修复、工具回放及说明。自身 diff_report.py 的实现另由 m2_loaders 独立复验，本报告只使用其已审接口验证五案联调。

## 冻结范围与执行结果

固定副本含 investigation 84 个文件，以及三份当前计划/验收/覆盖文档，全部原始 SHA256 见 snapshot.json。作者后续 CI 状态变更属于新元数据，不冒充本次已读文档。通过 PYTHONPATH 与 probes 的 frozen import 检查，执行的是本目录中的 src、evaluation、scripts 和 datasets；解释器及锁定依赖复用既有环境。

当前官方 seed、tool integration、selection 检查 + 原独立代理 18 探针 + 接续 9 检查 + canonical 7 检查：**107 passed**，零失败、零错误、零跳过。完整记录 `canonical-tests.log`、`canonical-tests.xml`。此前三项初审失败、一次 TI 残余问题和审查者错误断言的日志全部保留在父目录和两个历史 retest 中，解释见 `../final-retest/review.md`。

## canonical E4 修正成立

独立确认：

- C1 完整世界、observable、critical 和动作条件中均没有 E4H。
- critical 集合只有 E1、E2、E4；摘要分母为 3。
- TP 充分组合只有 E1/E2/E4；FP 无组合。
- E4 包含 asset 与 host/user history 的原始记录引用；source_tools 严格声明 asset/history。
- 所有 E4 获取路径记录具有同一 independence_group、同一 host、相同 approved_jobs 和完整活动时间范围，没有被冒充为多份独立事实。
- expected action 保留 asset/history 两种可接受获取途径，缺失条件统一 E4；获得其一后不会因 E4H 缺失重复奖励。
- 新摘要校验拒绝 source_tools 缺项、额外工具、空数组、重复工具、未知工具、字符串代替列表六种负例，且要求工具集合与实际引用记录所属集合精确一致。

该修正只调整作者/评测 annotation；公开告警和环境原始业务记录没有被改写成案例答案。开发侧 manifest/构造器可以持有语义 case ID，运行时 loader/server/selection 不据此分支输出判定。

## 其他已关闭问题与联调

- 原摘要三项失败均已关闭：hidden world 不可声明 observable；annotation 来源必须匹配记录工具；未被 mapping 访问的声明文件也核对 hash。
- TI 类型部分约束不再把 hash 请求值误解析为 IP；原负例返回 False，完整 type/value 规则继续正确。
- 非结构化 annotation、错误引用类型、虚构失败 envelope reason、未知 source、public/environment as_of 配对错误均拒绝。
- 五案观测状态、C1 镜像同事实/来源、独立网络证据、六种查询顺序、批准替代路径、C3 永久 history unavailable、空集/缺失/截断/缓存和 deadline 通过。
- C4/C5 27 组代表查询，以及反向/缓存/timeout 检查通过；回放不读取 oracle，不生成最终 verdict，不是 Agent benchmark。
- 作者构造器重建所有数据文件及 manifest 的原始字节与本次冻结数据一致。

## 包资源与文档检查

state 与 tools 的 package-data 均声明 schemas/*.schema.json；datasets、rubric 和 evaluation 在运行时包外，脚本从仓库路径读取，不声称 wheel 自带实验数据。README 依赖列表及 M2/M3 新增范围正确。

计划与验收说明保留“待提交/待同 SHA 双 CI”状态，M4 仅预算组件，未声称算法改进。工具规则文档的 v2 指纹及身份/键序约束与实现一致。

两项非阻塞文字收尾：验收副本仍为旧全包计数 446，作者已报告新全包 447，提交前应与最新 log/XML 对齐；README `evaluation/（Phase 2.4 起创建）` 是历史措辞，宜说明契约/loader 已存在、指标/evaluator 后续实现。它们不改变已审源码。

## 关键指纹

| 文件 | SHA256 |
|---|---|
| scripts/dataset_summary.py | 73690a5a2295beb3bedeb7d3ee27f65f20ca7a75ab2d07ac64d239913adc9f2e |
| scripts/build_seed_dataset.py | 10a582d135ca4a2746dfca99cc276a9bbd312a9f7e16cd413645a39da96cd1f7 |
| tools/selection.py | 29b859bca92722cb4990a6b9fc57ae8d2ec75eee901e821486d7abe92e75d0b5 |
| datasets/oracle/c1.json | 52ab5dfefdc1e1f7ce57541d44f9f257e17c65878aa7b6efe818fbcb24cda796 |
| datasets/manifest.json | ebfde18c250328ed475b1f2b8187254223a407304f038c8a39c9d940dec066fd |
| snapshot.json | b27791e02e0350527ec8d1ab91a3ed742bbcc758c9f4cdd36e730da47d7f5be2 |
| canonical_probes.py | 23db901bc7613e85726e5e546fbea114fcd5ae1b05e8fdda5856abdde9e49c0c |

结论：本轮主实现的数据/摘要/selection/五案工具联调范围通过，无代码阻塞。最终提交仍须精确核对两个远端 job 与被测 SHA；本地工程结果不证明优于基线，不替代 M5 实际模型请求边界或未来 Agent/evaluator 验收。
