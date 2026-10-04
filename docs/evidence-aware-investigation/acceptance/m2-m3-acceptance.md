# M2 数据层与 M3 五案工具集成验收

日期：2026-10-04。当前状态：本地自检与独立复核通过，待远端验证；提交后核对同一 SHA 的
`test` 和 `investigation-tests`，通过前不标完整里程碑完成。授权依据为用户
2026-10-04 的持续开发授权；没有付费模型调用、发布或真实安全处置。

## 交付能力

| 阶段 | 本次完成范围 | 不包含 |
|---|---|---|
| M2 | 5 public、4 物理 environment、5 oracle；闭合 Schema、语义校验、opaque ID；冻结 PowerShell G0–G4/B1–B3 五列门槛；双胞胎静态等价；摘要与作者重建命令 | M7 运行时充分性程序、M5 实际模型请求检查 |
| M3 | 已审查通用服务接入五案；实际回放；镜像记录身份/独立性保留；覆盖/缺失/空集、缓存与截断；冻结响应比较器及 27 组代表查询报告 | 真实 SOC、完整参数穷举、Agent 策略效果 |
| M4 | 此前已交付预算组件继续保留 | Registry、Dispatcher、Trace、模型适配仍待实现 |

判定表位于 `investigation/rubrics/powershell-v1.json`，版本 `powershell-v1`，
规范 SHA256 `5f45cdd8de85bdf93c72f20ddd657a21606accb8f9a4adc011b951a66a3dce39`。
静态规范化仅处理冻结的 envelope 元数据，业务引用存在时保持身份关系；
工具响应规则为 `tool-result-envelope-v2`，SHA256
`81d983ec1efd254c4098ec75321b80d7d4f4a71129321e123102cf0afb68c136`。
不能把静态、工具响应或模型请求三层检查互相替代。

## 数据核对与必要假设

- 全部种子案例属于 dev；不是训练/测试 benchmark。C4/C5 公开文件相同、共享
  `environment/shared-pair.json`，世界真值只存在于 oracle。隐藏关键证据不计入
  observable critical denominator，两案此分母均为 0，未来指标应报 NA。
- C1 的 EDR 与网络传感器独立；EDR 镜像保留同一事件/独立性分组。资产批准
  与 history 等价批准来自同一登记源；查询其一后不奖励重复批准核查。
- C2 当前 host、账号、job/hash/参数与批准窗口相符，网络仅批准内部目标。
  批准未来结束时间可晚于 as_of，不能与“尚未发布的证据”混淆。
- C3 实际作业与批准不符、存在外部连接，script 缺失、TI unknown、history
  永久不可用。没有可观察 TP/FP 充分组合；正常耗尽有用动作可 Suspicious，
  硬预算耗尽优先 Abstain。当前没有运行 Agent 判定这些结果。
- 所有安全行为、TI 声誉和批准信息都是合成世界事实，没有真实恶意处置。
- `datasets/manifest.json` 和 author builder 仅开发/评测侧使用；replay 不读
  oracle，加载器按三区隔离。规则不会按 case ID 返回答案。

## 问题、修复与独立复核

全部初始失败及独立复验存于 [m2-m3-evidence](m2-m3-evidence/)。复核使用独立
副本及文件 SHA，不把本地工作区当独立环境；各作者不复核自己的实现。

| 问题 | 修复与证据 |
|---|---|
| D1/D2：批准缺少明确时间覆盖、备用批准后仍奖励冗余查询 | 增加同活动窗口登记范围；初次采用双缺口检查通过 17 个探针，保留旧失败；最终把两种获取路径统一为同一 E4 fact，获得其一即不再奖励重复核查 |
| F1/F2：可见侧漏评测字段、oracle 动作约束未按工具类型检查 | 递归禁止评测专用字段；约束必须整体符合至少一个 acceptable tool；loaders 独立复验 110 通过，旧 9 失败保留 |
| R1/R2：响应归一掩盖调用引用、对象键顺序 | 引用存在时保留 ID；键序列参与比较；规则升 v2 |
| R3/R4：静态编码强转非字符串键、未锚定业务字典键 | 编码前严格校验；业务键和值都保护身份；rubric/diff 独立复验 117 通过，旧失败保留 |
| I1：混合 IP/hash TI 规则逐字段构造非法中间查询 | 一起解释完整依赖字段；部分 type-only 不重分类请求值，value-only 对不兼容类型为不匹配；两种顺序均验证 |
| I2–I4：摘要漏检 hidden observable、记录工具来源、不被映射访问的文件哈希 | 显式核对可观察性、来源与失败 envelope；验证全部声明文件；最终独立集成复验 109 通过 |
| I5：备用批准 acquisition 被列为第二个 critical fact | 统一 E4 与 asset/history 原始引用，C1 critical 分母为 3；不是要求两次获取同一事实，未来 Registry/评分均消费此身份约定 |
| I6：跨平台换行可能导致 manifest 物理哈希失效 | 数据 JSON 固定 LF、作者显式写 LF；独立比对解码业务内容不变，更新物理字节哈希并保留原快照 |

最终 [集成独立复核](m2-m3-evidence/integration-final/review.md) 在当前 LF 数据
与 canonical E4 快照上 **109 passed**，覆盖此前修复和新负例；审查者曾将
完整 host 来源下的不同 process 查询误写为 partial，原失败与更正解释均保留，
源码没有为迎合该错误断言而修改。其他早期快照与通过结论只覆盖当时范围，
当前最终冻结及 source-index 明确对应交付字节。

外部 `m2-helper-preparation.md` 是设计审查，本次新增实现复核没有把它改写成
实现验收。独立报告完整来源、被测快照、失败与复验命令分别归档。

## 自检与远端门槛

仓库根目录执行：

```powershell
investigation/.venv/Scripts/python.exe -m pytest investigation/tests -q
investigation/.venv/Scripts/python.exe investigation/scripts/dataset_summary.py
investigation/.venv/Scripts/python.exe investigation/scripts/replay_seed_tools.py
investigation/.venv/Scripts/python.exe -m pip check
```

Python 3.12，原锁定依赖没有新增。完整实验包自检 **447 passed**，`pip check`
无损坏依赖；五案回放成功，27 组双胞胎查询一致。测试日志、XML、数据摘要、完整实际返回和
双胞胎差异报告归档；源码/数据/规则快照同时记录工作区 SHA256 和 Git blob
哈希，换行差异单列。不把工作区字节冒充提交字节。

完整 CI 必须先确认 M2 门槛满足，再确认 M3 同一被测实现的联调门槛，之后
推进依赖它们的 M4。实际所测完整 commit、两个 job 和链接由通过后的状态
记录补充；文档后续更新仍指向真实所测源码。

## 后续依赖与实验结论

下一步 M4：公共 Evidence Registry → Dispatcher → Trace → 模型适配及用量
对账 → 集成复核。M5 辅助评测方案审查可以并行交付，不阻塞当前开发。

目前只证明合成数据和工具工程行为通过定义的测试范围。尚无模型实验，
不能宣称降低 False Close Rate、优于 ReAct 或节省调查成本。
