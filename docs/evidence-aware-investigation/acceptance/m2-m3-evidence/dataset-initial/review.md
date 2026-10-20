# M2 数据集独立复核

## 结论

修复后通过本次数据集专项复核。初次 15 个独立探针：13 通过、2 失败；修复后的独立冻结副本 17 个探针全部通过。初次失败日志和快照保留，未被覆盖。

审查对象：主实现编写的 build_seed_dataset.py、14 份案例 JSON、manifest.json。审查依据：minimal-cases.md、m2-helper-preparation.md。审查者此前编写了 rubric/normalization，因此本复核**不检查自己的 rubric/normalization，也不替代其独立复核**。

这是一项 M2 数据内容复核，不是 M3 全查询工具响应验收，不是 M5 实际模型输入检查，也不证明研判策略优越性。

## 版本和复现

- 初次快照来源 Git HEAD：`8f01f1fa22d7c0242793878a294176de425a283a`。数据为尚未提交的工作区字节；完整 SHA-256 清单在 snapshot.json。
- 初次命令：`python -m pytest test_dataset_independent.py -q --junitxml=initial-tests.xml`，工作目录为本复核根目录。
- 修复后命令：`python -m pytest test_dataset_independent.py -q --junitxml=tests.xml`，工作目录为 retest。
- 解释器：D:/project/Agent/m3-independent-foundations/investigation/.venv/Scripts/python.exe。
- 修复后 generator SHA-256：`8312f81fa88cb535c52a8941ebdc23f0324c28d4746e6286288a889ebafaf873`。
- 修复后 manifest SHA-256：`41de366715ada625f22fe136873fc43e66b20d386d973e9cf6d922d32b771a67`。
- 修复后 C1 环境 SHA-256：`b68d26d0946e735f1ad0bd8881740ea3bd21925d23d8da97fc1b9c5ea91279ad`。
- 修复后 C1 oracle SHA-256：`ffdf850e4db67ff3b014192231b4679bf863fdfe13a7ac08208e95d614fa7417`。

## 发现与修复历史

### D1 / P2：C1 否定批准核查缺少活动时间覆盖

初次 asset 记录只有 `approval_register_complete=true` 和空 approved_jobs，没有明确的批准登记覆盖区间；无法机械核对它是否与同一 host/活动窗口内的 history 等价事实一致。

主实现增加 `approval_register_window`。复核不仅检查字段存在：检查它包含当前告警发生时间、终点不超过 as_of、host 与告警相同、history register_window 完全一致、批准列表一致，asset query rule 的 host/as_of/complete 覆盖与事实一致。恢复通过。

### D2 / P2：C1 替代批准事实没有禁用冗余动作预期

初次批准动作 `when_missing_fact_keys=['E4']`，即使已有等价 E4H 仍会允许继续重复查询批准记录，可能误奖励冗余 Tool Call。

主实现改成 `['E4','E4H']`。复核检验状态语义：仅 E0/E1/E2 时动作仍适用；已有 E4 或 E4H 中任一个时都不再适用，已有两个也不适用。恢复通过。

## 已确认内容

- 五公开案例、四物理环境、五 oracle，manifest 14 个内容哈希全部一致；C4/C5 映射同一物理环境。
- generator 在独立副本再次生成与冻结数据逐文件字节一致。
- 所有案例为 dev；双胞胎属于同一 family 分组；无 test 调参或五案统计优势声明。
- 公开 alert 和所有 ToolRecord 的内容哈希与真实 payload 一致；来源记录 ID 为不含案例语义的 32 位十六进制字符串。记录的 event/observed/published 时间不超过 as_of。
- C1 有实际凭证读取和发送行为、同一 process_guid 的独立 network-sensor 佐证；镜像日志保留同一 payload/independence_group；asset/history 批准核查同一 source group，不制造独立支持；两条替代充分组合均保留。
- C2 正向批准记录和实际执行 host/account/job/hash/params 匹配、维护窗口包含事件；完整当前 network scope 只访问获批内部目标；TI unknown 不作为良性充分组合。
- C3 job/hash/params 与批准实际不匹配，脚本正文缺失、已观测新外部连接但无负载内容、TI unknown、history 永久 unavailable；无 TP/FP 充分组合，隐藏攻击正文未进入工具记录，允许 Suspicious 或预算/信息不足时 Abstain。
- C4/C5 公开输入逐字节相同、工具环境相同、隐藏世界真值不同；脚本/授权真值仅在 oracle；无可查 IOC；两者仅允许 Abstain，critical∩observable 为空。
- expected_actions 每个可接受工具都有与标注约束兼容的环境路由。该检查不等价于所有合法参数实际调用验收。

## 验证文件

- snapshot.json：初次 51 个审查/支持文件完整字节哈希。
- initial-tests.log / initial-tests.xml：13 passed、2 failed 原始记录。
- test_dataset_independent.py：初次独立探针。
- retest/snapshot.json：修复后数据/generator 冻结哈希。
- retest/test_dataset_independent.py：原始探针加 2 个修复语义检查。
- retest/tests.log / retest/tests.xml：17 passed。

## 保留边界

没有执行真实模型、没有验证 M5 评分器，Suspicious 的 stop_reason 条件将在 M5/M7 实现中检查，当前 oracle acceptable_verdicts 不是完整的预算相关决策函数。M2 数据规则与实际工具响应的一致性由后续 M3 五案联调负责；本次没有把有限探针说成全部查询穷举。
