# M2/M3 主实现最终复验：canonical E4 与固定 LF 字节

日期：2026-10-04（Asia/Shanghai），辅助代理 m3_diff。审查主实现的数据、scripts、selection、集成及说明；自己编写的 diff_report.py 另由 m2_loaders 独立验收，本报告不代替该项。

## 冻结与结果

最新固定副本：本目录 investigation（84 文件）+ 根 .gitattributes + 三份计划/验收/覆盖文档，指纹见 snapshot.json。原始初审、两个阶段 retest 和 canonical-final-retest 均保留。

执行固定副本中的官方 seed、tool integration、selection 检查、原代理 18 探针、接续 9 检查、canonical 7 检查、LF 2 检查：**109 passed**，零失败、零错误、零跳过。见 `lf-tests.log`、`lf-tests.xml`。锁定依赖解释器复用既有环境，代码和数据通过 PYTHONPATH/探针来源检查确定来自固定副本。

## canonical E4

独立确认 E4H 从完整世界、observable、critical、充分组合和 expected action 条件中移除；C1 critical 只有 E1/E2/E4，分母为 3，唯一 TP 组合 E1/E2/E4。E4 统一 asset 与 host/user history 原始引用，记录同主机、同批准作业集、同活动窗口和 independence_group；两种获取工具继续可选。

source_tools 必须非空、去重且与全部原始引用实际所属工具集合精确一致。缺工具、额外工具、空数组、重复工具、未知工具和字符串代替数组六种负例都拒绝。没有将重复获取的批准事实计为第二关键事实。

## LF 物理字节修正

Windows 默认 write_text 换行及 Git autocrlf 可令 Linux/Windows 上的文件字节和 manifest hash 不一致。修复限定：两条 dataset JSON `.gitattributes text eol=lf`，作者生成器显式 `newline="\n"`。

独立检查全部 15 份数据 JSON 没有 CRLF；相对于 `../canonical-final-retest`，逐文件 JSON 解码业务内容完全相同。manifest 除 file_sha256 字节指纹外也完全相同，原有 content_sha256、身份与调查事实没有因换行变化改写。当前 manifest 精确校验所有新 LF 字节，作者重建测试通过。只将这一层变化称为换行修正，不用旧 CRLF 物理哈希冒充当前文件。

原工作区只读 `git check-attr text eol` 确认 manifest.json 和 public/c1.json 均 text=set、eol=lf；两条 attributes 不扩展到产品代码或其他目录。

## 已关闭问题与范围

继承并重新验证 `../canonical-final-retest/review.md` 中各项：摘要拒绝 hidden observable、错误来源、悬空/错误类型引用、不结构化 annotation、虚构 unavailable reason、as_of 配对错误；全部声明文件均核 hash；TI 部分类型规则不误解析其他类型请求。

五案状态、C1 六种查询顺序与镜像/来源独立性、替代批准路径、C3 history 永久 unavailable、事件窗口、未知实体、截断、缓存、deadline 与 C4/C5 27 组代表查询回放均通过。replay 不读 oracle、不生成 verdict；public/environment 无 oracle 答案注入。包资源分区和文档的有限测试/待同 SHA 双 CI/M4 未完成边界成立。

历史中间错误断言保留：宽 host 完整来源的 process_id=None 意味着不同进程查询可得到 complete empty；审查者此前写成 partial 是测试假设错误，最终断言修正并说明，产品代码没有因此改动。

## 指纹与结论

所有源码、数据、文档和 attributes 原始 SHA256 见 snapshot.json；此前 canonical 数据/代码指纹见上一报告，二者不混用。主实现全包自检结果须在最终记录与最新 log/XML 对齐，并由提交后两个 CI job 精确核 SHA。

| 文件 | SHA256 |
|---|---|
| scripts/dataset_summary.py | 73690a5a2295beb3bedeb7d3ee27f65f20ca7a75ab2d07ac64d239913adc9f2e |
| scripts/build_seed_dataset.py | eb26f84cc9385e5c8d46fd5b2fc3e6c1f2c5ddcfda367ec358d42d79511c9993 |
| tools/selection.py | 29b859bca92722cb4990a6b9fc57ae8d2ec75eee901e821486d7abe92e75d0b5 |
| datasets/manifest.json | b939f8d9f23c73e27541c71233c8b6c6137230f4334e3745c04553dc869af4ba |
| datasets/oracle/c1.json | b2d007167a7e650d0988814a64895f8264806377fecdce49d35f15abe0c33a85 |
| .gitattributes | 460ba4ddf130e866dbc9fe7ef38d06f0ee8ca82ebf1ff9a2e9eff558b7ac0fb8 |
| snapshot.json | f6c3a26bceda11a80a886096951c62ae0a27b54eb1e2fd5e09dd07c0768da313 |
| lf_probes.py | 0143ef9ac59bce5318f6fa22e071cb0a269707536aa40df7a0f168df7a616753 |

结论：本轮主实现 M2 数据与 M3 工具联调范围通过，无代码阻塞。有限工程样例不证明研判策略优于基线，不代替未来 M5 实际模型请求、M4 Registry/Dispatcher/Trace/模型适配或完整 Agent 实验。
