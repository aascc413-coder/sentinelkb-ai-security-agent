# Synthetic engineering seed (M2)

五份 public、四份物理 environment、五份 oracle；所有案例均为 dev。C4/C5
共用 `environment/shared-pair.json`，公开输入相同，仅 oracle 的不可观察世界不同。
这五案验证工程机制，不构成统计 benchmark。

`powershell-dev-v2/` 是 M10b 的独立版本化开发集，在不改变本目录五案种子字节的前提下扩展到 12 案。其说明、manifest、public/environment/oracle 文件均在该目录；对应评测标注为 `../evaluation/annotations/powershell-dev-v2.json`。

- `public/`：仅告警，加载后交给 runtime。
- `environment/`：工具服务持有，不提前交给模型。
- `oracle/`：评测独占，含完整世界、可观察性和替代充分组合。
- `manifest.json`：开发/评测侧映射和文件哈希，不作为模型输入。
- `../rubrics/`：按告警族冻结的通用门槛，不包含案例答案。

开发命令（仓库根目录）：

```powershell
investigation/.venv/Scripts/python.exe investigation/scripts/dataset_summary.py
investigation/.venv/Scripts/python.exe investigation/scripts/dataset_split_audit.py
investigation/.venv/Scripts/python.exe investigation/scripts/replay_seed_tools.py
```

`dataset_split_audit.py` 是作者/评测侧命令，会读取 oracle。它验证 manifest、
文件哈希、映射、family 分组与 dev/test 切分，并使用冻结规范化规则阻止静态
等价的模型可见输入跨 family 或 split；禁止在 Agent 运行时导入。当前五案审计
结果应为 5 个 dev 案例、2 个 family，且只识别出 C4/C5 一个等价可见输入组。

作者标识在加载时一致重映射为 opaque ID；host/user/process、时间、payload
和内容哈希保持不变。镜像记录共享 event_id 与 independence_group；备用批准
查询与资产批准查询来自同一登记源，不重复计为独立证据。

`build_seed_dataset.py` 是包外作者工具，包含评测答案；运行它会重建种子数据
及 manifest，禁止在 Agent 内调用。更改数据后必须重新审查，而非只更新哈希。
JSON 使用 LF，并由 `.gitattributes` 固定，避免 Windows/Linux 检出改变物理
字节而使 manifest 哈希失效；作者重建命令同样显式写 LF。

来源和批准状态都是本地合成世界的设定。TI unknown、ATT&CK 映射、维护窗口、
来源不可用均不单独支持 TP 或 FP。C3 的实质风险支持 Suspicious，硬预算耗尽
优先 Abstain；C4/C5 在现有可观察信息下均应 Abstain。
