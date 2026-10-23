# M10b 十二案开发集验收记录

里程碑 / 状态：M10b；实现、主实现自检与辅助 AI 独立复核通过，待提交与同一提交双 CI。

提验日期：2026-10-24。

父依赖：M10a 已完成，实现在 `4520815` 通过双 CI；最终状态文档 `63fc9f8` 也通过双 CI（run 40011350036）。

## 1. 开发中识别并处理的问题

直接扩写案例会遇到一个方法有效性问题：原 `powershell-v1` 程序检查只识别固定的 credential-store 外传结构和三条 backup 文本。其他案例即使证据充分也无法得到 TP/FP；复制旧文本又会把“数据扩展”变成参数改写。

M10b 先完成最小通用化：

- 良性关闭要求实际 `script_observations` 与匹配批准中的 `expected_observations` 做完整、顺序无关的结构化多重集合比较；空集合、部分匹配和额外行为均不能通过。
- 直接攻击证据使用有限确定性词表：明确的敏感对象读取与同对象产物外传，或来源直接记录的未授权批量加密/删除。
- 无网络记录只有在对应查询覆盖完整时才可参与 G1/G4/B2；缺失、部分或不可用仍是 unknown。
- 旧 C1 credential 外传和 C2 backup 兼容路径保留并由原回归锁定。

该实现仍是窄域 PowerShell MVP 规则，不把任意模型描述当作 Evidence，也不声称覆盖全部攻击行为。

## 2. 数据交付

新增版本化数据根：`investigation/datasets/powershell-dev-v2/`。

- 12 个 dev 案例、7 个 family、10 个物理 environment。
- C1–C5 与 `synthetic-v1` 对应 JSON 逐字节一致。
- C6–C12 预期输出：`TP / FP / FP / Suspicious / Abstain / Abstain / TP`。
- C4/C5、C10/C11 是两组静态等价双胞胎，组内隐藏真值相反且均要求 Abstain。
- 新场景包括 Office 凭据外传、批准的 Office 报表、匹配与不匹配远程运维、遥测缺口、直接文件加密。
- 新评测标注：`evaluation/annotations/powershell-dev-v2.json`，绑定默认 Budget 与 `powershell-v1`。

数据由 `scripts/build_dev_dataset.py` 确定性生成。Manifest SHA256：

```text
859ea24b1faa5144f171f2930f80dbc92aa671988600d25449e0b153c66b5edc
```

评测标注 SHA256：

```text
084587fc32e3b78a56ff7e9e49498064a55781d5b067f010c9a49319375f61e8
```

## 3. 提验实现快照

| 文件 | Git blob SHA1 |
|---|---|
| `investigation/src/evidence_investigation/agents/sufficiency.py` | `b30ff9aa046a85aa7aaff6d81c42943ede910b91` |
| `investigation/scripts/dataset_split_audit.py` | `d98ef17bc5f0cc2f7100fcc9c59268b478db92d6` |
| `investigation/scripts/build_dev_dataset.py` | `b504ad93d097a0c2997929a3e916d2a1b56e5cfa` |
| `investigation/tests/test_agents.py` | `14df3c270f1a1b0172ad19bfc0f31b468d09cfa2` |
| `investigation/tests/test_dataset_split_audit.py` | `b645b5ac73bff361c3ef74dccf27c64e09315dd2` |
| `investigation/tests/test_dev_dataset_v2.py` | `b39390f0734b9dfe6d19bdb4c4d89cf4742a325b` |
| `investigation/tests/test_seed_dataset.py` | `29d467d13a0ad060b72490af6c919851c9bdcf42` |
| `investigation/datasets/powershell-dev-v2/README.md` | `046f370c64514d510cda99ffd366ef30681a6f40` |
| `investigation/evaluation/annotations/powershell-dev-v2.json` | `3f63df0fadbc2c657e344fd1bfe3ba08c39d806a` |
| `investigation/datasets/powershell-dev-v2/manifest.json` | `0fd88db913911a220c6e65afe398858279ca8fdb` |

Manifest 内另行绑定全部 12 public、10 environment 和 12 oracle 文件的 SHA256。

## 4. 主实现自检

```powershell
cd D:\project\Agent\sentinelkb\investigation
.\.venv\Scripts\python.exe scripts\build_dev_dataset.py
.\.venv\Scripts\python.exe scripts\dataset_split_audit.py --dataset datasets\powershell-dev-v2
.\.venv\Scripts\python.exe -m pytest tests\test_dev_dataset_v2.py tests\test_dataset_split_audit.py tests\test_agents.py -q
.\.venv\Scripts\python.exe -m pytest -q
```

实测：

- 数据审计：12 cases、7 families、dev=12；两组静态等价输入；manifest、类型映射、Oracle 引用、family split 与规范化分组全部通过。
- 重点测试：48 passed。
- 全量测试：721 passed in 13.86s。
- 构建器临时目录重建与已冻结 JSON、annotation 逐字节相同，所有生成 JSON 为 LF。
- 新增 7 案使用统一 Fake 工程模型运行，结果全部符合预期。
- 可见 public/environment 不含 case、family、split、ground truth 或 oracle 标注字段。
- `git diff --check`：通过。

## 5. 结论边界与风险

- 全部 12 案仍是公开 synthetic dev 数据；不能得出 blind 泛化、生产性能或统计优势结论。
- `expected_observations` 是封闭结构比较，适合可审计的本地 fixture；真实 SIEM/EDR 需要独立适配层将供应商事件映射到冻结行为结构。
- 有限直接攻击词表有意保持窄小。新增攻击类别必须增加明确规则、正反例和复核，不能依赖自由文本或 LLM 自评扩张。
- 数据审计使用 O(n²) 静态比较，12/60 案规模可接受；数百案例后再优化。

## 6. 待完成门槛

辅助 AI 独立复核已通过，详见 [M10b 独立技术复核](m10b-independent-review.md)：

- 10 个端到端负向探针全部阻止错误 TP/FP。
- 12 案、7 family、10 个物理环境及两组静态等价双胞胎经独立核对属实。
- 构建器逐字节复现，种子数据未改变，Oracle 引用校验兼容旧数据。
- 两项兼容性观察和一项 M10c 数据设计提示均不阻断 M10b。

剩余门槛：提交、推送并核对同一提交的 `test` 与 `investigation-tests`。

门槛完成后才将 M10b 标记为完成并开始 M10c（dev 20）。
