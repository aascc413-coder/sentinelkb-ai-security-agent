# powershell-dev-v3

M10c 冻结候选开发集：20 个公开 synthetic dev 案例、12 个 family、17 个物理环境。

- C1–C12 的 Public、Environment、Oracle JSON 与 `powershell-dev-v2` 对应文件逐字节一致。
- C13–C20 增加私钥外传、批准的软件盘点、批准不匹配伴随可重试超时、部分进程覆盖、批准源冲突双胞胎、永久 history error、未关联 TI 干扰和直接批量删除。
- C4/C5、C10/C11、C17/C18 为三组模型可见输入静态等价且隐藏真值相反的 counterfactual。
- `public/` 和 `environment/` 是运行时分区；`oracle/` 只供评测侧读取。
- 对应评测标注：`evaluation/annotations/powershell-dev-v3.json`。
- 作者协议及覆盖矩阵：`docs/evidence-aware-investigation/m10c-authoring-guide.md`。
- Prompt、rubric、预算和作者指南冻结哈希：`evaluation/freeze/powershell-dev-v3.json`。

该数据集用于开发和协议冻结，不是 blind test，也不支持生产性能或统计优势结论。M10d 的 40 个 test 案例必须由独立作者按冻结协议另行编写。
