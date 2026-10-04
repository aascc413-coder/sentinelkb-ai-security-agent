# 通用组件文档与 CI 独立复核

结论：**通过，限定文档与 workflow 配置审查；远端 CI 仍待执行，不代表 M2 / M3 / M4 整体完成。**

基础提交：63fa8089845a05ad7e45d785b0adf081fa2dd52e。五份被审文件先原样复制至本独立目录，以 SHA-256 冻结。复核者 m3_selection 未编写或修改本次被审文档及 workflow，未审查自己的 selection 实现，未重复执行代码测试。

## 检查结果

- workflow 的 push 增加 `codex/**`，pull_request 仍限定 main。两个既有 job、工作目录、安装流程保留；全局 contents: read，job 无写权限覆盖。此结论是配置审阅，尚未实际验证 GitHub 是否触发或执行通过。
- 实施计划保留完整父依赖；并行补充只允许依赖已验收 M1 的通用组件提前开发。M2 明确为设计审查已交付、工程未实现；M3 五案集成和 M4 剩余模块均明确未完成。
- README 与交付说明均区分独立通用样例和正式 M2 五案，不宣称研究效果或完整里程碑通过。
- 任务依赖、优先级、独占文件和跨作者复核角色明确，与本轮执行分工一致。提交推送由主实现统一执行；发布、收费资源、真实安全处置仍保留单独授权。
- 主测试日志为 275 passed；JUnit tests=275/errors=0/failures=0/skipped=0，与交付说明一致。pip-check 日志无冲突，demo 以 generic offline 模式呈现，不伪称五案回放。
- 工具初审报告为 144 官方通过、17 探针中 6 失败；独立复验报告为 171 通过，T1/T2 的修复与复验范围表述一致。
- 预算初审为 16 官方通过、11 探针中 6 失败；复验为 33 官方通过、旧 9 通过 / 2 失败、新 4 通过。交付说明保留旧失败，并明确旧断言要求累加成功、当前策略原子拒绝 overflow；没有将其改写为全绿。
- reviews.json 已核对，其结果、范围和独立报告路径与文档一致。初读时该文件尚未生成，主实现随后生成；最终审查时引用完整可定位，不构成剩余阻塞。
- M2 准备稿与外部副本字节相同，SHA-256=`78f2449e6fd07856d27e85bdf44b51c79fac1a2d09cfffd6bffafafdbfa6c942`；其性质为辅助设计建议，尚需主实现逐条处理，不能当作 M2 工程验收。

## 冻结 SHA-256

| 文件 | SHA-256 |
|---|---|
| .github/workflows/python-tests.yml | `3f02078656b8ea2d5fd342a6d2399bf0cbc135b17fd003c42609b57138c061eb` |
| investigation/README.md | `7becd08317b3bd937c42e733579c03e1f2d7699e46458158fe48bdeed1baab6a` |
| docs/evidence-aware-investigation/phase-2-implementation-plan.md | `8e27f576c5bf3f62cc4181799b6b46341fc1bf656c38ba08d84865f0a6b5fb95` |
| docs/evidence-aware-investigation/acceptance/m3-foundations-acceptance.md | `c9bd22ab754ddc667256ba949b2f87d8d26c681a37fcd200f920afd90f0e5129` |
| docs/evidence-aware-investigation/acceptance/m2-helper-preparation.md | `78f2449e6fd07856d27e85bdf44b51c79fac1a2d09cfffd6bffafafdbfa6c942` |

## 范围与限制

这次仅审查五份文档及 workflow 配置，并核对测试日志/XML和两组独立报告的事实对应关系。没有执行代码复验，没有核验实际远端 CI SHA，没有验证正式数据加载、C4/C5 响应或实际模型请求。技术模块正确性以各自独立复验报告为据；主实现提交后仍需双 CI 核对，完整阶段仍受 M2 工程依赖约束。
