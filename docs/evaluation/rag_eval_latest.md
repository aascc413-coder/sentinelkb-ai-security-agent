# SentinelKB RAG 评测报告

- 数据集：SentinelKB security RAG baseline `1.0.0`
- 运行时间：2026-08-15T17:09:46+08:00
- API：`http://127.0.0.1:8080`
- 通过率：**10/10 (100%)**
- 关键事实覆盖率：**100%**
- 来源命中率：**100%**
- 拒答准确率：**100%**
- 瞬时错误重试：`0` 次；最终 API 错误：`0` 个
- 延迟：P50 `2951 ms`，P95 `20461 ms`

| 用例 | 结果 | 事实覆盖 | 来源命中 | 拒答 | 重试 | 延迟(ms) |
|---|---:|---:|---:|---:|---:|---:|
| blue-falcon-event-id | PASS | 100% | 是 | 否 | 0 | 4731 |
| blue-falcon-account-action | PASS | 100% | 是 | 否 | 0 | 14919 |
| blue-falcon-log-scope | PASS | 100% | 是 | 否 | 0 | 20461 |
| blue-falcon-review-owner | PASS | 100% | 是 | 否 | 0 | 2217 |
| blue-falcon-unknown-manager | PASS | 100% | 是 | 是 | 0 | 1977 |
| incident-host-command | PASS | 100% | 是 | 否 | 0 | 2612 |
| incident-network-ioc | PASS | 100% | 是 | 否 | 0 | 2951 |
| incident-lateral-movement | PASS | 100% | 是 | 否 | 0 | 1948 |
| incident-vulnerability-hash | PASS | 100% | 是 | 否 | 0 | 3450 |
| unknown-annual-leave | PASS | 100% | 是 | 是 | 0 | 7125 |
