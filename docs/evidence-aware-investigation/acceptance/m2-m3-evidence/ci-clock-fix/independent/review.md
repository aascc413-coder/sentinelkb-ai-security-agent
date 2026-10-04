# CI 时钟断言修复独立复核

日期：2026-10-04（Asia/Shanghai），复核代理 m3_diff。范围为主实现的 test_tool_server.py 时钟断言变更及对应工具 timeout 行为，不修改作者文件或运行时实现。

## 原失败确认

官方 push CI run 37210072763、源码/记录 SHA 5ab13f9b72c8f53704694760a5f13bc8c9a487d5，在 `test_declared_latency_timeout_is_counted_without_evidence` 失败。完整官方日志固定副本 failed-ci.log 保留：timeout=50ms，实际 admission 已耗 16ms，返回 simulated_latency_ms=34、actual_duration_ms=16、cost=2，旧断言却要求模拟后端耗时固定 50ms。

这不是调查逻辑失效，而是测试将整段 deadline 等同于后端可用时长。PR 同 SHA 通过不能替代失败 push 的处理；保留失败记录，修复后新提交重新运行完整 CI 合理。

## 修复审查

作者只修改该测试：参数化 admission 0/16ms，注入现有公开 clock 接口；精确要求后端剩余 50/34ms、实际时长 0/16ms、cost=2、retryable timeout、无证据、一个后端调用，以及重试成功并增加后端计数。

没有改为宽松区间、删 deadline 断言或只检查 status；没有修改 runtime/server。冻结 server.py SHA256 与此前已验收版本相同。实际等待锁的 deadline 测试仍存在并重新执行通过，故逻辑时钟没有替代全部真实调度约束测试。

## 独立执行

复制调查包 84 文件到本目录 investigation；失败日志单独复制，snapshot.json 记录全部指纹。PYTHONPATH 指向此固定 src/evaluation，解释器只提供锁定依赖。

作者 server 33 项 + 独立 3 项：**36 passed**，零失败、零错误，见 review-tests.log/XML。

独立追加使用带 float 返回类型的 clock：
- admission 10ms + 总 deadline 50ms：后端只可用 40ms，返回 timeout、无证据、cost=2、实际时长 10ms，重试仍需再次调用后端；
- admission 60ms + deadline 50ms：后端不启动，cost/模拟耗时都为零，实际时长仍记录 60ms；
- 实际加载 server 来自固定副本。

这些检查依据 deadline、计费及证据安全的外部契约，未依赖内部调用次数或逐行镜像实现。没有降低原验收门槛。

## 指纹与结论

| 文件 | SHA256 |
|---|---|
| tests/test_tool_server.py | 46e5aa9208dc692f840dfbbdd8fabcc890a2fd472f311cb03b458b435f7df677 |
| tools/server.py（运行时未变） | 19af72dee7792475888f6b187d1b08b85accabb568f3d0e05c86ebf143064034 |
| snapshot.json | 54e88d5e35894cbf0bcee5480b497214b1f3eb69d9295ae8ffbbd50741bed178 |
| failed-ci.log | 90ec9896cfcf9149245e7ca5af60ef4445d56f0e973e933c56ae6cec4000e9ed |
| test_clock_probes.py | 08b634e64a4f05369430cdc0d2c3669b7568d515cd2db6cbead12b589c352517 |

结论：本次测试修复独立复核通过，无阻塞。历史 751c77d 的 447 passed 和成功 CI 保留原提交归属；本次新增参数使主实现当前全包计数增加为 448，应由新 log/XML 与新提交的双 CI 核实，不直接继承旧远端绿色状态。
