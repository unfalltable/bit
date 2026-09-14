# 本轮技术验证进度

用户已同意先验证隐私证明适配、共识/固定发行和手机能力。用户随后明确“手机先跳过”，因此不再访问手机；本轮 Android 测试状态为 SKIPPED_BY_USER。

已创建两个隔离 Rust 实验工程和执行脚本。便携 Rust 1.98.1、Go 1.27.1、LLVM-MinGW、ADB 位于本目录 .tools；ADB 服务已停止。

上游 Penumbra v2.1.1 对应源码提交 3a87ce786373113f9b82d3b6df9504998b7f44a7。Spend/Output 参数下载已匹配源仓库 LFS 哈希，共 28,930,752 字节。

CometBFT 通过 Go module v0.38.23 构建，实际源码 feb2aea4dc271d612129afc958cb844713ec792b。上游 version.go 的 fallback 常量为 0.38.22，因此命令显示 0.38.22；需要同时使用 go version -m 和模块来源记录说明，不能只看自报版本。没有改写上游版本常量。

源码审阅发现：Spend/Output verify 内部采用 unchecked 反序列化；票据 trial_decrypt 的 debug 日志包含票据明文，Note 的 Debug 包含 rseed。实验先严格解码并重编码比较证明字节，保持上游电路/参数不变；不安装 tracing subscriber。生产适配仍需要系统审查和日志测试。

实验构建遇到 Windows GNU 原生链接/汇编工具缺失，已用项目内 LLVM-MinGW 和明确 rust_env.ps1 配置处理。两个工程 release 构建成功。网络运行器显式 UTF-8 处理配置后运行通过。

本轮已完成：18 项固定发行实验测试全部通过；真实四节点空块实验通过，覆盖同高度状态一致、H+2、Finalize/Commit 两处故障恢复与投票权停止/恢复；真实证明已接入 `crates/bit-shielded` 严格 body/proof 适配，并由 `crates/bit-transaction` 组成完整 2 Spend、2 Output Transfer。5 组证明生成中位数 4.39 秒、严格验证中位数 26.32 ms，进程观测峰值工作集 121.02 MiB。Spend 授权、binding、重复 nullifier 和失败不留部分状态均通过。扫描 1000 条载荷识别 10 条归属票据，约 136.64 ms。手机未测试。

报告已写入 docs/BIT_第一轮技术验证报告.md，复跑命令见本目录 README.md。原始结果保存在 reports，运行进程已结束。summarize_results.py 仅从实际结果汇总，capture_evidence.py 保存源码、锁、二进制和报告摘要。

后续正式开发已经完成持久化 commitment tree、nullifier/anchor 索引、原子提交、ICS23 状态证明，并把 Transfer、九类质押信封、退出和罚没资金闭环接入 ABCI/JMT。最新四节点实验还通过标准 CometBFT RPC 注入真实重复投票证据，验证规范证据记录、Burn、H+2 移除、同高度 app hash 和处罚后的投票权停止/恢复。当前下一阶段是 JMT/RocksDB 底层故障注入、快照/历史证明、生产摘要与正式节点命令；独立 signer 仍未实现。

总体仍只是部分开发验证；已有完整 Transfer 密码学交易、链上原生授权和生产状态核心，但没有钱包、独立 signer、完整节点发布物或主网审查。手机和 Tor、多平台验证仍未完成。不要把实验通过转记为原规格 30 项任务完成，也不要重新访问手机。
