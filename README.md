# BIT

BIT 是一条以私密支付和原生质押为核心的独立单币 PoS 链。本目录已进入底层实现阶段；目前完成的是活跃规格基线、共识金额/交易编码、Spend/Output 的窄密码学适配、Transfer 的密码学验收入口、首版持久化共识状态层、ABCI v0.38 生命周期、固定总量与费用会计第一阶段，以及原生质押的确定性内存账本第一阶段。

先阅读 [活跃规格基线](D:/others/BIT/SPEC_BASELINE.md)、[总体开发方案](D:/others/BIT/docs/BIT_项目梳理与总体开发方案.md)、[D-002 区块产物规范编码](D:/others/BIT/docs/BIT_D-002_区块产物规范编码.md)、[D-004 状态设计](D:/others/BIT/docs/BIT_D-004_持久化状态设计.md)、[D-005 ABCI 生命周期设计](D:/others/BIT/docs/BIT_D-005_ABCI生命周期设计.md)、[D-006 固定总量与支付会计](D:/others/BIT/docs/BIT_D-006_固定总量与支付会计.md)、[D-007 原生质押设计](D:/others/BIT/docs/BIT_D-007_原生质押设计.md)、[D-008 退出与处罚设计](D:/others/BIT/docs/BIT_D-008_退出与处罚设计.md) 和 [最新开发进度](D:/others/BIT/docs/BIT_开发进度_2026-09-14.md)。`docs/solo` 仅作历史参考。

## 当前代码

- `crates/bit-types`：`Amount`、固定发行、规范 CBOR、严格 Protobuf envelope、哈希/ID、证明哈希、授权角色结构，以及版本化 execution summary/compact block 编解码和域分离哈希。
- `crates/bit-shielded`：固定 Penumbra v2.1.1 上游 Spend/Output body 及证明的唯一严格验证入口。
- `crates/bit-transaction`：完整 Transfer 以及 RegisterValidator、Delegate、CancelPending、Unbond、ClaimExit、UpdateValidator、UnjailValidator、RotateConsensusKey、ClaimCommission envelope 的链上下文、费用、Spend/Output 证明、Spend 授权、角色域分离 Ed25519 签名、共识键 PoP、公开价值 binding 和重复 nullifier 检查。
- `crates/bit-emission`：固定 1024 亿枚上限的整数会计，验证已发行量、当前供应量、容器总额、销毁量、已放弃额度和未来发行额度之间的恒等式；同时实现无追补的逐 epoch 发行、奖励与佣金容器变换及规范最低费。
- `crates/bit-staking`：验证者、质押池、持仓和退出票据的确定性账本；实现 pending 激活、U256 池份额/退出份额换算、自质押资格、候选排序、投票权边界、验证人序号、佣金延迟、双门槛解禁、共识密钥历史、实际签名 score、downtime jail、池奖励、Unbond/ClaimExit，以及永久 tombstone 和有界 SlashJob。
- `crates/bit-state`：基于 Cnidarium 0.83/JMT 0.11/RocksDB 8.1.1 的 schema v18 状态，维护真实 Penumbra TCT、供应会计、逐项质押/退出记录、持久化推进队列、H/H+1/H+2 集合及逐高度责任历史；Byzantine evidence 会核对历史地址、power、总 power、时间和组合年龄窗口，去重后原子扣减 P/X、累计 Burn 并持久化可恢复游标。状态提供两阶段原子提交、重启后可重建的最新/精确历史高度 ICS23 查询证明，以及绑定 app hash/链配置并按 4 MiB 分块校验的 RocksDB checkpoint 快照导出、传输重组与隔离恢复。
- `third_party/cnidarium`：固定 Cnidarium 0.83.0 的 MIT 许可源码及 BIT 最小耐久性补丁；Commit 在写 WAL 前验证完整批次，使用同步 RocksDB WriteBatch，并把写入/fsync 错误返回给停机路径。未修改的上游文件由 SHA-256 清单约束。
- `crates/bit-app`：确定性生命周期核心及固定 CometBFT ABCI v0.38 适配，严格解析实际 last commit、`next_validators_hash` 和 `FinalizeBlock.misbehavior`，按固定系统顺序完成计分、证据处罚、发行奖励、pending 激活、集合选择与有界队列推进；FinalizeBlock 从真实执行结果生成规范区块产物并把摘要写入可证明状态，同时返回验证人更新和自验后的最新/历史 ICS23 ProofOps；State Sync 接受 CometBFT 轻客户端提供的可信 app hash，逐块校验后在隔离数据库恢复并以耐久标记切换活动状态。
- `crates/bit-gateway`：基于同一 `ApplicationCore` 的只读 Axum 网关，首批提供健康检查、带证明网络参数、白名单状态证明、完整供应审计和有界 compact block 下载。网络与供应 DTO 会交叉核对同高货币政策，所有 compact 字节也与同高历史证明交叉核对；未配置 TLS 前只允许 loopback 监听。
- `contracts`、`config`、`tests/vectors`：从 BIT v1.2 主规格抽出的活跃机器合同、参考测试网配置和共享向量。
- `reference`：不依赖 Rust 的 Python 发行和编码 oracle。
- `feasibility`：真实证明、简化共识探针，以及复用生产 `bit-app`/JMT 状态核心的四节点 CometBFT 集成实验；不是生产节点发布物。

## 本机验证

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-baseline-checks.ps1
```

如已安装 `just`，也可运行 `just baseline`。基线同时启动四个本机 CometBFT/真实 BIT 应用进程，执行冻结的真实 2 Spend/2 Output Transfer，在链继续推进后按 Transfer 高度核对区块产物摘要与状态证明，并在应用重启后重查该旧高度；随后注入由临时测试验证人密钥签出的真实重复投票证据，并验证 H+2、罚没 Burn、JMT 重启和投票权恢复。主报告写入 `reports/development-baseline.json`，网络证据写入 `feasibility/reports/bit-app-network-result.json`。Android 按用户要求跳过，基线命令不会访问手机。

当前还没有完整公网 TLS/Tor 网关、正式节点命令、独立 signer、钱包或主网发布能力。只读网关已实现本机健康检查、网络参数、状态证明、完整供应 REST DTO 和 compact 下载；头同步、广播及其他 13 个合同操作仍待接入。真实四节点 CometBFT 实验已验证真实 Transfer、规范 execution/compact 摘要、本地不可变归档及重启读取、H+2、JMT 重启、app hash 一致、最新和精确历史高度 ICS23 查询、投票权停机/恢复，以及真实重复投票证据进入区块后的验证人移除与罚没 Burn；多节点真实退出仍待接入。状态集成测试继续覆盖 P/X 罚没、规范去重、永久 tombstone、全局每块上限、损坏 WriteBatch 写前拒绝、Commit 两侧崩溃恢复、逐块重启恢复，以及快照文件集/分块 hash/配置/状态根核验后的隔离恢复。ABCI State Sync 已实现快照发现、4 MiB chunk 传输、可信 app hash 绑定、坏块重取、隔离恢复和耐久活动状态切换；真实 CometBFT 新节点联网同步、独立轻客户端证人和跨平台恢复演练仍待完成。真实磁盘耗尽/fsync 错误注入、SDK 映射和长期增长测试仍待完成。`config/mainnet-inputs.template.json` 保持阻断状态。
