# BIT

BIT 是一条以私密支付和原生质押为核心的独立单币 PoS 链。本目录已进入底层实现阶段；目前完成的是活跃规格基线、共识金额/交易编码、Spend/Output 的窄密码学适配、Transfer 的密码学验收入口、首版持久化共识状态层、ABCI v0.38 生命周期、固定总量与费用会计第一阶段，以及原生质押的确定性内存账本第一阶段。

先阅读 [活跃规格基线](D:/others/BIT/SPEC_BASELINE.md)、[总体开发方案](D:/others/BIT/docs/BIT_项目梳理与总体开发方案.md)、[D-004 状态设计](D:/others/BIT/docs/BIT_D-004_持久化状态设计.md)、[D-005 ABCI 生命周期设计](D:/others/BIT/docs/BIT_D-005_ABCI生命周期设计.md)、[D-006 固定总量与支付会计](D:/others/BIT/docs/BIT_D-006_固定总量与支付会计.md)、[D-007 原生质押设计](D:/others/BIT/docs/BIT_D-007_原生质押设计.md)、[D-008 退出与处罚设计](D:/others/BIT/docs/BIT_D-008_退出与处罚设计.md) 和 [最新开发进度](D:/others/BIT/docs/BIT_开发进度_2026-09-14.md)。`docs/solo` 仅作历史参考。

## 当前代码

- `crates/bit-types`：`Amount`、固定发行、规范 CBOR、严格 Protobuf envelope、哈希/ID、证明哈希和授权角色结构。
- `crates/bit-shielded`：固定 Penumbra v2.1.1 上游 Spend/Output body 及证明的唯一严格验证入口。
- `crates/bit-transaction`：完整 Transfer 以及 RegisterValidator、Delegate、CancelPending、Unbond、ClaimExit、UpdateValidator、UnjailValidator、RotateConsensusKey、ClaimCommission envelope 的链上下文、费用、Spend/Output 证明、Spend 授权、角色域分离 Ed25519 签名、共识键 PoP、公开价值 binding 和重复 nullifier 检查。
- `crates/bit-emission`：固定 1024 亿枚上限的整数会计，验证已发行量、当前供应量、容器总额、销毁量、已放弃额度和未来发行额度之间的恒等式；同时实现无追补的逐 epoch 发行、奖励与佣金容器变换及规范最低费。
- `crates/bit-staking`：验证者、质押池、持仓和退出票据的确定性账本；实现 pending 激活、U256 池份额/退出份额换算、自质押资格、候选排序、投票权边界、验证人序号、佣金延迟、双门槛解禁、共识密钥历史、实际签名 score、downtime jail、池奖励、Unbond cohort 和双高度/时间成熟后的 ClaimExit。
- `crates/bit-state`：基于 Cnidarium 0.83/JMT 0.11/RocksDB 8.1.1 的 schema v15 状态，维护真实 Penumbra TCT、创世承诺、链时间、anchor 窗口、nullifier、交易索引、供应会计、逐项质押/退出记录、持久化退出推进队列、增量候选索引、H/H+1/H+2 实际验证者集合及逐高度责任历史，并提供两阶段原子提交和 ICS23 查询证明；真实 Transfer 和九类质押交易均已通过正式信封入口，其中退出链路另覆盖跨块成熟、落盘证明和重启恢复。
- `crates/bit-app`：确定性生命周期核心及固定 CometBFT ABCI v0.38 适配，严格解析实际 last commit 和 `next_validators_hash`，在 Prepare/Process/Finalize 统一执行“签名计分→发行/奖励→pending 激活→集合选择”，返回验证人 key/power 更新及自验后的 ICS23 ProofOps，并通过本机 TCP 协议往返测试。
- `contracts`、`config`、`tests/vectors`：从 BIT v1.2 主规格抽出的活跃机器合同、参考测试网配置和共享向量。
- `reference`：不依赖 Rust 的 Python 发行和编码 oracle。
- `feasibility`：真实证明、简化共识探针，以及复用生产 `bit-app`/JMT 状态核心的四节点 CometBFT 集成实验；不是生产节点发布物。

## 本机验证

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-baseline-checks.ps1
```

如已安装 `just`，也可运行 `just baseline`。基线同时启动四个本机 CometBFT/真实 BIT 应用进程验证 H+2、JMT 重启和投票权恢复；主报告写入 `reports/development-baseline.json`，网络证据写入 `feasibility/reports/bit-app-network-result.json`。Android 按用户要求跳过，基线命令不会访问手机。

当前还没有生产 execution/compact 摘要编码、正式节点命令、证据去重与 SlashJob 罚没、独立 signer、钱包或主网发布能力。应用已经持久化 H/H+1/H+2 实际集合，核对 last commit 成员/顺序/power 和请求中的 `next_validators_hash`，并阻止移除最后一个有效验证者；真实四节点 CometBFT 空块实验已验证 H+2、JMT 重启、app hash 一致、ICS23 查询与投票权停机/恢复。该实验仍使用加速 epoch 和临时域分离摘要，尚未覆盖多节点真实 Transfer/退出。退出暴露和双成熟已使用三个持久化有序队列推进；有界 SlashJob 是 D-008 后续切片。`supply/audit_snapshot` 的规范编码仍等待 SPEC-04 决议。持久化层仍需补故障注入、快照导入导出、历史证明和长期增长测试。`config/mainnet-inputs.template.json` 保持阻断状态。
