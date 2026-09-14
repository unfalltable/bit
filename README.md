# BIT

BIT 是一条以私密支付和原生质押为核心的独立单币 PoS 链。本目录已进入底层实现阶段；目前完成的是活跃规格基线、共识金额/交易编码、Spend/Output 的窄密码学适配、Transfer 的密码学验收入口、首版持久化共识状态层、ABCI v0.38 生命周期、固定总量与费用会计第一阶段，以及原生质押的确定性内存账本第一阶段。

先阅读 [活跃规格基线](D:/others/BIT/SPEC_BASELINE.md)、[总体开发方案](D:/others/BIT/docs/BIT_项目梳理与总体开发方案.md)、[D-004 状态设计](D:/others/BIT/docs/BIT_D-004_持久化状态设计.md)、[D-005 ABCI 生命周期设计](D:/others/BIT/docs/BIT_D-005_ABCI生命周期设计.md)、[D-006 固定总量与支付会计](D:/others/BIT/docs/BIT_D-006_固定总量与支付会计.md)、[D-007 原生质押设计](D:/others/BIT/docs/BIT_D-007_原生质押设计.md) 和 [最新开发进度](D:/others/BIT/docs/BIT_开发进度_2026-09-14.md)。`docs/solo` 仅作历史参考。

## 当前代码

- `crates/bit-types`：`Amount`、固定发行、规范 CBOR、严格 Protobuf envelope、哈希/ID、证明哈希和授权角色结构。
- `crates/bit-shielded`：固定 Penumbra v2.1.1 上游 Spend/Output body 及证明的唯一严格验证入口。
- `crates/bit-transaction`：完整 Transfer 以及 RegisterValidator、Delegate、CancelPending、UpdateValidator、UnjailValidator、RotateConsensusKey、ClaimCommission envelope 的链上下文、费用、Spend/Output 证明、Spend 授权、角色域分离 Ed25519 签名、共识键 PoP、公开价值 binding 和重复 nullifier 检查。
- `crates/bit-emission`：固定 1024 亿枚上限的整数会计，验证已发行量、当前供应量、容器总额、销毁量、已放弃额度和未来发行额度之间的恒等式；同时实现无追补的逐 epoch 发行、奖励与佣金容器变换及规范最低费。
- `crates/bit-staking`：验证者、质押池与持仓的确定性账本；实现 pending 容量、下一 epoch 激活、U256 份额换算、滑点退款、自质押资格、候选排序、投票权安全边界、验证人序号、佣金延迟、双门槛解禁、共识密钥历史、按 score 的池奖励和 operator 佣金领取。
- `crates/bit-state`：基于 Cnidarium 0.83/JMT 0.11/RocksDB 8.1.1 的 schema v9 状态，维护真实 Penumbra TCT、创世承诺、链时间、anchor 窗口、nullifier、交易索引、供应会计、费率配置及逐项质押记录，并提供两阶段原子提交和 ICS23 查询证明；真实 Transfer 和七类质押交易均已通过落盘、证明、重启和篡改拒绝测试。
- `crates/bit-app`：确定性生命周期核心及固定 CometBFT ABCI v0.38 适配，统一调度已启用的 Transfer/质押交易、CheckTx、提案筛选/重执行、Finalize/Commit 和证明查询，返回自验后的 ICS23 ProofOps，并通过本机 TCP 协议往返测试。
- `contracts`、`config`、`tests/vectors`：从 BIT v1.2 主规格抽出的活跃机器合同、参考测试网配置和共享向量。
- `reference`：不依赖 Rust 的 Python 发行和编码 oracle。
- `feasibility`：真实证明与四节点实验；不是生产应用。

## 本机验证

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-baseline-checks.ps1
```

如已安装 `just`，也可运行 `just baseline`。报告写入 `reports/development-baseline.json`。Android 按用户要求跳过，基线命令不会访问手机。

当前还没有生产 execution/compact 摘要编码、真实 CometBFT 多节点接入、实际 last_commit 签名得分生产器、ValidatorUpdates、在线率窗口、退出/罚没动作、独立 signer、钱包或主网发布能力。epoch 奖励分配与佣金领取已实现，但应用尚未自动从真实生效集合生成 score，因此仍不能声称完整自动结算。`supply/audit_snapshot` 的规范编码仍等待 SPEC-04 决议。持久化层仍需补故障注入、快照导入导出、历史证明和长期增长测试。`config/mainnet-inputs.template.json` 保持阻断状态。
