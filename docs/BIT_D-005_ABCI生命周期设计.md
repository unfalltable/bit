# BIT D-005 ABCI 生命周期设计

状态：`IN_PROGRESS`。确定性应用核心和 CometBFT 0.38 protobuf 适配已实现并通过本机 socket 往返测试；交易形式的验证人更新已经执行，但 ABCI ValidatorUpdates、可用快照、生产摘要编码器和真实多节点接线仍未完成。

## 1. 单一执行入口

`crates/bit-app` 位于 ABCI 网络适配与 `bit-state` 之间。CheckTx、PrepareProposal、ProcessProposal 和 FinalizeBlock 都调用同一个 envelope 验证与动作调度入口，不各自维护 Transfer 或质押规则。只有 Commit 消耗 FinalizeBlock 产生的 `PreparedBlock` 并写入 RocksDB。

应用协议版本和 `max_block_bytes` 已移入 `GenesisConfig`，由状态 schema v3 持久化。节点重启时给出不同值会拒绝打开数据库，避免同一 app hash 下使用不同本地执行限制。

## 2. 当前生命周期

| 核心方法 | 当前行为 |
|---|---|
| `info` | 返回持久化高度、app hash 和创世锁定的协议版本 |
| `check_tx` | 针对最新已提交状态的下一高度验证一笔交易，丢弃临时状态 |
| `prepare_proposal` | 保持候选输入顺序，在 Comet 请求上限与链上硬上限的较小值内筛选可执行交易；同块冲突会被过滤 |
| `process_proposal` | 在单个临时块视图中按顺序重执行；超字节预算或任何无效交易都拒绝提案 |
| `finalize_block` | 按顺序执行交易；每笔返回稳定代码，失败交易不留部分状态；只产生待提交批次 |
| `commit` | 每次只消费一个待提交批次；无 Finalize 或重复 Commit 均返回错误 |
| `query_latest_with_proof` | 复用 `bit-state` 最新高度 ICS23 查询 |

PrepareProposal、ProcessProposal 和 FinalizeBlock 都要求合法的 ABCI Timestamp，并把 Unix 秒传给同一块执行器。Finalize 与高度、摘要、供应和质押变更一起持久化链时间；时间相对 durable 状态倒退时停止执行。CheckTx 使用 durable 时间加一的预览值，只用于无副作用策略检查。

FinalizeBlock 已防御性处理无效交易，不因共识输入调用 `panic`。如果底层存储或已提交状态损坏，错误不会伪装成普通交易拒绝；网络适配必须让节点停止参与，而不能返回伪造的成功 app hash。

## 3. ABCI v0.38 适配

`abci::AbciApplication` 固定使用 `tendermint-abci` 与 `tendermint-proto` 0.40.4 的 `v0_38` 方言。同步 ABCI 连接通过一个共享执行锁进入私有 Tokio runtime，保证不同 socket 线程不会并发推进 Finalize/Commit。共识关键错误会设置共享 halted 标志；后续所有连接均停止处理。公开的 bind 入口拒绝非 loopback 地址及零长度读缓冲区，保持 ABCI 为节点内部接口。

`InitChain` 只在高度零接受，并与启动时配置的完整 `RequestInitChain` 逐字段相等。启动配置还检查 chain ID、创世时间、初始高度、Ed25519 验证者及投票权、区块和证据限制、应用版本，并要求 vote extension 启用高度为零。供给、分配和密码学清单的语义校验仍依赖 D-006 与最终创世编码，当前不能据此宣称主网创世已验收。

查询路径固定为 `/bit/state/key`。当前只服务最新已提交高度；`height=0` 表示最新高度。`prove=true` 时，应用先在本地验证 Cnidarium 生成的 ICS23 证明，再把每层 commitment proof 编码为 `jmt:v` ProofOp。历史高度查询随 D-004 历史快照实现补入。

本链的 vote extension 默认关闭：`ExtendVote` 始终返回空字节，`VerifyVoteExtension` 只接受空扩展。快照方法目前显式报告无可用快照并拒绝导入，避免依赖库默认响应被误解为已支持 State Sync。

## 4. 稳定交易结果代码

当前代码固定以下第一批结果：`0 OK`、`1 INVALID_ENVELOPE`、`2 INVALID_SHIELDED_PROOF`、`3 WRONG_CHAIN_CONTEXT`、`4 UNSUPPORTED_ACTION`、`5 UNKNOWN_ANCHOR`、`6 DUPLICATE_NULLIFIER`、`7 NULLIFIER_ALREADY_SPENT`、`8 TRANSACTION_ALREADY_APPLIED`、`9 BLOCK_BYTES_EXCEEDED`。

后续动作只能追加代码，不能重排已发布值。ABCI `ResponseCheckTx` 和 `ExecTxResult` 将直接映射这些数值；日志只作诊断，调用方不能解析日志决定业务状态。

## 5. 未决编码边界

`BlockRequest` 要求上层业务执行器显式提供 `execution_hash` 和 `compact_hash`。目前没有用零值或临时 JSON 替代 compact block，因为 SPEC-03 尚未冻结。D-006 与 compact 编码任务完成后，两类摘要必须由唯一规范编码器产生，并在 ProcessProposal 与 FinalizeBlock 中得到相同结果。

ABCI 适配通过 `FinalizeDigestProvider` 强制注入两个摘要来源；没有默认零值或用区块 hash 代替 compact hash 的降级路径。摘要生成失败会让应用进入 halted 状态。

## 6. 当前验证与下一切片

当前测试覆盖 v0.38 Info、InitChain、CheckTx、PrepareProposal、ProcessProposal、FinalizeBlock、Commit、Query、vote extension 和快照响应，并通过真实 TCP socket 完成 Info → InitChain → CheckTx → FinalizeBlock → Commit → ICS23 Query 往返。

下一步实现版本化 execution/compact 编码器及创世语义校验，然后把真实 Transfer 放进 CometBFT 四节点重放与崩溃恢复实验。D-004 同步补快照导入导出和历史高度证明；D-007 接入唯一的验证者集合生效函数与 H+2 测试。
