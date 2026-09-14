# BIT D-005 ABCI 生命周期设计

状态：`IN_PROGRESS`。确定性应用核心和 CometBFT 0.38 protobuf 适配已实现并通过本机 socket 往返测试；实际 last commit 已驱动在线计分、自动 epoch 结算和 ABCI ValidatorUpdates，H/H+1/H+2 集合与请求哈希已由持久状态核验。真实四节点 CometBFT 已接入同一 `bit-app`/JMT 核心并通过空块、重启和投票权实验；状态层已有本地可验证快照，ABCI State Sync、生产摘要编码器、正式节点命令和多节点真实 Transfer 仍未完成。

## 1. 单一执行入口

`crates/bit-app` 位于 ABCI 网络适配与 `bit-state` 之间。CheckTx、PrepareProposal、ProcessProposal 和 FinalizeBlock 都调用同一个 envelope 验证与动作调度入口，不各自维护 Transfer 或质押规则。只有 Commit 消耗 FinalizeBlock 产生的 `PreparedBlock` 并写入 RocksDB。

应用协议版本和 `max_block_bytes` 已移入 `GenesisConfig`，由状态 schema v3 持久化。节点重启时给出不同值会拒绝打开数据库，避免同一 app hash 下使用不同本地执行限制。

## 2. 当前生命周期

| 核心方法 | 当前行为 |
|---|---|
| `info` | 返回持久化高度、app hash 和创世锁定的协议版本 |
| `check_tx` | 针对最新已提交状态的下一高度验证一笔交易，丢弃临时状态 |
| `prepare_proposal` | 先核对 H+1 的 `next_validators_hash`，再从 local last commit 执行系统阶段并保持候选输入顺序筛选可执行交易；同块冲突会被过滤 |
| `process_proposal` | 核对请求哈希，从 proposed last commit 重放同一系统阶段和交易；超字节预算或任何无效输入都拒绝提案 |
| `finalize_block` | 核对请求哈希，从 decided last commit 执行签名计分和边界结算，再按顺序执行交易；只产生待提交批次和 H+2 ValidatorUpdates |
| `commit` | 每次只消费一个待提交批次；无 Finalize 或重复 Commit 均返回错误 |
| `query_latest_with_proof` | 复用 `bit-state` 最新高度 ICS23 查询 |

PrepareProposal、ProcessProposal 和 FinalizeBlock 都要求合法的 ABCI Timestamp 和恰好 32 字节的 `next_validators_hash`，并把 Unix 秒传给同一块执行器。请求哈希必须等于持久化 H+1 集合的 CometBFT 原生哈希。高度 1 不接受历史投票；之后每块必须提供 last commit，并逐项匹配 H-1 实际集合的规范顺序、地址和 power。地址严格为 CometBFT Ed25519 地址的 20 字节，power 必须为正，未知 flag、未知共识地址、重复地址和总 power 越界均拒绝。只有 `BLOCK_ID_FLAG_COMMIT` 增加 score，Nil/Absent 只记录未签机会。Finalize 与高度、摘要、供应、在线窗口、质押变更和三高度集合日程一起持久化；时间倒退或集合不一致时停止执行。

FinalizeBlock 同时严格归一化 `misbehavior`。仅接受 `DUPLICATE_VOTE` 和 `LIGHT_CLIENT_ATTACK`，要求 validator、20 字节地址、正 height/power/total power 及合法 Timestamp；状态层随后用逐高度历史集合复核责任、权重、时间和年龄，并把证据、处罚任务、Burn 与 validator updates 纳入同一候选区块。PrepareProposal/ProcessProposal 没有该字段，CometBFT 的证据模块负责在 FinalizeBlock 提供已验证证据，应用仍执行自己的历史责任和会计核验。

FinalizeBlock 已防御性处理无效交易，不因共识输入调用 `panic`。如果底层存储或已提交状态损坏，错误不会伪装成普通交易拒绝；网络适配必须让节点停止参与，而不能返回伪造的成功 app hash。

## 3. ABCI v0.38 适配

`abci::AbciApplication` 固定使用 `tendermint-abci` 与 `tendermint-proto` 0.40.4 的 `v0_38` 方言。同步 ABCI 连接通过一个共享执行锁进入私有 Tokio runtime，保证不同 socket 线程不会并发推进 Finalize/Commit。共识关键错误会设置共享 halted 标志；后续所有连接均停止处理。`HALT_NO_SAFE_VALIDATOR_SET` 还会先写入状态目录旁的版本化安全日志；启动时存在日志、可恢复临时日志、损坏日志或 chain context 不匹配都会拒绝服务。运维只能用精确记录摘要把日志改名归档，不能通过该操作修改或提交被拒区块的状态。公开的 bind 入口拒绝非 loopback 地址及零长度读缓冲区，保持 ABCI 为节点内部接口。

`InitChain` 只在高度零接受，并与启动时配置的完整 `RequestInitChain` 逐字段相等。启动配置还检查 chain ID、创世时间、初始高度、Ed25519 验证者及投票权、区块和证据限制、应用版本，并要求 vote extension 启用高度为零；InitChain 的 key/power 集合还必须精确等于 genesis staking 的 Active 集合。供给、分配和密码学清单的语义校验仍依赖 D-006 与最终创世编码，当前不能据此宣称主网创世已验收。

查询路径固定为 `/bit/state/key`。当前只服务最新已提交高度；`height=0` 表示最新高度。`prove=true` 时，应用先在本地验证 Cnidarium 生成的 ICS23 证明，再把每层 commitment proof 编码为 `jmt:v` ProofOp。历史高度查询随 D-004 历史快照实现补入。

本链的 vote extension 默认关闭：`ExtendVote` 始终返回空字节，`VerifyVoteExtension` 只接受空扩展。`bit-state` 已有本地 checkpoint 快照导出和隔离恢复 API；ABCI 快照方法仍显式报告无可用快照并拒绝导入，避免本地恢复能力被误解为已经完成 State Sync 的发现、传输、可信根校验和会话管理。

## 4. 稳定交易结果代码

当前代码固定以下第一批结果：`0 OK`、`1 INVALID_ENVELOPE`、`2 INVALID_SHIELDED_PROOF`、`3 WRONG_CHAIN_CONTEXT`、`4 UNSUPPORTED_ACTION`、`5 UNKNOWN_ANCHOR`、`6 DUPLICATE_NULLIFIER`、`7 NULLIFIER_ALREADY_SPENT`、`8 TRANSACTION_ALREADY_APPLIED`、`9 BLOCK_BYTES_EXCEEDED`。

后续动作只能追加代码，不能重排已发布值。ABCI `ResponseCheckTx` 和 `ExecTxResult` 将直接映射这些数值；日志只作诊断，调用方不能解析日志决定业务状态。

## 5. 未决编码边界

`BlockRequest` 要求上层业务执行器显式提供 `execution_hash` 和 `compact_hash`。目前没有用零值或临时 JSON 替代 compact block，因为 SPEC-03 尚未冻结。D-006 与 compact 编码任务完成后，两类摘要必须由唯一规范编码器产生，并在 ProcessProposal 与 FinalizeBlock 中得到相同结果。

ABCI 适配通过 `FinalizeDigestProvider` 强制注入两个摘要来源；没有默认零值或用区块 hash 代替 compact hash 的降级路径。摘要生成失败会让应用进入 halted 状态。四节点实验使用明确标记的域分离请求摘要，只用于在 SPEC-03 冻结前驱动真实应用状态机，不能作为生产 compact 编码。

## 6. 当前验证与下一切片

当前测试覆盖 v0.38 Info、InitChain、CheckTx、PrepareProposal、ProcessProposal、FinalizeBlock、Commit、Query、vote extension 和快照响应，并通过真实 TCP socket 完成 Info → InitChain → CheckTx → FinalizeBlock → Commit → ICS23 Query 往返。另有缩短 epoch 的应用测试以真实 commit power 自动结算奖励，检查返回的 Ed25519 key/power 更新只在 H+2 集合生效且重启后保持一致；错误请求哈希、commit power、缺失 commit、错误地址、非正 power、未知 block-id flag，以及证据的未知类型、缺失字段、非法地址/power/height/time 均被拒绝。

`comet_network_probe` 和 `run_bit_app_network.py` 启动四个由 CometBFT Go module v0.38.23 构建的进程及四个真实 BIT 应用状态实例，并同时记录二进制自报版本与 SHA-256。测试确认奖励更新在 H+2 生效；一个应用从 durable JMT 状态重启并追块，四节点在同一固定高度的 app hash 相同，最新状态返回 ICS23 proof。集成注入器使用隔离网络的临时验证人密钥构造 CometBFT 可验证的冲突 prevote，通过标准 RPC 广播后，四个应用一致执行证据持久化、Burn 和 H+2 验证人移除。处罚后停止一个仍有投票权的验证者，剩余 power 恰为三分之二时链停止，恢复该验证者后继续出块。每次运行的精确高度和证据哈希写入 `feasibility/reports/bit-app-network-result.json`。

下一步实现版本化 execution/compact 编码器及创世语义校验，形成正式节点命令，再把真实 Transfer 和退出放进四节点重放与崩溃恢复实验。D-004/D-010 同步把现有本地快照导出恢复接入轻客户端可信根和 ABCI State Sync，并补历史高度证明。
