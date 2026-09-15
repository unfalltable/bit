# BIT D-005 ABCI 生命周期设计

状态：`IN_PROGRESS`。确定性应用核心和 CometBFT 0.38 protobuf 适配已实现并通过本机 socket 往返测试；实际 last commit 已驱动在线计分、自动 epoch 结算和 ABCI ValidatorUpdates，H/H+1/H+2 集合与请求哈希已由持久状态核验。真实四节点 CometBFT 已接入同一 `bit-app`/JMT 核心，并通过真实 Transfer、ClaimGenesis、Unbond、ClaimExit、规范区块摘要、精确历史证明、退出中重启、证据处罚和投票权实验；正式 `bit-node` 已从两阶段批准的创世 bundle 重放状态并完成真实单节点 InitChain、出块、证明和重启。ABCI State Sync 已接入周期快照、轻客户端可信 app hash、隔离激活和真实三节点联网恢复，签名检查点与跨故障域验收仍未完成。

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
| `query_latest_with_proof` / `query_at_height_with_proof` | 复用 `bit-state` 最新或精确历史高度 ICS23 查询 |

PrepareProposal、ProcessProposal 和 FinalizeBlock 都要求合法的 ABCI Timestamp 和恰好 32 字节的 `next_validators_hash`，并把 Unix 秒传给同一块执行器。请求哈希必须等于持久化 H+1 集合的 CometBFT 原生哈希。高度 1 不接受历史投票；之后每块必须提供 last commit，并逐项匹配 H-1 实际集合的规范顺序、地址和 power。地址严格为 CometBFT Ed25519 地址的 20 字节，power 必须为正，未知 flag、未知共识地址、重复地址和总 power 越界均拒绝。只有 `BLOCK_ID_FLAG_COMMIT` 增加 score，Nil/Absent 只记录未签机会。Finalize 与高度、摘要、供应、在线窗口、质押变更和三高度集合日程一起持久化；时间倒退或集合不一致时停止执行。

FinalizeBlock 同时严格归一化 `misbehavior`。仅接受 `DUPLICATE_VOTE` 和 `LIGHT_CLIENT_ATTACK`，要求 validator、20 字节地址、正 height/power/total power 及合法 Timestamp；状态层随后用逐高度历史集合复核责任、权重、时间和年龄，并把证据、处罚任务、Burn 与 validator updates 纳入同一候选区块。PrepareProposal/ProcessProposal 没有该字段，CometBFT 的证据模块负责在 FinalizeBlock 提供已验证证据，应用仍执行自己的历史责任和会计核验。

FinalizeBlock 已防御性处理无效交易，不因共识输入调用 `panic`。如果底层存储或已提交状态损坏，错误不会伪装成普通交易拒绝；网络适配必须让节点停止参与，而不能返回伪造的成功 app hash。

## 3. ABCI v0.38 适配

`abci::AbciApplication` 固定使用 `tendermint-abci` 与 `tendermint-proto` 0.40.4 的 `v0_38` 方言。同步 ABCI 连接通过一个共享执行锁进入私有 Tokio runtime，保证不同 socket 线程不会并发推进 Finalize/Commit。共识关键错误会设置共享 halted 标志；后续所有连接均停止处理。`HALT_NO_SAFE_VALIDATOR_SET` 还会先写入状态目录旁的版本化安全日志；启动时存在日志、可恢复临时日志、损坏日志或 chain context 不匹配都会拒绝服务。运维只能用精确记录摘要把日志改名归档，不能通过该操作修改或提交被拒区块的状态。公开的 bind 入口拒绝非 loopback 地址及零长度读缓冲区，保持 ABCI 为节点内部接口。

`InitChain` 只在高度零接受，并与启动时配置的完整 `RequestInitChain` 逐字段相等。启动配置还检查 chain ID、创世时间、初始高度、Ed25519 验证者及投票权、区块和证据限制、应用版本，并要求 vote extension 启用高度为零；InitChain 的 key/power 集合还必须精确等于 genesis staking 的 Active 集合。供给、分配和密码学清单的语义校验仍依赖 D-006 与最终创世编码，当前不能据此宣称主网创世已验收。

正式入口 `bit-node start` 在打开工作状态前验证 identity 与 derived 两阶段签名阈值，对 bundle 执行全新高度零状态重放并逐字节比较生成文件，再从重放结果构造 `GenesisConfig` 和 `RequestInitChain`。节点保留 CometBFT 从 `genesis.json` 传入的原始 `app_state` JSON 字节，拒绝语义等价但字节不同的替换；ABCI 只监听 loopback，bundle 与状态目录必须互不包含。bundle 内的构建期 RocksDB 只作为仪式产物存在，节点不会直接信任或复制它。

查询路径固定为 `/bit/state/key`。`height=0` 表示最新高度，正高度表示精确的已提交历史高度；负数或高于最新提交的高度返回 `UNSUPPORTED_HEIGHT`，不会使应用停机。`prove=true` 时，应用先在本地验证 Cnidarium 生成的 ICS23 证明，再把每层 commitment proof 编码为 `jmt:v` ProofOp。响应高度和证明根都对应实际查询的状态版本。

本链的 vote extension 默认关闭：`ExtendVote` 始终返回空字节，`VerifyVoteExtension` 只接受空扩展。启用 `StateSyncConfig` 后，应用在配置间隔的 Commit 成功后自动为最新高度创建快照并保留有限数量，也保留显式创建入口；`ListSnapshots` 按高度倒序发布，`LoadSnapshotChunk` 逐块复核本地文件，`OfferSnapshot` 绑定 CometBFT 轻客户端提供的可信 app hash，`ApplySnapshotChunk` 支持乱序接收、坏块重取和 peer 拒绝。全部 chunk 通过规范 manifest 后，应用在独立目录重组、导入并完整打开状态，随后用耐久活动标记切换；标记临时文件可恢复，损坏或与历史高度的 ICS23 锚点不一致则拒绝启动。未配置 State Sync 时仍返回无快照或 `REJECT_FORMAT`，已有已提交状态或已执行 InitChain 的应用不会接受远端快照。

## 4. 稳定交易结果代码

当前代码固定以下第一批结果：`0 OK`、`1 INVALID_ENVELOPE`、`2 INVALID_SHIELDED_PROOF`、`3 WRONG_CHAIN_CONTEXT`、`4 UNSUPPORTED_ACTION`、`5 UNKNOWN_ANCHOR`、`6 DUPLICATE_NULLIFIER`、`7 NULLIFIER_ALREADY_SPENT`、`8 TRANSACTION_ALREADY_APPLIED`、`9 BLOCK_BYTES_EXCEEDED`。

后续动作只能追加代码，不能重排已发布值。ABCI `ResponseCheckTx` 和 `ExecTxResult` 将直接映射这些数值；日志只作诊断，调用方不能解析日志决定业务状态。

## 5. 区块产物边界

`BlockRequest` 不再接受外部提供的 `execution_hash` 或 `compact_hash`。FinalizeBlock 执行全部系统事件和交易后预览最终 TCT 根，由唯一编码器构造版本化 execution summary 与 compact block，再把两个域分离哈希写入同一候选状态。树根、产物和提交批次会在 Commit 前交叉核对；编码失败属于共识关键错误。

ABCI `bit.block.v1` 事件公开高度、两个摘要和 compact 字节数，状态键 `execution/block/<height>` 与 `compact/hash/<height>` 可用该高度的 ICS23 proof 核对。精确字节合同、排序、限制和哈希公式见 [D-002 区块产物规范编码](D:/others/BIT/docs/BIT_D-002_区块产物规范编码.md)。本地不可变归档和本机有界下载接口已实现，公网 TLS/Tor 服务仍待实现。

## 6. 当前验证与下一切片

当前测试覆盖 v0.38 Info、InitChain、CheckTx、PrepareProposal、ProcessProposal、FinalizeBlock、Commit、Query、vote extension 和快照响应，并通过真实 TCP socket 完成 Info → InitChain → CheckTx → FinalizeBlock → Commit → ICS23 Query 往返。State Sync 用例在两个独立应用间传输真实 RocksDB checkpoint，覆盖周期自动发布、错误 format/app hash、超量 chunk、非空目标拒绝、manifest 延后到达、坏块定位与 peer 拒绝、恢复后的高度/app hash/ICS23 proof、同步后继续提交、活动标记临时文件恢复、重启历史锚点验证和损坏标记拒绝启动。另有缩短 epoch 的应用测试以真实 commit power 自动结算奖励，检查返回的 Ed25519 key/power 更新只在 H+2 集合生效且重启后保持一致；错误请求哈希、commit power、缺失 commit、错误地址、非正 power、未知 block-id flag，以及证据的未知类型、缺失字段、非法地址/power/height/time 均被拒绝。

`comet_network_probe` 和 `run_bit_app_network.py` 启动四个由 CometBFT Go module v0.38.23 构建的进程及四个真实 BIT 应用状态实例，并同时记录二进制自报版本与 SHA-256。测试从两个创世承诺广播一笔冻结的 2 Spend/2 Output Groth16 Transfer，在链继续推进后按 Transfer 的精确高度核对交易/nullifier、TCT 根、供应审计和 execution/compact 状态证明、ABCI 事件及四节点 app hash。随后广播带 Ed25519 领取授权、binding 签名和两个 Groth16 Output 证明的 ClaimGenesis，四节点逐字节核对领取记录与供应容器转换；另一笔密码学有效且 tx id 不同的同领取权交易会到达 BIT CheckTx，并按已领取状态拒绝。

同一网络还动态生成真实 Unbond 与 ClaimExit。Unbond 使用普通委托的 PositionOwner 授权、释放值费用、零额但有真实证明的 blinding Output，在四节点精确核对 P/X/Q/F、ticket、cohort、交易记录和 TCT 根；cohort 进入 Unbonding 后立即成对重启一个应用与共识进程，旧高度证明不变，随后等待高度和链时间同时成熟。ClaimExit 用真实 Groth16 Output 把退出值转回私密池，四节点核对已领取票据、耗尽 cohort、供应容器、树根和 app hash；另一笔 tx id 不同的同 ticket 交易由 BIT CheckTx 拒绝。之后再次重启并核对 Transfer、ClaimGenesis、待领取及已领取退出记录的历史证明。测试还确认奖励更新在 H+2 生效、应用从 durable JMT 状态重启并追块。集成注入器使用隔离网络的临时验证人密钥构造 CometBFT 可验证的冲突 prevote，通过标准 RPC 广播后，四个应用一致执行证据持久化、Burn 和 H+2 验证人移除。处罚后停止一个仍有投票权的验证者，剩余 power 恰为三分之二时链停止，恢复该验证者后继续出块。每次运行的精确高度和哈希写入 `feasibility/reports/bit-app-network-result.json`。

`run-genesis-node-smoke.py` 使用 CometBFT 临时生成的真实 FilePV 共识密钥构造公开测试 identity，完成两阶段 2-of-2 签名、物化和独立重放，再启动正式 `bit-node`。测试要求真实 CometBFT 接受完整 InitChain，区块 1 header 提交物化 app hash，初始验证人 power 为 4，`meta/genesis_manifest_hash` 返回 ICS23 证明；随后成对重启应用和 CometBFT 并继续出块。结果与二进制 SHA-256 写入 `reports/genesis-node-smoke.json`。

`run-state-sync-smoke.py` 使用相同正式 `bit-node` 启动两个源节点和一个全新目标节点。两个 RPC 源在信任高度返回同一块哈希，CometBFT 据此执行轻客户端验证；一个指定 P2P 发布者按 5 块间隔生成应用快照。目标节点发现并激活快照、追上源链，在应用和 CometBFT 成对重启后继续出块，并再次核对导入高度的历史状态值和 ICS23 proof。物理 RocksDB checkpoint 可能因各副本 compaction 布局不同而具有不同字节，因此本轮没有让多个发布者以相同 height/format 混合供块；生产分发需要指定发布者、镜像同一快照，或后续改为规范逻辑快照。结果写入 `reports/state-sync-smoke.json`。

ClaimGenesis 和退出闭环均已完成四节点真实广播、供应转换、重复领取拒绝和重启后历史证明，正式节点 State Sync 已完成发现、下载、可信 app hash、隔离激活、追块和重启验证。下一步由 D-010 完成签名检查点、可信期过期/更新、中断下载恢复及跨独立故障域来源；D-022 继续完成头同步、广播与公网入口。
