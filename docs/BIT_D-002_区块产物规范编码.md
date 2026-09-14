# BIT D-002 区块产物规范编码

状态：`IN_PROGRESS`。版本 1 的执行摘要与紧凑区块字节合同、严格解码器、域分离哈希、共享黄金向量、ABCI/状态接线及本地不可变归档已经实现。按高度下载接口、跨节点保留策略和轻客户端消费仍待 D-010/D-022 完成。

## 1. 共同外层

两种产物都使用 RFC 8949 确定性 CBOR，只允许定长数组、最短整数、确定长度字节串、布尔值和 null。解码后必须重新编码为逐字节相同的结果；未知版本、字段数、标签、非最短表示、尾随字节或超过限制的内容一律拒绝。

共同外层为 7 项数组：

```text
[version, chain_context, height, block_time_seconds,
 shielded_tree_root, transactions, events]
```

`version=1`；三个哈希/根字段为 32 字节；高度必须大于零。`Amount` 和事件中的 `u128 score` 都是恰好 16 字节的大端无符号整数。单个完整产物最大 64 MiB，交易与事件各最多 100000 项。

## 2. 执行摘要

`transactions` 按区块原始交易位置连续编号，每项为：

```text
[index, SHA256(raw_envelope), result_code, accepted]
accepted = null
         / [tx_id, effect_hash_64, action_tag, fee]
```

只有 `result_code=0` 时 `accepted` 必须存在，失败结果必须是 null。这样摘要同时绑定原始 envelope、稳定结果码以及成功执行所用的交易 ID、效果哈希、动作和费用。

摘要哈希固定为：

```text
SHA256("bit/execution-summary/v1" || len_u64_be(cbor) || cbor)
```

## 3. 紧凑区块

紧凑区块只包含成功交易，仍保留其原始区块索引，且索引严格递增。每项为：

```text
[index, tx_id, action, nullifiers, output_commitments,
 output_bodies, memo_ciphertext_or_null]
```

`action` 直接复用交易正文的规范 Action 编码。每笔最多 8 个 nullifier 和 8 个 Output；`output_commitments` 与 `output_bodies` 必须等长。Output body 是交易中已经严格解码验证过的原始 Penumbra v2.1.1 `OutputBody` protobuf 字节，每项 1..8192 字节。存在 Output 时必须有恰好 528 字节的 memo 密文；无 Output 时 memo 必须为 null。

紧凑区块哈希固定为：

```text
SHA256("bit/compact-block/v1" || len_u64_be(cbor) || cbor)
```

## 4. 公共系统事件

两种产物包含完全相同的事件流。每个事件先独立规范编码，再按完整编码字节严格升序排列；相同事件字节不能重复。标签与形状如下：

| 标签 | 事件 | CBOR 数组 |
|---:|---|---|
| 0 | PreviousCommit | `[0, height]` |
| 1 | RewardSettlement | `[1, epoch, issuance_quota, distributed, fee_reserve_remainder, rewards]` |
| 2 | Activation | `[2, position_id, result_tag, amount_or_shares, reason_or_null]` |
| 3 | ValidatorSet | `[3, validators]` |
| 4 | ValidatorUpdate | `[4, consensus_pubkey, power]` |
| 5 | Evidence | `[5, evidence_hash, validator_id, newly_tombstoned, slashed_active_assets]` |
| 6 | SlashAdvance | `[6, touched_jobs, touched_cohorts, completed_jobs, slashed_exit_assets]` |
| 7 | ExitAdvance | `[7, exposure_recorded, matured]` |

奖励记录按 `validator_id` 升序；验证人集合按 stake 降序、再按 `validator_id` 升序；Slash/Exit 的哈希列表均严格升序。退款原因固定为 0 ValidatorIneligible、1 PoolInsolvent、2 ZeroShares、3 MinimumSharesNotMet。

## 5. 共识接线与证据

`FinalizeBlock` 在同一候选状态中完成系统阶段和交易执行，预览最终 TCT 根，构造两种产物，再把两个哈希写入 `execution/block/<height:020>` 与 `compact/hash/<height:020>`。候选状态随后重新核对树根，避免摘要与提交状态分离。调用方不能注入或替换摘要。

ABCI 返回一个 `bit.block.v1` 事件，包含 height、execution_hash、compact_hash 和 compact_bytes；哈希可通过最新高度 ICS23 查询证明核对。共享空块向量由 Rust 与独立 Python oracle 交叉验证。四节点 CometBFT 探针还执行一笔真实 2 Spend/2 Output Groth16 Transfer，核对交易、nullifier、TCT 根、两个产物哈希、ABCI 事件及四份 JMT app hash 一致。

当前 ABCI 事件只公开摘要与紧凑区块长度。完整产物已经进入本地不可变归档，但服务接口、历史证明与客户端扫描属于下一阶段，不能仅凭本实现宣称恢复服务已经完成。

## 6. 本地不可变归档

每个应用状态目录包含独立的 `block-artifacts-v1` 非共识归档。Finalize 生成并严格验证两种产物后，把 `execution.cbor` 与 `compact.cbor` 写入 `pending/<height>`，对两个文件执行同步落盘；此时按高度读取仍不可见。JMT Commit 成功后，应用把完整目录原子重命名到 `blocks/<height>`，不会覆盖已经发布的高度。

若进程在 JMT 已提交、归档目录尚未发布的窗口崩溃，重启会验证暂存字节、两种域分离哈希、共同块字段、公共事件和成功交易集合，再以最新 JMT 中的 `execution/block/<height>` 与 `compact/hash/<height>` ICS23 证明核对后发布。高于 durable 状态的暂存目录视为未提交 Finalize 并清理；高于状态的已发布目录、冲突字节、非规范路径、符号链接、超限或损坏文件都会拒绝打开或读取。

`ApplicationCore::block_artifacts(height)` 只返回已经发布且重新验证过的完整产物。四节点探针逐节点读取真实 Transfer 高度的两个归档文件，要求字节、链上摘要和 ABCI 事件一致，并在应用重启后再次读取。归档不进入 JMT app hash，也不随当前 State Sync 快照自动补齐历史；远端归档复制、保留下限、删档治理和下载服务仍需单独实现。
