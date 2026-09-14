# BIT D-004 持久化状态设计

状态：`IN_PROGRESS`。可运行状态层已接入 ABCI 和供应会计，并在 Windows 桌面工具链通过测试；快照、历史证明和完整故障注入仍待后续实现。

## 1. 边界与依赖

`bit-state` 是共识状态的唯一持久化入口。底层固定使用 Cnidarium 0.83.0、JMT 0.11.0 和 RocksDB 8.1.1；隐私票据承诺树使用已冻结的 Penumbra v2.1.1 TCT。数据库值、TCT frontier、JMT 节点和 RocksDB 版本由同一个 Cargo.lock 固定。

状态层可在块上下文中完成 Transfer 校验，也为执行层已验证角色签名与共识键 PoP 的质押动作提供授权后 staging 接口。它不维护明文地址余额表，也不接受调用方直接写 nullifier；公开 fee 和质押本金均作为供应容器之间的原子移动记账。

## 2. 状态结构

当前实现使用九个 JMT 子存储区：`shielded`、`transactions`、`execution`、`compact`、`supply`、`emission`、`fees`、`genesis` 和 `staking`。元数据留在主 JMT。

| 键 | 值 | 约束 |
|---|---|---|
| `meta/version` | 4 字节大端 schema 版本 | 当前为 11，未知版本拒绝启动 |
| `meta/height` | 8 字节大端状态高度 | 必须等于 Cnidarium 最新版本 |
| `meta/block_time_seconds` | 8 字节大端 Unix 秒 | ABCI 区块时间，不允许相对 durable 状态倒退 |
| `meta/chain_context` | 32 字节 | 创世后不可变 |
| `meta/native_asset_id` | 32 字节 | 创世后不可变 |
| `meta/protocol_version` | 8 字节 | ABCI 报告和执行规则版本，创世后不可变 |
| `meta/max_block_bytes` | 8 字节 | 区块内交易字节硬上限，创世后不可变 |
| `meta/max_tx_lifetime_blocks` | 8 字节 | 创世后不可变 |
| `meta/max_envelope_bytes` | 8 字节 | 创世后不可变 |
| `meta/anchor_retention_blocks` | 8 字节 | 创世后不可变 |
| `meta/genesis_commitments_hash` | 32 字节 | 按清单顺序绑定创世隐私承诺，创世后不可变 |
| `meta/monetary_policy_hash` | 32 字节 | 绑定规范货币政策编码，创世后不可变 |
| `emission/policy` | 规范货币政策字节 | 重启时逐字节核对 |
| `emission/completed_epochs` | 8 字节大端整数 | 已结算 epoch 数 |
| `emission/forfeited_unissued` | 16 字节大端 Amount | 空合格集合永久放弃的额度 |
| `supply/max_supply` | 16 字节大端 Amount | 固定为 10,240,000,000,000,000,000 原子单位 |
| `supply/genesis` | 16 字节大端 Amount | 必须等于货币政策中的创世供应量 |
| `supply/cumulative_minted` | 16 字节大端 Amount | 创世后累计实际新增发行量 |
| `supply/burned` | 16 字节大端 Amount | 累计永久销毁量，不恢复发行额度 |
| `supply/shielded_total` | 16 字节大端 Amount | 私密池总量 Q |
| `supply/stake_total` | 16 字节大端 Amount | 质押容器总量 ΣP |
| `supply/pending_delegation_total` | 16 字节大端 Amount | 待生效委托 D |
| `supply/exit_total` | 16 字节大端 Amount | 退出容器总量 ΣX |
| `supply/commission_total` | 16 字节大端 Amount | 佣金容器总量 ΣC |
| `fees/reserve` | 16 字节大端 Amount | 费用及待分配发行池 F |
| `fees/base_atomic` | 16 字节大端 Amount | 每笔交易基础费 |
| `fees/per_kib_atomic` | 16 字节大端 Amount | 完整规范 envelope 每 KiB 费用，向上取整 |
| `fees/per_spend_proof_atomic` | 16 字节大端 Amount | 每份 Spend proof 费用 |
| `fees/per_output_proof_atomic` | 16 字节大端 Amount | 每份 Output proof 费用 |
| `fees/new_position_surcharge_atomic` | 16 字节大端 Amount | 创建持仓附加费 |
| `fees/validator_registration_surcharge_atomic` | 16 字节大端 Amount | 注册验证者附加费 |
| `genesis/unclaimed_total` | 16 字节大端 Amount | 未领取创世分配 G |
| `staking/parameters` | v3 严格持久化记录 | 创世后不可变，包含最低委托、自质押、容量、投票权、在线率、jail、佣金通知和证据窗口参数 |
| `staking/validators/<validator_id>` | v5 Validator 记录 | 键必须匹配 operator 与 chain context 派生 ID；含 sequence、累计佣金、签名窗口/epoch score、待生效变更、jail 标记和共识键历史 |
| `staking/pools/<validator_id>` | v1 StakePool 记录 | pool 资产和 pending 分别交叉核对 P、D |
| `staking/positions/<position_id>` | v1 StakePosition 记录 | owner 不可修改，恢复收据严格为 512 字节 |
| `staking/capacity/<epoch_hex>` | v1 ActivationCapacity 记录 | 接受数减取消数不得下溢 |
| `staking/effective_schedule` | v1 三高度实际集合记录 | 在已提交高度 H 保存 H/H+1/H+2 的规范顺序、power 和 CometBFT 集合哈希 |
| `shielded/tree_root` | 32 字节 TCT 根 | 必须与 frontier 重算结果一致 |
| `shielded/tree_frontier` | 固定依赖版本的 bincode TCT | 纳入 JMT；解码前限制为 64 MiB |
| `shielded/anchor/<height>` | 32 字节 TCT 根 | 只保留配置窗口 |
| `shielded/anchor_by_root/<root>` | 8 字节高度 | Transfer anchor 快速判定 |
| `shielded/nullifier/<nf>` | 高度和 tx_id | 永不按 anchor 窗口裁剪 |
| `transactions/applied/<tx_id>` | 高度、effect hash、anchor、数量 | 防止同一 envelope 重放 |
| `execution/block/<height>` | 32 字节执行摘要 | 与状态高度同批提交 |
| `compact/hash/<height>` | 32 字节 compact 摘要 | 与状态高度同批提交 |

初始化时按签名创世清单的顺序校验并插入隐私承诺，然后关闭高度零 TCT block；非法字段元素或重复承诺会在写盘前拒绝。清单摘要使用 `BIT-GENESIS-COMMITMENTS-V1 || count_be_u64 || commitments` 的 SHA-256，重启配置必须给出同一有序清单。主网清单仍属于未批准外部输入。

TCT frontier 使用 bincode 是节点内部状态格式，不是网络协议。创世承诺加入不可变状态时 schema 从 1 提升为 2；protocol version 和区块字节上限进入持久化共识配置后提升为 3；供应与发行字段进入同一状态树后提升为 4；最低费参数和交易记录中的实际/最低费进入状态后提升为 5；逐项质押参数、validator、pool、position 和 activation-capacity 记录进入状态后提升为 6；完整验证人元数据进入 schema v7；链时间、佣金/jail 参数、验证人 sequence、待生效佣金和共识键历史进入 schema v8；逐验证人累计佣金及与供应容器 C 的交叉校验进入 schema v9；实际签名滑动窗口与 epoch score 进入 schema v10；三高度实际验证者集合及其 CometBFT 哈希进入 schema v11。任何后续依赖或结构升级也必须提升 `meta/version` 并提供确定性迁移，不能在旧数据库上静默换编码。

## 3. 块生命周期

1. `begin_block_at(h,time)` 从最新不可变快照读取高度、链时间、TCT 和实际验证者集合日程，要求 `h = durable_height + 1`、`time >= durable_time`，并核对 frontier、树根、日程高度和质押逻辑集合。
2. 每笔 Transfer 先检查 chain context、动作类型、anchor 和 tx_id，再执行证明与签名校验；得到 nullifier 后，在当前 `StateDelta` 中检查同块及历史冲突。
3. 所有 nullifier、output commitment 和费用会计都通过后才写入 delta。TCT 与供应状态均在副本上完成变更，任何失败都不会留下部分更新。
4. 每块系统阶段先要求请求中的 `next_validators_hash` 等于持久化 H+1 集合哈希；H>1 时 last commit 必须逐项匹配 H-1 集合的规范顺序、地址和 power。epoch 首块再结算发行、按确定性顺序激活 pending、选择验证集合，并把返回更新应用为 H+2 集合。
5. `prepare()` 重新验证供应、质押恒等式及质押逻辑集合与 H+2 实际集合一致，关闭当前 TCT block，把新根、frontier、anchor、供应字段、触及的质押记录、三高度集合日程、执行摘要、compact 摘要和高度写入同一个 delta，并调用 Cnidarium `prepare_commit` 计算下一 JMT 根。
6. `commit()` 调用 `commit_batch`，用单个 RocksDB WriteBatch 落盘全部 JMT、索引和值。返回的 app hash 必须等于 prepare 阶段的根；成功后才替换进程内质押镜像。

Prepare 结果被丢弃时，数据库版本不变。重启后从最后 durable 高度重新执行相同输入，必须产生同一个 app hash。测试已覆盖这条边界。

## 4. 查询证明

`query_latest_with_proof` 返回原始值、状态版本、app hash 和 Cnidarium 生成的 ICS23 proof。主 JMT 键使用一层证明；九个子存储区使用“子树值到子树根、子树根到全局根”的两层证明。`QueryProof::verify` 同时处理存在和不存在证明。

当前接口只保证最新快照。Cnidarium 进程内缓存可保留少量旧快照，但重启后的任意历史高度证明、快照导入导出和可信状态同步将在 D-004 后续切片实现。

## 5. 已验证不变量

- 空目录只初始化一次高度零状态；相同配置可重启，chain context 等不可变配置变化时拒绝打开。
- 状态高度与 Cnidarium 版本严格相等，倒退或缺键时停止打开，不自动清库。
- schema 回退、无法解码的 TCT frontier、非法或重复创世承诺均拒绝启动或初始化。
- Commit 前崩溃不产生 durable 写入；相同区块重放得到相同 app hash。
- 同交易、同块和跨块 nullifier 冲突均被拒绝，失败交易不写 tx_id、不写 nullifier、不推进 TCT。
- anchor 只在配置窗口内有效；裁剪 anchor 不裁剪 nullifier 或当前状态。
- 主存储、子存储的 ICS23 成员和非成员证明都能针对返回的 app hash 验证。
- 真实 2 Spend/2 Output Transfer 使用四份 Groth16 证明、两份 Spend 授权和 binding 签名完成验证、Prepare、RocksDB Commit、重启恢复及重启后的 ICS23 查询；同一 envelope 在下一高度被 tx_id 重放检查拒绝。
- 创世资产容器必须精确合计为创世供应量；Transfer fee 原子执行 `Q -= fee; F += fee`，总供应量不变，余额不足时交易和供应状态均不变。
- `T = Q + ΣP + D + ΣX + ΣC + F + G = G0 + Mint - Burn`，且 `Mint + K` 必须等于按 epoch 已调度额度；任一持久化字段被独立篡改时节点拒绝打开。
- 最低费使用完整规范 envelope 字节数向上取整到 KiB，并叠加 Spend/Output proof 数量和动作附加费；低费交易在 Groth16 前拒绝，费率配置变化时旧数据库拒绝打开。
- `completed_epochs` 必须等于提交高度推导出的 `max(0,(h-1)/epoch_blocks)`；缺少边界系统结算时 Prepare 失败且 durable 高度不推进。
- validator、pool、position 和 activation-capacity 使用独立 JMT 键；重启逐项解码并重建账本，拒绝键/ID 不符、非法编码、质押参数变化、份额索引不一致及 `sum(P)`/`sum(D)`/`sum(C)` 与供应容器不一致。
- 实际验证者按 CometBFT 的 power 降序、地址升序形成唯一集合并计算原生集合哈希；错误的 `next_validators_hash`、last commit 成员、顺序或 power 在修改系统状态前拒绝。
- H 返回的 ValidatorUpdates 只改变 H+2 集合；三高度滚动日程与质押逻辑集合在 Prepare 和重启时交叉核对。任何错误会回滚系统阶段的内存变更，移除最后一个有效验证者返回 `HALT_NO_SAFE_VALIDATOR_SET`。

## 6. 后续工作

D-004 仍需完成 RocksDB 磁盘满、fsync 失败、文件损坏和版本回退的故障注入；快照分块导出/隔离导入；重启后的历史证明服务；长期 nullifier、frontier 与 JMT 增长测试。D-005 已把同一执行器接到 CheckTx、ProcessProposal、FinalizeBlock、Commit 和 Query，后续还需真实 CometBFT 多节点集成。
