# BIT D-004 持久化状态设计

状态：`IN_PROGRESS`。可运行状态层已接入 ABCI 和供应会计，并在 Windows 桌面工具链通过测试；本地分块校验快照、ABCI State Sync 传输与隔离激活、重启后精确历史高度证明已实现，跨平台恢复演练和完整故障注入仍待后续实现。

## 1. 边界与依赖

`bit-state` 是共识状态的唯一持久化入口。底层固定使用 Cnidarium 0.83.0、JMT 0.11.0 和 RocksDB 8.1.1；隐私票据承诺树使用已冻结的 Penumbra v2.1.1 TCT。数据库值、TCT frontier、JMT 节点和 RocksDB 版本由同一个 Cargo.lock 固定。

状态层可在块上下文中完成 Transfer 校验，也为执行层已验证角色签名与共识键 PoP 的质押动作提供授权后 staging 接口。它不维护明文地址余额表，也不接受调用方直接写 nullifier；公开 fee 和质押本金均作为供应容器之间的原子移动记账。

## 2. 状态结构

当前实现使用九个 JMT 子存储区：`shielded`、`transactions`、`execution`、`compact`、`supply`、`emission`、`fees`、`genesis` 和 `staking`。元数据留在主 JMT。

| 键 | 值 | 约束 |
|---|---|---|
| `meta/version` | 4 字节大端 schema 版本 | 当前为 20，未知版本拒绝启动 |
| `meta/height` | 8 字节大端状态高度 | 必须等于 Cnidarium 最新版本 |
| `meta/block_time_seconds` | 8 字节大端 Unix 秒 | ABCI 区块时间，不允许相对 durable 状态倒退 |
| `meta/genesis_manifest_hash` | 32 字节 | 已签 identity manifest 的哈希，非零且创世后不可变 |
| `meta/chain_context` | 32 字节 | 创世后不可变 |
| `meta/native_asset_id` | 32 字节 | 创世后不可变 |
| `meta/protocol_version` | 8 字节 | ABCI 报告和执行规则版本，创世后不可变 |
| `meta/max_block_bytes` | 8 字节 | 区块内交易字节硬上限，创世后不可变 |
| `meta/max_tx_lifetime_blocks` | 8 字节 | 创世后不可变 |
| `meta/max_envelope_bytes` | 8 字节 | 创世后不可变 |
| `meta/anchor_retention_blocks` | 8 字节 | 创世后不可变 |
| `meta/genesis_commitments_hash` | 32 字节 | 按清单顺序绑定创世隐私承诺，创世后不可变 |
| `meta/genesis_claims_hash` | 32 字节 | 绑定按 claim ID 排序的公开领取权集合，创世后不可变 |
| `meta/monetary_policy_hash` | 32 字节 | 绑定规范货币政策编码，创世后不可变 |
| `<substore>/_meta/version` | 8 字节大端状态高度 | 九个子存储每个版本都写入，必须等于主树版本与 `meta/height` |
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
| `genesis/claims/<claim_id>` | v1 GenesisClaimStatus | 领取公钥、金额和可选领取高度；键、清单和 G 容器在重启时交叉核对 |
| `staking/parameters` | v4 严格持久化记录 | 创世后不可变，另含退出双窗口、Byzantine 罚没率和每块 cohort 处理上限 |
| `staking/validators/<validator_id>` | v5 Validator 记录 | 键必须匹配 operator 与 chain context 派生 ID；含 sequence、累计佣金、签名窗口/epoch score、待生效变更、jail 标记和共识键历史 |
| `staking/pools/<validator_id>` | v1 StakePool 记录 | pool 资产和 pending 分别交叉核对 P、D |
| `staking/positions/<position_id>` | v1 StakePosition 记录 | owner 不可修改，恢复收据严格为 512 字节 |
| `staking/capacity/<epoch_hex>` | v1 ActivationCapacity 记录 | 接受数减取消数不得下溢 |
| `staking/candidates/<validator_id>` | v1 CandidateIndex 记录 | stake 降序、ID 升序索引必须与 validator/pool/position 精确一致 |
| `staking/exits/cohorts/<cohort_id>` | v1 ExitCohort 记录 | C/U、暴露和成熟双条件、状态必须与票据及参数一致 |
| `staking/exits/tickets/<ticket_id>` | v1 ExitTicket 记录 | owner/position/cohort/units/sequence/claimed 严格交叉校验 |
| `staking/exits/exposure_queue/<height>/<cohort_id>` | v1 ExitQueueEntry | 到达暴露高度后删除并建立双成熟索引 |
| `staking/exits/maturity_height_queue/<height>/<cohort_id>` | v1 ExitQueueEntry | 高度严格超过目标后只处理一次 |
| `staking/exits/maturity_time_queue/<seconds>/<cohort_id>` | v1 ExitQueueEntry | 链时间严格超过目标后只处理一次 |
| `staking/effective_schedule` | v1 三高度实际集合记录 | 在已提交高度 H 保存 H/H+1/H+2 的规范顺序、power 和 CometBFT 集合哈希 |
| `staking/effective_history/<height>` | v1 ValidatorSetHistoryRecord | 保存该高度真实集合及经过共识确认的链时间，供处罚责任与成员/总权重核验 |
| `staking/slash_jobs/<validator_id>` | v1 SlashJob | 处罚率、证据高度、冻结范围、当前游标、处理数量及 P/X 累计罚没 |
| `staking/evidence/<evidence_hash>` | v1 EvidenceRecord | 规范证据字段、验证人身份和接受高度；键、hash、历史责任及任务关系在重启时复核 |
| `shielded/tree_root` | 32 字节 TCT 根 | 必须与 frontier 重算结果一致 |
| `shielded/tree_frontier` | 固定依赖版本的 bincode TCT | 纳入 JMT；解码前限制为 64 MiB |
| `shielded/anchor/<height>` | 32 字节 TCT 根 | 只保留配置窗口 |
| `shielded/anchor_by_root/<root>` | 8 字节高度 | Transfer anchor 快速判定 |
| `shielded/nullifier/<nf>` | 高度和 tx_id | 永不按 anchor 窗口裁剪 |
| `transactions/applied/<tx_id>` | 高度、effect hash、anchor、数量 | 防止同一 envelope 重放 |
| `execution/block/<height>` | 32 字节执行摘要 | 与状态高度同批提交 |
| `compact/hash/<height>` | 32 字节 compact 摘要 | 与状态高度同批提交 |

初始化要求 `genesis_manifest_hash` 非零，并要求 `chain_context = SHA256("bit/chain/v1" || genesis_manifest_hash)`；两者写入同一高度零状态，重启时逐字节核对。随后按签名创世清单的顺序校验并插入隐私承诺，再关闭高度零 TCT block；非法字段元素或重复承诺会在写盘前拒绝。承诺摘要使用 `BIT-GENESIS-COMMITMENTS-V1 || count_be_u64 || commitments` 的 SHA-256，重启配置必须给出同一有序清单。公开领取项校验派生 ID、Ed25519 公钥、正数金额、ID/公钥唯一性和 G 容器上界，再按 claim ID 排序计算 `BIT-GENESIS-CLAIMS-V1` 摘要。主网身份清单、签名和真实分配仍属于未批准外部输入，依赖顺序见 D-025。

TCT frontier 使用 bincode 是节点内部状态格式，不是网络协议。创世承诺加入不可变状态时 schema 从 1 提升为 2；protocol version 和区块字节上限进入持久化共识配置后提升为 3；供应与发行字段进入同一状态树后提升为 4；最低费参数和交易记录中的实际/最低费进入状态后提升为 5；逐项质押参数、validator、pool、position 和 activation-capacity 记录进入状态后提升为 6；完整验证人元数据进入 schema v7；链时间、佣金/jail 参数、验证人 sequence、待生效佣金和共识键历史进入 schema v8；逐验证人累计佣金及与供应容器 C 的交叉校验进入 schema v9；实际签名滑动窗口与 epoch score 进入 schema v10；三高度实际验证者集合及其 CometBFT 哈希进入 schema v11；逐验证人的持久化候选排序记录进入 schema v12；退出参数、cohort 和 ticket 进入 schema v13；退出暴露/成熟队列进入 schema v14；逐高度真实验证者责任集合进入 schema v15；Byzantine evidence 和 SlashJob 进入 schema v16；规范供应审计快照进入 schema v17；九个子存储的逐高度版本标记和可重建历史证明进入 schema v18；创世领取清单、逐项状态和 G 容器交叉核对进入 schema v19；identity manifest hash 与 chain context 的派生关系和不可变存储进入 schema v20。任何后续依赖或结构升级也必须提升 `meta/version` 并提供确定性迁移，不能在旧数据库上静默换编码。

## 3. 块生命周期

1. `begin_block_at(h,time)` 从最新不可变快照读取高度、链时间、TCT 和实际验证者集合日程，要求 `h = durable_height + 1`、`time >= durable_time`，并核对 frontier、树根、日程高度和质押逻辑集合。
2. 每笔 Transfer 或已启用原生动作先检查 chain context、动作、anchor 和 tx_id，再执行证明与签名校验；ClaimGenesis 还从当前 `StateDelta` 读取领取公钥、金额和状态，因此同块第二次领取也会被拒绝。
3. 所有 nullifier、output commitment、业务状态和费用会计都通过后才写入 delta。TCT、供应、质押和领取记录均在候选状态上完成变更，任何失败都不会留下部分更新。
4. 每块系统阶段先要求请求中的 `next_validators_hash` 等于持久化 H+1 集合哈希；H>1 时 last commit 必须逐项匹配 H-1 集合。随后验证和去重 Byzantine evidence、墓碑化及创建 SlashJob；epoch 首块再结算发行、激活 pending 和选择集合，然后在全局 cohort 上限内推进处罚与退出队列，并把更新应用为 H+2 集合。
5. `prepare()` 重新验证供应、质押恒等式及质押逻辑集合与 H+2 实际集合一致，关闭当前 TCT block，把新根、frontier、anchor、供应字段、触及的质押记录、三高度集合日程、执行摘要、compact 摘要和高度写入同一个 delta，并调用 Cnidarium `prepare_commit` 计算下一 JMT 根。
6. `commit()` 调用固定 Cnidarium 0.83.0 的 BIT 补丁：先解析并验证完整 RocksDB WriteBatch 的头部、记录数量、列族 put/delete 标签、varint 和每个 key/value 边界，再以 WAL 开启且 `WriteOptions.sync=true` 的单次写入落盘全部 JMT、索引和值。写入或 fsync 错误通过 `Result` 返回停机路径；返回的 app hash 必须等于 prepare 阶段的根，成功后才替换进程内质押镜像。

Prepare 结果被丢弃或批次在写前失败时，数据库版本不变。重启后从最后 durable 高度重新执行相同输入，必须产生同一个 app hash。若同步写入已经完成、但进程在发布新内存快照前退出，当前进程保持旧视图并停止服务；重启会从 WAL 中恢复完整的新版本。测试用仅在测试构建启用的一次性故障点覆盖这三条边界。

## 4. 查询证明

`query_latest_with_proof` 和 `query_at_height_with_proof` 返回原始值、状态版本、app hash 和 Cnidarium 生成的 ICS23 proof。主 JMT 键使用一层证明；九个子存储区使用“子树值到子树根、子树根到全局根”的两层证明。`QueryProof::verify` 同时处理存在和不存在证明。

schema v20 延续 v18 的统一版本证明规则：创世及每个区块给九个子存储分别写入 `<prefix>/_meta/version`，要求标记、子树 JMT 版本、主树版本和 `meta/height` 全部等于提交高度。节点启动会校验最新标记；精确历史查询还会在指定版本逐项校验全部标记。Cnidarium 的固定补丁可在进程缓存缺失时，以同一旧版本重建主树和全部子树的只读快照，因此重启后仍可生成该高度的证明；未来高度返回明确的不可用错误。`meta/genesis_manifest_hash` 属于主树，可返回一层证明；创世领取记录属于 `genesis` 子树，可返回成员或非成员证明。

## 5. 状态快照

`export_snapshot` 从最新 durable 状态创建 RocksDB 物理 checkpoint。导出前、独立打开 checkpoint 后和导出完成时分别读取完整 `StateSummary`，三者必须一致；独立打开同时执行当前 schema 的全部 TCT、供应、质押、队列、集合、证据和索引不变量检查。导出目录只在所有检查成功后从同父目录临时路径原子改名发布，不能位于正在运行的数据库目录内，也不会覆盖已有路径。

每个快照根目录只允许 `manifest.bit`、`manifest.sha256` 和 `db/`。`manifest.bit` 是严格规范二进制，绑定格式版本、4 MiB chunk 大小、存储 schema、状态高度、链时间、存储版本、app hash、TCT 根、chain context、货币政策 hash、总字节数，以及排序后的安全相对文件名、文件长度和各 chunk SHA-256；域分离后的清单 hash 同时写入固定 65 字节的 `manifest.sha256`。实现限制清单为 64 MiB、文件数为 100000、目录项为 200000、目录深度为 16、总数据为 16 TiB，并拒绝链接、设备、非规范路径、额外文件和非规范清单。

`import_snapshot` 要求目标不存在且位于快照目录外。它先校验清单与 chain context，再逐文件、逐 chunk 复制到同父目录的隔离临时数据库并同步文件；随后用完整 `GenesisConfig` 独立打开恢复状态，核对 manifest 中的 schema、高度、链时间、版本、app hash、TCT 根和货币政策 hash。全部通过后才原子发布目标数据库并重新打开。

ABCI State Sync 使用固定 format 1。chunk 0 携带规范 manifest，后续 chunk 与 manifest 中的数据库 chunk 一一对应，每块不超过 4 MiB，总数不超过 CometBFT 默认的 100000 上限。`OfferSnapshot` 只在高度零且尚未 InitChain 的空应用上接受请求，并要求快照元数据的高度、数量、snapshot ID、chain context、schema 与本地规则一致，同时要求 manifest 声明的 app hash 等于 CometBFT 从轻客户端状态提供的 `RequestOfferSnapshot.app_hash`。传输会话可乱序落盘；manifest 到达后校验所有已收块，坏块要求重取并返回对应 peer，全部块通过后才重组成普通快照。

恢复继续经过 `import_snapshot` 的文件集、chunk hash、完整配置和状态不变量检查，目标写入由 snapshot ID 派生的独立状态目录。通过后先同步写入带校验和的活动状态标记，再替换进程内状态；重启根据标记选择该目录并再次核对高度、app hash 和 chain context。有效的临时标记会自动完成发布，冲突、损坏或指向不一致状态的标记会拒绝启动。应用状态目录与共识 signer 水位目录没有复用，State Sync 不接触签名状态。D-010 仍需实现独立证人、可信期与检查点更新流程，并用真实 CometBFT 新节点执行联网恢复及断点演练。

## 6. 已验证不变量

- 空目录只初始化一次高度零状态；相同配置可重启，genesis manifest hash、chain context 等不可变配置变化时拒绝打开，二者派生关系不成立时写盘前拒绝。
- 状态高度、主 JMT 版本和九个子存储版本标记严格相等，倒退或缺键时停止打开，不自动清库。
- schema 回退、无法解码的 TCT frontier、非法或重复创世承诺均拒绝启动或初始化。
- Commit 前崩溃不产生 durable 写入；相同区块重放得到相同 app hash。
- 截断的原生 RocksDB WriteBatch 会在触碰 WAL 前被解析器拒绝，处罚高度、EvidenceRecord、SlashJob、tombstone 和 Burn 均不产生部分状态；同一批次重放得到相同 app hash。
- RocksDB Commit 开启 WAL 同步并传播写入/fsync 错误。同步写入完成但内存快照发布前的故障会让进程保持旧视图；关闭并重启后恢复完整新版本及同一 app hash，不会重复处罚。
- 同交易、同块和跨块 nullifier 冲突均被拒绝，失败交易不写 tx_id、不写 nullifier、不推进 TCT。
- anchor 只在配置窗口内有效；裁剪 anchor 不裁剪 nullifier 或当前状态。
- 主存储、子存储的 ICS23 成员和非成员证明都能针对最新或精确历史高度返回的 app hash 验证；释放并重启 RocksDB 后仍可重建旧版本证明。
- 快照导出绑定完整状态摘要和逐 chunk hash；额外文件、非规范清单、错误不可变配置、篡改数据、已有目标或源目录内目标都会在发布前拒绝，合法恢复保持同一 app hash/TCT 根并可继续提交新区块。
- ABCI State Sync 拒绝错误 format、错误轻客户端 app hash、不同 chain/schema 和超量 chunk；乱序数据可先落盘，manifest 到达后会定位坏块并要求重取。完整恢复保持同一高度、app hash 和 ICS23 proof，活动状态标记支持临时文件崩溃恢复并对损坏保持关闭。
- 真实 2 Spend/2 Output Transfer 使用四份 Groth16 证明、两份 Spend 授权和 binding 签名完成验证、Prepare、RocksDB Commit、重启恢复及重启后的 ICS23 查询；同一 envelope 在下一高度被 tx_id 重放检查拒绝。
- 创世资产容器必须精确合计为创世供应量；Transfer fee 原子执行 `Q -= fee; F += fee`，总供应量不变，余额不足时交易和供应状态均不变。
- 创世领取清单哈希与启动配置不可变；领取记录的键、派生 ID、公钥、金额、高度和未领取合计会与供应容器 G 交叉核对。ClaimGenesis 原子执行 `G -= amount; Q += amount-fee; F += fee`，成功后记录领取高度。
- `T = Q + ΣP + D + ΣX + ΣC + F + G = G0 + Mint - Burn`，且 `Mint + K` 必须等于按 epoch 已调度额度；任一持久化字段被独立篡改时节点拒绝打开。
- 最低费使用完整规范 envelope 字节数向上取整到 KiB，并叠加 Spend/Output proof 数量和动作附加费；低费交易在 Groth16 前拒绝，费率配置变化时旧数据库拒绝打开。
- `completed_epochs` 必须等于提交高度推导出的 `max(0,(h-1)/epoch_blocks)`；缺少边界系统结算时 Prepare 失败且 durable 高度不推进。
- validator、pool、position、activation-capacity、candidate、exit cohort 和 exit ticket 使用独立 JMT 键；重启逐项解码并重建账本，拒绝键/ID 不符、非法编码、质押参数变化、份额/候选/票据索引不一致及 `sum(P)`/`sum(D)`/`sum(X)`/`sum(C)` 与供应容器不一致。
- 实际验证者按 CometBFT 的 power 降序、地址升序形成唯一集合并计算原生集合哈希；错误的 `next_validators_hash`、last commit 成员、顺序或 power 在修改系统状态前拒绝。
- H 返回的 ValidatorUpdates 只改变 H+2 集合；三高度滚动日程与质押逻辑集合在 Prepare 和重启时交叉核对。任何错误会回滚系统阶段的内存变更，移除最后一个有效验证者返回 `HALT_NO_SAFE_VALIDATOR_SET`。
- Byzantine evidence 的类型、时间、年龄、责任集合、单个及总 power 都从历史状态复核；相同 hash 不重复处罚。活动池和未成熟责任 cohort 的扣减分别与 P、X 及累计 Burn 同批守恒。
- SlashJob 使用确定性冻结边界和持久游标，全体任务每块合计不超过配置上限；逐块重启测试确认游标、处理数和累计罚没不倒退、不重复。

## 7. 后续工作

D-004 仍需完成真实磁盘配额耗尽、操作系统 fsync 失败、数据库文件损坏和版本回退的进程级故障注入；快照跨平台恢复与长期 nullifier、frontier、JMT 历史版本增长测试。D-005 已把同一执行器接到完整 ABCI 生命周期和 State Sync，并完成真实四节点/JMT 重启、真实 Transfer、生产 execution/compact 摘要、精确历史查询及重复投票处罚实验；后续还需执行真实 CometBFT 新节点 State Sync、实现区块产物下载和正式节点命令，并覆盖多节点真实退出。
