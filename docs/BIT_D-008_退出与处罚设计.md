# BIT D-008 退出与处罚设计

状态：`IN_PROGRESS`。Unbond、ClaimExit、CometBFT Byzantine evidence、永久 tombstone、按比例 Burn 和可恢复的有界 SlashJob 已进入正式状态与 ABCI 链路；真实重复投票已在四节点 CometBFT 网络完成端到端注入，处罚过程底层存储故障注入和极端停链处置规程仍待完成。

## 1. 退出对象与标识

每次 Unbond 销毁活动持仓份额，并使用交易执行前的 position sequence 派生 `ticket_id`。同一验证人同一零基 exit epoch 的退出值聚合到唯一 `cohort_id`。票据保存不可变 owner、position、cohort、退出份额和创建时 position sequence；领取时使用票据自己的 sequence，成功一次后置为 claimed 且 sequence 加一。

cohort 保存当前资产 C、总退出份额 U、暴露截止高度、暴露截止链时间、成熟高度、成熟链时间和状态。新 cohort 以 `units=assets` 建立；已有且仍处于 `PendingExposure` 的 cohort 按 `floor(added_assets*U/C)` 增加份额。最后一张未领取票据领取全部剩余 C，其他票据按 `floor(ticket_units*C/U)` 领取，避免整数尾差成为无主资产。

所有 ID 都由 `bit-types` 的域分离 SHA-256 函数重新推导。持久化解码会拒绝键/ID 不一致、零份额、非法状态/sequence、缺少 position/cohort、票据份额总和不等于 cohort U、资产/份额零值不一致和非规范字节。

## 2. Unbond 执行

Unbond 只接受活动 position、精确 position sequence、正 shares、足够的 `min_gross` 和不高于签名 `max_fee` 的实际费用。池按 U256 中间乘法计算 gross；销毁池内最后全部份额时取走全部剩余池资产。退出部分在交易提交时离开 P，不再参与后续 epoch 奖励。

当前 epoch 为 `floor((height-1)/epoch_blocks)`，暴露截止固定为 `下一 epoch 首块 + 1 = 当前 epoch 末高度 + 2`，覆盖 CometBFT v0.38 的 H+2 ValidatorUpdates 生效规则。普通委托可全部退出；如果 self-bond 退出会清空最后一个合格候选，整笔交易以 `LastValidatorBond` 回滚。

费用来源有两种：

- `SHIELDED`：`P -= gross; X += gross; Q -= fee; F += fee`，交易必须包含私密 Spend。
- `RELEASED_VALUE`：要求 `gross > fee`，并执行 `P -= gross; X += gross-fee; F += fee`；公开 binding 只释放 fee，不能把退出本金提前作为可花费输出。

position、pool、validator 候选记录、cohort、ticket 和全部供应容器在同一候选事务及 RocksDB WriteBatch 中提交。

## 3. 暴露截止、成熟与领取

系统阶段在达到 `exposure_end_height` 时记录该块经过共识验证的链时间，并计算：

```text
maturity_height = exposure_end_height + unbonding_blocks
maturity_time = exposure_end_time + unbonding_seconds
```

只有 `current_height > maturity_height` 且 `current_chain_time > maturity_time` 时，cohort 才进入 `Mature`。参考参数为 241920 块和 1209600 秒，并在参数校验中强制两项退出窗口分别大于证据窗口。暴露高度、成熟高度和成熟时间分别使用按 deadline/cohort 排序的持久化队列；每项达到对应条件时删除一次，两个成熟索引都删除后才置为 Mature。链时间停滞不会造成已经达到高度的历史 cohort 被每块反复扫描。

ClaimExit 从当前状态重新计算票据 quote，并要求它精确等于信封签名的 `expected_release`。未成熟、重复领取、过期 sequence 或报价变化都会在任何状态写入前拒绝。领取费用同样支持：

- `SHIELDED`：`X -= release; Q += release; Q -= fee; F += fee`。
- `RELEASED_VALUE`：要求 `release > fee`，执行 `X -= release; Q += release-fee; F += fee`。

## 4. 证据验证、处罚与持久化

schema v13 新增退出 cohort/ticket，v14 增加三个推进队列，v15 增加逐高度真实 CometBFT 集合及链时间。schema v16 新增 `staking/evidence/<evidence_hash>` 和 `staking/slash_jobs/<validator_id>`。证据记录和任务使用严格版本化编码，启动时重新核对键、规范 hash、历史责任集合、验证人身份、tombstone 和任务关系。

ABCI v0.38 `FinalizeBlock.misbehavior` 只接受重复投票和轻客户端攻击。适配层严格检查类型、20 字节地址、正 height/power/total power 和合法 Timestamp；状态层再按证据高度读取历史责任集合，逐项核对地址、单个 power、集合总 power 和链时间。过期判定遵循 CometBFT 的组合规则：只有块龄和时间龄都超过上限才拒绝。证据 hash 绑定 chain context、类型、地址、power、高度、时间和总 power；相同证据再次出现不会重复处罚。

第一次有效重大证据立即把验证人永久置为 Tombstoned，停止委托与待生效变更，输出当前有效共识键的 power=0，并按 500 bps 从当前活动池 P 扣除和计入 `supply/burned`。Pending 本金不扣罚；独立佣金 C 不作为委托本金扣罚。属于证据范围且尚未成熟的 cohort 按同一比例从 X 扣除并 Burn。

SlashJob 在证据接受时冻结当时已有的 validator-local cohort 范围，保存结束键、当前游标、已处理数量及 P/X 累计罚没。所有未完成任务按 validator_id 和 exit_epoch/cohort_id 稳定排序，共享每块最多 `slash_cohorts_per_block` 项的全局上限。游标也跨过不在责任范围或已经成熟的记录，避免重复扫描；任务未完成时拒绝相关 Unbond 和 ClaimExit，pending 激活会转为可退款状态。任务、被修改 cohort、供应 Burn、证据记录和集合日程在同一个 JMT/RocksDB 批次提交。

测试覆盖池份额退出、尾差、双成熟边界、两类费用、epoch 交错、证据字段/责任/power 校验、两个年龄维度的单独超限与同时超限、永久 tombstone、重复证据、供应守恒、全局处理上限、跨块游标、FinalizeBlock 已 prepare 但 Commit 前中断后的确定性重放、损坏 RocksDB WriteBatch 的写前拒绝、同步写入后但内存快照发布前的重启恢复、每块关闭并重启后的继续执行，以及 evidence/job/cohort 的 ICS23 证明。真实 Unbond/ClaimExit 信封继续使用 Groth16、PositionOwner Ed25519、binding 和正式交易分发入口。

四节点集成测试另外使用 CometBFT v0.38.23 原生类型和临时 FilePV 密钥构造两个同高度、同轮次、同类型但 BlockID 冲突的已签名 prevote，并通过 `/broadcast_evidence` 提交。测试从区块读取与目标验证人地址匹配的证据，确认该验证人在包含证据后的 H+1 仍存在、H+2 被移除，四个独立应用的 `staking/evidence/<hash>` ICS23 查询值完全相同、`supply/burned` 非零且相同，并在处罚后只保留三个验证人。随后停止其中一个仍有投票权的节点，剩余 power 恰为三分之二时链停止，节点恢复后四节点继续出块。

## 5. 最后安全验证人停签记录

若 downtime jail、epoch 集合选择或有效重大证据产生的更新会把非空实际集合变为空，候选区块继续返回 `HALT_NO_SAFE_VALIDATOR_SET`，不会提交 tombstone、Burn 或集合日程的部分状态。ABCI 在停止请求前把触发上下文写到状态目录旁的 `<state-dir>.safety-halt-v1`。v1 记录绑定 chain context、最后已提交高度和 app hash、尝试高度/区块 hash/链时间、`next_validators_hash` 以及按规范 hash 排序去重后的完整 evidence 字段；文件末尾带域分离 SHA-256 校验和。

写入使用同目录临时文件、文件 `sync_all` 和原子 rename；Unix 继续同步父目录。崩溃若留下完整临时文件，下一次读取会先提升为正式记录；正式或临时记录损坏、不可读、与 chain context 不同，节点都拒绝启动。已有不同记录也不会被覆盖。

运维读取与确认命令为：

```powershell
cargo run -p bit-app --example safety_halt_admin -- inspect <STATE_DIR>
cargo run -p bit-app --example safety_halt_admin -- acknowledge <STATE_DIR> <RECORD_HASH>
```

`acknowledge` 要求完整 32 字节记录摘要，成功后把原记录改名为带摘要的审计归档，不删除证据，也不改变共识状态。它只用于完成协调处置后的启动解锁；若 CometBFT 重放相同危险区块，节点会生成同一摘要并再次停机。单验证人环境不能借确认操作跳过有效处罚，多验证人生产网络应通过仍安全的集合完成正常 tombstone 和 H+2 移除。

## 6. 下一切片

1. 在现有同步 WriteBatch、预写编码校验和确定性提交边界故障测试之外，增加真实磁盘配额耗尽与操作系统 fsync 失败的进程级注入；停签日志本身已覆盖临时文件恢复、损坏、路径不可写、冲突防覆盖和精确摘要确认。
2. 为需要人工修复最后验证人集合的极端网络冻结正式治理/升级恢复规程；现有确认操作不会修改共识状态或跳过证据。
3. 接入公开事件、gateway/indexer 和钱包的“处罚结算中”状态。
