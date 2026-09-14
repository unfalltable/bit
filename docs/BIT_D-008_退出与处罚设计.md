# BIT D-008 退出与处罚设计

状态：`IN_PROGRESS`。Unbond、ExitCohort、ExitTicket、双高度/链时间成熟和 ClaimExit 已进入正式交易、会计、状态持久化与查询证明链；证据解析/去重、永久 tombstone、按比例销毁和可恢复的有界 SlashJob 尚未实现。

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

## 4. 持久化与验证证据

schema v13 新增 `staking/exits/cohorts/<cohort_id>` 和 `staking/exits/tickets/<ticket_id>`；schema v14 增加 exposure、maturity-height 和 maturity-time 三个 ExitQueueEntry 索引；schema v15 增加 `staking/effective_history/<height>`，逐高度保存真实 CometBFT 集合及链时间。创世、区块触及写入、重启读取、账本校验和 `sum(cohort.assets)=supply.exit_total` 全部已接入；退出对象、队列及历史责任集合均可生成针对最新 app hash 的 ICS23 成员或非成员证明。

测试覆盖池份额退出、cohort 份额、最后领取尾差、双条件严格大于边界、未成熟与重复领取拒绝、最后验证者自质押保护、两类费用容器变化、跨七个区块推进、epoch 奖励交错、落盘、重启和 ICS23 证明。真实信封测试使用 Spend/Output Groth16 证明、PositionOwner Ed25519 授权、binding、实时 sequence/quote 和统一正式交易分发入口执行 Unbond 与 ClaimExit。

## 5. 下一切片

1. 使用已落盘的历史责任集合接入 CometBFT Byzantine evidence 规范校验和 evidence hash 去重。
2. 实现永久 tombstone、活动池罚没、供应 Burn 及按 `exposure_end_height >= infraction_height` 选择未成熟 cohort。
3. 将 cohort 扣罚拆成每块最多 128 项的持久化 SlashJob；任务存在时冻结该验证人的激活、Unbond 和 ClaimExit，崩溃重启不得重复扣罚。
4. 把真实退出和处罚故障恢复加入多节点 CometBFT 场景。
