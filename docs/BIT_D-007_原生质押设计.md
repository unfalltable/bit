# BIT D-007 原生质押设计

状态：`IN_PROGRESS`。本文记录已经进入代码和测试的第一阶段，不代表 D-007 已完成，也不包含 D-008 的退出与处罚实现。

## 1. 唯一身份与对象

`crates/bit-staking` 直接复用 `bit-types` 的 `validator_id` 和 `position_id`，域分别为 `bit/validator/v1` 与 `bit/position/v1`，并绑定 32 字节 chain context。注册和创建持仓都会重新推导 ID，调用方提供不一致的 ID 时拒绝。

账本包含 `Validator`、`StakePool`、`StakePosition` 和逐激活 epoch 容量账。持仓 owner 不提供修改入口；self-bond 只以活动持仓的有序索引记录。所有公开状态变更先在账本副本执行，完整不变量通过后才替换原状态，失败不会留下 pool、position 或容量的部分修改。

## 2. Pending 与激活

普通委托最低 1 BIT，自质押最低 1000 BIT。新 Delegate 进入 `Pending`，记录创建高度、目标激活 epoch、最低可接受份额和恢复收据，不获得当前周期奖励，也不产生投票权。每个激活 epoch 的参考容量是 1000 个；容量不足时在建仓前拒绝。取消尚未处理的 pending 会归还一个容量名额，已处理的条目不会重新释放配额。

epoch 批量激活采用固定顺序：先按 position_id 处理 self-bond，再按 position_id 处理普通委托。这样同一边界内先建立验证者自质押资格，普通委托不会因节点本地遍历顺序得到不同结果。

激活份额严格使用 U256 中间乘法：

```text
P=0,S=0: minted = D
其他正常池: minted = floor(D*S/P)
P' = P + D
S' = S + minted
```

结果必须大于零，并满足持仓创建时的 `min_shares`；失败转为 `RefundablePending`。若验证者在激活时停用、不接受委托、普通委托缺少最低活动 self-bond，或池已处于 `P=0,S>0` 的资不抵债状态，同样转为可退款，资金不会进入活动池。`P>0,S=0` 视为损坏状态并拒绝。

## 3. 池价值与验证集合

持仓价值为 `floor(shares*P/S)`。部分销毁按同一比例，销毁池内最后全部份额时领取所有剩余 P，整数舍入留在原池且不会形成永久残余。奖励只允许加入已有份额的池，settled epoch 必须单调增加。

候选资格要求状态为 Candidate 或 Active、接受委托且活动 self-bond 的当前池价值达到最低值。候选按池资产降序、validator_id 字节升序排列，截取参考上限 64。投票权为 `floor(P/power_unit_atomic)`，默认单位 1 BIT；单项及选中总和均检查不超过 `2^60-1`，不使用浮点或临时缩放。

## 4. 供应会计接口

`bit-emission` 已增加三项原子转换，为后续非 Transfer 执行器提供唯一会计入口：

- 创建 pending：`Q -= deposit + fee; D += deposit; F += fee`；
- 激活：`D -= deposit; P += deposit`；
- 取消或激活失败退款：`D -= release; Q += release - fee; F += fee`。

每次转换后重新核对固定总量和七容器恒等式。余额不足、费用超过释放额或任何算术溢出都会保持原状态。

## 5. 本阶段验证

schema v7 为 parameters、validator、pool、position 和 capacity 分别定义版本化、定长整数、大端序的持久化编码；validator v2 记录完整公开元数据并拒绝重复 consensus key，position 的恢复收据严格为 512 字节。解码拒绝未知枚举、非规范布尔、重复索引、截断、尾随字节、非法 Amount、非法 UTF-8 和不符合定长规则的收据。每个对象使用独立 JMT 键，更新阶段只写本次触及的记录。

交易层现已对 RegisterValidator、Delegate 和 CancelPending 验证独立角色域的 Ed25519 签名。注册的 consensus-pop 域与 operator 域分离，自质押的 operator key 从当前状态解析。三类动作与 Spend/Output 证明、Spend 授权、最低费和公开 lock/release 一起进入同一个 binding equation。应用核心的 CheckTx、PrepareProposal、ProcessProposal 和 FinalizeBlock 都通过统一动作调度进入该执行器。

状态层在同一候选副本中验证 commitment tree、nullifier/tx_id、供应容器和质押账本，任一检查失败都不修改区块 overlay。Prepare 同时验证 `sum(pool.P)=供应容器 P` 与全部 pending/refundable 本金之和等于供应容器 D。持久内存镜像仅在 RocksDB batch 成功提交后替换，重启从逐项记录重建并重跑全部不变量。

测试覆盖 ID 不匹配、最低委托和自质押、延后激活、旧周期奖励后的份额报价、U256 大数乘除、最低份额滑点、零份额、验证者失去资格、资不抵债池、容量耗尽与取消释放、确定性批量顺序、候选排序、投票权上限、最后份额清空残余、编码严格性、账本篡改与失败原子性。供应测试覆盖 `Q/D/P/F` 的完整往返和余额不足回滚；RocksDB 集成测试覆盖 self-bond 从 pending 到 Active、四类 ICS23 证明、重启恢复及 pool/P 交叉篡改拒绝。

## 6. 完成 D-007 还需要

1. 已完成 RegisterValidator、Delegate、CancelPending；继续完成 UpdateValidator、Unjail 和 RotateConsensusKey 的状态转换与角色签名/PoP 校验。
2. 实现佣金延迟变更、共识键历史、在线率窗口、jail 双重等待条件和 operator sequence。
3. 把真实 epoch 签名得分、旧池奖励分配和增量候选索引接到现有“发行结算→激活→集合选择”原子系统阶段。
4. 从选中集合生成 CometBFT ValidatorUpdates，并做 H/H+1/H+2 真实集合哈希验证。
5. 落实最后合格验证者保护和 `HALT_NO_SAFE_VALIDATOR_SET`，再进入 D-008 退出 cohort、ticket 与 SlashJob。
