# BIT D-006 固定总量与支付会计

状态：`IN_PROGRESS`。固定总量、供应恒等式、创世分配、最低手续费、Transfer 费用入池、逐 epoch 发行算法、高度/结算计数、由 last commit 驱动的池奖励/佣金分配、佣金领取和可证明审计快照已经实现并持久化；H+2 实际集合已核验，钱包收发闭环仍待完成。

## 1. 会计边界

`bit-emission` 是 BIT 供应量与最低费规则的整数会计模块。它只处理原子单位，不使用浮点数，不读取本地时间，也不从节点配置推导主网参数。货币政策由创世配置给出规范编码及哈希，状态打开和每次变更都会重新验证；费率字段也在创世时写入状态并在重启时逐项核对。

固定上限为 `M = 10,240,000,000,000,000,000` 原子单位，即 1024 亿 BIT、8 位小数。销毁只减少当前供应量，不恢复未来发行额度；空合格集合对应的 epoch 额度永久计入 `K`，以后不追补。

## 2. 共识恒等式

状态在创世、块开始、Prepare 和重启时验证以下关系：

```text
T = Q + ΣP + D + ΣX + ΣC + F + G
I = G0 + Mint
T = I - Burn
Mint + K = U(e)
M = I + K + Future(e)
0 <= I <= M
```

其中 `Q` 是私密池，`ΣP` 是质押池，`D` 是待生效委托，`ΣX` 是退出池，`ΣC` 是佣金池，`F` 是费用及待分配发行池，`G` 是未领取创世分配。`U(e)` 是完成 `e` 个 epoch 后的计划发行量。

任何加法都使用受检查的 `u128`，落盘 Amount 统一为 16 字节大端值。单独改写任何容器、累计铸造量、销毁量或已放弃额度，都会破坏至少一条恒等式并使节点拒绝载入状态。

## 3. 已实现转换

| 转换 | 会计变化 | 当前接入情况 |
|---|---|---|
| 创世初始化 | 分配容器之和必须等于 `G0` | 已接入状态高度 0 |
| Transfer fee | `Q -= fee; F += fee` | 已接入真实 Transfer 执行与原子提交 |
| 创世领取 | `G -= released; Q += released - fee; F += fee` | 会计函数已实现，动作执行器未接入 |
| 合格 epoch | `Mint += quota; F += quota` | 新 epoch 首块根据已累计实际签名 score 自动执行 |
| 空合格集合 epoch | `K += quota` | score 总和为零时自动放弃且不追补 |
| 费用/发行分配 | `F -= reward + commission; ΣP += reward; ΣC += commission` | 已按 score 和 validator commission 接入旧池，余数留 F |
| 佣金领取 | `ΣC -= released; Q += released - fee; F += fee` | ClaimCommission 已接入真实证明交易 |
| 解除质押 | `ΣP -= gross; ΣX += gross[-fee]; Q/F 按 fee_source 变化` | Unbond 已接入真实证明交易 |
| 退出领取 | `ΣX -= released; Q += released-fee; F += fee` | ClaimExit 已接入真实证明交易 |
| 销毁 | 来源容器减少，`Burn` 等量增加 | 会计函数已实现，业务动作未接入 |

所有转换都先在 `SupplyState` 副本上计算并验证，再整体替换原状态。状态层对 Transfer 采用同样顺序：先验证交易和全部 output commitment，再在 TCT 与供应副本上执行，最后一起写入 `StateDelta`。因此费用不足、证明失败、重复 nullifier 或非法 commitment 都不会留下部分会计状态。

最低费用按完整规范 envelope 计算：

```text
min_fee = base + ceil(canonical_envelope_bytes / 1024) * per_kib
        + spend_count * per_spend_proof
        + output_count * per_output_proof
        + applicable_surcharge
```

参考费率为 base 1,000、每 KiB 200、每份 Spend/Output proof 各 500、创建持仓附加 100,000、注册验证者附加 100,000,000 原子单位。所有乘加均检查溢出。当前 Transfer 使用标准费类；低于 minimum fee 的交易会在 Groth16 验证前以稳定错误拒绝，实际 fee 和 minimum fee 一起进入交易状态记录。

## 4. 持久化与证明

货币政策、政策哈希、六项费率、供应累计量、七类资产容器、完成 epoch 数和已放弃额度都纳入当前 schema v18 的 JMT（这些字段最初在 v5 引入）。它们与高度、TCT、交易索引、execution 摘要、compact 摘要、质押/退出记录、供应审计快照、三高度实际验证者集合及九个子存储版本标记在同一个 RocksDB WriteBatch 中提交。每个 validator v5 记录其 `commission_accrued`、签名窗口和 epoch score，重启时要求佣金总和精确等于供应容器 `ΣC`；全部 exit cohort 资产之和必须精确等于供应容器 `ΣX`。

`supply/audit_snapshot` 已冻结版本 1 规范值。它是 19 项 CBOR 数组：版本号、按本节恒定顺序排列的 16 个 Amount、`completed_epochs` 和 `monetary_policy_hash`。每个 Amount 必须编码为精确 16 字节大端 byte string，政策哈希必须为 32 字节，整数必须使用最短 CBOR 表示。顺序依次为 `M, G0, Mint, Burn, I, T, U(e), K, Future(e), Q, ΣP, D, ΣX, ΣC, F, G`。解码器要求无尾随字节、重新编码逐字节相等，并重新验证全部供应恒等式。

创世和每个区块提交都会从同一候选 `SupplyAudit` 生成快照，与组成字段原子写入 JMT。节点打开数据库时解码快照，并要求它和逐键重算结果完全相等；因此缺失、非规范编码或单字段篡改都会拒绝启动。通用 ABCI Query 可返回该键在最新或指定已提交高度 app hash 下的 ICS23 成员证明，重启后仍可重建旧高度。Rust 与独立 Python oracle 共用 `tests/vectors/supply-audit-vectors.json`，四节点探针按真实 Transfer 高度核对四份带证明规范值完全一致。REST DTO 与 SDK 映射仍由 D-022 补齐。

提交高度 `h` 对应的已结算 epoch 数固定为 `max(0, (h-1)/epoch_blocks)`。高度 1 和每个 epoch 的末块不会提前结算，下一 epoch 首块才要求计数增加。应用先读取 `h-1` 的 last commit 并累加真实签名 power；边界块在一个候选副本中消费上一 epoch score，决定发行或放弃，把当时全部 F 按 score 分 gross，再按 validator commission 拆到 P/C。PrepareProposal、ProcessProposal 和 FinalizeBlock 都执行同一顺序，任何失败保持 durable 状态不变。

## 5. 已验证场景

- 创世容器合计错误会在写盘前拒绝。
- 真实 2 Spend/2 Output Transfer 的 1,000,000 原子单位 fee 从私密池转入费用池，当前供应量保持 15,000,000,000；重启后结果一致。
- 对 `fees/reserve` 返回的 ICS23 成员证明可针对提交后的 app hash 验证。
- 对 `fees/base_atomic` 返回的 ICS23 成员证明可验证；本地费率与落盘费率不一致时拒绝重启。
- `supply/audit_snapshot` 在创世和提交后均可解码为强类型快照并验证 ICS23 成员证明；共享黄金向量固定跨语言字节，四节点在链继续推进后按 Transfer 高度核对相同快照。
- 1、1024、1025 字节边界验证了 KiB 向上取整，创建持仓和注册验证者附加费分别独立覆盖。
- 真实证明 envelope 被改为零 fee 后，在密码学验证前得到低费错误且不留下状态；原始足额交易继续正常提交。
- 高度 0、1、720、721、1440、1441 的结算计数边界与规格一致；缩短为 2 块的测试 epoch 在高度 3 缺少系统结算时拒绝 Prepare，durable 状态仍停在高度 2，重启结果不变。
- 私密池不足以支付 fee 时，交易标记、TCT 和供应字段均不变化。
- 连续两个 epoch 分别覆盖正常新增发行和空集合放弃，`Mint + K = U(e)`。
- 两个验证人按 1:3 score 分配 101 原子单位时得到 25/75 gross，1 原子余数留 F；佣金分别按 5% 和 10% 向下取整为 1/7，P/C 与账本逐项交叉一致。
- 单验证人状态集成测试覆盖 `quota + 既有 F → P/C`、旧池结算 epoch、ClaimCommission 的 `C→Q/F`、sequence、Commit 和重启恢复。
- 销毁后未来发行预算不增加；人为篡改持久化费用池后，重启校验拒绝数据库。

## 6. 完成 D-006 还需要

1. 四节点实验已验证 H/H+1/H+2 实际集合、last commit power、请求哈希、奖励后投票权，以及真实 Transfer 的费用、交易/nullifier 证明、TCT 根和 execution/compact 摘要一致；下一步补区块产物分发及多节点真实退出。
2. 为钱包和网关提供带证明的费率、在线率、奖励和佣金报价接口。
3. 接入 GenesisClaim 和 Slash 等剩余容器转换；Delegate、Unbond、ClaimExit 和 ClaimCommission 已接入。
4. 为已冻结的 `supply/audit_snapshot` 增加 REST DTO 和面向 SDK 的跨语言解码器；共识值、最新/历史高度查询、共享测试向量和严格 Rust 解码器已经完成。
5. 完成真实钱包 A 到 B 的构造、扫描、余额变化和重启恢复闭环，并在多节点 CometBFT 环境验证供应状态一致。
