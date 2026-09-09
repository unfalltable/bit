# 机器合同的规范性补充

本目录是需要实现的合同。基础密码学字节格式以 D-001/D-003 固定的上游规范、实际参数和验证向量为准；不得用这里的 bytes 类型填随机数据后认为实现完成。

## 编码与 ID

Protobuf envelope 的字段严格按编号递增；repeated 元素顺序有意义，同一 repeated 字段连续编码；默认值按固定生成器规则省略。禁止重复 singular、未知字段、非最短 varint、错误 wire type、未定义 Role、额外签名。解码前严格扫描，解码后重新编码逐字节比较。canonical_body 不能换为 JSON；全体节点只接受唯一编码。CDDL 只定义形状，<2^120、字段间关系、CBOR 最短编码等另有语义检查。

`position_id = SHA256("solo/position/v1" || chain_context32 || owner_pubkey32)`。随机 position_nonce 只用于派生 owner 私钥与恢复收据，不必公开或让节点知道。`validator_id=SHA256("solo/validator/v1"||chain_context32||operator_pubkey32)`。`cohort_id=SHA256("solo/cohort/v1"||chain_context32||validator_id32||exit_epoch_u64be)`。`ticket_id=SHA256("solo/ticket/v1"||chain_context32||position_id32||pre_increment_position_sequence_u64be)`。生成后检查唯一，哈希碰撞不得覆盖旧记录。所有整数在哈希中定长，不拼可变长十进制文本。

## 签名清单

先按输入顺序放 SPEND 授权；随后最多一个 POSITION_OWNER；再 OPERATOR；再 CONSENSUS_POP；再 GENESIS_CLAIM。没有的角色不放空签名。所有授权共同绑定同一64字节 effect_hash；Spend/Binding 采用原上游类型；Ed25519按docs/03第3.11节加各自role_domain。Spend 用上游随机化花费授权，其他公钥为严格 Ed25519。任何多余/遗漏/重复 role,index 都拒绝。

Transfer：仅 Spend 授权。Delegate：新 owner 授权；self_bond=true 额外要求目标验证者 operator 对相同主体签名，且登记自质押绑定。CancelPending/Unbond：当前持仓 owner。ClaimExit：ticket 对应持仓 owner。RegisterValidator：新 operator 和新 consensus PoP。Update/Unjail/ClaimCommission：当前 operator。Rotate：当前 operator 和新 consensus PoP。ClaimGenesis：创世 claim_pubkey。绑定签名独立存在，不替代这些授权。

ClaimExit/CancelPending 的 expected-release 必须等于本次执行状态计算结果，变化即 E_STALE_QUOTE，不用客户端数字制造正余额。ClaimCommission requested-amount 必须正数且不超过已记佣金余额；允许部分领取。ClaimGenesis expected-amount 与创世权利完全相等。Unbond 的 min-gross 仅约束退出内部换算，不授权额外公开释放；RELEASED_VALUE 只释放等于 fee 的部分。

SHIELDED 要求净费用由私密交易价值承担且公开释放额按全额输出；RELEASED_VALUE 允许在公开可领取值内扣费。两者仍执行同一绑定等式，禁止负输出和费用多扣。max-fee>=body.fee。新委托 receipt 必须512字节且非空；节点只能验证长度/主体绑定，无法替用户解密验证收据。

## 普通 memo 与支付请求

私密 memo 固定为 canonical_body 第10项：528字节或 null。上游 v2.1.1 交易级 MemoCiphertext 与 OutputBody.wrapped_memo_key 配套；直接复用加解密与包装，字段参与 effect_hash。普通支付默认带空或有效正文 memo，return_address 每笔派生新地址。一个交易的全部输出共享同一 memo，不开放多收款人差异备注。无输出时为null。上游事实见[S23][S24]。

`solo:<encoded_address>?amount=<8dp_decimal>&network=<chain_context_hex>&invoice=<base64url_128bit>&expires=<unix_seconds>` 为钱包 URI。金额可缺省；不得含私钥、付款签名或执行脚本。拒绝重复金额、负数、指数格式、错误链、未知 req-* 必需字段、超长 URI。普通地址无身份保证；昵称本地保存不替代地址校验。扫描二维码不能自动广播。

发票有随机 invoice_id；付款人在受保护 memo 中携带固定版本结构 (invoice_id、可选订单摘要、可选退款联系信息)，对账只在收款钱包本地完成。公开 API 不建立 invoice_id→付款地址索引。过期发票收到钱仍入账，标记迟到，不自动退款。

## 集合延迟

ValidatorUpdates 在 H 返回，H+2 生效；下一 epoch 首块 H 更新时，退出责任截止为 H+1。不要只写“等14天”而漏掉有效块数和历史集合。该值由实际引擎集成向量确认，参考配置为2。

## 绝不从本合同推导的结论

这里不提供已验证的主网密钥/创世名单，不提供重新生成的生产 ZK 参数，不证明用户匿名或链安全。`bytes`、JSON schema、OpenAPI 校验通过只说明合同结构，不说明密码学实现已完成。
