# BIT D-025 CLI 与创世清单

状态：`IN_PROGRESS`。创世公开领取权的共识身份、状态编码、交易执行和证明查询已经实现；identity manifest v1 的规范编码、多方签名包、离线 CLI 与首版 release preflight 已实现。manifest hash 已绑定高度零状态、chain context 和网关证明；派生结果清单、完整 InitChain 构建和真实外部输入仍待完成。

## 1. 哈希依赖顺序

创世身份输入与派生状态必须分开，避免 `chain_context`、`claim_id` 和初始状态根互相引用：

```text
身份输入（链 ID、政策、资源限制、claim_pubkey + amount、初始验证人公钥等）
  -> 规范 identity manifest bytes
  -> genesis_manifest_hash
  -> chain_context = SHA256("bit/chain/v1" || genesis_manifest_hash)
  -> claim_id / validator_id / position_id 等派生标识
  -> 高度零状态、TCT 根和 app hash
  -> 派生结果清单与独立复核签名
```

`claim_id` 不进入产生 `genesis_manifest_hash` 的身份主体。身份主体只记录领取公钥和金额；节点在得到 `chain_context` 后使用 `SHA256("bit/genesis-claim-id/v1" || chain_context || claim_pubkey || amount_be_16)` 派生领取 ID。最终派生结果可以列出 `claim_id`、状态根和 app hash 供签署者复核，但不能反向改变身份 hash。

当前代码已固定上述 `claim_id` 公式。identity manifest 的机器合同位于 `bit-genesis`；`GenesisConfig` 现在必须携带非零 manifest hash，并要求其派生结果等于 chain context。manifest hash 与 chain context 会写入高度零 JMT，重启时作为不可变配置核对。现阶段仍不能仅凭 identity manifest 生成主网创世，因为完整配置转换、状态结果清单与第二阶段签名尚未闭合。

## 2. 创世领取状态

`GenesisConfig.genesis_claims` 的每项包含 `claim_id`、32 字节 Ed25519 `claim_pubkey` 和正数 `amount`。初始化拒绝 ID 派生不符、非法公钥、零金额、重复 ID、重复公钥，以及领取项合计超过 `genesis/unclaimed_total` 的配置。

清单集合按 `claim_id` 排序后计算：

```text
SHA256(
  "BIT-GENESIS-CLAIMS-V1" ||
  count_be_u64 ||
  (claim_id || claim_pubkey || amount_be_16)...
)
```

结果写入 `meta/genesis_claims_hash`，重启时与启动配置逐字节核对。每项状态写入 `genesis/claims/<claim_id_hex>`；版本 1 值固定为 58 字节：`version_u8 || claim_pubkey_32 || amount_be_16 || claimed_u8 || claimed_at_height_be_u64`。未领取时 flag 和高度都为零；已领取时 flag 为 1 且高度必须在 `1..=state_height`。

节点重启会重新扫描全部领取记录，核对键、派生 ID、不可变清单和领取高度，并要求“未映射的 G 余额 + 尚未领取条目总额”精确等于供应容器 G。清单、领取状态和供应字段任一单独篡改都会拒绝启动。

## 3. ClaimGenesis 执行

ClaimGenesis 使用动作 tag 10，包含 `claim_id`、`expected_amount` 和 `fee_source`。交易必须满足：

- 状态中存在该领取权且尚未使用；
- `expected_amount` 与创世记录完全相等且大于零；
- `claim_pubkey` 以 `bit/genesis-claim/v1` 域对同一 effect hash 签名；
- Spend/Output Groth16 证明、Spend 授权、binding、anchor、nullifier、最低费和规范 envelope 全部通过；
- `RELEASED_VALUE` 要求领取额大于费用，`SHIELDED` 要求至少一个私密 Spend。

成功时原子执行 `G -= amount; Q += amount - fee; F += fee`，把领取高度与交易、nullifier、TCT、供应审计写入同一 JMT 批次。相同领取权的后续交易在授权阶段返回过期状态报价，不会再次释放资产。

`GET /v1/network` 返回 `genesis_manifest_hash`、`genesis_claims_hash` 及各自同高 ICS23 证明；`GET /v1/state/proof?key=meta/genesis_manifest_hash` 可独立取得身份哈希证明，`GET /v1/state/proof?key=genesis/claims/<claim_id>` 可取得单项成员或非成员证明。客户端必须针对已验证区块头的 app hash 校验证明，并按本节固定记录格式解码。

## 4. Identity manifest v1

机器合同见 `contracts/genesis_identity.cddl`。`BIT-GENESIS-IDENTITY` v1 使用确定长数组和最短形式 canonical CBOR。顶层固定为 16 项：

```text
[
  "BIT-GENESIS-IDENTITY", 1,
  chain_id, genesis_time_unix_seconds, source_commit,
  crypto_manifest_sha256, consensus_parameters_sha256, native_asset_id,
  key_derivation_version, address_encoding_version,
  [protocol_version, max_block_bytes, max_tx_lifetime_blocks,
   max_envelope_bytes, anchor_retention_blocks],
  monetary_policy_cbor,
  allocations,
  genesis_claims,
  genesis_commitments,
  [initial_validators, [approval_threshold, approval_signers]]
]
```

`source_commit` 只接受 20 或 32 字节；所有 SHA-256、公钥、asset ID、allocation ID 和承诺均为固定 32 字节。金额继续使用 16 字节大端 bstr。JSON 仅是仪式输入格式，金额必须是十进制字符串、小写 hex 不带 `0x`；被签名的身份是 CBOR 字节而不是 JSON 文本。

数组按 `allocation_id` 严格递增，签署者公钥同样严格递增；解码器拒绝非最短整数、非规范顺序、重复项和尾随字节。manifest hash 固定为：

```text
SHA256("BIT-GENESIS-IDENTITY-V1" || cbor_len_be_u64 || canonical_cbor)
```

每笔创世资金只在 `allocations` 中记录一次，kind 只能是 `GENESIS_CLAIM`、`SHIELDED_COMMITMENT`、`VALIDATOR_SELF_BOND` 或 `FEE_RESERVE`。领取、承诺和自质押记录必须分别引用同 kind 的唯一 allocation；非费用储备 allocation 必须恰好被映射一次，费用储备最多一项。所有 allocation 金额之和必须精确等于 G0，且 `0 < G0 < M`。该约束消除 manifest 内的重复计算；分配依据在现实中是否代表同一权益仍需独立审阅。

## 5. 多方签名包

签名消息固定为：

```text
"BIT-GENESIS-APPROVAL-V1" || genesis_manifest_hash
```

签名包 `BIT-GENESIS-SIGNATURES` v1 绑定 manifest hash，按签署者 Ed25519 公钥排序并携带 64 字节签名。验证器拒绝未授权、重复、乱序、错误 manifest、错误签名和未达到 manifest 内阈值的包。`genesis sign --append` 会先核验已有部分签名，再追加本机签名；密钥文件只接受 32 字节原始值或 64 位小写 hex，CLI 不接受命令行明文私钥参数。

公开测试向量位于 `tests/vectors/genesis-identity-vectors.json`，包含完整 CBOR、manifest hash、chain context、签名消息和达到阈值的签名包。测试私钥只存在单元测试夹具中，明确禁止用于主网。

## 6. CLI 与 preflight

当前命令：

```text
bit genesis build --input INPUT.json --output identity.cbor
bit genesis validate --manifest identity.cbor [--signatures approvals.cbor]
bit genesis verify --manifest identity.cbor [--signatures approvals.cbor]
bit genesis inspect --manifest identity.cbor
bit genesis sign --manifest identity.cbor --key-file KEY \
  --output approvals.cbor [--append previous.cbor]
bit release preflight --input mainnet.json \
  --manifest identity.cbor --signatures approvals.cbor \
  --crypto-manifest crypto/manifest.json --parameters frozen-params.json
```

`inspect` 输出 manifest/policy hash、chain context、四类分配合计，以及派生的 claim、validator 和自质押 position ID。`build` 和 `sign` 默认拒绝覆盖已有文件。

首版 preflight 从实际证据计算 `mainnet_ready`，不采信输入 JSON 中的同名布尔值。它核对 manifest 与 JSON 身份逐字节一致、多方签名阈值、crypto/参数文件 SHA-256、当前 Git HEAD 与干净工作区、G0 分配闭环、`Mint/Burn/K/e=0`、`Future=M-G0`、发布产物文件哈希，并要求提供派生状态哈希及非空检查点、独立端点、安全审查和平台签名材料。默认模板会明确列出 blockers 并以非零退出码结束。

## 7. 尚未完成的 D-025 范围

1. 冻结派生结果清单的规范编码和第二阶段复核签名，将 identity 输入实际构造成完整 `GenesisConfig`、CometBFT genesis 与高度零状态根。
2. manifest hash 与 chain context 已进入不可变状态；继续把 policy hash、crypto hash、资源参数和全部初始容器接入生产 `InitChain`，拒绝节点本地覆盖。
3. 对初始私密承诺执行完整曲线/资产检查，对验证者自质押执行 staking 参数、投票权和元数据检查；生成可独立重放的完整创世产物。
4. 将检查点、独立端点、安全审查、平台证书和发布产物升级为有明确字段、签名范围及撤销语义的证据合同。
5. 实现 `genesis claim` 的钱包构造流程，并由真实参与者填写、独立签署主网公钥、金额、验证人和发布材料。

`config/mainnet-inputs.template.json` 继续保持 `mainnet_ready=false`。空数组和布尔值不构成经济批准、分配授权或发布证据。
