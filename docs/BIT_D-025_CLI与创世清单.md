# BIT D-025 CLI 与创世清单

状态：`IN_PROGRESS`。创世公开领取权的共识身份、状态编码、交易执行和证明查询已经实现；完整创世 manifest 的规范编码、多方签名、CLI 生成/核验、主网 preflight 和真实外部输入仍待完成。

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

当前代码已固定上述 `claim_id` 公式。完整 identity manifest 的字段顺序、编码和签名阈值仍需以机器合同落地，现阶段不能据此生成主网创世。

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

`GET /v1/network` 返回 `genesis_claims_hash` 及同高 ICS23 证明；`GET /v1/state/proof?key=genesis/claims/<claim_id>` 可取得单项成员或非成员证明。客户端必须针对已验证区块头的 app hash 校验证明，并按本节固定记录格式解码。

## 4. 尚未完成的 D-025 范围

1. 冻结 identity manifest、派生结果清单和签名包的规范编码及共享黄金向量。
2. 实现 CLI 的 `genesis build`、`genesis verify`、`genesis sign`、`genesis inspect` 和 `release-preflight`。
3. 校验领取权、初始私密承诺、初始自质押和验证人身份不重复计入创世供应。
4. 校验签署者集合、阈值、来源 commit、crypto manifest、货币政策、初始状态根和构建产物哈希。
5. 由真实参与者填写并独立签署主网公钥、金额、验证人、检查点发布者、审查和发布材料。

`config/mainnet-inputs.template.json` 继续保持 `mainnet_ready=false`。空数组和布尔值不构成经济批准、分配授权或发布证据。
