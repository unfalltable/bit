# BIT D-025 CLI 与创世清单

状态：`IN_PROGRESS`。创世公开领取权的共识身份、状态编码、交易执行和证明查询已经实现；identity manifest v1、派生结果 manifest v1、两阶段多方签名包、运行时输入合同、确定性高度零构建器、独立重放校验器、正式节点入口、离线 CLI 与 release preflight 已实现。manifest hash 已绑定高度零状态、chain context 和网关证明；真实外部输入、发布证据合同与生产运维仍待完成。

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

当前代码已固定上述 `claim_id` 公式。identity manifest 的机器合同位于 `bit-genesis`；`GenesisConfig` 必须携带非零 manifest hash，并要求其派生结果等于 chain context。manifest hash 与 chain context 会写入高度零 JMT，重启时作为不可变配置核对。`genesis materialize` 已把 identity、达到阈值的第一阶段签名和运行时输入转换成完整配置及高度零状态；`verify-bundle` 与 `bit-node` 会再次清空状态重放，并验证第二阶段阈值后才允许启动。主网仍必须由真实参与者提供并签署外部输入。

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

## 6. 派生结果 manifest v1

`BIT-GENESIS-DERIVED` v1 是 identity 签署后的第二阶段结果。它绑定 identity manifest hash、chain context、完整运行时输入文件 SHA-256、派生 claim ID、validator ID、自质押 position ID、CometBFT 共识地址和投票权，以及创世承诺摘要、领取摘要、TCT 根、JMT app hash、创世 execution/compact hash 与最终 CometBFT genesis 文件 SHA-256。运行时输入 hash 必须逐字节等于 identity 中已签署的 `consensus_parameters_sha256`，不能在第一阶段签署后替换另一套费用、质押、验证人元数据或恢复收据。

派生 claim 和 validator 数量必须与 identity 精确一致，并按 allocation ID 严格递增。验证器使用 identity 中的公钥和金额重新计算所有 ID、共识地址及领取/承诺摘要；零结果哈希、零投票权、超出 CometBFT 安全总投票权、缺项、增项或篡改均拒绝。派生清单哈希固定为：

```text
SHA256("BIT-GENESIS-DERIVED-V1" || cbor_len_be_u64 || canonical_cbor)
```

第二阶段签名消息固定为：

```text
"BIT-GENESIS-DERIVED-APPROVAL-V1" ||
identity_manifest_hash || derived_manifest_hash
```

`BIT-GENESIS-DERIVED-SIGNATURES` v1 继续使用 identity 中冻结的签署者集合和阈值，并独立于第一阶段签名。这样签署者可以先批准不含循环派生值的身份输入，再复核真实构建所得的 app hash 与 CometBFT genesis。相同黄金向量由 Rust 和 Python 标准库独立核对 canonical CBOR 与两个哈希域。

## 7. 运行时输入与确定性物化

`config/genesis-runtime-inputs.schema.json` 固定 `BIT-GENESIS-RUNTIME-INPUTS` v1。文件包含完整费用参数、质押与处罚参数、CometBFT 限制，以及按 allocation ID 排序的验证人显示元数据和每个自质押仓位的 512 字节恢复收据。金额和可能超过 JavaScript 安全整数范围的总投票权上限使用规范十进制字符串，哈希和收据使用小写 hex；未知字段、错误版本、重复或乱序验证人、全零收据、不安全总投票权、无效时间窗和无法产生正投票权的初始自质押均拒绝。

identity 的 `consensus_parameters_sha256` 是这份运行时输入文件原始字节的 SHA-256。公开测试夹具通过 `.gitattributes` 固定 LF，避免跨平台换行改变测试 hash；真实仪式必须先冻结最终字节再建立和签署 identity。构建器不会生成恢复收据或主网参与者材料。

`genesis materialize` 先验证第一阶段签名阈值和运行时 hash，再执行以下过程：

1. 从唯一 allocation 表构造领取、私密承诺、费用储备和自质押供应容器；
2. 派生 validator/position/claim ID，注册验证人元数据，写入真实 512 字节恢复收据，将创世自质押激活并计算安全投票权；
3. 在同目录临时 staging 中真实初始化 Cnidarium/JMT/TCT 高度零状态并读取 app hash 与树根；
4. 生成 CometBFT v0.38 可解析的 `genesis.json`，再生成绑定其 SHA-256 的 derived manifest；
5. 写入 `identity.cbor`、第一阶段签名、原始运行时输入、`state/`、`genesis.json`、`derived.cbor` 和 `build-report.json`，最后以单次目录 rename 发布。目标已存在时拒绝覆盖，失败时不发布半成品。

物化结束后才能知道 derived manifest hash，因此构建目录本身不包含第二阶段签名。签署者必须对目录内的 `derived.cbor` 执行 `sign-derived`，把达到阈值的签名包与构建目录一起发布；正式节点接入时必须同时要求并验证该签名包。

创世 execution/compact 标记分别使用 `SHA256("BIT-GENESIS-EXECUTION-V1" || identity_hash || runtime_hash)` 和对应 COMPACT 域。它们是高度零初始化标记；正常高度从 1 开始，继续使用 D-002 的规范区块产物编码与 hash 域。

公开 fixture 连续构建两次会得到相同的 app hash、TCT 根、CometBFT genesis 和 derived bytes；黄金结果位于 `tests/vectors/genesis-materialized-vectors.json`。`verify-bundle` 不信任 bundle 内的 RocksDB，而是在新的临时目录从 identity、第一阶段签名和运行时输入重建全部确定性文件，逐字节比较 genesis、derived 和报告，再验证第二阶段签名。输入必须是普通文件/目录，拒绝符号链接、超限文件、缺项、非规范 JSON 和任何重放差异。

`bit-node start` 只接受 bundle、第二阶段签名、独立状态目录和 loopback ABCI 地址。它从已验证结果构造 `GenesisConfig` 和完整 `RequestInitChain`，保留 `genesis.json` 中 CometBFT 实际传递的原始 `app_state` JSON 字节，拒绝本地参数覆盖和 bundle/state 路径重叠。由 Go module v0.38.23 构建的实际 CometBFT 二进制（自报 0.38.22）已完成 InitChain 并连续出块；区块 1 header 的 app hash、初始验证人投票权和 ICS23 manifest 证明均与重放结果一致，应用与 CometBFT 成对重启后继续推进。

## 8. CLI 与 preflight

当前命令：

```text
bit genesis build --input INPUT.json --output identity.cbor
bit genesis validate --manifest identity.cbor [--signatures approvals.cbor]
bit genesis verify --manifest identity.cbor [--signatures approvals.cbor]
bit genesis inspect --manifest identity.cbor
bit genesis sign --manifest identity.cbor --key-file KEY \
  --output approvals.cbor [--append previous.cbor]
bit genesis inspect-runtime --input runtime-inputs.json
bit genesis materialize --manifest identity.cbor \
  --signatures approvals.cbor --runtime-inputs runtime-inputs.json \
  --output genesis-bundle
bit genesis verify-bundle --bundle genesis-bundle \
  --derived-signatures genesis-bundle/derived-signatures.cbor
bit genesis build-derived --manifest identity.cbor \
  --input DERIVED.json --output derived.cbor
bit genesis verify-derived --manifest identity.cbor \
  --derived derived.cbor [--signatures derived-approvals.cbor]
bit genesis inspect-derived --manifest identity.cbor --derived derived.cbor
bit genesis sign-derived --manifest identity.cbor --derived derived.cbor \
  --key-file KEY --output derived-approvals.cbor [--append previous.cbor]
bit release preflight --input mainnet.json \
  --manifest identity.cbor --signatures approvals.cbor \
  --crypto-manifest crypto/manifest.json \
  --derived-manifest derived.cbor --derived-signatures derived-approvals.cbor \
  --runtime-inputs runtime-inputs.json --cometbft-genesis genesis.json
bit-node start --bundle genesis-bundle --state-dir node-state \
  --listen 127.0.0.1:26658
```

identity `inspect` 输出 manifest/policy hash、chain context、四类分配合计，以及派生的 claim、validator 和自质押 position ID。`inspect-runtime` 严格解码运行时合同并输出文件 SHA-256。derived `inspect` 输出两阶段 manifest hash、运行时输入 hash、状态根、app hash 和 CometBFT genesis hash。`verify-bundle` 输出两阶段审批数和已复算的关键哈希。`materialize` 和所有 `build`、`sign` 命令默认拒绝覆盖已有目标；节点未指定 `--derived-signatures` 时只读取 bundle 内的 `derived-signatures.cbor`。

preflight 从实际证据计算 `mainnet_ready`，不采信输入 JSON 中的同名布尔值。它核对 identity manifest 与 JSON 身份逐字节一致、第一阶段签名阈值、crypto/参数文件 SHA-256、派生 manifest 文件哈希与全部摘要字段、第二阶段签名阈值、运行时输入和 CometBFT genesis 文件哈希、当前 Git HEAD 与干净工作区、G0 分配闭环、`Mint/Burn/K/e=0`、`Future=M-G0`、发布产物文件哈希，并要求非空检查点、独立端点、安全审查和平台签名材料。默认模板会明确列出 blockers 并以非零退出码结束。

## 9. 尚未完成的 D-025 范围

1. 对初始私密承诺执行资产语义检查；当前已经拒绝非法曲线字段、重复承诺，并对验证者自质押执行 staking 参数、投票权、元数据和恢复收据检查。
2. 将检查点、独立端点、安全审查、平台证书和发布产物升级为有明确字段、签名范围及撤销语义的证据合同。
3. 实现 `genesis claim` 的钱包构造流程，并由真实参与者填写、独立签署主网公钥、金额、验证人和发布材料。
4. 补生产服务管理、节点目录权限、备份恢复、发布安装包和多机创世演练；单机集成证据不能替代独立故障域验收。

`config/mainnet-inputs.template.json` 继续保持 `mainnet_ready=false`。空数组和布尔值不构成经济批准、分配授权或发布证据。
