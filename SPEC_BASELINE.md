# BIT 活跃开发基线

状态：`IN_PROGRESS`。基线日期：2026-09-08。当前协议规格：BIT 1.2。

## 规范来源优先级

1. `docs/BIT_完整开发规格_Codex版_v1.2_1024亿固定总量.md` 是当前产品与协议主规格。
2. 根目录 `contracts/`、`config/`、`tests/vectors/` 是从主规格抽出的活跃机器合同；修改协议时必须与主规格、实现和向量一并更新。
3. `docs/BIT_规格差异与待决策清单.md` 记录未决事项和已知冲突。
4. `docs/solo/` 是历史参考。其 Solo/SLC/uslc 命名、2% 年率、旧供给上限、签名域及测试链参数不得进入 BIT 活跃实现。
5. `feasibility/` 是前置实验和证据，不是生产链实现。

## 已冻结约束

- 项目、代币及代码均为 BIT；原子单位 `ubit`，8 位精度。
- 累计发行硬上限为 102,400,000,000 BIT，即 `10240000000000000000` 原子单位。
- 金额共识编码为 16 字节大端，第一字节必须为 0，范围 `[0, 2^120)`；JSON 只使用规范十进制字符串。
- 固定预算减半策略不因销毁恢复发行额度，没有尾部增发。旧持续年率模型无效。
- 交易签名主体使用确定性 CBOR 固定数组；外层 envelope 使用严格规范 Protobuf wire；effect hash 为 64 字节 BLAKE2b-512。
- 每笔最多 8 个 Spend、8 个 Output、1 个业务动作；证明顺序为全部 Spend 后全部 Output。
- 未知动作、未知 envelope 字段、非最短编码、重复 singular 字段、错序或额外授权全部拒绝。
- 生产代码仅允许一个原生资产的业务入口；上游多资产类型不构成启用多资产功能。

## 当前实现状态

`crates/bit-types` 已实现金额、所有业务动作的 CBOR 形状、交易结构检查、严格 envelope wire、证明哈希关联、授权角色顺序、ID/哈希域和参考固定发行策略。它不验证上游 Spend/Output body、ZK 证明、花费签名、binding 签名或 Ed25519 授权，也不访问链状态。

因此当前代码是 D-002 的首个可执行基线，不是完整交易执行器。任何调用者都必须在后续密码学和状态层继续验证，不能只以 `decode_canonical` 成功作为交易有效。

## 显式未决，不得填默认值

- `SPEC-01`：创世 manifest 的身份输入、派生输出和 `genesis_manifest_hash` 的无环定义。
- `SPEC-02`：最终 `native_asset_id`、地址 HRP 与完整密钥派生向量。
- `SPEC-03`：完整 compact records、memo、树增量和恢复收据编码。
- `SPEC-04`：supply/audit snapshot 的规范状态值及证明映射。
- `SPEC-05`～`SPEC-09`：检查点、节点配对、多退出领取、创世锁定和选择性付款凭证。
- 主网 G0、epoch/减半参数、分配名单、验证者及所有真实签名与审查材料。

参考测试网配置只用于开发和向量。`mainnet-inputs.template.json` 必须保持 `mainnet_ready=false`，直至真实外部输入通过预检。

## 变更纪律

共识字段或编码变化必须同步更新 CDDL/Proto、Rust 实现、独立 Python oracle、黄金向量及迁移说明。协议输入不得使用浮点或 JavaScript Number。无法由本层验证的状态和密码学条件必须在 API 上保持显式，禁止用假校验返回成功。
