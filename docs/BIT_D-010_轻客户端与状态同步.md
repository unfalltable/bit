# BIT D-010 轻客户端与状态同步

状态：`IN_PROGRESS`。正式 `bit-node` 的应用快照发布、ABCI State Sync、两个 RPC 轻客户端来源和真实 CometBFT 空节点恢复已经实现；签名检查点的 v1 字节合同、阈值验证、策略轮换和可信期状态机也已实现。钱包头验证与可信状态持久化、中断续传和跨独立故障域验收尚未完成。

## 1. 信任边界

状态快照不是独立信任根。新节点必须先固定创世 identity、chain context 和 CometBFT genesis，再从外部给定的可信高度与块哈希开始验证后续头。CometBFT State Sync 至少配置两个 RPC 服务器；服务器一致只提供交叉检查，安全性仍来自可信根、验证者集合变化规则和未过期的信任期。

CometBFT 在 `OfferSnapshot` 中把轻客户端已验证状态对应的 app hash 交给应用。BIT 要求它与快照 manifest 的 app hash 完全一致，再检查 snapshot ID、chain context、schema、高度、文件集合和每个 chunk hash。应用导入后独立打开状态并执行全部持久化不变量，因此 P2P 快照发布者不能仅靠伪造 manifest 改变已验证状态根。

钱包和只读客户端仍必须实现自己的已验证头存储、相邻头/验证者集合验证和 ICS23 proof 校验。节点 State Sync 通过不代表钱包 D-010 已完成。

## 2. 快照发布

正式节点用以下参数启用应用快照服务：

```text
bit-node start --bundle BUNDLE --state-dir STATE --listen 127.0.0.1:26658 \
  --state-sync-dir SNAPSHOTS \
  [--state-sync-interval-blocks 1000] \
  [--state-sync-keep-recent 2]
```

发布间隔必须大于零，保留数限制为 1 至 100。bundle、活动状态和快照目录必须两两隔离，目录解析同时拒绝利用相对路径或现有父目录绕过包含关系。满足间隔的 Commit 完成后自动生成 RocksDB checkpoint；导出前后和独立打开 checkpoint 后的完整状态摘要必须一致。发布失败会记录服务错误，但不会回滚或篡改已经成功提交的共识状态。

`ListSnapshots` 按高度倒序返回快照，`LoadSnapshotChunk` 每次读取时复核本地 chunk。format 1 的 chunk 0 是规范 manifest，其余 chunk 对应 manifest 中有序文件分块，每块不超过 4 MiB，总数不超过 100000。

## 3. 下载与原子激活

目标应用只有在高度零、未执行 InitChain 且没有已提交状态时接受快照。接收会话允许 chunk 乱序到达；manifest 到达后立即校验已有块，损坏块返回精确 `refetch_chunks` 和对应 `reject_senders`。完整数据先在隔离目录重组，再通过 `PersistentState::import_snapshot` 校验文件、哈希、schema、不可变配置、TCT、供应、质押和索引不变量。

导入成功后，应用先同步写入带校验和的活动状态标记，再切换内存状态。标记包含 snapshot ID、导入高度、app hash 和 chain context。启动时存在有效临时标记会完成原子发布；损坏、冲突、目录类型错误或 chain context 不符会拒绝启动。

节点同步后可以继续提交新区块。此后重启把活动标记当作历史安全锚点：当前高度必须不低于导入高度，应用在导入高度读取 `meta/height` 的 ICS23 成员证明，并要求 storage version、值和证明根分别等于标记高度、该高度的大端编码和标记 app hash。证明自身也必须通过验证。这样可以发现活动数据库被替换或锚点历史损坏，同时允许正常追块。

## 4. 真实网络验证

`scripts/run-state-sync-smoke.py` 构造并两阶段签署公开测试创世 bundle，启动两个源节点和一个空目标节点。两个 RPC 源在信任高度返回同一块哈希；一个指定 P2P 发布者每 5 块生成快照。目标节点通过正式 `bit-node` 和 CometBFT 完成快照发现、下载、可信 app hash 核对、激活和追块，再成对重启应用与 CometBFT 并继续出块。

当前记录中目标激活高度 25，约 21.4 秒后追到高度 47，重启后继续到 52；导入高度的 genesis manifest 值、`meta/height`、活动 app hash 和历史 ICS23 proof 均通过。机器结果位于 `reports/state-sync-smoke.json`。直接 ABCI 测试另外覆盖错误 format/app hash、超量 chunk、乱序传输、坏块重取、恶意 peer 拒绝、临时标记恢复和损坏标记关闭。

## 5. 物理快照发布约束

当前快照是 RocksDB 物理 checkpoint。两个状态相同的副本可能因 compaction 时序不同而产生不同文件和 snapshot ID，而 CometBFT `LoadSnapshotChunk` 请求只带 height、format 和 index。若多个 peer 在同一 height/format 发布不同物理快照，目标可能从不同发布者混合取得不兼容 chunk。

现阶段网络应为每个 height/format 指定一个快照发布者，其他节点可以镜像该发布者生成的完全相同快照。生产多来源分发需要在以下方案中完成并验证一项：规范逻辑状态快照；按 snapshot ID 路由的协议扩展；或内容寻址镜像与 P2P 发布约束。两个独立 RPC 轻客户端来源已经用于验证可信头，但不等于已有两个独立物理快照发布者。

## 6. 签名检查点与可信期

`crates/bit-light-client` 冻结了 `BIT-CHECKPOINT-POLICY`、`BIT-CHECKPOINT-POLICY-APPROVALS`、`BIT-CHECKPOINT` 和 `BIT-SIGNED-CHECKPOINT` 四种规范 CBOR 产物。精确字段、顺序和哈希/签名域见 `contracts/checkpoint.cddl`，Rust 与独立 Python oracle 共同锁定 `tests/vectors/checkpoint-vectors.json`。

发布者策略绑定 `genesis_manifest_hash`、派生 `chain_context` 和创世签署的运行时参数 SHA-256。策略列出有序唯一的 Ed25519 发布者公钥、阈值、启用时间、信任期、预警期、序号、前一策略哈希和是否立即撤销前策略；策略自身必须达到创世 identity 审批公钥的原阈值。轮换策略必须序号连续且引用活动策略哈希。非立即撤销时，仅已接受的旧检查点可沿用到自身到期，旧发布者不能再导入新检查点；立即撤销会清除旧锚点并要求新策略检查点。

每个检查点绑定策略、创世和网络，明确记录 CometBFT `header_height`/`header_hash` 及其认证的 `state_height = header_height - 1`/`app_hash`，并包含生成与到期秒数。有效期不得长于策略信任期，策略信任期必须严格短于签署运行时配置的解除质押秒数。发布者按策略阈值签名；这些签名只表示发布者背书，不改变共识状态或验证者权力。

`TrustStore` 区分 `needs_checkpoint`、`not_yet_valid`、`current`、`expiring_soon`、`expired` 和 `conflict`。正常更新只接受严格递增高度；两个达到阈值但同高度指向不同头或 app hash 的检查点会进入持久化调用方必须保存的冲突锁定状态。当前锚点到期后，普通导入一律返回 `TrustExpired`；重新建立信任必须额外传入用户或操作员从独立渠道核对的精确 checkpoint hash，网关多数响应不能绕过这一步。

`bit network verify-checkpoint` 同时读取签署的 genesis identity、运行时输入、策略、策略审批和签名检查点，复核全部绑定、阈值、解除质押关系、当前时间及 `--expected-checkpoint-hash`。主网输入 schema 和 `bit release preflight` 另外要求策略、策略审批、可信检查点的文件 SHA-256 及逐字段副本，并与实际签名产物逐项核对。`GET /v1/checkpoints` 只发布经过密码学验证且数量有界的候选产物，返回固定的 `manual_confirmation_required`，并在响应前核对目录绑定的 genesis/chain 与实际应用状态；它不是自动信任入口。

迁移规则是拒绝旧形状。活跃 BIT 此前没有已冻结的检查点 wire version，因此只有上述 version 1 可以进入可信存储；缺少 `expires_at_seconds`、策略哈希或 app hash 的旧草案对象不做字段补全，也不能从 `issued_at` 本地推导到期时间。升级后的客户端若没有 v1 锚点，从 `needs_checkpoint` 开始并要求显式导入。

## 7. 剩余工作

1. 把已验证策略、签名检查点和冲突标记原子持久化到钱包数据库，并做进程崩溃、时钟回拨、长期离线和策略轮换恢复测试。
2. 对 State Sync 下载中断、进程崩溃、peer 切换、旧快照淘汰和磁盘空间不足做真实进程级恢复测试。
3. 在独立机器和故障域部署 RPC、P2P 快照及归档来源，验证来源独立性、限流、可用性和恶意响应。
4. 实现钱包/SDK 的相邻头与验证者集合验证、ICS23 proof、compact 连续性，并接入 Rust NetworkClient、Tor 网络出口与 W39 恢复界面。
5. 把检查点构建、分签、轮换、撤销和网关目录装载串成正式运营流程；当前库能构建签名对象，CLI 与主网 preflight 能验证最终产物，但正式节点尚未装载真实发布者材料。
