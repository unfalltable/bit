# BIT D-010 轻客户端与状态同步

状态：`IN_PROGRESS`。正式 `bit-node` 的应用快照发布、ABCI State Sync、两个 RPC 轻客户端来源和真实 CometBFT 空节点恢复已经实现；钱包轻客户端、签名检查点、可信期更新、中断续传和跨独立故障域验收尚未完成。

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

## 6. 剩余工作

1. 冻结签名检查点的规范编码、发布者集合、阈值、生成时间、到期时间、轮换和撤销语义，并把检查点绑定到 genesis 与网络配置。
2. 实现信任期即将到期、已经过期、检查点冲突和长期离线的状态机；过期后必须要求重新建立信任，不能自动相信多数 HTTP 响应。
3. 对下载中断、进程崩溃、peer 切换、旧快照淘汰和磁盘空间不足做真实进程级恢复测试。
4. 在独立机器和故障域部署 RPC、P2P 快照及归档来源，验证来源独立性、限流、可用性和恶意响应。
5. 实现钱包/SDK 的头验证、证明验证、compact 连续性和可信状态持久化，并接入网关、Tor 网络出口与恢复界面。
