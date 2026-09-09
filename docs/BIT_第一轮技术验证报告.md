# BIT 第一轮技术验证报告

日期：2026-09-08。结论：**桌面端密码学原语、完整 Transfer 密码学验收入口与基础 ABCI 共识实验通过，可以继续做状态存储和链执行；完整 S1 和产品验收尚未完成。** Android 真机按用户要求跳过，状态为 `SKIPPED_BY_USER`。

本轮承接用户确认后的可行性验证。原始 BIT v1.2 规格及 Solo 资料保留不变；实验位于独立的 `feasibility` 目录。测试参数不构成主网政策，实验密钥不涉及真实资产。

## 1. 结果与项目难度判断

| 对象 | 本轮结果 | 能得出的结论 |
|---|---|---|
| 原版 Spend/Output 电路和参数 | 真实生成、严格解码后验证成功，5 组样本 | 这组上游原语在当前 Windows 桌面环境能运行 |
| 完整 Transfer 验收 | 2 Spend、2 Output、4 份证明、2 份 Spend 授权、528 字节加密 memo 和 binding 签名共同绑定 BIT effect hash | 桌面测试夹具可形成并验证一笔完整规范 envelope；仍需持久化账本和主网本币 ID |
| BIT 固定发行整数实现 | 18 项 Rust 测试通过 | 已覆盖指定发行边界和若干份额计算；不等于完整会计验收 |
| 4 个 CometBFT + 4 个 Rust ABCI 进程 | 同高度状态一致、H+2、生效前后重放与投票权门槛检查通过 | 基础连接和空块发行状态机能共同运行 |
| 票据试解密 | 1,000 条载荷扫描成功，识别 10 条属于自己的票据 | 有桌面计算及载荷体积样本，完整同步协议仍待实现 |
| Android、Tor 与多平台 | 未测；Android 为用户主动跳过 | 不推算手机体验，不标设备性能通过 |

**项目仍然属于高难度工程。** 本轮降低了“上游真实证明能否跑起来”“BIT Transfer 能否完整绑定”和“Rust 应用能否与选定 CometBFT 模块配合”的不确定性。剩余主要工作是把该交易入口接入持久化状态，再完成资产授权、质押处罚及恢复闭环。当前证据不足以承诺完整工期或主网质量。

可供机器读取的结果：[feasibility-summary.json](D:/others/BIT/feasibility/reports/feasibility-summary.json)。其中总体范围明确为 `PARTIAL_FEASIBILITY_ONLY`，各项 `PASS` 仅适用于对应实验。

## 2. 环境与来源

| 项目 | 本轮实测或使用值 |
|---|---|
| 宿主 | Windows 11，系统版本 10.0.22631 |
| CPU / 内存 | Intel Core i5-1335U，10 核、12 逻辑处理器；物理内存 33,974,157,312 字节 |
| Rust | 1.98.1，`x86_64-pc-windows-gnu`，release 开启溢出检查 |
| 原生工具 | 项目内 LLVM-MinGW 20250812；不修改系统 PATH |
| Go | 1.27.1，Windows amd64 |
| Python | 3.14.7，负责启动进程、采集结果与汇总 |
| Penumbra | v2.1.1；提交 `3a87ce786373113f9b82d3b6df9504998b7f44a7`；上游工作区检查为空 |
| CometBFT | Go module v0.38.23；来源提交 `feb2aea4dc271d612129afc958cb844713ec792b` |
| Rust ABCI/Proto | `tendermint-abci`、`tendermint-proto` 均固定为 0.40.4，使用 v0.38 消息 |

Rust 依赖已保存在各实验的 `Cargo.lock`。这是当前环境解析和编译成功的实验锁；未沿用 Penumbra 原工程的完整构建锁，也未按其 Rust 1.83 工具链复现。Penumbra 自身的部署组合不是本轮的 BIT 组合，因此不能据版本标签声称整栈天然兼容。[上游 Cargo 配置](https://github.com/penumbra-zone/penumbra/blob/v2.1.1/Cargo.toml)、[上游 flake 配置](https://github.com/penumbra-zone/penumbra/blob/v2.1.1/flake.nix)。

**发现一处版本显示不一致：** 本次构建的 CometBFT 命令输出 `0.38.22`，而 `go version -m` 记录的主模块为 v0.38.23。核对该模块的 `version/version.go`，其 fallback 常量确实是 `0.38.22`。本轮没有修改上游常量。后续发布必须同时固定来源提交、模块摘要、构建方式与二进制摘要，不能仅依赖命令自报版本。[上游 version.go](https://github.com/cometbft/cometbft/blob/v0.38.23/version/version.go)、[本地模块证据](D:/others/BIT/feasibility/reports/comet-module.json)。

下载记录保存在 `reports`。Rust/Go 对照已取得的官方摘要，证明参数对照上游 LFS 摘要；LLVM-MinGW 与 ADB 的记录只包含本次下载 SHA-256，不能混称为已验证发布者签名。ADB 曾在用户表示有设备时准备，用户要求跳过后已停止服务；本轮没有执行手机测试。

初次构建遇到 Windows GNU 链接/汇编工具缺失，已用项目内工具和 `rust_env.ps1` 解决；初次网络启动遇到 Python 默认 GBK 读取配置失败，已改为显式 UTF-8 后重跑通过。这些是已解决的实验环境问题。当前 Windows 实验不改变总体方案中正式节点的平台边界。

## 3. 真实证明及价值边界

### 3.1 实际执行内容

程序使用原版电路、真实证明参数及验证密钥。临时生成测试密钥，构造真实票据、承诺树和 Spend witness，生成两份 Spend 与两份 Output 证明。

每组金额样例为两个 75 BIT 输入、100 BIT 收款输出和 49.99 BIT 找零，价值绑定样例另计 0.01 BIT 手续费。测试资产 ID 为字段值 1，尚未定义最终 `native_asset_id`。

除原语方程外，程序现已组成并验证一笔 2 Spend、2 Output 的完整 BIT Transfer envelope：canonical CBOR body、64 字节 BIT effect hash、四份 proof hash、528 字节真实加密 memo、两份随机化 Spend 授权和 binding signature 使用同一 effect hash。规范 envelope 为 2,762 字节，验证后将两个 nullifier 与两个输出承诺一次性写入内存账本夹具。

该夹具使用字段值 1 的参考测试本币 ID。`native_asset_id` 通过验证上下文显式传入，主网模板仍为空；内存账本也不构成可上链的持久化状态。非 Transfer 动作的链上权益和角色授权尚未验证。

证明参数如下，加载前逐个验证 SHA-256，并通过上游加载接口的参数 ID 校验：

| 参数 | 字节数 | SHA-256 |
|---|---:|---|
| Spend | 21,673,392 | `87eca85bef562803fb9684c56c0a6db84aa6d0791b1c00b909e6f2a5c2cff452` |
| Output | 7,257,360 | `c9e97866edd6c815a7bcb2f3b5493713794369692bb96e5a2e682613c330e4a8` |
| 合计 | 28,930,752 | 约 28.93 MB，未包含安装包、其他运行依赖 |

负例包括错误 nullifier、错误 Output 价值承诺、错误长度和畸形证明、错误 Spend 授权、错误 binding 签名、同一 nullifier 放入另一笔签名与证明均有效的 envelope、正价值外币输出以及未覆盖的手续费，均被拒绝。错误授权和错误 binding 交易没有留下部分状态。单个外币反例不能证明所有合法入口的单币闭包；零值票据、组合动作、创世入口、公开发行及原生动作仍需完整审查。

### 3.2 桌面测量

固定 `RAYON_NUM_THREADS=4`；每组内依次生成两份 Spend 和两份 Output，内部允许上游并行。共 5 组。每组验证时间是四份证明严格解码及证明验证的累计时间。

| 指标 | 结果 |
|---|---:|
| 两 Spend + 两 Output 证明生成中位数 | **4,388.70 ms** |
| 生成最小 / 最大值 | 4,017.09 / 4,471.09 ms |
| 四份证明验证中位数 | **26.32 ms** |
| 验证最小 / 最大值 | 19.92 / 35.25 ms |
| 参数加载，包括读文件、摘要核对及加载校验 | 205.83 ms |
| 进程观测峰值工作集 | **121.02 MiB** |
| 整个实验进程用时 | 22.91 秒 |

工作集由 Windows 进程计数器轮询取得，不是手机内存、私有堆峰值或完整钱包占用。5 个同一进程样本不足以建立生产 p95，未控制文件缓存、温度或系统并发负载。证明计时不含交易规划、网络广播及共识确认，不能作为完整付款时间或网络 TPS。

证据：[真实证明结果](D:/others/BIT/feasibility/reports/proof-result.json)、[原始样本](D:/others/BIT/feasibility/reports/proof-stdout.json)、[实验源码](D:/others/BIT/feasibility/proof-probe/src/main.rs)。

### 3.3 必须纳入正式适配的发现

1. **严格解码。** 上游 Spend 和 Output 验证内部使用 `deserialize_compressed_unchecked`。实验在进入这些验证前增加有校验的解码，并重编码核对字节规范性。正式入口必须统一这条路径，进一步覆盖曲线点、子群和全部公共字段，不能让其他调用绕过适配层。这是明确的适配要求，本轮没有证明上游存在可利用漏洞。[Spend 源码](D:/others/BIT/feasibility/upstream/penumbra/crates/core/component/shielded-pool/src/spend/proof.rs:327)、[Output 源码](D:/others/BIT/feasibility/upstream/penumbra/crates/core/component/shielded-pool/src/output/proof.rs:208)。
2. **拒绝单位元 binding 公钥。** 验证测试发现，零输入、零输出、零手续费会形成单位元 binding 公钥，此时签名无法真正绑定消息。正式适配已显式拒绝该公钥，因此空 Transfer 不能通过密码学验收。
3. **日志保护。** `NotePayload::trial_decrypt` 的 debug 事件包含 `?note`，而 `Note::Debug` 输出金额、地址和 `rseed`。实验没有安装 tracing subscriber；正式钱包必须从调用和格式化层处理脱敏，并验证开启 debug、异常及诊断导出时不会泄露秘密。[扫描日志](D:/others/BIT/feasibility/upstream/penumbra/crates/core/component/shielded-pool/src/note_payload.rs:24)、[Note 格式化](D:/others/BIT/feasibility/upstream/penumbra/crates/core/component/shielded-pool/src/note.rs:413)。
4. **依赖边界。** 关闭默认 features 仍会引入上游 IBC 等类型依赖；出现类型依赖不等于启用了对应链动作，但正式 BIT 执行器必须以动作白名单和入口测试落实范围。

## 4. 固定发行与真实四节点网络

### 4.1 整数模型

实验固定累计上限为 `10240000000000000000` 原子单位，即 1024 亿 BIT；金额以 `u128` 计算、十进制字符串序列化，比例乘法使用 U256 中间结果。创世量采用 1 亿 BIT 测试夹具，未批准为主网值。

实际通过 18 个 Rust 测试，覆盖固定上限与有符号范围、6 个选定黄金检查点、小预算跨减半周期穷举、销毁不重开发行空间、永久未发不补发、重复/乱序结算拒绝且保持状态、不合法状态和参数、零配额后仍可能有配额、大位移及 epoch 溢出、金额 JSON、比例精度、首次结算和状态序列化。

这些测试包含简化份额舍入样例；没有完整质押池、退出队列、费用分配和罚没执行器，也没有完成独立 BIT oracle 与生产 Rust 的全量差分。因此不能把本次 18 项与旧 Solo 的 20 项、文档中计划的验收数量混算为产品通过数。[测试日志](D:/others/BIT/feasibility/reports/consensus-unit.log)、[整数源码](D:/others/BIT/feasibility/consensus-probe/src/economics.rs)。

### 4.2 网络场景与观察

同一台电脑启动 4 个真实 CometBFT 进程和 4 个独立 Rust ABCI 进程，通信绑定 loopback，全部使用随机测试创世密钥。应用明确拒绝用户交易；每个 epoch 10 块、每 2 个 epoch 减半，只为加快边界检查。领取资格固定为真，未实现真实奖励评分。

| 检查 | 实际观察 |
|---|---|
| 状态一致 | 四节点第 40 高度状态字节完全一致，其 SHA-256 与各自第 41 区块头 app hash 相同 |
| H+2 | 高度 5 提交验证者权重更新；高度 5、6 为 10，高度 7 为 11 |
| FinalizeBlock 故障 | 节点 0 在高度 11 计算后、响应前退出；持久状态仍为高度 10、结算 0 个 epoch，重启后成功重放 |
| Commit 故障 | 节点 1 在高度 21 写入后、响应前退出；已持久化高度 21、结算 2 个 epoch，重启后继续运行 |
| 重放后会计 | 第 40 高度四节点均完成 3 个 epoch，新增累计发行 `6393750000000000000` 原子单位，无重复结算造成的分歧 |
| 投票权不足 | 停止两个共识进程后，剩余权重不足 2/3；等待稳定后观察窗口内高度停在 42 |
| 恢复投票权 | 重启其中一个共识进程，三个在线节点恢复并达到高度 46 |

第 40 高度状态摘要：`a92b1e0b5579fcf4fb048cd11a8294988e2eea53fa8f4ad933946f825557bc73`。状态摘要包含随机创世公钥，换一次新网络不要求得到相同固定值；要求同次运行的独立节点一致。

H+2 与上游应用要求相符。[CometBFT 应用规范](https://github.com/cometbft/cometbft/blob/v0.38.23/spec/abci/abci%2B%2B_app_requirements.md)。检查器读取本地 RPC，并未实现轻客户端头验证。故障注入导致的 ABCI 断连及共识失败日志是预设场景，恢复后的断言通过。

状态保存采用 JSON 文件、文件同步与 rename，app hash 是该状态的 SHA-256；尚未采用 JMT/RocksDB、证明型查询或快照同步。进程退出实验不能等同于物理断电、磁盘损坏和所有持久化窗口验证。

CometBFT 使用内置 FilePV 签名器，没有实现规范要求的独立 BIT signer，也未测防双签状态回退。四节点共用宿主，不能代表四个独立故障域。隐私证明实验与这个网络尚未打通。

证据：[网络结果](D:/others/BIT/feasibility/reports/network-result.json)、[运行器](D:/others/BIT/feasibility/scripts/run_network.py)、[ABCI 应用](D:/others/BIT/feasibility/consensus-probe/src/main.rs)。本轮启动的网络与证明进程已结束，实验目录和日志保留。

## 5. 扫描体积与手机延期的影响

扫描样本为 1,000 个原版 NotePayload，其中 10 个属于被测账户；最新重跑实际试解密约 136.64 ms，识别数量正确。序列化载荷总计 252,000 字节，即该夹具平均每个输出 252 字节。

这是**桌面内存中的单次扫描及独立载荷编码**，未包含完整 compact 记录、memo、恢复收据、树更新、区块头、状态证明、数据库、下载及 Tor 开销。

条件估算：若全网长期保持 20 笔/秒，每笔 2 个输出，仅按本次未压缩 NotePayload 大小计算，每天为 `20 × 2 × 252 × 86400 = 870912000` 字节，即 **约 0.871 GB/日**。这是指定负载的算术估算，不是网络流量实测或完整协议下界；压缩、编码及完整记录尚未测量。

所以桌面“扫描算得快”仍不足以确认手机长期同步体验。后续必须先冻结完整 compact/收据格式，再确定日常吞吐、离线恢复和流量预算；Android 实验恢复时再测真实证明耗时、内存、发热、后台恢复、长历史与 Tor。当前不要求用户连接手机。

## 6. 下一阶段方案与完成标准

建议继续保持底层优先，按以下依赖顺序实施。这里是后续路线，本报告没有将它们标记为已开发。

| 顺序 | 具体工作 | 完成标准 |
|---|---|---|
| 1. 统一 BIT 开发基线 | 将 BIT v1.2 的命名、固定发行、金额类型、配置和机器合同落实到新的活跃目录；补独立发行 oracle | 无旧年率入口混用；规范向量能独立重建并与实现交叉验证 |
| 2. 完成最小真实交易 | 桌面验收入口已完成；继续冻结正式本币 ID、补 CLI 构建器并接入节点 | CLI 能构建真实支付；任一关键字段篡改、重复花费、错误资产与错误授权均被拒绝 |
| 3. 接入可恢复账本 | JMT/RocksDB、nullifier/anchor、原子提交、状态证明、独立 signer 与防双签 | 真实支付进入四节点账本；重放根一致；提交窗口故障不重复执行；冲突签名被拒绝 |
| 4. 完成质押资金闭环 | 质押、奖励、退出、成熟领取、手续费和罚没；补原生动作的所有权授权及价值边界 | 支付→质押→奖励→退出→领取→再支付可运行，完整供给守恒与负例覆盖 |
| 5. 再扩钱包和网络 | compact/收据、恢复、Tor、平台构建与设备验证；之后接入界面 | 新设备能从授权备份恢复全部权益；伪造/遗漏数据可发现；平台指标有实测 |

当前具体优先项已转为第 3 步：实现持久化 commitment tree、nullifier/anchor 索引、原子提交和状态证明，并将 Transfer 接入 ABCI。独立 signer 需同步形成可执行设计。手机延期不妨碍这些桌面工作，但 S1 的平台与隐私网络验收仍保持未完成。

## 7. 如何复现与查证

本机运行命令及前置条件见 [实验 README](D:/others/BIT/feasibility/README.md)。关键源文件、锁文件、二进制和报告摘要见 [provenance.json](D:/others/BIT/feasibility/reports/provenance.json)。这份来源记录不等于正式发布清单、SBOM 或独立安全审计。

总体方案与规格差异仍分别见 [项目梳理](D:/others/BIT/docs/BIT_项目梳理与总体开发方案.md)、[待决策清单](D:/others/BIT/docs/BIT_规格差异与待决策清单.md)。其“本次执行记录”描述此前的资料梳理阶段，技术实验的最新事实以本报告及原始结果为准。
