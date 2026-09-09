# 15　Codex 全量开发执行手册

## 15.1 使用方式

将本包放进空 Git 仓库（或目标仓库的规格目录），根目录保留 `AGENTS.md`，把 `codex/START_PROMPT.md` 的内容作为开发任务。不要只把一段产品描述交给模型，让它自行补充共识和加密细节。

Codex 支持通过仓库内 AGENTS.md 读取项目级工作规则。本文利用该机制固定安全要求、命令与完成证据，不声称一次上下文调用必然能完成全部代码和审查。[S21]

全量目标必须一次列入 backlog；按依赖顺序自动推进。任务拆分是工程执行顺序，不是删功能的 MVP。需要人工的真实主网公钥、正式商店证书、外部审计报告等记录为外部输入，但不因此停止实现本可完成的其他功能。

## 15.2 开发顺序与依赖

D-001 依赖/平台冻结 → D-002 类型与规范编码 → D-003 密码学适配 → D-004 状态存储 → D-005 ABCI → D-006 支付与会计 → D-007 原生质押 → D-008 退出与处罚 → D-009 发行奖励 → D-010 轻客户端与同步 → D-011 vault → D-012 钱包计划与恢复 → D-013 FFI → D-014..D-018 页面 → D-019 signer → D-020 node-agent → D-021 节点 UI → D-022 gateway → D-023 indexer → D-024 explorer → D-025 CLI/创世 → D-026 完整部署 → D-027 E2E/故障 → D-028 隐私 → D-029 性能 → D-030 发布与安全证据。

允许界面布局和公开索引等独立任务并行，但共享编码、会计、密钥和网络协议必须由唯一基础模块提供，不让多个代理各造一套。

## 15.3 必须提供的项目命令

```text
just bootstrap         # 检查锁版本、工具链、系统依赖，不改变主网状态
just fmt-check
just lint
just unit
just crypto-vectors
just protocol-properties
just localnet
just integration
just wallet-e2e
just node-e2e
just explorer-e2e
just privacy-test
just chaos-test
just perf-test
just supply-invariants
just reproducible-build
just build-release
just release-preflight
just test-all
```

这些命令是需要实现的交付合同；文档包本身未附完整链源码，所以目前不能声称它们可运行。命令未能执行时必须报告原因，不能把跳过当通过。生成 `reports/*.json` 时包含命令、退出码、环境、版本、时间、日志哈希和测试数量。

## 15.4 迭代交付证据

每完成一个任务，更新 `codex/implementation_status.json`：status 为 NOT_STARTED/IN_PROGRESS/IMPLEMENTED/TESTED/BLOCKED；列实际文件、测试命令与日志路径。初始状态全部 NOT_STARTED，不预填通过。

未经测试的代码最多标 IMPLEMENTED。依赖缺失、平台不可用和外部审计缺失分别记录，不能用空的 successful=true 报告伪造完整交付。上下文不足时写 `codex/NEXT.md` 记录已完成、未完成和下一命令，不能总结“全部完成”后丢弃剩余模块。

## 15.5 禁止的捷径

不得改成 ERC-20、Solana 代币、另链智能合约或中心化数据库；不得在不通知规格变更的情况下改成公开转账；不得生成可流通 staking token；不得让服务器保存种子/完整查看密钥；不得凭 HTTP 成功把钱记为到账；不得以 UI 定时器生成奖励；不得把 testnet 私钥或开发证明参数用于 mainnet。

若上游 API 与假设不符，查看锁定源码并修改 adapter，而不是新写一个同名假函数。若电路无法不变地复用，必须记录具体差异与阻断，不能关闭验证。

## 15.6 对主网外部输入的处理

软件应完整实现网络创建、清单签名、主网 preflight 和发布功能。实际创世分配对象、私钥持有人、商店开发者账号、真实运营节点、检查点发布者和审计报告只能由真实参与者提供。

Codex 可以生成格式和验证工具，不能冒充这些人签字或自动替用户决定融资、上币及法律结论。缺少它们时完成完整 localnet/testnet 与 release candidate；`mainnet_ready` 必须为 false，并准确列出缺失，不得把它理解成允许删掉功能。
