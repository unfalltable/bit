# BIT 技术可行性实验

本目录用于用户确认后的前置验证：真实 Spend/Output 原语、共识与货币会计边界、设备资源测量。用户随后要求“手机先跳过”，Android 为 `SKIPPED_BY_USER`，本轮已完成可独立进行的桌面实验。

原始规格保留在 `docs`。只按 BIT v1.2 的固定累计发行规则开展经济实验；旧 Solo 会计模型不作为新发行权威。

工具安装在本目录 `.tools`，下载记录保存到 `reports`，不修改系统 PATH。测试密钥只用于隔离测试。不得连接真实资产网络，不使用手机现有钱包或个人数据。

它是隔离实验，不是完整 BIT 链、正式钱包或主网实现。阅读 [第一轮技术验证报告](D:/others/BIT/docs/BIT_第一轮技术验证报告.md) 了解结果及限制。

## 已执行结果

| 项目 | 结果 |
|---|---|
| 完整两 Spend + 两 Output Transfer | 5 组真实证明通过；生成中位数 4.39 秒、严格 proof 验证中位数 26.32 ms；完整 envelope、Spend 授权、binding 和重复 nullifier 负例通过 |
| 固定发行与有限会计边界 | 18 个 Rust 测试通过 |
| 真实四节点 + Rust ABCI/JMT | 同高度状态一致、H+2、应用重启、真实重复投票处罚、ICS23、投票权不足停止及恢复检查通过 |
| 手机 | 用户跳过；ADB 服务已停止 |

密码学程序已经组成并验收完整 BIT Transfer，但本目录的早期 proof probe 只写入内存账本夹具。当前四节点网络复用生产 `bit-app` 与 JMT/RocksDB 状态核心，仍只处理没有用户交易的区块；它已通过标准 CometBFT RPC 注入真实重复投票证据并验证处罚，但没有独立 signer。四个节点运行于同一宿主。总体状态仍是部分开发验证通过。

## 目录

- `proof-probe/`：真实 Penumbra v2.1.1 原语和扫描实验，包含 Cargo.lock。
- `consensus-probe/`：Rust ABCI 空块状态机与独立固定发行数学实验，包含 Cargo.lock。
- `evidence-injector/`：仅用于 `bit-app-probe-*` 隔离测试链的 CometBFT 重复投票证据生成与广播工具。
- `scripts/`：项目内工具准备、构建环境、网络运行、证明测量和证据汇总。
- `reports/`：实际结果、构建和单测日志、下载与来源摘要。
- `runtime/`：每轮本地网配置、测试密钥、状态与日志；被 gitignore 忽略。
- `.tools/`、`upstream/`、`target/`、`target-consensus/`：本机工具、固定上游源码和构建缓存；被 gitignore 忽略。

## 在当前机器复跑

以下命令依赖本目录已准备好的工具、上游源码、证明参数和 Cargo 缓存。请从 `D:\others\BIT` 的 PowerShell 运行。测试会更新 `reports` 下同名结果；每轮网络仍保留独立的 `runtime/network-*` 目录。

先构建并验证整数模型；每条 cargo 命令失败时停止：

```powershell
. .\feasibility\scripts\rust_env.ps1
$env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath('.\feasibility\target-consensus')
cargo test --release --locked --manifest-path .\feasibility\consensus-probe\Cargo.toml 2>&1 | Tee-Object -FilePath .\feasibility\reports\consensus-unit.log
if ($LASTEXITCODE -ne 0) { throw 'Consensus unit tests failed' }
cargo build --release --locked --manifest-path .\feasibility\consensus-probe\Cargo.toml 2>&1 | Tee-Object -FilePath .\feasibility\reports\consensus-build.log
if ($LASTEXITCODE -ne 0) { throw 'Consensus build failed' }
$env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath('.\feasibility\target')
cargo build --release --locked --manifest-path .\feasibility\proof-probe\Cargo.toml 2>&1 | Tee-Object -FilePath .\feasibility\reports\proof-build.log
if ($LASTEXITCODE -ne 0) { throw 'Proof build failed' }
```

再分别运行真实网络及证明实验，最后生成汇总与来源记录：

```powershell
py -B .\feasibility\scripts\run_network.py
if ($LASTEXITCODE -ne 0) { throw 'Network experiment failed; inspect reports' }
py -B .\feasibility\scripts\run_proof_probe.py
if ($LASTEXITCODE -ne 0) { throw 'Proof experiment failed; inspect reports' }
py -B .\feasibility\scripts\summarize_results.py
if ($LASTEXITCODE -ne 0) { throw 'Summary generation failed' }
py -B .\feasibility\scripts\capture_evidence.py
```

网络运行器要求本地端口 `28700–28703`、`28800–28803`、`28900–28903` 空闲，会创建随机测试创世、启动实际进程并自动清理本次启动的进程。证明运行器固定使用 4 个 Rayon 线程和 5 组样本，不访问手机。Windows 工作集采集使其目前仅适用于 Windows。

网络基准要求同次运行各节点状态一致；创世公钥每轮随机，不要求跨轮状态哈希相同。性能也会随宿主负载变化，不能把样本中位数当成通过阈值。

## 换机器需要重新准备的内容

这不是完整的一键安装包。`bootstrap_tools.py` 负责项目内 Rust/Go 基础工具；默认跳过 Android，仅显式 `--include-android-tools` 才准备 ADB，且不会自动连接设备。LLVM-MinGW、上游源码、证明参数和 CometBFT 需另行按下列记录准备：

- [基础下载记录](D:/others/BIT/feasibility/reports/tool-downloads.json) 和 [LLVM-MinGW 记录](D:/others/BIT/feasibility/reports/native-linker-download.json) 包含本轮 URL、大小和摘要；LLVM-MinGW 放到 `.tools/llvm-mingw-20250812-msvcrt-x86_64`。
- Penumbra 仓库放到 `upstream/penumbra`，固定提交 `3a87ce786373113f9b82d3b6df9504998b7f44a7`；不需要拉取所有 LFS 大文件。
- 仅下载 [参数记录](D:/others/BIT/feasibility/reports/proof-parameter-downloads.json) 中两项到 `.tools/downloads/spend_pk.bin`、`output_pk.bin`；证明程序每次验证其摘要。
- 用本地 Go 构建 `github.com/cometbft/cometbft/cmd/cometbft@v0.38.23`，`GOBIN` 指向 `.tools/bin`、`GOPATH` 指向 `.tools/go-home`、`CGO_ENABLED=0`。模块来源见 [comet-module.json](D:/others/BIT/feasibility/reports/comet-module.json)。其 fallback 版本显示 0.38.22，必须结合 `go version -m` 核实。

锁文件和 SHA-256 记录便于核对本次输入，不代表独立构建复现、供应链审计或主网发布验收已完成。

## 证据入口

[汇总](D:/others/BIT/feasibility/reports/feasibility-summary.json) · [证明](D:/others/BIT/feasibility/reports/proof-result.json) · [网络](D:/others/BIT/feasibility/reports/network-result.json) · [18 项测试](D:/others/BIT/feasibility/reports/consensus-unit.log) · [来源与摘要](D:/others/BIT/feasibility/reports/provenance.json)
