# 09　公开 API、本地 SDK、错误与幂等

## 9.1 三类接口必须分开

公开 HTTP/gRPC：只提供公开数据、证明和交易广播，无钱包注册、无余额修改、无恢复词上传。

钱包 FFI：进程内本地调用，处理解锁、扫描、计划、证明和签名，不监听公网端口。

节点管理 IPC：Unix domain socket 或 Windows named pipe，OS ACL + 随机会话 token；仅管理本机节点，不具备钱包资金签名权限。

`contracts/openapi.yaml` 定义公开 REST；`contracts/solo.proto` 定义 envelope 与查询结构；`contracts/local_sdk.json` 定义本地接口签名和访问等级。它们是需要实现的合同，不是已经存在的服务。

## 9.2 公开服务

| 方法/路径 | 用途 | 信任要求 |
|---|---|---|
| GET /v1/network | chain_context、genesis hash、版本、资源参数 | 与内置/核对过的 manifest 比较 |
| GET /v1/headers | 从起始高度获取头与实际验证集合 | 本地轻客户端验证，限制每批数量 |
| GET /v1/compact-blocks | 通用 compact block 区间 | 必须带 hash/state proof，验证完整性 |
| POST /v1/transactions | 提交 canonical envelope | 返回只是接收状态，不等于到账 |
| GET /v1/transactions/{tx_id} | 入块/待定与结果证明 | 验证 inclusion、结果及对应头 |
| GET /v1/state/proof | 指定公开 key 的值/不存在证明 | 精确绑定 state_height，不信单独 value |
| GET /v1/validators | 公开验证者目录 | 分页，状态结果可附证明 |
| GET /v1/validators/{id} | 验证者状态与佣金 | 验证状态证明 |
| GET /v1/positions/{id} | 公开独立持仓状态 | 钱包优先从通用同步恢复，减少聚类 |
| GET /v1/exit-tickets/{id} | 退出等待、当前值、证明 | 不以接口估算代替签名时链验证 |
| GET /v1/supply | 发行与容器总账 | 与状态根证明绑定 |
| GET /v1/fees | 当前固定费参数与报价高度 | 费用公式钱包也独立实现 |
| GET /v1/checkpoints | 多方签名检查点候选 | 不是自动信任入口 |
| GET /health/live | 进程存活 | 不包含内部地址、敏感配置 |
| GET /health/ready | 同步与服务就绪 | 不表示链已去中心化或资产安全 |

所有主网钱包请求走 Tor。body/query 严格上限；范围请求 limit 默认 100、最多 500 个小对象，compact 最大批次通过总字节限制独立限制；禁止任意反射查询或不受限全文搜索。公开接口不要求以手机号注册 API key。

## 9.3 API 共同字段

ID 为规范小写十六进制（32 字节则 64 hex）；地址按 HRP 规范；金额是十进制字符串，无正号、指数、千位分隔或负值。时间用 RFC3339 UTC，内部 chain_time 用 seconds/nanos 的确切整数表示。所有返回含 `protocol_version`、`state_height`、`verified_header_height`（服务声明，客户端仍要验证）。

证明数据固定标明 proof_format 与版本。空值必须区分不存在、未索引、节点没同步及未知交易，不能统称 NOT_FOUND。区块浏览器索引未知不说明交易没有发生。

## 9.4 广播幂等与重试

客户端用 tx_id 作为幂等标识。相同字节重播最多得到相同交易的状态；服务器不得替用户改费、替换收款输出或重新签名。不同 tx_id 即使备注相同也不是同一笔链上付款，不按 invoice_id 在全网查隐私交易。

HTTP 超时、429、503 返回可重试信息和 Retry-After，但钱包先保持原交易预留。已确认重复提交返回 CONFIRMED 状态与证明；mempool 暂时缺失返回 UNKNOWN/MEMPOOL_EVICTED，不宣布支付失败。

## 9.5 钱包 FFI 组

生命周期：`wallet_create/wallet_restore/wallet_unlock/wallet_lock/wallet_change_password/wallet_delete_local`。

安全：`backup_begin/backup_reveal_chunk/verify_backup/export_encrypted_backup/import_backup`；导出每次有本地授权，不允许任意对象 Debug 输出。

同步：`sync_start/pause/status/import_checkpoint`；进度事件为不可变 DTO。

支付：`receive_request_create/parse_payment_uri/plan_payment/prove_plan/confirm_and_sign/broadcast_signed/transaction_status/rebroadcast`。

质押：`validators_list/plan_delegate/list_positions/plan_cancel_pending/plan_unbond/list_exit_tickets/plan_claim_exit/plan_claim_commission`。

节点权限：`parse_node_request/approve_validator_request/export_approval`。该组只接受枚举的已知请求和字段，禁止 `sign_arbitrary_bytes`。

本地数据：`contacts_* / invoices_* / export_history / diagnostic_preview`。

所有 plan 带 plan_id、chain_context、state_height、effect_summary、fee、expires_height、input_reservations。`confirm_and_sign` 只签用户刚看过且摘要未变的 plan；后台变更任何金额均失效。

## 9.6 本地 IPC

node-agent 提供 `InspectHost, GetStatus, InstallRuntime, Start, Stop, ImportVerifiedSnapshot, CreateConsensusIdentity, MakeRegistrationRequest, ApplySignedOperatorTx, ExportDiagnostics, PrepareUpgrade, ApplyApprovedUpgrade`。

默认只本机。凭 OS ACL 和短会话 token 访问；请求 ID、操作类型、参数完整性与权限分级记录到脱敏日志。不能把任意字符串传给 shell；可执行路径来自签名安装清单且无 shell 插值。

手机与桌面交换带 nonce、chain_context、node_fingerprint、过期时间/高度的 QR 包；手机签过的包只授权明示动作。没有可信本机配对时，不开放远程管理 HTTP 端口。

## 9.7 错误码族

格式/版本：E_BAD_ENCODING、E_SIZE_LIMIT、E_UNSUPPORTED_VERSION、E_CHAIN_MISMATCH。

密码学：E_INVALID_PROOF、E_INVALID_SIGNATURE、E_INVALID_BINDING、E_DOUBLE_SPEND、E_UNKNOWN_ANCHOR。

资金：E_INSUFFICIENT_FUNDS、E_INSUFFICIENT_FEE、E_AMOUNT_RANGE、E_SLIPPAGE、E_STALE_QUOTE。

质押：E_POSITION_NOT_FOUND、E_OWNER_MISMATCH、E_SEQUENCE、E_VALIDATOR_INELIGIBLE、E_EXIT_IMMATURE、E_ALREADY_CLAIMED、E_SLASH_PENDING。

网络/客户端：E_NETWORK_UNKNOWN、E_PRIVACY_UNAVAILABLE、E_TRUST_EXPIRED、E_CONFLICTING_HEADERS、E_SCAN_INCOMPLETE、E_VAULT_LOCKED。

节点：E_SIGNER_ROLLBACK、E_DOUBLE_SIGN_ATTEMPT、E_DISK_FULL、E_SNAPSHOT_INVALID、E_PROTOCOL_UPGRADE_REQUIRED。

错误响应不回显 seed、地址列表、完整证明 witness 或未脱敏请求。内外码映射需完整测试，不允许前端因未知错误默认显示成功。

## 9.8 浏览器只读补充接口

`GET /v1/blocks`（cursor/limit，最多100）、`GET /v1/blocks/{height}`（头、公开tx_id与证明）、`GET /v1/validators/{id}/events`（公开佣金/证据/变更，分页）、`GET /v1/upgrades`（多方签名软件升级公告）。同样不接受恢复词或私密地址查询。升级公告仅是发布者建议；网关返回某高度不代表拥有修改共识或自动安装的权力。

REST共19个操作；solo.proto中只定义其中4个高频gRPC镜像，其余通过REST，不要求为所有接口维护第二套独立业务规则。

补充质押错误：E_ACTIVATION_CAPACITY表示本次激活周期容量已满，未扣款；E_LAST_VALIDATOR_BOND表示本次主动操作将清空合格验证集合，需要替代节点，不能通过跳过自质押规则绕过。
