# BIT D-022 RPC、API 与网关

状态：`IN_PROGRESS`。公开只读网关的首批五类能力已经实现：健康检查、带证明网络参数、白名单状态证明、完整供应审计和有界 compact block 下载。交易广播、头同步、验证人/持仓/退出查询、检查点与浏览器接口仍待后续切片。

## 1. 信任边界

`bit-gateway` 与 ABCI 共享同一个 `ApplicationCore`，不另开 RocksDB，也不维护第二份业务状态。ABCI 的执行写锁和状态层的读写锁保证查询只观察完整提交版本。网关返回的值不是可信结论；客户端仍必须用已验证区块头中的 app hash 验证 ICS23 proof。

`verified_header_height` 是网关声明的本地轻客户端覆盖高度，使用单调接口更新。它低于应用状态高度时 `/health/ready` 返回 503；成功的业务响应会携带声明高度，客户端不能把该字段当成证明。独立轻客户端和可信期管理属于 D-010。

当前服务不终止 TLS，因此 `serve_local` 强制只绑定 loopback。公网部署必须由后续受控 TLS/Tor ingress 代理，不能把该明文监听直接改成 `0.0.0.0`。

## 2. 已实现接口

| 方法与路径 | 行为 |
|---|---|
| `GET /health/live` | 仅说明网关进程存活 |
| `GET /health/ready` | 要求应用状态可读且 verified header height 不落后 |
| `GET /v1/network?height=` | 返回 genesis identity manifest hash、chain context、本币 ID、政策/资源限制、创世承诺摘要和领取清单摘要，并附组成这些字段的同高证明 |
| `GET /v1/state/proof?key=&height=` | 高度 0/省略表示最新，正数表示精确历史高度；返回原值、app hash 和一至两段 ICS23 proof |
| `GET /v1/supply?height=` | 严格解码同高 `supply/audit_snapshot` 与 `emission/policy`，返回完整供应容器、减半阶段、下一配额和发行完成状态，并附两份证明 |
| `GET /v1/compact-blocks?from_height=&limit=&max_bytes=` | 连续返回本地归档中的规范 compact bytes、域分离 hash 和同高 `compact/hash` 证明 |

完整机器合同位于 [OpenAPI 3.1](D:/others/BIT/contracts/openapi.yaml)。

## 3. 公开键与资源限制

状态证明不是任意数据库反射。键最长 256 ASCII 字节；只允许固定网络/费用/TCT 根/供应键，以及 transaction、nullifier、区块摘要、创世领取状态和选定公开 staking 记录前缀。`meta/genesis_manifest_hash`、`meta/genesis_claims_hash` 和 `genesis/claims/<claim_id>` 均可证明；领取状态的版本化 58 字节格式由 D-025 固定。TCT frontier、子存储版本标记、内部推进队列、SlashJob 游标和未知键空间不会由网关暴露。缺失、无法解析或越界的查询参数统一返回 JSON `E_BAD_QUERY` 或对应的稳定错误码。

compact 请求默认最多 100 块、硬上限 100 块；规范 compact 载荷默认最多 4 MiB、硬上限 16 MiB。首块已经超过请求上限时返回 413；本地归档缺失时返回 503 `E_ARTIFACT_UNAVAILABLE`，不会用空结果伪装同步完成。`block_artifacts_with_proofs` 会重新验证归档字节，并要求同一高度的历史证明值与 compact hash 精确相等。

## 4. 编码

高度和 Amount 在 JSON 中使用无符号十进制字符串。32 字节 ID 与 app hash 使用规范小写十六进制。规范二进制值和每段 protobuf `CommitmentProof` 使用标准 Base64。`proof_format` 固定为 `ics23:jmt:v1`；主树键返回一段 proof，子存储键返回“子树到子树根、子树根到主根”两段 proof。

## 5. 后续工作

下一阶段接入 CometBFT 已验证头源与真实 TLS 入口，再实现 `/v1/headers` 和交易广播。其后补验证人、持仓、退出票据、检查点和浏览器分页接口，并对 429/超时、并发、缓存、Tor 入口与恶意证明请求做压力和故障测试。
