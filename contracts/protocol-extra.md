# BIT 1.2 编码与授权补充

Protobuf envelope 字段按编号递增，repeated 元素保持顺序并连续出现。禁止未知字段、重复 singular 字段、非最短 varint、错误 wire type、未定义角色及额外签名。解码后必须重新编码并逐字节相同。

`position_id = SHA256("bit/position/v1" || chain_context32 || owner_pubkey32)`。

`validator_id = SHA256("bit/validator/v1" || chain_context32 || operator_pubkey32)`。

`cohort_id = SHA256("bit/cohort/v1" || chain_context32 || validator_id32 || exit_epoch_u64be)`。

`ticket_id = SHA256("bit/ticket/v1" || chain_context32 || position_id32 || pre_increment_position_sequence_u64be)`。

授权按 Spend 输入顺序排列，随后依次最多一个 POSITION_OWNER、OPERATOR、CONSENSUS_POP、GENESIS_CLAIM。Spend/Binding 使用固定上游类型；其他角色在 `role_domain || effect_hash64` 上使用严格 Ed25519。角色域分别为 `bit/owner/v1`、`bit/operator/v1`、`bit/consensus-pop/v1`、`bit/genesis-claim/v1`。

Transfer 只需 Spend。Delegate 需要新 owner，self bond 另需 operator。CancelPending、Unbond、ClaimExit 需要当前 owner。RegisterValidator 需要 operator 和 consensus PoP。UpdateValidator、UnjailValidator、ClaimCommission 需要 operator。RotateConsensusKey 需要 operator 和新 consensus PoP。ClaimGenesis 需要 claim key。Binding 签名始终独立存在。

本文件不授权主网参数或密钥。业务动作的公开释放值必须由执行状态核对；本层结构解码不能替代状态授权、证明或签名验证。
