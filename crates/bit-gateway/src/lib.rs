//! Bounded, read-only HTTP access to proof-bearing BIT state and compact blocks.

use axum::{
    extract::{rejection::QueryRejection, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bit_app::{ApplicationCore, Error as CoreError};
use bit_state::QueryProof;
use bit_types::{
    MonetaryPolicy, SupplyAuditSnapshot, EMPTY_SET_POLICY, MAX_SUPPLY_ATOMIC, POLICY_ID,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

pub const DEFAULT_COMPACT_LIMIT: u32 = 100;
pub const MAX_COMPACT_LIMIT: u32 = 100;
pub const DEFAULT_COMPACT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_COMPACT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STATE_KEY_BYTES: usize = 256;
pub const PROOF_FORMAT: &str = "ics23:jmt:v1";

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("public API listener must use a loopback address until TLS termination is configured")]
    NonLoopback,
    #[error("failed to bind public API: {0}")]
    Bind(#[source] io::Error),
    #[error("public API server failed: {0}")]
    Serve(#[source] io::Error),
}

#[derive(Clone)]
struct GatewayState {
    core: Arc<ApplicationCore>,
    verified_header_height: Arc<AtomicU64>,
}

/// A read-only router over the same application core used by ABCI.
pub struct PublicApi {
    router: Router,
    verified_header_height: Arc<AtomicU64>,
}

impl PublicApi {
    pub fn new(core: Arc<ApplicationCore>, verified_header_height: u64) -> Self {
        let verified_header_height = Arc::new(AtomicU64::new(verified_header_height));
        let state = GatewayState {
            core,
            verified_header_height: verified_header_height.clone(),
        };
        let router = Router::new()
            .route("/health/live", get(live))
            .route("/health/ready", get(ready))
            .route("/v1/network", get(network))
            .route("/v1/state/proof", get(state_proof))
            .route("/v1/supply", get(supply))
            .route("/v1/compact-blocks", get(compact_blocks))
            .with_state(state);
        Self {
            router,
            verified_header_height,
        }
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Advance the locally verified CometBFT header height monotonically.
    pub fn observe_verified_header(&self, height: u64) {
        self.verified_header_height
            .fetch_max(height, Ordering::AcqRel);
    }

    /// Serve plain HTTP only on loopback. A separately configured TLS gateway
    /// may proxy this listener when public exposure is required.
    pub async fn serve_local(self, address: SocketAddr) -> Result<(), ServeError> {
        if !address.ip().is_loopback() {
            return Err(ServeError::NonLoopback);
        }
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(ServeError::Bind)?;
        axum::serve(listener, self.router)
            .await
            .map_err(ServeError::Serve)
    }
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn live() -> Json<Health> {
    Json(Health { status: "live" })
}

async fn ready(State(state): State<GatewayState>) -> Result<Json<Health>, ApiError> {
    let summary = state
        .core
        .state_summary()
        .await
        .map_err(ApiError::internal)?;
    let verified = state.verified_header_height.load(Ordering::Acquire);
    if verified < summary.state_height {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "E_HEADER_BEHIND",
            "verified header height is behind application state",
        ));
    }
    Ok(Json(Health { status: "ready" }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkQuery {
    #[serde(default)]
    height: u64,
}

async fn network(
    State(state): State<GatewayState>,
    query: Result<Query<NetworkQuery>, QueryRejection>,
) -> Result<Json<NetworkResponse>, ApiError> {
    let Query(query) = query.map_err(ApiError::bad_query)?;
    let supply_proof = query_at(&state.core, "supply/audit_snapshot", query.height).await?;
    let height = supply_proof.storage_version;
    let snapshot = decode_supply_snapshot(&supply_proof)?;
    let policy_proof = query_same_state(&state.core, "emission/policy", &supply_proof).await?;
    let policy = decode_monetary_policy(&policy_proof, &snapshot)?;
    let chain_context = query_same_state(&state.core, "meta/chain_context", &supply_proof).await?;
    let native_asset_id =
        query_same_state(&state.core, "meta/native_asset_id", &supply_proof).await?;
    let protocol_version =
        query_same_state(&state.core, "meta/protocol_version", &supply_proof).await?;
    let max_block_bytes =
        query_same_state(&state.core, "meta/max_block_bytes", &supply_proof).await?;
    let max_tx_lifetime_blocks =
        query_same_state(&state.core, "meta/max_tx_lifetime_blocks", &supply_proof).await?;
    let max_envelope_bytes =
        query_same_state(&state.core, "meta/max_envelope_bytes", &supply_proof).await?;
    let anchor_retention_blocks =
        query_same_state(&state.core, "meta/anchor_retention_blocks", &supply_proof).await?;
    let genesis_commitments_hash =
        query_same_state(&state.core, "meta/genesis_commitments_hash", &supply_proof).await?;
    let genesis_claims_hash =
        query_same_state(&state.core, "meta/genesis_claims_hash", &supply_proof).await?;

    let protocol_version_value = decode_u64(&protocol_version)?;
    let info = state.core.info().await.map_err(ApiError::internal)?;
    if protocol_version_value != info.protocol_version {
        return Err(ApiError::internal_message(
            "protocol version differs from application configuration",
        ));
    }

    let response = NetworkResponse {
        meta: ApiMeta {
            protocol_version: protocol_version_value,
            state_height: height.to_string(),
            verified_header_height: state
                .verified_header_height
                .load(Ordering::Acquire)
                .to_string(),
        },
        network: NetworkDto {
            chain_context: decode_hash32_hex(&chain_context)?,
            native_asset_id: decode_hash32_hex(&native_asset_id)?,
            genesis_commitments_hash: decode_hash32_hex(&genesis_commitments_hash)?,
            genesis_claims_hash: decode_hash32_hex(&genesis_claims_hash)?,
            protocol_version: protocol_version_value,
            max_supply: MAX_SUPPLY_ATOMIC.to_string(),
            monetary_policy_hash: hex::encode(snapshot.monetary_policy_hash),
            emission_policy_id: POLICY_ID,
            empty_eligible_set_policy: EMPTY_SET_POLICY,
            burn_reopens_issuance: false,
            tail_emission_enabled: false,
            epoch_blocks: policy.epoch_blocks.to_string(),
            halving_interval_epochs: policy.halving_interval_epochs.to_string(),
            max_block_bytes: decode_u64(&max_block_bytes)?.to_string(),
            max_tx_lifetime_blocks: decode_u64(&max_tx_lifetime_blocks)?.to_string(),
            max_envelope_bytes: decode_u64(&max_envelope_bytes)?.to_string(),
            anchor_retention_blocks: decode_u64(&anchor_retention_blocks)?.to_string(),
        },
        proofs: NetworkProofsDto {
            supply: proof_dto(supply_proof)?,
            monetary_policy: proof_dto(policy_proof)?,
            chain_context: proof_dto(chain_context)?,
            native_asset_id: proof_dto(native_asset_id)?,
            protocol_version: proof_dto(protocol_version)?,
            max_block_bytes: proof_dto(max_block_bytes)?,
            max_tx_lifetime_blocks: proof_dto(max_tx_lifetime_blocks)?,
            max_envelope_bytes: proof_dto(max_envelope_bytes)?,
            anchor_retention_blocks: proof_dto(anchor_retention_blocks)?,
            genesis_commitments_hash: proof_dto(genesis_commitments_hash)?,
            genesis_claims_hash: proof_dto(genesis_claims_hash)?,
        },
    };
    Ok(Json(response))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateProofQuery {
    key: String,
    #[serde(default)]
    height: u64,
}

async fn state_proof(
    State(state): State<GatewayState>,
    query: Result<Query<StateProofQuery>, QueryRejection>,
) -> Result<Json<StateProofResponse>, ApiError> {
    let Query(query) = query.map_err(ApiError::bad_query)?;
    validate_public_key(&query.key)?;
    let proof = query_at(&state.core, &query.key, query.height).await?;
    let meta = meta_for_proof(&state, &proof).await?;
    Ok(Json(StateProofResponse {
        meta,
        result: proof_dto(proof)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupplyQuery {
    #[serde(default)]
    height: u64,
}

async fn supply(
    State(state): State<GatewayState>,
    query: Result<Query<SupplyQuery>, QueryRejection>,
) -> Result<Json<SupplyResponse>, ApiError> {
    let Query(query) = query.map_err(ApiError::bad_query)?;
    let proof = query_at(&state.core, "supply/audit_snapshot", query.height).await?;
    let snapshot = decode_supply_snapshot(&proof)?;
    let policy_proof = query_same_state(&state.core, "emission/policy", &proof).await?;
    let policy = decode_monetary_policy(&policy_proof, &snapshot)?;
    let meta = meta_for_proof(&state, &proof).await?;
    Ok(Json(SupplyResponse {
        meta,
        supply: SupplyDto::from_snapshot(snapshot, &policy)?,
        proof: proof_dto(proof)?,
        policy_proof: proof_dto(policy_proof)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactQuery {
    from_height: u64,
    limit: Option<u32>,
    max_bytes: Option<usize>,
}

async fn compact_blocks(
    State(state): State<GatewayState>,
    query: Result<Query<CompactQuery>, QueryRejection>,
) -> Result<Json<CompactBlocksResponse>, ApiError> {
    let Query(query) = query.map_err(ApiError::bad_query)?;
    if query.from_height == 0 {
        return Err(ApiError::bad_request(
            "E_BAD_HEIGHT",
            "from_height must be greater than zero",
        ));
    }
    let limit = query.limit.unwrap_or(DEFAULT_COMPACT_LIMIT);
    if limit == 0 || limit > MAX_COMPACT_LIMIT {
        return Err(ApiError::bad_request(
            "E_SIZE_LIMIT",
            "limit must be between 1 and 100",
        ));
    }
    let max_bytes = query.max_bytes.unwrap_or(DEFAULT_COMPACT_BYTES);
    if max_bytes == 0 || max_bytes > MAX_COMPACT_BYTES {
        return Err(ApiError::bad_request(
            "E_SIZE_LIMIT",
            "max_bytes must be between 1 and 16777216",
        ));
    }

    let info = state.core.info().await.map_err(ApiError::internal)?;
    let mut height = query.from_height;
    let mut bytes = 0usize;
    let mut items = Vec::new();
    while height <= info.last_block_height && items.len() < limit as usize {
        let proven = state
            .core
            .block_artifacts_with_proofs(height)
            .await
            .map_err(ApiError::internal)?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "E_ARTIFACT_UNAVAILABLE",
                    "compact block is not available in the local archive",
                )
            })?;
        let next_bytes = bytes
            .checked_add(proven.artifacts.compact_block.len())
            .ok_or_else(|| ApiError::internal_message("compact response size overflow"))?;
        if next_bytes > max_bytes {
            if items.is_empty() {
                return Err(ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "E_SIZE_LIMIT",
                    "the first compact block exceeds max_bytes",
                ));
            }
            break;
        }
        bytes = next_bytes;
        items.push(CompactBlockDto {
            height: height.to_string(),
            canonical_block_base64: BASE64.encode(&proven.artifacts.compact_block),
            compact_hash: hex::encode(proven.artifacts.compact_hash),
            proof: proof_dto(proven.compact_proof)?,
        });
        height = height
            .checked_add(1)
            .ok_or_else(|| ApiError::internal_message("compact height overflow"))?;
    }
    let complete_to_tip = height > info.last_block_height;
    let next_height = (!complete_to_tip).then(|| height.to_string());
    Ok(Json(CompactBlocksResponse {
        meta: ApiMeta {
            protocol_version: info.protocol_version,
            state_height: info.last_block_height.to_string(),
            verified_header_height: state
                .verified_header_height
                .load(Ordering::Acquire)
                .to_string(),
        },
        items,
        next_height,
        complete_to_tip,
        canonical_bytes: bytes.to_string(),
    }))
}

async fn query_at(core: &ApplicationCore, key: &str, height: u64) -> Result<QueryProof, ApiError> {
    let result = if height == 0 {
        core.query_latest_with_proof(key).await
    } else {
        core.query_at_height_with_proof(key, height).await
    };
    match result {
        Ok(proof) => {
            proof
                .verify()
                .map_err(|_| ApiError::internal_message("state proof self-verification failed"))?;
            Ok(proof)
        }
        Err(CoreError::State(bit_state::Error::StateHeightUnavailable { .. })) => {
            Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "E_STATE_HEIGHT_UNAVAILABLE",
                "requested state height is unavailable",
            ))
        }
        Err(error) => Err(ApiError::internal(error)),
    }
}

async fn query_same_state(
    core: &ApplicationCore,
    key: &str,
    anchor: &QueryProof,
) -> Result<QueryProof, ApiError> {
    let proof = query_at(core, key, anchor.storage_version).await?;
    if proof.storage_version != anchor.storage_version || proof.app_hash != anchor.app_hash {
        return Err(ApiError::internal_message(
            "state changed while assembling a proof bundle",
        ));
    }
    Ok(proof)
}

fn required_value<'a>(proof: &'a QueryProof, name: &'static str) -> Result<&'a [u8], ApiError> {
    proof
        .value
        .as_deref()
        .ok_or_else(|| ApiError::internal_message(name))
}

fn decode_hash32_hex(proof: &QueryProof) -> Result<String, ApiError> {
    let value = required_value(proof, "required network hash is missing")?;
    if value.len() != 32 {
        return Err(ApiError::internal_message(
            "required network hash has an invalid length",
        ));
    }
    Ok(hex::encode(value))
}

fn decode_u64(proof: &QueryProof) -> Result<u64, ApiError> {
    let value = required_value(proof, "required network integer is missing")?;
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| ApiError::internal_message("required network integer is invalid"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn decode_supply_snapshot(proof: &QueryProof) -> Result<SupplyAuditSnapshot, ApiError> {
    let bytes = required_value(proof, "supply audit snapshot is missing")?;
    SupplyAuditSnapshot::decode_canonical(bytes)
        .map_err(|_| ApiError::internal_message("supply audit snapshot is invalid"))
}

fn decode_monetary_policy(
    proof: &QueryProof,
    snapshot: &SupplyAuditSnapshot,
) -> Result<MonetaryPolicy, ApiError> {
    let bytes = required_value(proof, "monetary policy is missing")?;
    let policy = MonetaryPolicy::decode_canonical(bytes)
        .map_err(|_| ApiError::internal_message("monetary policy is invalid"))?;
    let hash = policy
        .hash()
        .map_err(|_| ApiError::internal_message("monetary policy hash failed"))?;
    if hash != snapshot.monetary_policy_hash {
        return Err(ApiError::internal_message(
            "monetary policy differs from supply audit snapshot",
        ));
    }
    Ok(policy)
}

async fn meta_for_proof(state: &GatewayState, proof: &QueryProof) -> Result<ApiMeta, ApiError> {
    let info = state.core.info().await.map_err(ApiError::internal)?;
    Ok(ApiMeta {
        protocol_version: info.protocol_version,
        state_height: proof.storage_version.to_string(),
        verified_header_height: state
            .verified_header_height
            .load(Ordering::Acquire)
            .to_string(),
    })
}

fn proof_dto(proof: QueryProof) -> Result<ProofDto, ApiError> {
    proof
        .verify()
        .map_err(|_| ApiError::internal_message("state proof self-verification failed"))?;
    Ok(ProofDto {
        state_height: proof.storage_version.to_string(),
        key: proof.key,
        exists: proof.value.is_some(),
        value_base64: proof.value.map(|value| BASE64.encode(value)),
        proof_format: PROOF_FORMAT,
        proof_ops_base64: proof
            .proof
            .proofs
            .iter()
            .map(|item| BASE64.encode(item.encode_to_vec()))
            .collect(),
        app_hash: hex::encode(proof.app_hash),
    })
}

fn validate_public_key(key: &str) -> Result<(), ApiError> {
    if key.is_empty() || key.len() > MAX_STATE_KEY_BYTES || !key.is_ascii() {
        return Err(ApiError::bad_request(
            "E_BAD_KEY",
            "state key is empty, too long, or not ASCII",
        ));
    }
    const EXACT: &[&str] = &[
        "meta/version",
        "meta/height",
        "meta/chain_context",
        "meta/native_asset_id",
        "meta/protocol_version",
        "meta/max_block_bytes",
        "meta/max_tx_lifetime_blocks",
        "meta/max_envelope_bytes",
        "meta/anchor_retention_blocks",
        "meta/genesis_commitments_hash",
        "meta/genesis_claims_hash",
        "meta/monetary_policy_hash",
        "shielded/tree_root",
        "emission/policy",
        "supply/audit_snapshot",
        "fees/base_atomic",
        "fees/per_kib_atomic",
        "fees/per_spend_proof_atomic",
        "fees/per_output_proof_atomic",
        "fees/new_position_surcharge_atomic",
        "fees/validator_registration_surcharge_atomic",
    ];
    const PREFIXES: &[&str] = &[
        "transactions/applied/",
        "shielded/nullifier/",
        "execution/block/",
        "compact/hash/",
        "genesis/claims/",
        "staking/validators/",
        "staking/pools/",
        "staking/positions/",
        "staking/exits/cohorts/",
        "staking/exits/tickets/",
        "staking/effective_history/",
        "staking/evidence/",
    ];
    let allowed = EXACT.contains(&key)
        || PREFIXES.iter().any(|prefix| {
            key.strip_prefix(prefix).is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        });
    if !allowed {
        return Err(ApiError::bad_request(
            "E_KEY_NOT_PUBLIC",
            "state key is not exposed by the public API",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
pub struct ApiMeta {
    pub protocol_version: u64,
    pub state_height: String,
    pub verified_header_height: String,
}

#[derive(Serialize)]
pub struct ProofDto {
    pub state_height: String,
    pub key: String,
    pub exists: bool,
    pub value_base64: Option<String>,
    pub proof_format: &'static str,
    pub proof_ops_base64: Vec<String>,
    pub app_hash: String,
}

#[derive(Serialize)]
pub struct StateProofResponse {
    pub meta: ApiMeta,
    pub result: ProofDto,
}

#[derive(Serialize)]
pub struct NetworkResponse {
    pub meta: ApiMeta,
    pub network: NetworkDto,
    pub proofs: NetworkProofsDto,
}

#[derive(Serialize)]
pub struct NetworkDto {
    pub chain_context: String,
    pub native_asset_id: String,
    pub genesis_commitments_hash: String,
    pub genesis_claims_hash: String,
    pub protocol_version: u64,
    pub max_supply: String,
    pub monetary_policy_hash: String,
    pub emission_policy_id: &'static str,
    pub empty_eligible_set_policy: &'static str,
    pub burn_reopens_issuance: bool,
    pub tail_emission_enabled: bool,
    pub epoch_blocks: String,
    pub halving_interval_epochs: String,
    pub max_block_bytes: String,
    pub max_tx_lifetime_blocks: String,
    pub max_envelope_bytes: String,
    pub anchor_retention_blocks: String,
}

#[derive(Serialize)]
pub struct NetworkProofsDto {
    pub supply: ProofDto,
    pub monetary_policy: ProofDto,
    pub chain_context: ProofDto,
    pub native_asset_id: ProofDto,
    pub protocol_version: ProofDto,
    pub max_block_bytes: ProofDto,
    pub max_tx_lifetime_blocks: ProofDto,
    pub max_envelope_bytes: ProofDto,
    pub anchor_retention_blocks: ProofDto,
    pub genesis_commitments_hash: ProofDto,
    pub genesis_claims_hash: ProofDto,
}

#[derive(Serialize)]
pub struct SupplyResponse {
    pub meta: ApiMeta,
    pub supply: SupplyDto,
    pub proof: ProofDto,
    pub policy_proof: ProofDto,
}

#[derive(Serialize)]
pub struct SupplyDto {
    pub max_supply: String,
    pub genesis: String,
    pub minted: String,
    pub burned: String,
    pub issued_total: String,
    pub total: String,
    pub scheduled_to_date: String,
    pub forfeited_unissued: String,
    pub future_issuance_budget: String,
    pub shielded: String,
    pub stake: String,
    pub pending: String,
    pub exits: String,
    pub commission: String,
    pub fees: String,
    pub genesis_unclaimed: String,
    pub completed_epochs: String,
    pub halving_index: String,
    pub halving_interval_epochs: String,
    pub epoch_blocks: String,
    pub next_halving_height: Option<String>,
    pub current_era_budget: String,
    pub next_epoch_quota: String,
    pub emission_finished: bool,
    pub monetary_policy_hash: String,
}

impl SupplyDto {
    fn from_snapshot(
        value: SupplyAuditSnapshot,
        policy: &MonetaryPolicy,
    ) -> Result<Self, ApiError> {
        let halving_index = value.completed_epochs / policy.halving_interval_epochs;
        let remaining_at_era_start = if halving_index >= 128 {
            0
        } else {
            policy.future_budget() >> halving_index
        };
        let current_era_budget = remaining_at_era_start - remaining_at_era_start / 2;
        let next_epoch_quota = policy
            .quota(value.completed_epochs)
            .map_err(|_| ApiError::internal_message("next issuance quota overflow"))?;
        let emission_finished = value.future_issuance_budget.value() == 0;
        let next_halving_height = if emission_finished {
            None
        } else {
            let next_era = halving_index
                .checked_add(1)
                .ok_or_else(|| ApiError::internal_message("halving index overflow"))?;
            let next_era_epoch = next_era
                .checked_mul(policy.halving_interval_epochs)
                .ok_or_else(|| ApiError::internal_message("halving epoch overflow"))?;
            let height = next_era_epoch
                .checked_mul(policy.epoch_blocks)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| ApiError::internal_message("halving height overflow"))?;
            Some(height.to_string())
        };
        Ok(Self {
            max_supply: value.max_supply.value().to_string(),
            genesis: value.genesis_supply.value().to_string(),
            minted: value.cumulative_minted.value().to_string(),
            burned: value.burned.value().to_string(),
            issued_total: value.issued_total.value().to_string(),
            total: value.current_supply.value().to_string(),
            scheduled_to_date: value.scheduled_to_date.value().to_string(),
            forfeited_unissued: value.forfeited_unissued.value().to_string(),
            future_issuance_budget: value.future_issuance_budget.value().to_string(),
            shielded: value.shielded_total.value().to_string(),
            stake: value.stake_total.value().to_string(),
            pending: value.pending_delegation_total.value().to_string(),
            exits: value.exit_total.value().to_string(),
            commission: value.commission_total.value().to_string(),
            fees: value.fee_reserve.value().to_string(),
            genesis_unclaimed: value.unclaimed_genesis_total.value().to_string(),
            completed_epochs: value.completed_epochs.to_string(),
            halving_index: halving_index.to_string(),
            halving_interval_epochs: policy.halving_interval_epochs.to_string(),
            epoch_blocks: policy.epoch_blocks.to_string(),
            next_halving_height,
            current_era_budget: current_era_budget.to_string(),
            next_epoch_quota: next_epoch_quota.to_string(),
            emission_finished,
            monetary_policy_hash: hex::encode(value.monetary_policy_hash),
        })
    }
}

#[derive(Serialize)]
pub struct CompactBlocksResponse {
    pub meta: ApiMeta,
    pub items: Vec<CompactBlockDto>,
    pub next_height: Option<String>,
    pub complete_to_tip: bool,
    pub canonical_bytes: String,
}

#[derive(Serialize)]
pub struct CompactBlockDto {
    pub height: String,
    pub canonical_block_base64: String,
    pub compact_hash: String,
    pub proof: ProofDto,
}

#[derive(Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: &'static str,
}

struct ApiError {
    status: StatusCode,
    body: ApiErrorBody,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            body: ApiErrorBody { code, message },
        }
    }

    fn bad_request(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    fn bad_query(_error: QueryRejection) -> Self {
        Self::bad_request("E_BAD_QUERY", "query parameters are invalid")
    }

    fn internal(_error: impl std::fmt::Display) -> Self {
        Self::internal_message("public read failed")
    }

    fn internal_message(message: &'static str) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "E_INTERNAL", message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use bit_app::BlockRequest;
    use bit_emission::{FeePolicy, GenesisAllocation};
    use bit_staking::{StakingBook, StakingParameters};
    use bit_state::GenesisConfig;
    use bit_types::MonetaryPolicy;
    use serde_json::Value;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn genesis() -> GenesisConfig {
        let monetary_policy = MonetaryPolicy::reference_testnet();
        GenesisConfig {
            chain_context: [1; 32],
            native_asset_id: [2; 32],
            protocol_version: 1,
            max_block_bytes: 1_000_000,
            max_tx_lifetime_blocks: 20,
            max_envelope_bytes: 65_536,
            anchor_retention_blocks: 8,
            genesis_allocation: GenesisAllocation::unclaimed_only(monetary_policy.genesis_supply),
            fee_policy: FeePolicy::reference_testnet(),
            monetary_policy,
            genesis_staking: StakingBook::new([1; 32], StakingParameters::reference_testnet())
                .unwrap(),
            genesis_commitments: Vec::new(),
            genesis_claims: Vec::new(),
            genesis_execution_hash: [3; 32],
            genesis_compact_hash: [4; 32],
        }
    }

    async fn json(router: Router, uri: &str) -> (StatusCode, Value) {
        let response = router
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 32 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn routes_return_bounded_proof_bearing_data() {
        let directory = TempDir::new().unwrap();
        let core = Arc::new(
            ApplicationCore::open(directory.path().to_path_buf(), genesis())
                .await
                .unwrap(),
        );
        let api = PublicApi::new(core.clone(), 0);
        let router = api.router();

        let (status, supply) = json(router.clone(), "/v1/supply").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(supply["meta"]["state_height"], "0");
        assert_eq!(supply["supply"]["max_supply"], "10240000000000000000");
        assert_eq!(supply["supply"]["halving_index"], "0");
        assert_eq!(supply["supply"]["halving_interval_epochs"], "35040");
        assert_eq!(supply["supply"]["epoch_blocks"], "720");
        assert_eq!(supply["supply"]["next_halving_height"], "25228801");
        assert_eq!(
            supply["supply"]["current_era_budget"],
            "5115000000000000000"
        );
        assert_eq!(supply["supply"]["next_epoch_quota"], "145976027397260");
        assert_eq!(supply["supply"]["emission_finished"], false);
        assert_eq!(supply["proof"]["proof_format"], PROOF_FORMAT);
        assert_eq!(supply["policy_proof"]["key"], "emission/policy");
        assert_eq!(
            supply["proof"]["proof_ops_base64"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        let (status, network) = json(router.clone(), "/v1/network").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(network["meta"]["state_height"], "0");
        assert_eq!(network["network"]["chain_context"], hex::encode([1; 32]));
        assert_eq!(network["network"]["native_asset_id"], hex::encode([2; 32]));
        assert_eq!(network["network"]["protocol_version"], 1);
        assert_eq!(
            network["network"]["emission_policy_id"],
            "BUDGET_HALVING_EPOCH_V1"
        );
        assert_eq!(network["network"]["max_block_bytes"], "1000000");
        assert_eq!(network["proofs"]["monetary_policy"]["state_height"], "0");
        assert_eq!(
            network["proofs"]["genesis_claims_hash"]["key"],
            "meta/genesis_claims_hash"
        );
        assert_eq!(
            network["proofs"]["chain_context"]["app_hash"],
            network["proofs"]["supply"]["app_hash"]
        );

        let (status, _) = json(
            router.clone(),
            "/v1/state/proof?key=shielded%2Ftree_frontier",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, claim) = json(
            router.clone(),
            &format!(
                "/v1/state/proof?key=genesis%2Fclaims%2F{}",
                hex::encode([0x44; 32])
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(claim["result"]["exists"], false);
        assert_eq!(
            claim["result"]["proof_ops_base64"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        let finalized = core
            .finalize_block(BlockRequest {
                height: 1,
                block_time_seconds: 1,
                transactions: Vec::new(),
                last_commit: None,
                byzantine_evidence: Vec::new(),
                next_validators_hash: core.expected_next_validators_hash(1).await.unwrap(),
            })
            .await
            .unwrap();
        core.commit().await.unwrap();

        let (status, error) = json(router.clone(), "/health/ready").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error["code"], "E_HEADER_BEHIND");

        api.observe_verified_header(1);

        let (status, ready) = json(router.clone(), "/health/ready").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ready["status"], "ready");

        let (status, network) = json(router.clone(), "/v1/network?height=1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(network["meta"]["state_height"], "1");
        assert_eq!(network["proofs"]["monetary_policy"]["state_height"], "1");

        let (status, supply) = json(router.clone(), "/v1/supply?height=1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(supply["proof"]["state_height"], "1");
        assert_eq!(supply["policy_proof"]["state_height"], "1");

        let (status, error) = json(router.clone(), "/v1/network?unknown=1").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error["code"], "E_BAD_QUERY");

        let (status, compact) = json(
            router.clone(),
            "/v1/compact-blocks?from_height=1&limit=1&max_bytes=16777216",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(compact["items"][0]["height"], "1");
        assert_eq!(
            BASE64
                .decode(
                    compact["items"][0]["canonical_block_base64"]
                        .as_str()
                        .unwrap()
                )
                .unwrap(),
            finalized.artifacts.compact_block
        );
        assert_eq!(
            compact["items"][0]["compact_hash"],
            hex::encode(finalized.artifacts.compact_hash)
        );
        assert_eq!(compact["complete_to_tip"], true);

        let (status, error) =
            json(router.clone(), "/v1/compact-blocks?from_height=1&limit=101").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error["code"], "E_SIZE_LIMIT");

        let (status, error) = json(router.clone(), "/v1/compact-blocks").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error["code"], "E_BAD_QUERY");

        let (status, proof) = json(
            router.clone(),
            "/v1/state/proof?key=compact%2Fhash%2F00000000000000000001&height=1",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(proof["result"]["state_height"], "1");
        assert_eq!(proof["result"]["exists"], true);

        let (status, error) = json(router, "/v1/state/proof?key=meta%2Fheight&height=2").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(error["code"], "E_STATE_HEIGHT_UNAVAILABLE");

        let public_address: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let result = PublicApi::new(core, 1).serve_local(public_address).await;
        assert!(matches!(result, Err(ServeError::NonLoopback)));
    }
}
