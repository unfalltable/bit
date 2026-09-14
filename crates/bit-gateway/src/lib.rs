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
use bit_types::SupplyAuditSnapshot;
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
    let bytes = proof
        .value
        .as_deref()
        .ok_or_else(|| ApiError::internal_message("supply audit snapshot is missing"))?;
    let snapshot = SupplyAuditSnapshot::decode_canonical(bytes)
        .map_err(|_| ApiError::internal_message("supply audit snapshot is invalid"))?;
    let meta = meta_for_proof(&state, &proof).await?;
    Ok(Json(SupplyResponse {
        meta,
        supply: SupplyDto::from(snapshot),
        proof: proof_dto(proof)?,
    }))
}

#[derive(Deserialize)]
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
        "meta/monetary_policy_hash",
        "shielded/tree_root",
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
pub struct SupplyResponse {
    pub meta: ApiMeta,
    pub supply: SupplyDto,
    pub proof: ProofDto,
}

#[derive(Serialize)]
pub struct SupplyDto {
    pub max_supply: String,
    pub genesis_supply: String,
    pub cumulative_minted: String,
    pub burned: String,
    pub issued_total: String,
    pub total: String,
    pub scheduled_to_date: String,
    pub forfeited_unissued: String,
    pub future_issuance_budget: String,
    pub shielded_total: String,
    pub stake_total: String,
    pub pending_delegation_total: String,
    pub exit_total: String,
    pub commission_total: String,
    pub fee_reserve: String,
    pub unclaimed_genesis_total: String,
    pub completed_epochs: String,
    pub monetary_policy_hash: String,
}

impl From<SupplyAuditSnapshot> for SupplyDto {
    fn from(value: SupplyAuditSnapshot) -> Self {
        Self {
            max_supply: value.max_supply.value().to_string(),
            genesis_supply: value.genesis_supply.value().to_string(),
            cumulative_minted: value.cumulative_minted.value().to_string(),
            burned: value.burned.value().to_string(),
            issued_total: value.issued_total.value().to_string(),
            total: value.current_supply.value().to_string(),
            scheduled_to_date: value.scheduled_to_date.value().to_string(),
            forfeited_unissued: value.forfeited_unissued.value().to_string(),
            future_issuance_budget: value.future_issuance_budget.value().to_string(),
            shielded_total: value.shielded_total.value().to_string(),
            stake_total: value.stake_total.value().to_string(),
            pending_delegation_total: value.pending_delegation_total.value().to_string(),
            exit_total: value.exit_total.value().to_string(),
            commission_total: value.commission_total.value().to_string(),
            fee_reserve: value.fee_reserve.value().to_string(),
            unclaimed_genesis_total: value.unclaimed_genesis_total.value().to_string(),
            completed_epochs: value.completed_epochs.to_string(),
            monetary_policy_hash: hex::encode(value.monetary_policy_hash),
        }
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
        assert_eq!(supply["proof"]["proof_format"], PROOF_FORMAT);
        assert_eq!(
            supply["proof"]["proof_ops_base64"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        let (status, _) = json(
            router.clone(),
            "/v1/state/proof?key=shielded%2Ftree_frontier",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

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
