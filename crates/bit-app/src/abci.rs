//! Synchronous CometBFT ABCI v0.38 adapter for [`ApplicationCore`].
//!
//! `tendermint-abci` serves each connection on a blocking thread. This adapter
//! serializes calls through one execution lock and drives the asynchronous core
//! on a private Tokio runtime. Consensus-critical failures set a shared halted
//! flag before terminating the current ABCI request.

use crate::state_sync::{
    active_state_path, persist_active_state_marker, read_active_state_marker,
    validate_active_state_path, validate_active_summary, ActiveStateMarker, ApplyDecision,
    CompletedIncomingSnapshot, StateSyncManager,
};
use crate::{
    encode_hex, read_safety_halt, safety_halt_journal_path, ApplicationCore, BlockRequest,
    Error as CoreError, FinalizeOutcome, Hash32, LastCommit, SafetyHaltError, SafetyHaltRecord,
    StateSyncConfig, TxResult,
};
use bit_staking::{CommitVote, ValidatorStatus, COMETBFT_ADDRESS_BYTES};
use bit_state::{ByzantineEvidence, ByzantineEvidenceKind, GenesisConfig, PersistentState};
use ics23::commitment_proof::Proof;
use prost::Message;
use std::{
    collections::BTreeSet,
    fmt::Display,
    fs, io,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
};
use tendermint_abci::{Application, Server, ServerBuilder};
use tendermint_proto::v0_38::{
    abci::{
        response_apply_snapshot_chunk, response_offer_snapshot, response_process_proposal,
        response_verify_vote_extension, CommitInfo, Event, EventAttribute, ExecTxResult,
        ExtendedCommitInfo, Misbehavior, MisbehaviorType, RequestApplySnapshotChunk,
        RequestCheckTx, RequestExtendVote, RequestFinalizeBlock, RequestInfo, RequestInitChain,
        RequestLoadSnapshotChunk, RequestOfferSnapshot, RequestPrepareProposal,
        RequestProcessProposal, RequestQuery, RequestVerifyVoteExtension,
        ResponseApplySnapshotChunk, ResponseCheckTx, ResponseCommit, ResponseExtendVote,
        ResponseFinalizeBlock, ResponseInfo, ResponseInitChain, ResponseListSnapshots,
        ResponseLoadSnapshotChunk, ResponseOfferSnapshot, ResponsePrepareProposal,
        ResponseProcessProposal, ResponseQuery, ResponseVerifyVoteExtension, Snapshot,
        ValidatorUpdate as ProtoValidatorUpdate,
    },
    crypto::{public_key, ProofOp, ProofOps},
    types::BlockIdFlag,
};

pub const STATE_QUERY_PATH: &str = "/bit/state/key";
pub const PROOF_OP_TYPE: &str = "jmt:v";
pub const CODESPACE: &str = "bit";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum QueryCode {
    Ok = 0,
    UnsupportedPath = 1,
    InvalidKey = 2,
    UnsupportedHeight = 3,
}

#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("failed to resolve ABCI listen address: {0}")]
    Resolve(#[source] io::Error),
    #[error("ABCI listen address did not resolve to any socket")]
    EmptyAddress,
    #[error("ABCI may only listen on loopback, got {0}")]
    NonLoopback(SocketAddr),
    #[error("ABCI read buffer must be greater than zero")]
    EmptyReadBuffer,
    #[error("failed to bind ABCI server: {0}")]
    Abci(#[source] Box<tendermint_abci::Error>),
}

#[derive(Clone)]
pub struct AbciConfig {
    pub application_name: String,
    pub application_version: String,
    /// Exact genesis request accepted by `InitChain`.
    pub expected_init_chain: RequestInitChain,
    /// Zero retains all CometBFT blocks. Pruning policy will set this later.
    pub retain_height: i64,
    /// Local snapshot repository and retention policy. `None` disables State Sync.
    pub state_sync: Option<StateSyncConfig>,
}

impl AbciConfig {
    fn validate(&self, genesis: &GenesisConfig) -> crate::Result<()> {
        if self.application_name.is_empty() {
            return Err(CoreError::InvalidConfig(
                "application_name must not be empty",
            ));
        }
        if self.application_version.is_empty() {
            return Err(CoreError::InvalidConfig(
                "application_version must not be empty",
            ));
        }
        if self.retain_height < 0 {
            return Err(CoreError::InvalidConfig(
                "retain_height must be zero or positive",
            ));
        }

        let request = &self.expected_init_chain;
        if request.chain_id.is_empty()
            || request.chain_id.len() > 50
            || !request.chain_id.is_ascii()
        {
            return Err(CoreError::InvalidConfig(
                "chain_id must be 1..=50 ASCII bytes",
            ));
        }
        if request.initial_height != 1 {
            return Err(CoreError::InvalidConfig("initial_height must equal one"));
        }
        let Some(time) = request.time else {
            return Err(CoreError::InvalidConfig("genesis time is required"));
        };
        if time.seconds <= 0 || !(0..1_000_000_000).contains(&time.nanos) {
            return Err(CoreError::InvalidConfig("genesis time is invalid"));
        }
        if request.app_state_bytes.is_empty() {
            return Err(CoreError::InvalidConfig(
                "canonical genesis app state is required",
            ));
        }
        if request.validators.is_empty() {
            return Err(CoreError::InvalidConfig(
                "at least one genesis validator is required",
            ));
        }

        let mut validator_keys: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut total_power = 0i64;
        for validator in &request.validators {
            if validator.power <= 0 {
                return Err(CoreError::InvalidConfig(
                    "genesis validator power must be positive",
                ));
            }
            total_power =
                total_power
                    .checked_add(validator.power)
                    .ok_or(CoreError::InvalidConfig(
                        "genesis validator power total overflow",
                    ))?;
            let Some(key) = validator.pub_key.as_ref() else {
                return Err(CoreError::InvalidConfig(
                    "genesis validator public key is required",
                ));
            };
            let Some(public_key::Sum::Ed25519(key)) = key.sum.as_ref() else {
                return Err(CoreError::InvalidConfig(
                    "genesis validators must use Ed25519",
                ));
            };
            if key.len() != 32 {
                return Err(CoreError::InvalidConfig(
                    "Ed25519 validator public keys must be 32 bytes",
                ));
            }
            if !validator_keys.insert(key.clone()) {
                return Err(CoreError::InvalidConfig(
                    "duplicate genesis validator public key",
                ));
            }
        }
        if total_power == 0 {
            return Err(CoreError::InvalidConfig(
                "genesis validator power total must be positive",
            ));
        }
        let staking_validators: BTreeSet<(Vec<u8>, i64)> = genesis
            .genesis_staking
            .validators()
            .filter(|validator| validator.status == ValidatorStatus::Active)
            .map(|validator| {
                Ok((
                    validator.consensus_pubkey.to_vec(),
                    i64::try_from(validator.voting_power).map_err(|_| {
                        CoreError::InvalidConfig("staking validator power exceeds i64")
                    })?,
                ))
            })
            .collect::<crate::Result<_>>()?;
        let request_validators: BTreeSet<(Vec<u8>, i64)> = request
            .validators
            .iter()
            .map(|validator| {
                let key = validator
                    .pub_key
                    .as_ref()
                    .and_then(|key| key.sum.as_ref())
                    .and_then(|sum| match sum {
                        public_key::Sum::Ed25519(key) => Some(key.clone()),
                        _ => None,
                    })
                    .ok_or(CoreError::InvalidConfig(
                        "genesis validator public key is invalid",
                    ))?;
                Ok((key, validator.power))
            })
            .collect::<crate::Result<_>>()?;
        if staking_validators != request_validators {
            return Err(CoreError::InvalidConfig(
                "InitChain validators differ from genesis staking set",
            ));
        }

        let Some(params) = request.consensus_params.as_ref() else {
            return Err(CoreError::InvalidConfig(
                "consensus parameters are required",
            ));
        };
        let Some(block) = params.block else {
            return Err(CoreError::InvalidConfig(
                "consensus block parameters are required",
            ));
        };
        let expected_max_bytes = i64::try_from(genesis.max_block_bytes)
            .map_err(|_| CoreError::InvalidConfig("max_block_bytes exceeds i64"))?;
        if block.max_bytes != expected_max_bytes {
            return Err(CoreError::InvalidConfig(
                "consensus and application max block bytes differ",
            ));
        }
        if block.max_gas < -1 {
            return Err(CoreError::InvalidConfig("consensus max gas is invalid"));
        }
        let Some(evidence) = params.evidence else {
            return Err(CoreError::InvalidConfig(
                "consensus evidence parameters are required",
            ));
        };
        if evidence.max_age_num_blocks <= 0
            || evidence.max_bytes < 0
            || evidence.max_bytes > block.max_bytes
        {
            return Err(CoreError::InvalidConfig(
                "consensus evidence limits are invalid",
            ));
        }
        let Some(evidence_duration) = evidence.max_age_duration else {
            return Err(CoreError::InvalidConfig(
                "consensus evidence duration is required",
            ));
        };
        if evidence_duration.seconds <= 0 || !(0..1_000_000_000).contains(&evidence_duration.nanos)
        {
            return Err(CoreError::InvalidConfig(
                "consensus evidence duration is invalid",
            ));
        }
        let Some(validator_params) = params.validator.as_ref() else {
            return Err(CoreError::InvalidConfig(
                "consensus validator parameters are required",
            ));
        };
        if validator_params.pub_key_types != ["ed25519"] {
            return Err(CoreError::InvalidConfig(
                "consensus validator key type must be exactly ed25519",
            ));
        }
        let Some(version) = params.version else {
            return Err(CoreError::InvalidConfig(
                "consensus application version is required",
            ));
        };
        if version.app != genesis.protocol_version {
            return Err(CoreError::InvalidConfig(
                "consensus and application protocol versions differ",
            ));
        }
        if params
            .abci
            .is_some_and(|abci| abci.vote_extensions_enable_height != 0)
        {
            return Err(CoreError::InvalidConfig(
                "vote extensions must remain disabled",
            ));
        }
        Ok(())
    }
}

struct Inner {
    core: ApplicationCore,
    runtime: tokio::runtime::Runtime,
    execution: Mutex<()>,
    config: AbciConfig,
    genesis: GenesisConfig,
    state_path: PathBuf,
    chain_context: Hash32,
    state_sync: StateSyncManager,
    initialized: AtomicBool,
    halted: AtomicBool,
}

#[derive(Clone)]
pub struct AbciApplication {
    inner: Arc<Inner>,
}

impl AbciApplication {
    pub fn open(
        state_path: PathBuf,
        genesis: GenesisConfig,
        config: AbciConfig,
    ) -> crate::Result<Self> {
        config.validate(&genesis)?;
        let chain_context = genesis.chain_context;
        if let Some(record) = read_safety_halt(&state_path)? {
            if record.chain_context != chain_context {
                return Err(SafetyHaltError::Corrupt(
                    "active halt journal belongs to another chain context",
                )
                .into());
            }
            return Err(CoreError::SafetyHaltActive {
                journal: safety_halt_journal_path(&state_path),
                record_hash: encode_hex(&record.record_hash()),
            });
        }
        let marker = read_active_state_marker(&state_path)?;
        if marker
            .as_ref()
            .is_some_and(|marker| marker.chain_context != chain_context)
        {
            return Err(CoreError::StateSync(
                "active state marker belongs to another chain context".to_owned(),
            ));
        }
        let active_path = match marker.as_ref() {
            Some(marker) => active_state_path(&state_path, &marker.snapshot_id)?,
            None => state_path.clone(),
        };
        if marker.is_some() {
            validate_active_state_path(&active_path)?;
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| CoreError::InvalidConfig("failed to create ABCI runtime"))?;
        let core = runtime.block_on(ApplicationCore::open(active_path.clone(), genesis.clone()))?;
        if let Some(marker) = marker.as_ref() {
            let summary = runtime.block_on(core.state_summary())?;
            validate_active_summary(marker, &summary, &genesis)?;
        }
        let initialized = runtime.block_on(core.info())?.last_block_height > 0;
        let state_sync = StateSyncManager::new(
            &active_path,
            &state_path,
            chain_context,
            config.state_sync.clone(),
        )?;
        Ok(Self {
            inner: Arc::new(Inner {
                core,
                runtime,
                execution: Mutex::new(()),
                config,
                genesis,
                state_path,
                chain_context,
                state_sync,
                initialized: AtomicBool::new(initialized),
                halted: AtomicBool::new(false),
            }),
        })
    }

    pub fn bind<A: ToSocketAddrs>(
        &self,
        address: A,
        read_buffer_bytes: usize,
    ) -> std::result::Result<Server<Self>, BindError> {
        if read_buffer_bytes == 0 {
            return Err(BindError::EmptyReadBuffer);
        }
        let addresses: Vec<SocketAddr> = address
            .to_socket_addrs()
            .map_err(BindError::Resolve)?
            .collect();
        if addresses.is_empty() {
            return Err(BindError::EmptyAddress);
        }
        if let Some(address) = addresses.iter().find(|address| !address.ip().is_loopback()) {
            return Err(BindError::NonLoopback(*address));
        }
        ServerBuilder::new(read_buffer_bytes)
            .bind(addresses.as_slice(), self.clone())
            .map_err(|error| BindError::Abci(Box::new(error)))
    }

    pub fn is_halted(&self) -> bool {
        self.inner.halted.load(Ordering::Acquire)
    }

    /// Export the current committed state into the configured State Sync repository.
    pub fn create_state_sync_snapshot(&self) -> crate::Result<Snapshot> {
        let _guard = self.execution_guard();
        let summary = self
            .inner
            .runtime
            .block_on(self.inner.core.state_summary())?;
        if summary.state_height == 0 {
            return Err(CoreError::StateSync(
                "cannot publish a height-zero state-sync snapshot".to_owned(),
            ));
        }
        if let Some(existing) = self.inner.state_sync.existing_snapshot(&summary)? {
            return Ok(existing);
        }
        let destination = self
            .inner
            .state_sync
            .snapshot_destination(summary.state_height)?;
        self.inner
            .runtime
            .block_on(self.inner.core.export_state_snapshot(destination.clone()))?;
        self.inner
            .state_sync
            .register_created_snapshot(&destination, &summary)
    }

    fn complete_state_sync(&self, incoming: CompletedIncomingSnapshot) -> crate::Result<()> {
        let chunk_paths = incoming.chunk_paths()?;
        let materialized = incoming.materialized_path();
        incoming
            .manifest
            .materialize_state_sync_snapshot(&chunk_paths, &materialized)?;
        let active_path =
            active_state_path(&self.inner.state_path, &incoming.manifest.snapshot_id)?;
        remove_orphan_active_state(&active_path)?;
        let replacement = self
            .inner
            .runtime
            .block_on(PersistentState::import_snapshot(
                materialized,
                active_path,
                self.inner.genesis.clone(),
            ))?;
        let summary = self.inner.runtime.block_on(replacement.summary())?;
        let marker = ActiveStateMarker {
            snapshot_id: incoming.manifest.snapshot_id,
            state_height: incoming.manifest.state_height,
            app_hash: incoming.manifest.app_hash,
            chain_context: incoming.manifest.chain_context,
        };
        validate_active_summary(&marker, &summary, &self.inner.genesis)?;
        persist_active_state_marker(&self.inner.state_path, &marker)?;
        if let Err(error) = self
            .inner
            .runtime
            .block_on(self.inner.core.replace_state(replacement))
        {
            self.halt(format!(
                "state-sync marker was published but state activation failed: {error}"
            ));
        }
        self.inner.initialized.store(true, Ordering::Release);
        incoming.finish();
        Ok(())
    }

    fn ensure_live(&self) {
        if self.is_halted() {
            panic!("BIT ABCI application is halted");
        }
    }

    fn is_initialized(&self) -> bool {
        self.inner.initialized.load(Ordering::Acquire)
    }

    fn ensure_initialized(&self) {
        self.ensure_live();
        if !self.is_initialized() {
            self.halt("consensus request received before InitChain");
        }
    }

    fn execution_guard(&self) -> MutexGuard<'_, ()> {
        self.ensure_live();
        self.inner
            .execution
            .lock()
            .unwrap_or_else(|_| self.halt("ABCI execution lock was poisoned"))
    }

    fn halt(&self, reason: impl Display) -> ! {
        self.inner.halted.store(true, Ordering::Release);
        panic!("BIT ABCI fatal error: {reason}");
    }

    fn init_chain_mismatch(&self, request: &RequestInitChain) -> Option<&'static str> {
        let expected = &self.inner.config.expected_init_chain;
        if request.time != expected.time {
            Some("time")
        } else if request.chain_id != expected.chain_id {
            Some("chain_id")
        } else if request.consensus_params != expected.consensus_params {
            Some("consensus_params")
        } else if request.validators != expected.validators {
            Some("validators")
        } else if request.app_state_bytes != expected.app_state_bytes {
            Some("app_state_bytes")
        } else if request.initial_height != expected.initial_height {
            Some("initial_height")
        } else {
            None
        }
    }

    fn query_rejection(code: QueryCode, log: &'static str) -> ResponseQuery {
        ResponseQuery {
            code: code as u32,
            log: log.to_owned(),
            codespace: CODESPACE.to_owned(),
            ..Default::default()
        }
    }

    fn map_tx_result(result: TxResult) -> ExecTxResult {
        ExecTxResult {
            code: result.code as u32,
            data: result.tx_id.map_or_else(Vec::new, |id| id.to_vec()).into(),
            log: result.log.to_owned(),
            codespace: CODESPACE.to_owned(),
            ..Default::default()
        }
    }

    fn map_finalize(&self, outcome: FinalizeOutcome) -> ResponseFinalizeBlock {
        let block_event = Event {
            r#type: "bit.block.v1".to_owned(),
            attributes: vec![
                EventAttribute {
                    key: "height".to_owned(),
                    value: outcome.height.to_string(),
                    index: true,
                },
                EventAttribute {
                    key: "execution_hash".to_owned(),
                    value: encode_hex(&outcome.artifacts.execution_hash),
                    index: true,
                },
                EventAttribute {
                    key: "compact_hash".to_owned(),
                    value: encode_hex(&outcome.artifacts.compact_hash),
                    index: true,
                },
                EventAttribute {
                    key: "compact_bytes".to_owned(),
                    value: outcome.artifacts.compact_block.len().to_string(),
                    index: false,
                },
            ],
        };
        ResponseFinalizeBlock {
            tx_results: outcome
                .transaction_results
                .into_iter()
                .map(Self::map_tx_result)
                .collect(),
            validator_updates: outcome
                .validator_updates
                .into_iter()
                .map(|update| ProtoValidatorUpdate {
                    pub_key: Some(tendermint_proto::v0_38::crypto::PublicKey {
                        sum: Some(public_key::Sum::Ed25519(update.consensus_pubkey.to_vec())),
                    }),
                    power: i64::try_from(update.power).unwrap_or_else(|_| {
                        self.halt("validator power does not fit CometBFT int64")
                    }),
                })
                .collect(),
            app_hash: outcome.app_hash.to_vec().into(),
            events: vec![block_event],
            ..Default::default()
        }
    }

    fn proof_ops(&self, proof: bit_state::QueryProof) -> ProofOps {
        if let Err(error) = proof.verify() {
            self.halt(format!(
                "generated ICS23 proof failed verification: {error}"
            ));
        }
        let mut ops = Vec::with_capacity(proof.proof.proofs.len());
        for commitment_proof in proof.proof.proofs {
            let key = match commitment_proof.proof.as_ref() {
                Some(Proof::Exist(value)) => value.key.clone(),
                Some(Proof::Nonexist(value)) => value.key.clone(),
                Some(Proof::Batch(_)) | Some(Proof::Compressed(_)) | None => {
                    self.halt("unsupported ICS23 proof shape produced by state storage")
                }
            };
            ops.push(ProofOp {
                r#type: PROOF_OP_TYPE.to_owned(),
                key,
                data: commitment_proof.encode_to_vec(),
            });
        }
        ProofOps { ops }
    }

    fn is_request_height_error(error: &CoreError) -> bool {
        matches!(
            error,
            CoreError::State(bit_state::Error::HeightMismatch { .. })
        )
    }
}

impl Application for AbciApplication {
    fn info(&self, _request: RequestInfo) -> ResponseInfo {
        let _guard = self.execution_guard();
        match self.inner.runtime.block_on(self.inner.core.info()) {
            Ok(info) => ResponseInfo {
                data: self.inner.config.application_name.clone(),
                version: self.inner.config.application_version.clone(),
                app_version: info.protocol_version,
                last_block_height: i64::try_from(info.last_block_height)
                    .unwrap_or_else(|_| self.halt("committed height exceeds i64")),
                last_block_app_hash: info.last_block_app_hash.to_vec().into(),
            },
            Err(error) => self.halt(format!("Info failed: {error}")),
        }
    }

    fn init_chain(&self, request: RequestInitChain) -> ResponseInitChain {
        self.ensure_live();
        if let Some(field) = self.init_chain_mismatch(&request) {
            self.halt(format!(
                "InitChain {field} differs from the configured genesis"
            ));
        }
        let _guard = self.execution_guard();
        let summary = match self.inner.runtime.block_on(self.inner.core.state_summary()) {
            Ok(summary) => summary,
            Err(error) => self.halt(format!("InitChain state lookup failed: {error}")),
        };
        if summary.state_height != 0 {
            self.halt("InitChain received after block execution began");
        }
        self.inner.initialized.store(true, Ordering::Release);
        ResponseInitChain {
            consensus_params: request.consensus_params,
            validators: request.validators,
            app_hash: summary.app_hash.to_vec().into(),
        }
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        self.ensure_live();
        if request.path != STATE_QUERY_PATH {
            return Self::query_rejection(QueryCode::UnsupportedPath, "unsupported query path");
        }
        if request.data.is_empty() {
            return Self::query_rejection(QueryCode::InvalidKey, "query key is empty");
        }
        let key = match std::str::from_utf8(&request.data) {
            Ok(key) => key,
            Err(_) => {
                return Self::query_rejection(QueryCode::InvalidKey, "query key is not UTF-8");
            }
        };
        let _guard = self.execution_guard();
        let proof = match self
            .inner
            .runtime
            .block_on(self.inner.core.query_latest_with_proof(key))
        {
            Ok(proof) => proof,
            Err(error) => self.halt(format!("Query failed: {error}")),
        };
        let height = i64::try_from(proof.storage_version)
            .unwrap_or_else(|_| self.halt("query height exceeds i64"));
        if request.height < 0 || (request.height != 0 && request.height != height) {
            return Self::query_rejection(
                QueryCode::UnsupportedHeight,
                "only the latest committed height is available",
            );
        }
        let value = proof.value.clone().unwrap_or_default();
        let proof_ops = request.prove.then(|| self.proof_ops(proof));
        ResponseQuery {
            code: QueryCode::Ok as u32,
            key: request.data,
            value: value.into(),
            proof_ops,
            height,
            codespace: CODESPACE.to_owned(),
            ..Default::default()
        }
    }

    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        self.ensure_initialized();
        let _guard = self.execution_guard();
        match self
            .inner
            .runtime
            .block_on(self.inner.core.check_tx(&request.tx))
        {
            Ok(result) => {
                let result = Self::map_tx_result(result);
                ResponseCheckTx {
                    code: result.code,
                    data: result.data,
                    log: result.log,
                    codespace: result.codespace,
                    ..Default::default()
                }
            }
            Err(error) => self.halt(format!("CheckTx failed: {error}")),
        }
    }

    fn prepare_proposal(&self, request: RequestPrepareProposal) -> ResponsePrepareProposal {
        self.ensure_initialized();
        let Ok(height) = u64::try_from(request.height) else {
            return ResponsePrepareProposal { txs: Vec::new() };
        };
        let Ok(max_tx_bytes) = u64::try_from(request.max_tx_bytes) else {
            return ResponsePrepareProposal { txs: Vec::new() };
        };
        let Ok(block_time_seconds) = block_time_seconds(request.time.as_ref()) else {
            return ResponsePrepareProposal { txs: Vec::new() };
        };
        let Ok(last_commit) = extended_last_commit(height, request.local_last_commit.as_ref())
        else {
            return ResponsePrepareProposal { txs: Vec::new() };
        };
        let Ok(next_validators_hash) = next_validators_hash(&request.next_validators_hash) else {
            return ResponsePrepareProposal { txs: Vec::new() };
        };
        let transactions = request.txs.into_iter().map(Vec::from).collect();
        let _guard = self.execution_guard();
        match self
            .inner
            .runtime
            .block_on(self.inner.core.prepare_proposal_at_with_commit(
                height,
                block_time_seconds,
                transactions,
                max_tx_bytes,
                last_commit.as_ref(),
                next_validators_hash,
            )) {
            Ok(proposal) => ResponsePrepareProposal {
                txs: proposal.transactions.into_iter().map(Into::into).collect(),
            },
            Err(error) if Self::is_request_height_error(&error) => {
                ResponsePrepareProposal { txs: Vec::new() }
            }
            Err(error) => self.halt(format!("PrepareProposal failed: {error}")),
        }
    }

    fn process_proposal(&self, request: RequestProcessProposal) -> ResponseProcessProposal {
        self.ensure_initialized();
        let reject = || ResponseProcessProposal {
            status: response_process_proposal::ProposalStatus::Reject as i32,
        };
        let Ok(height) = u64::try_from(request.height) else {
            return reject();
        };
        let Ok(block_time_seconds) = block_time_seconds(request.time.as_ref()) else {
            return reject();
        };
        let Ok(last_commit) = decided_last_commit(height, request.proposed_last_commit.as_ref())
        else {
            return reject();
        };
        let Ok(next_validators_hash) = next_validators_hash(&request.next_validators_hash) else {
            return reject();
        };
        let transactions: Vec<Vec<u8>> = request.txs.into_iter().map(Vec::from).collect();
        let _guard = self.execution_guard();
        match self
            .inner
            .runtime
            .block_on(self.inner.core.process_proposal_at_with_commit(
                height,
                block_time_seconds,
                &transactions,
                last_commit.as_ref(),
                next_validators_hash,
            )) {
            Ok(true) => ResponseProcessProposal {
                status: response_process_proposal::ProposalStatus::Accept as i32,
            },
            Ok(false) => reject(),
            Err(error) if Self::is_request_height_error(&error) => reject(),
            Err(error) => self.halt(format!("ProcessProposal failed: {error}")),
        }
    }

    fn extend_vote(&self, _request: RequestExtendVote) -> ResponseExtendVote {
        self.ensure_live();
        ResponseExtendVote {
            vote_extension: Vec::new().into(),
        }
    }

    fn verify_vote_extension(
        &self,
        request: RequestVerifyVoteExtension,
    ) -> ResponseVerifyVoteExtension {
        self.ensure_live();
        ResponseVerifyVoteExtension {
            status: if request.vote_extension.is_empty() {
                response_verify_vote_extension::VerifyStatus::Accept
            } else {
                response_verify_vote_extension::VerifyStatus::Reject
            } as i32,
        }
    }

    fn finalize_block(&self, request: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        self.ensure_initialized();
        let height = u64::try_from(request.height)
            .unwrap_or_else(|_| self.halt("FinalizeBlock height is not positive"));
        if height == 0 || request.hash.len() != 32 {
            self.halt("FinalizeBlock height or block hash is invalid");
        }
        let attempted_block_hash: Hash32 = request
            .hash
            .as_ref()
            .try_into()
            .expect("block hash length is checked");
        let block_time_seconds =
            block_time_seconds(request.time.as_ref()).unwrap_or_else(|error| self.halt(error));
        let last_commit = decided_last_commit(height, request.decided_last_commit.as_ref())
            .unwrap_or_else(|error| self.halt(error));
        let next_validators_hash = next_validators_hash(&request.next_validators_hash)
            .unwrap_or_else(|error| self.halt(error));
        let byzantine_evidence = normalize_byzantine_evidence(&request.misbehavior)
            .unwrap_or_else(|error| self.halt(error));
        let _guard = self.execution_guard();
        let committed = self
            .inner
            .runtime
            .block_on(self.inner.core.state_summary())
            .unwrap_or_else(|error| self.halt(format!("state summary lookup failed: {error}")));
        let block = BlockRequest {
            height,
            block_time_seconds,
            transactions: request.txs.into_iter().map(Vec::from).collect(),
            last_commit,
            byzantine_evidence: byzantine_evidence.clone(),
            next_validators_hash,
        };
        match self
            .inner
            .runtime
            .block_on(self.inner.core.finalize_block(block))
        {
            Ok(outcome) => self.map_finalize(outcome),
            Err(error @ CoreError::State(bit_state::Error::NoSafeValidatorSet)) => {
                let record = SafetyHaltRecord::no_safe_validator_set(
                    self.inner.chain_context,
                    committed.state_height,
                    committed.app_hash,
                    height,
                    attempted_block_hash,
                    block_time_seconds,
                    next_validators_hash,
                    byzantine_evidence,
                )
                .unwrap_or_else(|journal_error| {
                    self.halt(format!(
                        "FinalizeBlock failed: {error}; safety halt record construction failed: {journal_error}"
                    ))
                });
                let record_hash = encode_hex(&record.record_hash());
                crate::safety::persist_safety_halt(&self.inner.state_path, &record)
                    .unwrap_or_else(|journal_error| {
                        self.halt(format!(
                            "FinalizeBlock failed: {error}; safety halt journal persistence failed: {journal_error}"
                        ))
                    });
                self.halt(format!(
                    "FinalizeBlock failed: {error}; durable safety halt record {record_hash} written to {}",
                    safety_halt_journal_path(&self.inner.state_path).display()
                ))
            }
            Err(error) => self.halt(format!("FinalizeBlock failed: {error}")),
        }
    }

    fn commit(&self) -> ResponseCommit {
        self.ensure_initialized();
        let _guard = self.execution_guard();
        match self.inner.runtime.block_on(self.inner.core.commit()) {
            Ok(_) => ResponseCommit {
                retain_height: self.inner.config.retain_height,
            },
            Err(error) => self.halt(format!("Commit failed: {error}")),
        }
    }

    fn list_snapshots(&self) -> ResponseListSnapshots {
        self.ensure_live();
        let _guard = self.execution_guard();
        let snapshots = self.inner.state_sync.list_snapshots().unwrap_or_default();
        ResponseListSnapshots { snapshots }
    }

    fn offer_snapshot(&self, request: RequestOfferSnapshot) -> ResponseOfferSnapshot {
        self.ensure_live();
        let _guard = self.execution_guard();
        let summary = self.inner.runtime.block_on(self.inner.core.state_summary());
        let pristine_summary = match summary {
            Ok(summary) if !self.is_initialized() && summary.state_height == 0 => Some(summary),
            Ok(_) => None,
            Err(_) => {
                return ResponseOfferSnapshot {
                    result: response_offer_snapshot::Result::Abort as i32,
                };
            }
        };
        let result = self
            .inner
            .state_sync
            .offer(
                request.snapshot.as_ref(),
                &request.app_hash,
                pristine_summary.as_ref(),
            )
            .unwrap_or(response_offer_snapshot::Result::Abort);
        ResponseOfferSnapshot {
            result: result as i32,
        }
    }

    fn load_snapshot_chunk(&self, request: RequestLoadSnapshotChunk) -> ResponseLoadSnapshotChunk {
        self.ensure_live();
        let _guard = self.execution_guard();
        let chunk = self
            .inner
            .state_sync
            .load_chunk(request.height, request.format, request.chunk)
            .unwrap_or_default();
        ResponseLoadSnapshotChunk {
            chunk: chunk.into(),
        }
    }

    fn apply_snapshot_chunk(
        &self,
        request: RequestApplySnapshotChunk,
    ) -> ResponseApplySnapshotChunk {
        self.ensure_live();
        let _guard = self.execution_guard();
        match self
            .inner
            .state_sync
            .apply_chunk(request.index, &request.chunk, &request.sender)
        {
            Ok(ApplyDecision::Response {
                result,
                refetch_chunks,
                reject_senders,
            }) => ResponseApplySnapshotChunk {
                result: result as i32,
                refetch_chunks,
                reject_senders,
            },
            Ok(ApplyDecision::Complete(incoming)) => match self.complete_state_sync(*incoming) {
                Ok(()) => ResponseApplySnapshotChunk {
                    result: response_apply_snapshot_chunk::Result::Accept as i32,
                    refetch_chunks: Vec::new(),
                    reject_senders: Vec::new(),
                },
                Err(_) => ResponseApplySnapshotChunk {
                    result: response_apply_snapshot_chunk::Result::RejectSnapshot as i32,
                    refetch_chunks: Vec::new(),
                    reject_senders: reject_sender(&request.sender),
                },
            },
            Err(_) => ResponseApplySnapshotChunk {
                result: response_apply_snapshot_chunk::Result::Abort as i32,
                refetch_chunks: Vec::new(),
                reject_senders: Vec::new(),
            },
        }
    }
}

fn reject_sender(sender: &str) -> Vec<String> {
    (!sender.is_empty())
        .then(|| sender.to_owned())
        .into_iter()
        .collect()
}

fn remove_orphan_active_state(path: &Path) -> crate::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CoreError::StateSync(format!(
            "cannot inspect orphan state-sync database {}: {error}",
            path.display()
        ))),
        Ok(metadata) if metadata.file_type().is_symlink() => Err(CoreError::StateSync(format!(
            "orphan state-sync database is a symlink: {}",
            path.display()
        ))),
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path).map_err(|error| {
            CoreError::StateSync(format!(
                "cannot remove orphan state-sync database {}: {error}",
                path.display()
            ))
        }),
        Ok(_) => Err(CoreError::StateSync(format!(
            "orphan state-sync database is not a directory: {}",
            path.display()
        ))),
    }
}

fn block_time_seconds(
    timestamp: Option<&tendermint_proto::google::protobuf::Timestamp>,
) -> std::result::Result<u64, String> {
    let timestamp = timestamp.ok_or_else(|| "block time is missing".to_owned())?;
    if timestamp.seconds < 0 || !(0..1_000_000_000).contains(&timestamp.nanos) {
        return Err("block time is invalid".to_owned());
    }
    u64::try_from(timestamp.seconds).map_err(|_| "block time does not fit u64".to_owned())
}

fn normalize_byzantine_evidence(
    misbehavior: &[Misbehavior],
) -> std::result::Result<Vec<ByzantineEvidence>, String> {
    misbehavior
        .iter()
        .map(|item| {
            let kind = match MisbehaviorType::try_from(item.r#type) {
                Ok(MisbehaviorType::DuplicateVote) => ByzantineEvidenceKind::DuplicateVote,
                Ok(MisbehaviorType::LightClientAttack) => ByzantineEvidenceKind::LightClientAttack,
                Ok(MisbehaviorType::Unknown) | Err(_) => {
                    return Err("FinalizeBlock contains an unknown misbehavior type".to_owned());
                }
            };
            let validator = item
                .validator
                .as_ref()
                .ok_or_else(|| "FinalizeBlock misbehavior is missing its validator".to_owned())?;
            let validator_address = validator.address.as_ref().try_into().map_err(|_| {
                "FinalizeBlock misbehavior validator address must contain 20 bytes".to_owned()
            })?;
            let validator_power = u64::try_from(validator.power)
                .map_err(|_| "FinalizeBlock misbehavior validator power is negative".to_owned())?;
            if validator_power == 0 {
                return Err("FinalizeBlock misbehavior validator power must be positive".to_owned());
            }
            let infraction_height = u64::try_from(item.height)
                .map_err(|_| "FinalizeBlock misbehavior height is negative".to_owned())?;
            if infraction_height == 0 {
                return Err("FinalizeBlock misbehavior height must be positive".to_owned());
            }
            let time = item.time.as_ref().ok_or_else(|| {
                "FinalizeBlock misbehavior is missing its infraction time".to_owned()
            })?;
            if time.seconds < 0 || !(0..1_000_000_000).contains(&time.nanos) {
                return Err("FinalizeBlock misbehavior time is invalid".to_owned());
            }
            let infraction_time_seconds = u64::try_from(time.seconds)
                .map_err(|_| "FinalizeBlock misbehavior time does not fit u64".to_owned())?;
            let infraction_time_nanos = u32::try_from(time.nanos)
                .map_err(|_| "FinalizeBlock misbehavior nanos do not fit u32".to_owned())?;
            let total_voting_power = u64::try_from(item.total_voting_power).map_err(|_| {
                "FinalizeBlock misbehavior total voting power is negative".to_owned()
            })?;
            if total_voting_power == 0 {
                return Err(
                    "FinalizeBlock misbehavior total voting power must be positive".to_owned(),
                );
            }
            Ok(ByzantineEvidence {
                kind,
                validator_address,
                validator_power,
                infraction_height,
                infraction_time_seconds,
                infraction_time_nanos,
                total_voting_power,
            })
        })
        .collect()
}

fn next_validators_hash(bytes: &[u8]) -> std::result::Result<Hash32, String> {
    bytes
        .try_into()
        .map_err(|_| "next_validators_hash must contain exactly 32 bytes".to_owned())
}

fn decided_last_commit(
    height: u64,
    commit: Option<&CommitInfo>,
) -> std::result::Result<Option<LastCommit>, String> {
    let Some(commit) = commit else {
        return if height == 1 {
            Ok(None)
        } else {
            Err("previous commit is missing after height one".to_owned())
        };
    };
    if commit.round < 0 {
        return Err("previous commit round is negative".to_owned());
    }
    let votes = commit
        .votes
        .iter()
        .map(|vote| {
            let validator = vote
                .validator
                .as_ref()
                .ok_or_else(|| "previous commit vote has no validator".to_owned())?;
            commit_vote(&validator.address, validator.power, vote.block_id_flag)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    last_commit_for_height(height, votes)
}

fn extended_last_commit(
    height: u64,
    commit: Option<&ExtendedCommitInfo>,
) -> std::result::Result<Option<LastCommit>, String> {
    let Some(commit) = commit else {
        return if height == 1 {
            Ok(None)
        } else {
            Err("previous commit is missing after height one".to_owned())
        };
    };
    if commit.round < 0 {
        return Err("previous commit round is negative".to_owned());
    }
    let votes = commit
        .votes
        .iter()
        .map(|vote| {
            let validator = vote
                .validator
                .as_ref()
                .ok_or_else(|| "previous commit vote has no validator".to_owned())?;
            commit_vote(&validator.address, validator.power, vote.block_id_flag)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    last_commit_for_height(height, votes)
}

fn commit_vote(address: &[u8], power: i64, flag: i32) -> std::result::Result<CommitVote, String> {
    let consensus_address: [u8; COMETBFT_ADDRESS_BYTES] = address
        .try_into()
        .map_err(|_| "validator address must contain exactly 20 bytes".to_owned())?;
    let power = u64::try_from(power)
        .ok()
        .filter(|power| *power != 0)
        .ok_or_else(|| "validator power must be positive".to_owned())?;
    let flag = BlockIdFlag::try_from(flag)
        .map_err(|_| "previous commit contains an unknown block-id flag".to_owned())?;
    let signed = match flag {
        BlockIdFlag::Commit => true,
        BlockIdFlag::Absent | BlockIdFlag::Nil => false,
        BlockIdFlag::Unknown => {
            return Err("previous commit contains an unknown block-id flag".to_owned())
        }
    };
    Ok(CommitVote {
        consensus_address,
        power,
        signed,
    })
}

fn last_commit_for_height(
    height: u64,
    votes: Vec<CommitVote>,
) -> std::result::Result<Option<LastCommit>, String> {
    if height == 1 {
        if votes.is_empty() {
            Ok(None)
        } else {
            Err("height one cannot contain previous commit votes".to_owned())
        }
    } else {
        Ok(Some(LastCommit { votes }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bit_emission::{FeePolicy, GenesisAllocation};
    use bit_staking::{
        consensus_address, StakingBook, StakingParameters, RECOVERY_RECEIPT_BYTES,
        TESTNET_MIN_SELF_BOND_ATOMIC,
    };
    use bit_types::{position_id, validator_id, Amount, MonetaryPolicy};
    use decaf377::Fq;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        panic::{catch_unwind, AssertUnwindSafe},
        thread,
    };
    use tempfile::TempDir;
    use tendermint_abci::ClientBuilder;
    use tendermint_proto::{
        google::protobuf::{Duration, Timestamp},
        v0_38::{
            abci::{
                request, response, CommitInfo, Request, Response, Validator, ValidatorUpdate,
                VoteInfo,
            },
            crypto::PublicKey,
            types::{
                AbciParams, BlockIdFlag, BlockParams, ConsensusParams, EvidenceParams,
                ValidatorParams, VersionParams,
            },
        },
    };

    fn genesis(max_block_bytes: u64) -> GenesisConfig {
        let mut native_asset_id = [0; 32];
        native_asset_id.copy_from_slice(&Fq::from(1u64).to_bytes());
        let monetary_policy = MonetaryPolicy::reference_testnet();
        let chain_context = [1; 32];
        let operator = [6; 32];
        let validator_id = validator_id(&chain_context, &operator);
        let consensus_pubkey = [7; 32];
        let owner = [8; 32];
        let position_id = position_id(&chain_context, &owner);
        let principal = Amount::new(TESTNET_MIN_SELF_BOND_ATOMIC).unwrap();
        let mut genesis_staking =
            StakingBook::new(chain_context, StakingParameters::reference_testnet()).unwrap();
        genesis_staking
            .register_validator(validator_id, operator, consensus_pubkey, 500)
            .unwrap();
        genesis_staking
            .open_pending_delegation(
                0,
                0,
                position_id,
                owner,
                validator_id,
                principal,
                Amount::ZERO,
                true,
                vec![9; RECOVERY_RECEIPT_BYTES],
            )
            .unwrap();
        genesis_staking.activate_pending(&position_id, 1).unwrap();
        assert_eq!(
            genesis_staking.apply_validator_set().unwrap()[0].power,
            1_000
        );
        GenesisConfig {
            chain_context,
            native_asset_id,
            protocol_version: 1,
            max_block_bytes,
            max_tx_lifetime_blocks: 20,
            max_envelope_bytes: 65_536,
            anchor_retention_blocks: 8,
            genesis_allocation: GenesisAllocation {
                shielded: Amount::ZERO,
                stake: principal,
                pending_delegation: Amount::ZERO,
                exits: Amount::ZERO,
                commission: Amount::ZERO,
                fee_reserve: Amount::ZERO,
                unclaimed_genesis: Amount::new(
                    monetary_policy.genesis_supply.value() - principal.value(),
                )
                .unwrap(),
            },
            fee_policy: FeePolicy::reference_testnet(),
            monetary_policy,
            genesis_staking,
            genesis_commitments: Vec::new(),
            genesis_execution_hash: [2; 32],
            genesis_compact_hash: [3; 32],
        }
    }

    fn init_chain(max_block_bytes: i64) -> RequestInitChain {
        RequestInitChain {
            time: Some(Timestamp {
                seconds: 1_800_000_000,
                nanos: 0,
            }),
            chain_id: "bit-test-cap1024-1".to_owned(),
            consensus_params: Some(ConsensusParams {
                block: Some(BlockParams {
                    max_bytes: max_block_bytes,
                    max_gas: -1,
                }),
                evidence: Some(EvidenceParams {
                    max_age_num_blocks: 10_000,
                    max_age_duration: Some(Duration {
                        seconds: 86_400,
                        nanos: 0,
                    }),
                    max_bytes: 1024,
                }),
                validator: Some(ValidatorParams {
                    pub_key_types: vec!["ed25519".to_owned()],
                }),
                version: Some(VersionParams { app: 1 }),
                abci: Some(AbciParams {
                    vote_extensions_enable_height: 0,
                }),
            }),
            validators: vec![ValidatorUpdate {
                pub_key: Some(PublicKey {
                    sum: Some(public_key::Sum::Ed25519(vec![7; 32])),
                }),
                power: 1_000,
            }],
            app_state_bytes: vec![0xa1, 0x00, 0x01].into(),
            initial_height: 1,
        }
    }

    fn application(dir: &TempDir, max_block_bytes: u64) -> AbciApplication {
        let expected_init_chain = init_chain(max_block_bytes as i64);
        AbciApplication::open(
            dir.path().to_path_buf(),
            genesis(max_block_bytes),
            AbciConfig {
                application_name: "bit-app".to_owned(),
                application_version: env!("CARGO_PKG_VERSION").to_owned(),
                expected_init_chain,
                retain_height: 0,
                state_sync: None,
            },
        )
        .unwrap()
    }

    fn state_sync_application(
        state_path: PathBuf,
        snapshot_directory: PathBuf,
        max_block_bytes: u64,
    ) -> AbciApplication {
        AbciApplication::open(
            state_path,
            genesis(max_block_bytes),
            AbciConfig {
                application_name: "bit-app".to_owned(),
                application_version: env!("CARGO_PKG_VERSION").to_owned(),
                expected_init_chain: init_chain(max_block_bytes as i64),
                retain_height: 0,
                state_sync: Some(StateSyncConfig {
                    snapshot_directory,
                    keep_recent: 2,
                }),
            },
        )
        .unwrap()
    }

    fn genesis_next_validators_hash() -> Vec<u8> {
        genesis(1_000_000)
            .genesis_staking
            .effective_validator_set()
            .unwrap()
            .comet_hash()
            .to_vec()
    }

    #[test]
    fn config_and_init_chain_are_strict() {
        let dir = TempDir::new().unwrap();
        let app = application(&dir, 1_000_000);
        let expected = init_chain(1_000_000);
        assert_eq!(app.init_chain_mismatch(&expected), None);
        let mut changed = expected.clone();
        changed.chain_id.push_str("-other");
        assert_eq!(app.init_chain_mismatch(&changed), Some("chain_id"));

        let response = Application::init_chain(&app, expected.clone());
        assert_eq!(response.consensus_params, expected.consensus_params);
        assert_eq!(response.validators, expected.validators);
        assert_eq!(response.app_hash.len(), 32);
        let bound = app.bind("127.0.0.1:0", 1024).unwrap();
        assert!(bound.local_addr().starts_with("127.0.0.1:"));
        drop(bound);
        assert!(matches!(
            app.bind("0.0.0.0:0", 1024),
            Err(BindError::NonLoopback(_))
        ));

        let mismatch_dir = TempDir::new().unwrap();
        let mut mismatched_init = init_chain(1_000_000);
        mismatched_init.validators[0].power += 1;
        assert!(matches!(
            AbciApplication::open(
                mismatch_dir.path().to_path_buf(),
                genesis(1_000_000),
                AbciConfig {
                    application_name: "bit-app".to_owned(),
                    application_version: "0.1.0".to_owned(),
                    expected_init_chain: mismatched_init,
                    retain_height: 0,
                    state_sync: None,
                },
            ),
            Err(CoreError::InvalidConfig(_))
        ));

        let bad_dir = TempDir::new().unwrap();
        let mut bad_init = init_chain(999_999);
        bad_init
            .consensus_params
            .as_mut()
            .unwrap()
            .abci
            .as_mut()
            .unwrap()
            .vote_extensions_enable_height = 2;
        let result = AbciApplication::open(
            bad_dir.path().to_path_buf(),
            genesis(999_999),
            AbciConfig {
                application_name: "bit-app".to_owned(),
                application_version: "0.1.0".to_owned(),
                expected_init_chain: bad_init,
                retain_height: 0,
                state_sync: None,
            },
        );
        assert!(matches!(result, Err(CoreError::InvalidConfig(_))));
    }

    #[test]
    fn v038_mapping_covers_lifecycle_queries_votes_and_snapshots() {
        let dir = TempDir::new().unwrap();
        let app = application(&dir, 1_000_000);
        Application::init_chain(&app, init_chain(1_000_000));
        let info = Application::info(&app, RequestInfo::default());
        assert_eq!(info.data, "bit-app");
        assert_eq!(info.app_version, 1);
        assert_eq!(info.last_block_height, 0);

        let checked = Application::check_tx(
            &app,
            RequestCheckTx {
                tx: vec![0xff].into(),
                ..Default::default()
            },
        );
        assert_eq!(checked.code, 1);

        let prepared = Application::prepare_proposal(
            &app,
            RequestPrepareProposal {
                height: 1,
                max_tx_bytes: 1_000_000,
                txs: vec![vec![0xff].into()],
                time: Some(Timestamp {
                    seconds: 1_800_000_001,
                    nanos: 0,
                }),
                next_validators_hash: genesis_next_validators_hash().into(),
                ..Default::default()
            },
        );
        assert!(prepared.txs.is_empty());
        let processed = Application::process_proposal(
            &app,
            RequestProcessProposal {
                height: 1,
                txs: vec![vec![0xff].into()],
                time: Some(Timestamp {
                    seconds: 1_800_000_001,
                    nanos: 0,
                }),
                next_validators_hash: genesis_next_validators_hash().into(),
                ..Default::default()
            },
        );
        assert_eq!(
            processed.status,
            response_process_proposal::ProposalStatus::Reject as i32
        );

        let finalized = Application::finalize_block(
            &app,
            RequestFinalizeBlock {
                hash: vec![9; 32].into(),
                height: 1,
                time: Some(Timestamp {
                    seconds: 1_800_000_001,
                    nanos: 0,
                }),
                next_validators_hash: genesis_next_validators_hash().into(),
                ..Default::default()
            },
        );
        assert_eq!(finalized.app_hash.len(), 32);
        assert!(finalized.tx_results.is_empty());
        assert_eq!(finalized.events.len(), 1);
        assert_eq!(finalized.events[0].r#type, "bit.block.v1");
        let execution_hash = finalized.events[0]
            .attributes
            .iter()
            .find(|attribute| attribute.key == "execution_hash")
            .unwrap()
            .value
            .clone();
        let compact_hash = finalized.events[0]
            .attributes
            .iter()
            .find(|attribute| attribute.key == "compact_hash")
            .unwrap()
            .value
            .clone();
        assert_eq!(execution_hash.len(), 64);
        assert_eq!(compact_hash.len(), 64);
        assert_eq!(Application::commit(&app).retain_height, 0);

        assert_eq!(
            app.inner
                .runtime
                .block_on(app.inner.core.state_summary())
                .unwrap()
                .block_time_seconds,
            1_800_000_001
        );

        let query = Application::query(
            &app,
            RequestQuery {
                data: b"meta/height".to_vec().into(),
                path: STATE_QUERY_PATH.to_owned(),
                height: 1,
                prove: true,
            },
        );
        assert_eq!(query.code, QueryCode::Ok as u32);
        assert_eq!(query.height, 1);
        assert_eq!(query.value.len(), 8);
        let ops = query.proof_ops.unwrap().ops;
        assert!(!ops.is_empty());
        for op in ops {
            assert_eq!(op.r#type, PROOF_OP_TYPE);
            ics23::CommitmentProof::decode(op.data.as_slice()).unwrap();
        }
        for (key, expected) in [
            ("execution/block/00000000000000000001", execution_hash),
            ("compact/hash/00000000000000000001", compact_hash),
        ] {
            let query = Application::query(
                &app,
                RequestQuery {
                    data: key.as_bytes().to_vec().into(),
                    path: STATE_QUERY_PATH.to_owned(),
                    height: 1,
                    prove: true,
                },
            );
            assert_eq!(query.code, QueryCode::Ok as u32);
            assert_eq!(hex::encode(query.value), expected);
            assert!(query.proof_ops.is_some());
        }

        assert!(Application::extend_vote(&app, RequestExtendVote::default())
            .vote_extension
            .is_empty());
        assert_eq!(
            Application::verify_vote_extension(&app, RequestVerifyVoteExtension::default()).status,
            response_verify_vote_extension::VerifyStatus::Accept as i32
        );
        assert_eq!(
            Application::verify_vote_extension(
                &app,
                RequestVerifyVoteExtension {
                    vote_extension: vec![1].into(),
                    ..Default::default()
                }
            )
            .status,
            response_verify_vote_extension::VerifyStatus::Reject as i32
        );
        assert!(Application::list_snapshots(&app).snapshots.is_empty());
        assert_eq!(
            Application::offer_snapshot(&app, RequestOfferSnapshot::default()).result,
            response_offer_snapshot::Result::RejectFormat as i32
        );
        assert_eq!(
            Application::apply_snapshot_chunk(&app, RequestApplySnapshotChunk::default()).result,
            response_apply_snapshot_chunk::Result::Abort as i32
        );
    }

    #[test]
    fn state_sync_restores_unordered_chunks_refetches_corruption_and_restarts() {
        let root = TempDir::new().unwrap();
        let source = state_sync_application(
            root.path().join("source-state"),
            root.path().join("source-snapshots"),
            1_000_000,
        );
        Application::init_chain(&source, init_chain(1_000_000));
        let finalized = Application::finalize_block(
            &source,
            RequestFinalizeBlock {
                hash: vec![9; 32].into(),
                height: 1,
                time: Some(Timestamp {
                    seconds: 1_800_000_001,
                    nanos: 0,
                }),
                next_validators_hash: genesis_next_validators_hash().into(),
                ..Default::default()
            },
        );
        Application::commit(&source);
        let expected_app_hash = finalized.app_hash.to_vec();

        let snapshot = source.create_state_sync_snapshot().unwrap();
        assert_eq!(snapshot.height, 1);
        assert_eq!(snapshot.format, crate::STATE_SYNC_SNAPSHOT_FORMAT);
        assert!(snapshot.chunks >= 2);
        assert_eq!(source.create_state_sync_snapshot().unwrap(), snapshot);
        assert_eq!(
            Application::list_snapshots(&source).snapshots,
            vec![snapshot.clone()]
        );
        let chunks = (0..snapshot.chunks)
            .map(|index| {
                Application::load_snapshot_chunk(
                    &source,
                    RequestLoadSnapshotChunk {
                        height: snapshot.height,
                        format: snapshot.format,
                        chunk: index,
                    },
                )
                .chunk
                .to_vec()
            })
            .collect::<Vec<_>>();
        assert!(chunks.iter().all(|chunk| !chunk.is_empty()));

        let target_state = root.path().join("target-state");
        let target_snapshots = root.path().join("target-snapshots");
        let target =
            state_sync_application(target_state.clone(), target_snapshots.clone(), 1_000_000);
        let mut unsupported = snapshot.clone();
        unsupported.format += 1;
        assert_eq!(
            Application::offer_snapshot(
                &target,
                RequestOfferSnapshot {
                    snapshot: Some(unsupported),
                    app_hash: expected_app_hash.clone().into(),
                },
            )
            .result,
            response_offer_snapshot::Result::RejectFormat as i32
        );
        let mut excessive = snapshot.clone();
        excessive.chunks = 100_001;
        let mut excessive_metadata = excessive.metadata.to_vec();
        excessive_metadata[28..32].copy_from_slice(&100_001u32.to_be_bytes());
        excessive.metadata = excessive_metadata.into();
        assert_eq!(
            Application::offer_snapshot(
                &target,
                RequestOfferSnapshot {
                    snapshot: Some(excessive),
                    app_hash: expected_app_hash.clone().into(),
                },
            )
            .result,
            response_offer_snapshot::Result::Reject as i32
        );
        let mut wrong_app_hash = expected_app_hash.clone();
        wrong_app_hash[0] ^= 1;
        assert_eq!(
            Application::offer_snapshot(
                &target,
                RequestOfferSnapshot {
                    snapshot: Some(snapshot.clone()),
                    app_hash: wrong_app_hash.into(),
                },
            )
            .result,
            response_offer_snapshot::Result::Reject as i32
        );
        assert_eq!(
            Application::offer_snapshot(
                &source,
                RequestOfferSnapshot {
                    snapshot: Some(snapshot.clone()),
                    app_hash: expected_app_hash.clone().into(),
                },
            )
            .result,
            response_offer_snapshot::Result::Abort as i32
        );
        let offer = Application::offer_snapshot(
            &target,
            RequestOfferSnapshot {
                snapshot: Some(snapshot.clone()),
                app_hash: expected_app_hash.clone().into(),
            },
        );
        assert_eq!(offer.result, response_offer_snapshot::Result::Accept as i32);

        let manifest_first = Application::apply_snapshot_chunk(
            &target,
            RequestApplySnapshotChunk {
                index: 0,
                chunk: chunks[0].clone().into(),
                sender: "manifest-peer".to_owned(),
            },
        );
        assert_eq!(
            manifest_first.result,
            response_apply_snapshot_chunk::Result::Accept as i32
        );
        let mut corrupt = chunks[1].clone();
        corrupt[0] ^= 1;
        let incremental_corruption = Application::apply_snapshot_chunk(
            &target,
            RequestApplySnapshotChunk {
                index: 1,
                chunk: corrupt.clone().into(),
                sender: "bad-peer".to_owned(),
            },
        );
        assert_eq!(
            incremental_corruption.result,
            response_apply_snapshot_chunk::Result::Accept as i32
        );
        assert_eq!(incremental_corruption.refetch_chunks, vec![1]);
        assert_eq!(incremental_corruption.reject_senders, vec!["bad-peer"]);
        assert_eq!(
            Application::offer_snapshot(
                &target,
                RequestOfferSnapshot {
                    snapshot: Some(snapshot.clone()),
                    app_hash: expected_app_hash.clone().into(),
                },
            )
            .result,
            response_offer_snapshot::Result::Accept as i32
        );
        let early = Application::apply_snapshot_chunk(
            &target,
            RequestApplySnapshotChunk {
                index: 1,
                chunk: corrupt.into(),
                sender: "bad-peer".to_owned(),
            },
        );
        assert_eq!(
            early.result,
            response_apply_snapshot_chunk::Result::Accept as i32
        );
        for index in (2..snapshot.chunks).rev() {
            let response = Application::apply_snapshot_chunk(
                &target,
                RequestApplySnapshotChunk {
                    index,
                    chunk: chunks[usize::try_from(index).unwrap()].clone().into(),
                    sender: "good-peer".to_owned(),
                },
            );
            assert_eq!(
                response.result,
                response_apply_snapshot_chunk::Result::Accept as i32
            );
        }
        let manifest_response = Application::apply_snapshot_chunk(
            &target,
            RequestApplySnapshotChunk {
                index: 0,
                chunk: chunks[0].clone().into(),
                sender: "manifest-peer".to_owned(),
            },
        );
        assert_eq!(
            manifest_response.result,
            response_apply_snapshot_chunk::Result::Accept as i32
        );
        assert_eq!(manifest_response.refetch_chunks, vec![1]);
        assert_eq!(manifest_response.reject_senders, vec!["bad-peer"]);

        let completed = Application::apply_snapshot_chunk(
            &target,
            RequestApplySnapshotChunk {
                index: 1,
                chunk: chunks[1].clone().into(),
                sender: "good-peer".to_owned(),
            },
        );
        assert_eq!(
            completed.result,
            response_apply_snapshot_chunk::Result::Accept as i32
        );
        assert!(completed.refetch_chunks.is_empty());
        assert_eq!(
            Application::info(&target, RequestInfo::default()).last_block_height,
            1
        );
        let query = Application::query(
            &target,
            RequestQuery {
                data: b"meta/height".to_vec().into(),
                path: STATE_QUERY_PATH.to_owned(),
                height: 1,
                prove: true,
            },
        );
        assert_eq!(query.code, QueryCode::Ok as u32);
        assert_eq!(query.value.as_ref(), 1u64.to_be_bytes());
        query.proof_ops.unwrap().ops.iter().for_each(|proof| {
            ics23::CommitmentProof::decode(proof.data.as_slice()).unwrap();
        });
        assert_eq!(
            Application::offer_snapshot(
                &target,
                RequestOfferSnapshot {
                    snapshot: Some(snapshot),
                    app_hash: expected_app_hash.into(),
                },
            )
            .result,
            response_offer_snapshot::Result::Abort as i32
        );

        drop(target);
        let marker = root.path().join("target-state.active-state-v1");
        let temporary_marker = root.path().join("target-state.active-state-v1.tmp");
        std::fs::rename(&marker, &temporary_marker).unwrap();
        let reopened =
            state_sync_application(target_state.clone(), target_snapshots.clone(), 1_000_000);
        assert_eq!(
            Application::info(&reopened, RequestInfo::default()).last_block_height,
            1
        );
        assert!(marker.is_file());
        assert!(!temporary_marker.exists());
        drop(reopened);

        let mut marker_bytes = std::fs::read(&marker).unwrap();
        let last_marker_byte = marker_bytes.len() - 1;
        marker_bytes[last_marker_byte] ^= 1;
        std::fs::write(&marker, marker_bytes).unwrap();
        let corrupt_reopen = AbciApplication::open(
            target_state,
            genesis(1_000_000),
            AbciConfig {
                application_name: "bit-app".to_owned(),
                application_version: env!("CARGO_PKG_VERSION").to_owned(),
                expected_init_chain: init_chain(1_000_000),
                retain_height: 0,
                state_sync: Some(StateSyncConfig {
                    snapshot_directory: target_snapshots,
                    keep_recent: 2,
                }),
            },
        );
        assert!(matches!(corrupt_reopen, Err(CoreError::StateSync(_))));
    }

    #[test]
    fn block_timestamp_validation_rejects_missing_and_malformed_values() {
        assert_eq!(
            block_time_seconds(None),
            Err("block time is missing".to_owned())
        );
        assert_eq!(
            block_time_seconds(Some(&Timestamp {
                seconds: -1,
                nanos: 0,
            })),
            Err("block time is invalid".to_owned())
        );
        assert_eq!(
            block_time_seconds(Some(&Timestamp {
                seconds: 1,
                nanos: 1_000_000_000,
            })),
            Err("block time is invalid".to_owned())
        );
        assert_eq!(
            block_time_seconds(Some(&Timestamp {
                seconds: 42,
                nanos: 999_999_999,
            })),
            Ok(42)
        );
    }

    #[test]
    fn byzantine_evidence_normalization_is_strict() {
        let valid = Misbehavior {
            r#type: MisbehaviorType::DuplicateVote as i32,
            validator: Some(Validator {
                address: vec![7; COMETBFT_ADDRESS_BYTES].into(),
                power: 11,
            }),
            height: 9,
            time: Some(Timestamp {
                seconds: 42,
                nanos: 123,
            }),
            total_voting_power: 31,
        };
        let normalized = normalize_byzantine_evidence(std::slice::from_ref(&valid)).unwrap();
        assert_eq!(normalized.len(), 1);
        assert_eq!(
            normalized[0],
            ByzantineEvidence {
                kind: ByzantineEvidenceKind::DuplicateVote,
                validator_address: [7; COMETBFT_ADDRESS_BYTES],
                validator_power: 11,
                infraction_height: 9,
                infraction_time_seconds: 42,
                infraction_time_nanos: 123,
                total_voting_power: 31,
            }
        );

        let mut malformed = valid.clone();
        malformed.r#type = MisbehaviorType::Unknown as i32;
        assert!(normalize_byzantine_evidence(&[malformed]).is_err());
        malformed = valid.clone();
        malformed.validator.as_mut().unwrap().address = vec![7; 19].into();
        assert!(normalize_byzantine_evidence(&[malformed]).is_err());
        malformed = valid.clone();
        malformed.validator.as_mut().unwrap().power = 0;
        assert!(normalize_byzantine_evidence(&[malformed]).is_err());
        malformed = valid.clone();
        malformed.height = 0;
        assert!(normalize_byzantine_evidence(&[malformed]).is_err());
        malformed = valid.clone();
        malformed.time.as_mut().unwrap().nanos = 1_000_000_000;
        assert!(normalize_byzantine_evidence(&[malformed]).is_err());
        malformed = valid;
        malformed.total_voting_power = -1;
        assert!(normalize_byzantine_evidence(&[malformed]).is_err());
    }

    #[test]
    fn unsafe_validator_removal_writes_restart_lock_and_replay_halts_again() {
        let dir = TempDir::new().unwrap();
        let state_path = dir.path().to_path_buf();
        let app = application(&dir, 1_000_000);
        Application::init_chain(&app, init_chain(1_000_000));
        let validators_hash = genesis_next_validators_hash();
        Application::finalize_block(
            &app,
            RequestFinalizeBlock {
                hash: vec![9; 32].into(),
                height: 1,
                time: Some(Timestamp {
                    seconds: 1_800_000_001,
                    nanos: 0,
                }),
                next_validators_hash: validators_hash.clone().into(),
                ..Default::default()
            },
        );
        Application::commit(&app);
        let committed = app
            .inner
            .runtime
            .block_on(app.inner.core.state_summary())
            .unwrap();

        let evidence = Misbehavior {
            r#type: MisbehaviorType::DuplicateVote as i32,
            validator: Some(Validator {
                address: consensus_address(&[7; 32]).to_vec().into(),
                power: 1_000,
            }),
            height: 1,
            time: Some(Timestamp {
                seconds: 1_800_000_001,
                nanos: 0,
            }),
            total_voting_power: 1_000,
        };
        let unsafe_request = RequestFinalizeBlock {
            hash: vec![10; 32].into(),
            height: 2,
            time: Some(Timestamp {
                seconds: 1_800_000_002,
                nanos: 0,
            }),
            decided_last_commit: Some(CommitInfo {
                round: 0,
                votes: vec![VoteInfo {
                    validator: Some(Validator {
                        address: consensus_address(&[7; 32]).to_vec().into(),
                        power: 1_000,
                    }),
                    block_id_flag: BlockIdFlag::Commit as i32,
                }],
            }),
            misbehavior: vec![evidence],
            next_validators_hash: validators_hash.into(),
            ..Default::default()
        };
        assert!(catch_unwind(AssertUnwindSafe(|| {
            Application::finalize_block(&app, unsafe_request.clone())
        }))
        .is_err());
        assert!(app.is_halted());
        assert_eq!(
            app.inner
                .runtime
                .block_on(app.inner.core.state_summary())
                .unwrap()
                .state_height,
            1
        );

        let record = read_safety_halt(&state_path).unwrap().unwrap();
        assert_eq!(record.committed_height, 1);
        assert_eq!(record.committed_app_hash, committed.app_hash);
        assert_eq!(record.attempted_height, 2);
        assert_eq!(record.attempted_block_hash, [10; 32]);
        assert_eq!(record.evidence.len(), 1);
        let record_hash = record.record_hash();

        assert!(matches!(
            AbciApplication::open(
                state_path.clone(),
                genesis(1_000_000),
                AbciConfig {
                    application_name: "bit-app".to_owned(),
                    application_version: env!("CARGO_PKG_VERSION").to_owned(),
                    expected_init_chain: init_chain(1_000_000),
                    retain_height: 0,
                    state_sync: None,
                },
            ),
            Err(CoreError::SafetyHaltActive { .. })
        ));

        let archive = crate::acknowledge_safety_halt(&state_path, record_hash).unwrap();
        assert!(archive.is_file());
        drop(app);

        let reopened = AbciApplication::open(
            state_path.clone(),
            genesis(1_000_000),
            AbciConfig {
                application_name: "bit-app".to_owned(),
                application_version: env!("CARGO_PKG_VERSION").to_owned(),
                expected_init_chain: init_chain(1_000_000),
                retain_height: 0,
                state_sync: None,
            },
        )
        .unwrap();
        assert_eq!(
            Application::info(&reopened, RequestInfo::default()).last_block_height,
            1
        );
        assert!(catch_unwind(AssertUnwindSafe(|| {
            Application::finalize_block(&reopened, unsafe_request)
        }))
        .is_err());
        assert_eq!(
            read_safety_halt(&state_path)
                .unwrap()
                .unwrap()
                .record_hash(),
            record_hash
        );
    }

    #[test]
    fn decided_commit_decoding_is_strict_and_preserves_commit_flags() {
        assert_eq!(next_validators_hash(&[9; 32]), Ok([9; 32]));
        assert!(next_validators_hash(&[9; 31]).is_err());
        assert!(decided_last_commit(1, None).unwrap().is_none());
        assert!(decided_last_commit(2, None).is_err());

        let valid = CommitInfo {
            round: 0,
            votes: vec![
                VoteInfo {
                    validator: Some(Validator {
                        address: vec![7; COMETBFT_ADDRESS_BYTES].into(),
                        power: 11,
                    }),
                    block_id_flag: BlockIdFlag::Commit as i32,
                },
                VoteInfo {
                    validator: Some(Validator {
                        address: vec![8; COMETBFT_ADDRESS_BYTES].into(),
                        power: 13,
                    }),
                    block_id_flag: BlockIdFlag::Nil as i32,
                },
            ],
        };
        let decoded = decided_last_commit(2, Some(&valid)).unwrap().unwrap();
        assert_eq!(decoded.votes.len(), 2);
        assert!(decoded.votes[0].signed);
        assert!(!decoded.votes[1].signed);
        assert_eq!(decoded.votes[0].power, 11);

        let mut malformed = valid.clone();
        malformed.votes[0].validator.as_mut().unwrap().address = vec![0; 19].into();
        assert!(decided_last_commit(2, Some(&malformed)).is_err());
        malformed = valid.clone();
        malformed.votes[0].validator.as_mut().unwrap().power = 0;
        assert!(decided_last_commit(2, Some(&malformed)).is_err());
        malformed = valid;
        malformed.votes[0].block_id_flag = BlockIdFlag::Unknown as i32;
        assert!(decided_last_commit(2, Some(&malformed)).is_err());
    }

    #[test]
    fn v038_socket_roundtrip_commits_and_returns_proof() {
        let dir = TempDir::new().unwrap();
        let app = application(&dir, 1_000_000);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_app = app.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for _ in 0..6 {
                let request: Request = read_message(&mut stream);
                let value = match request.value.unwrap() {
                    request::Value::Info(request) => {
                        response::Value::Info(Application::info(&server_app, request))
                    }
                    request::Value::InitChain(request) => {
                        response::Value::InitChain(Application::init_chain(&server_app, request))
                    }
                    request::Value::CheckTx(request) => {
                        response::Value::CheckTx(Application::check_tx(&server_app, request))
                    }
                    request::Value::FinalizeBlock(request) => response::Value::FinalizeBlock(
                        Application::finalize_block(&server_app, request),
                    ),
                    request::Value::Commit(_) => {
                        response::Value::Commit(Application::commit(&server_app))
                    }
                    request::Value::Query(request) => {
                        response::Value::Query(Application::query(&server_app, request))
                    }
                    _ => panic!("unexpected socket test request"),
                };
                write_message(&mut stream, &Response { value: Some(value) });
            }
        });

        let mut client = ClientBuilder::default().connect(address).unwrap();
        assert_eq!(client.info(RequestInfo::default()).unwrap().app_version, 1);
        assert_eq!(
            client
                .init_chain(init_chain(1_000_000))
                .unwrap()
                .app_hash
                .len(),
            32
        );
        assert_eq!(
            client
                .check_tx(RequestCheckTx {
                    tx: vec![0xff].into(),
                    ..Default::default()
                })
                .unwrap()
                .code,
            1
        );
        assert_eq!(
            client
                .finalize_block(RequestFinalizeBlock {
                    hash: vec![9; 32].into(),
                    height: 1,
                    time: Some(Timestamp {
                        seconds: 1_800_000_001,
                        nanos: 0,
                    }),
                    next_validators_hash: genesis_next_validators_hash().into(),
                    ..Default::default()
                })
                .unwrap()
                .app_hash
                .len(),
            32
        );
        assert_eq!(client.commit().unwrap().retain_height, 0);
        let query = client
            .query(RequestQuery {
                data: b"meta/height".to_vec().into(),
                path: STATE_QUERY_PATH.to_owned(),
                height: 0,
                prove: true,
            })
            .unwrap();
        assert_eq!(query.code, 0);
        assert_eq!(query.height, 1);
        assert!(query.proof_ops.is_some());
        drop(client);
        server.join().unwrap();
        drop(app);
    }

    fn read_message<M: Message + Default>(stream: &mut TcpStream) -> M {
        let mut length = 0u64;
        let mut shift = 0u32;
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            length |= u64::from(byte[0] & 0x7f) << shift;
            if byte[0] & 0x80 == 0 {
                break;
            }
            shift += 7;
            assert!(shift < 64, "invalid ABCI length prefix");
        }
        let length = usize::try_from(length).unwrap();
        let mut bytes = vec![0u8; length];
        stream.read_exact(&mut bytes).unwrap();
        M::decode(bytes.as_slice()).unwrap()
    }

    fn write_message<M: Message>(stream: &mut TcpStream, message: &M) {
        let bytes = message.encode_to_vec();
        let mut length = bytes.len() as u64;
        while length >= 0x80 {
            stream.write_all(&[((length as u8) & 0x7f) | 0x80]).unwrap();
            length >>= 7;
        }
        stream.write_all(&[length as u8]).unwrap();
        stream.write_all(&bytes).unwrap();
        stream.flush().unwrap();
    }
}
