//! Deterministic BIT application lifecycle over the persistent consensus state.
//!
//! This crate owns transaction selection, proposal re-execution, finalization,
//! and commit ordering. The network-facing ABCI 0.38 adapter will translate
//! protobuf requests into these methods without duplicating execution rules.

pub mod abci;
mod artifact_archive;
mod artifacts;
mod safety;
mod state_sync;

pub use artifact_archive::artifact_archive_path;
pub use artifacts::BlockArtifacts;
pub use safety::{
    acknowledge_safety_halt, decode_hash_hex, encode_hex, read_safety_halt,
    safety_halt_journal_path, SafetyHaltError, SafetyHaltReason, SafetyHaltRecord,
};
pub use state_sync::{StateSyncConfig, STATE_SYNC_SNAPSHOT_FORMAT};

use bit_staking::{CommitVote, ConsensusPowerUpdate};
use bit_state::{
    ByzantineEvidence, CommitReceipt, GenesisConfig, PersistentState, PreparedBlock, QueryProof,
    StateSnapshotManifest, StateSummary,
};
use bit_transaction::Error as TransactionError;
use std::path::PathBuf;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

use artifact_archive::{ArtifactArchive, StagedArtifacts};

pub type Hash32 = [u8; 32];

pub struct ProvenBlockArtifacts {
    pub artifacts: BlockArtifacts,
    pub execution_proof: QueryProof,
    pub compact_proof: QueryProof,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid application configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("safety halt journal operation failed: {0}")]
    SafetyHaltJournal(#[from] SafetyHaltError),
    #[error("safety halt {record_hash} is active at {journal}")]
    SafetyHaltActive {
        journal: PathBuf,
        record_hash: String,
    },
    #[error("state operation failed: {0}")]
    State(#[from] bit_state::Error),
    #[error("state sync operation failed: {0}")]
    StateSync(String),
    #[error("block artifact operation failed: {0}")]
    BlockArtifact(#[from] bit_types::Error),
    #[error("block artifact shielded payload failed: {0}")]
    BlockArtifactShielded(#[from] bit_shielded::ShieldedError),
    #[error("block artifact archive failed: {0}")]
    ArtifactArchive(String),
    #[error("FinalizeBlock already produced an uncommitted block")]
    PendingBlockExists,
    #[error("Commit called without a finalized block")]
    NoPendingBlock,
    #[error("finalized block has {actual} transaction bytes, exceeding limit {maximum}")]
    FinalizedBlockTooLarge { actual: u64, maximum: u64 },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppInfo {
    pub protocol_version: u64,
    pub last_block_height: u64,
    pub last_block_app_hash: Hash32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TxCode {
    Ok = 0,
    InvalidEnvelope = 1,
    InvalidShieldedProof = 2,
    WrongChainContext = 3,
    UnsupportedAction = 4,
    UnknownAnchor = 5,
    DuplicateNullifier = 6,
    NullifierAlreadySpent = 7,
    TransactionAlreadyApplied = 8,
    BlockBytesExceeded = 9,
    FeeTooLow = 10,
    InvalidAuthorization = 11,
    StaleState = 12,
    InvalidAction = 13,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxResult {
    pub code: TxCode,
    pub log: &'static str,
    pub tx_id: Option<Hash32>,
}

impl TxResult {
    fn accepted(tx_id: Hash32) -> Self {
        Self {
            code: TxCode::Ok,
            log: "accepted",
            tx_id: Some(tx_id),
        }
    }

    fn block_bytes_exceeded() -> Self {
        Self {
            code: TxCode::BlockBytesExceeded,
            log: "block transaction byte budget exceeded",
            tx_id: None,
        }
    }

    pub fn is_ok(&self) -> bool {
        self.code == TxCode::Ok
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedProposal {
    pub transactions: Vec<Vec<u8>>,
    pub rejected: Vec<TxResult>,
    pub total_transaction_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockRequest {
    pub height: u64,
    pub block_time_seconds: u64,
    pub transactions: Vec<Vec<u8>>,
    /// Actual votes for height `height - 1`; absent only at height one.
    pub last_commit: Option<LastCommit>,
    /// CometBFT-validated Byzantine evidence included in this finalized block.
    pub byzantine_evidence: Vec<ByzantineEvidence>,
    /// CometBFT header hash of the validator set effective at `height + 1`.
    pub next_validators_hash: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LastCommit {
    pub votes: Vec<CommitVote>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizeOutcome {
    pub height: u64,
    pub app_hash: Hash32,
    pub shielded_tree_root: Hash32,
    pub transaction_results: Vec<TxResult>,
    pub accepted_transactions: usize,
    pub validator_updates: Vec<ConsensusPowerUpdate>,
    pub artifacts: BlockArtifacts,
}

struct PendingCommit {
    block: PreparedBlock,
    artifacts: StagedArtifacts,
}

pub struct ApplicationCore {
    state: RwLock<PersistentState>,
    protocol_version: u64,
    chain_context: Hash32,
    max_block_bytes: u64,
    max_tx_lifetime_blocks: u64,
    max_envelope_bytes: usize,
    artifact_archive: ArtifactArchive,
    pending: Mutex<Option<PendingCommit>>,
}

impl ApplicationCore {
    pub async fn open(state_path: PathBuf, genesis: GenesisConfig) -> Result<Self> {
        let archive_path = artifact_archive_path(&state_path);
        Self::open_with_artifact_archive(state_path, archive_path, genesis).await
    }

    async fn open_with_artifact_archive(
        state_path: PathBuf,
        archive_path: PathBuf,
        genesis: GenesisConfig,
    ) -> Result<Self> {
        let protocol_version = genesis.protocol_version;
        let chain_context = genesis.chain_context;
        let max_block_bytes = genesis.max_block_bytes;
        let max_tx_lifetime_blocks = genesis.max_tx_lifetime_blocks;
        let max_envelope_bytes = genesis.max_envelope_bytes;
        let state = PersistentState::open(state_path, genesis).await?;
        let artifact_archive = match ArtifactArchive::open(archive_path) {
            Ok(archive) => archive,
            Err(error) => {
                state.close().await;
                return Err(error);
            }
        };
        if let Err(error) = artifact_archive.recover(&state).await {
            state.close().await;
            return Err(error);
        }
        Ok(Self {
            state: RwLock::new(state),
            protocol_version,
            chain_context,
            max_block_bytes,
            max_tx_lifetime_blocks,
            max_envelope_bytes,
            artifact_archive,
            pending: Mutex::new(None),
        })
    }

    pub async fn info(&self) -> Result<AppInfo> {
        let summary = self.state.read().await.summary().await?;
        Ok(AppInfo {
            protocol_version: self.protocol_version,
            last_block_height: summary.state_height,
            last_block_app_hash: summary.app_hash,
        })
    }

    pub async fn state_summary(&self) -> Result<StateSummary> {
        Ok(self.state.read().await.summary().await?)
    }

    pub async fn expected_next_validators_hash(&self, block_height: u64) -> Result<Hash32> {
        Ok(self
            .state
            .read()
            .await
            .expected_next_validators_hash(block_height)
            .await?)
    }

    /// Check a transaction against the latest committed state without writes.
    pub async fn check_tx(&self, transaction: &[u8]) -> Result<TxResult> {
        let state = self.state.read().await;
        let height = next_height(state.summary().await?.state_height)?;
        let mut block = state.begin_block_preview(height, [0; 32], [0; 32]).await?;
        match block.verify_and_stage_transaction(transaction).await {
            Ok(tx_id) => Ok(TxResult::accepted(tx_id)),
            Err(error) => rejection_or_state_error(error),
        }
    }

    /// Select executable transactions in input order under both byte limits.
    pub async fn prepare_proposal(
        &self,
        height: u64,
        candidates: Vec<Vec<u8>>,
        requested_max_tx_bytes: u64,
    ) -> Result<PreparedProposal> {
        let summary = self.state.read().await.summary().await?;
        let block_time_seconds = summary
            .block_time_seconds
            .checked_add(1)
            .ok_or(Error::InvalidConfig("block time seconds overflow"))?;
        self.prepare_proposal_at(
            height,
            block_time_seconds,
            candidates,
            requested_max_tx_bytes,
        )
        .await
    }

    pub async fn prepare_proposal_at(
        &self,
        height: u64,
        block_time_seconds: u64,
        candidates: Vec<Vec<u8>>,
        requested_max_tx_bytes: u64,
    ) -> Result<PreparedProposal> {
        let next_validators_hash = self.expected_next_validators_hash(height).await?;
        self.prepare_proposal_at_with_commit(
            height,
            block_time_seconds,
            candidates,
            requested_max_tx_bytes,
            None,
            next_validators_hash,
        )
        .await
    }

    pub async fn prepare_proposal_at_with_commit(
        &self,
        height: u64,
        block_time_seconds: u64,
        candidates: Vec<Vec<u8>>,
        requested_max_tx_bytes: u64,
        last_commit: Option<&LastCommit>,
        next_validators_hash: Hash32,
    ) -> Result<PreparedProposal> {
        let limit = requested_max_tx_bytes.min(self.max_block_bytes);
        let state = self.state.read().await;
        let mut block = state
            .begin_block_at(height, block_time_seconds, [0; 32], [0; 32])
            .await?;
        block
            .stage_consensus_system(
                last_commit.map(|commit| commit.votes.as_slice()),
                &[],
                next_validators_hash,
            )
            .await?;
        let mut transactions = Vec::new();
        let mut rejected = Vec::new();
        let mut total_transaction_bytes = 0u64;

        for transaction in candidates {
            let transaction_bytes = u64::try_from(transaction.len())
                .map_err(|_| Error::InvalidConfig("transaction length does not fit in u64"))?;
            let Some(next_total) = total_transaction_bytes.checked_add(transaction_bytes) else {
                rejected.push(TxResult::block_bytes_exceeded());
                continue;
            };
            if next_total > limit {
                rejected.push(TxResult::block_bytes_exceeded());
                continue;
            }
            match block.verify_and_stage_transaction(&transaction).await {
                Ok(_) => {
                    total_transaction_bytes = next_total;
                    transactions.push(transaction);
                }
                Err(error) => rejected.push(rejection_or_state_error(error)?),
            }
        }

        Ok(PreparedProposal {
            transactions,
            rejected,
            total_transaction_bytes,
        })
    }

    /// Re-execute a proposal in order. Any invalid transaction rejects it.
    pub async fn process_proposal(&self, height: u64, transactions: &[Vec<u8>]) -> Result<bool> {
        let summary = self.state.read().await.summary().await?;
        let block_time_seconds = summary
            .block_time_seconds
            .checked_add(1)
            .ok_or(Error::InvalidConfig("block time seconds overflow"))?;
        self.process_proposal_at(height, block_time_seconds, transactions)
            .await
    }

    pub async fn process_proposal_at(
        &self,
        height: u64,
        block_time_seconds: u64,
        transactions: &[Vec<u8>],
    ) -> Result<bool> {
        let next_validators_hash = self.expected_next_validators_hash(height).await?;
        self.process_proposal_at_with_commit(
            height,
            block_time_seconds,
            transactions,
            None,
            next_validators_hash,
        )
        .await
    }

    pub async fn process_proposal_at_with_commit(
        &self,
        height: u64,
        block_time_seconds: u64,
        transactions: &[Vec<u8>],
        last_commit: Option<&LastCommit>,
        next_validators_hash: Hash32,
    ) -> Result<bool> {
        if total_bytes(transactions)? > self.max_block_bytes {
            return Ok(false);
        }
        let state = self.state.read().await;
        let mut block = state
            .begin_block_at(height, block_time_seconds, [0; 32], [0; 32])
            .await?;
        block
            .stage_consensus_system(
                last_commit.map(|commit| commit.votes.as_slice()),
                &[],
                next_validators_hash,
            )
            .await?;
        for transaction in transactions {
            if let Err(error) = block.verify_and_stage_transaction(transaction).await {
                rejection_or_state_error(error)?;
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Execute all transactions and stage one block for Commit.
    ///
    /// Invalid transactions get stable results and leave no partial state. A
    /// proposal containing them should already have been rejected by
    /// `process_proposal`, but finalization remains panic-free and deterministic.
    pub async fn finalize_block(&self, request: BlockRequest) -> Result<FinalizeOutcome> {
        let actual_bytes = total_bytes(&request.transactions)?;
        if actual_bytes > self.max_block_bytes {
            return Err(Error::FinalizedBlockTooLarge {
                actual: actual_bytes,
                maximum: self.max_block_bytes,
            });
        }
        let mut pending = self.pending.lock().await;
        if pending.is_some() {
            return Err(Error::PendingBlockExists);
        }
        let state = self.state.read().await;
        let mut block = state
            .begin_block_at(request.height, request.block_time_seconds, [0; 32], [0; 32])
            .await?;
        let system = block
            .stage_consensus_system(
                request
                    .last_commit
                    .as_ref()
                    .map(|commit| commit.votes.as_slice()),
                &request.byzantine_evidence,
                request.next_validators_hash,
            )
            .await?;
        let mut transaction_results = Vec::with_capacity(request.transactions.len());
        for transaction in &request.transactions {
            let result = match block.verify_and_stage_transaction(transaction).await {
                Ok(tx_id) => TxResult::accepted(tx_id),
                Err(error) => rejection_or_state_error(error)?,
            };
            transaction_results.push(result);
        }
        let shielded_tree_root = block.preview_shielded_tree_root()?;
        let artifacts = artifacts::build_block_artifacts(
            self.chain_context,
            request.height,
            request.block_time_seconds,
            shielded_tree_root,
            &request.transactions,
            &transaction_results,
            &system,
            self.max_envelope_bytes,
            self.max_tx_lifetime_blocks,
        )?;
        let staged_artifacts = self.artifact_archive.stage(&artifacts)?;
        block.set_block_digests(artifacts.execution_hash, artifacts.compact_hash);
        let prepared = match block.prepare().await {
            Ok(prepared) => prepared,
            Err(error) => {
                self.artifact_archive.discard(&staged_artifacts)?;
                return Err(error.into());
            }
        };
        if prepared.shielded_tree_root != shielded_tree_root {
            self.artifact_archive.discard(&staged_artifacts)?;
            return Err(bit_state::Error::CorruptState(
                "compact block tree root differs from prepared state".to_owned(),
            )
            .into());
        }
        let outcome = FinalizeOutcome {
            height: prepared.state_height,
            app_hash: prepared.app_hash,
            shielded_tree_root: prepared.shielded_tree_root,
            accepted_transactions: prepared.transaction_count,
            transaction_results,
            validator_updates: system.validator_updates,
            artifacts,
        };
        *pending = Some(PendingCommit {
            block: prepared,
            artifacts: staged_artifacts,
        });
        Ok(outcome)
    }

    /// Durably commit the block produced by the last successful finalization.
    pub async fn commit(&self) -> Result<CommitReceipt> {
        let pending = self
            .pending
            .lock()
            .await
            .take()
            .ok_or(Error::NoPendingBlock)?;
        let receipt = self.state.read().await.commit(pending.block)?;
        self.artifact_archive.publish(pending.artifacts)?;
        Ok(receipt)
    }

    pub async fn query_latest_with_proof(&self, key: &str) -> Result<QueryProof> {
        Ok(self.state.read().await.query_latest_with_proof(key).await?)
    }

    pub async fn query_at_height_with_proof(&self, key: &str, height: u64) -> Result<QueryProof> {
        Ok(self
            .state
            .read()
            .await
            .query_at_height_with_proof(key, height)
            .await?)
    }

    /// Load and validate a durably published block artifact pair.
    pub fn block_artifacts(&self, height: u64) -> Result<Option<BlockArtifacts>> {
        self.artifact_archive.load(height)
    }

    /// Load a published artifact pair and bind both files to the application
    /// hash committed at their exact block height.
    pub async fn block_artifacts_with_proofs(
        &self,
        height: u64,
    ) -> Result<Option<ProvenBlockArtifacts>> {
        let Some(artifacts) = self.block_artifacts(height)? else {
            return Ok(None);
        };
        let execution_proof = self
            .artifact_hash_proof(
                &format!("execution/block/{height:020}"),
                height,
                &artifacts.execution_hash,
            )
            .await?;
        let compact_proof = self
            .artifact_hash_proof(
                &format!("compact/hash/{height:020}"),
                height,
                &artifacts.compact_hash,
            )
            .await?;
        Ok(Some(ProvenBlockArtifacts {
            artifacts,
            execution_proof,
            compact_proof,
        }))
    }

    async fn artifact_hash_proof(
        &self,
        key: &str,
        height: u64,
        expected: &Hash32,
    ) -> Result<QueryProof> {
        let proof = self.query_at_height_with_proof(key, height).await?;
        proof.verify().map_err(|error| {
            Error::ArtifactArchive(format!(
                "historical state proof for artifact block {height} failed: {error}"
            ))
        })?;
        if proof.value.as_deref() != Some(expected.as_slice()) {
            return Err(Error::ArtifactArchive(format!(
                "artifact block {height} differs from its historical state proof"
            )));
        }
        Ok(proof)
    }

    pub(crate) async fn export_state_snapshot(
        &self,
        destination: PathBuf,
    ) -> Result<StateSnapshotManifest> {
        Ok(self.state.read().await.export_snapshot(destination).await?)
    }

    pub(crate) async fn replace_state(&self, replacement: PersistentState) -> Result<()> {
        let pending = self.pending.lock().await;
        if pending.is_some() {
            return Err(Error::PendingBlockExists);
        }
        let mut state = self.state.write().await;
        let previous = std::mem::replace(&mut *state, replacement);
        drop(state);
        drop(pending);
        previous.close().await;
        Ok(())
    }

    pub async fn close(self) {
        if let Some(pending) = self.pending.into_inner() {
            let _ = self.artifact_archive.discard(&pending.artifacts);
        }
        self.state.into_inner().close().await;
    }
}

fn next_height(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or(Error::InvalidConfig("state height overflow"))
}

fn total_bytes(transactions: &[Vec<u8>]) -> Result<u64> {
    transactions.iter().try_fold(0u64, |total, transaction| {
        let len = u64::try_from(transaction.len())
            .map_err(|_| Error::InvalidConfig("transaction length does not fit in u64"))?;
        total
            .checked_add(len)
            .ok_or(Error::InvalidConfig("block transaction bytes overflow"))
    })
}

fn rejection_or_state_error(error: bit_state::Error) -> Result<TxResult> {
    let (code, log) = match error {
        bit_state::Error::Transaction(TransactionError::Types(_)) => {
            (TxCode::InvalidEnvelope, "invalid transaction envelope")
        }
        bit_state::Error::Transaction(TransactionError::Shielded(_)) => (
            TxCode::InvalidShieldedProof,
            "invalid shielded proof or signature",
        ),
        bit_state::Error::Transaction(TransactionError::WrongChainContext) => {
            (TxCode::WrongChainContext, "wrong chain context")
        }
        bit_state::Error::Transaction(TransactionError::UnsupportedAction) => {
            (TxCode::UnsupportedAction, "unsupported action")
        }
        bit_state::Error::Transaction(TransactionError::UnknownAnchor)
        | bit_state::Error::UnknownAnchor => (TxCode::UnknownAnchor, "unknown anchor"),
        bit_state::Error::Transaction(TransactionError::DuplicateNullifier)
        | bit_state::Error::DuplicateNullifier => {
            (TxCode::DuplicateNullifier, "duplicate nullifier")
        }
        bit_state::Error::Transaction(TransactionError::NullifierAlreadySpent)
        | bit_state::Error::NullifierAlreadySpent => {
            (TxCode::NullifierAlreadySpent, "nullifier already spent")
        }
        bit_state::Error::Transaction(TransactionError::TransactionAlreadyApplied)
        | bit_state::Error::TransactionAlreadyApplied => (
            TxCode::TransactionAlreadyApplied,
            "transaction already applied",
        ),
        bit_state::Error::Transaction(TransactionError::FeeTooLow { .. }) => (
            TxCode::FeeTooLow,
            "transaction fee is below required minimum",
        ),
        bit_state::Error::Transaction(
            TransactionError::InvalidAuthorization { .. }
            | TransactionError::AuthorizationKeyNotFound { .. }
            | TransactionError::IdentifierMismatch(_),
        ) => (
            TxCode::InvalidAuthorization,
            "transaction authorization is invalid",
        ),
        bit_state::Error::Transaction(TransactionError::StaleStateQuote(_)) => {
            (TxCode::StaleState, "transaction state quote is stale")
        }
        bit_state::Error::Transaction(TransactionError::InvalidFeeSource(_))
        | bit_state::Error::Staking(_) => (TxCode::InvalidAction, "transaction action is invalid"),
        bit_state::Error::Accounting(bit_emission::Error::Insufficient(_)) => {
            (TxCode::InvalidAction, "transaction value is insufficient")
        }
        error => return Err(Error::State(error)),
    };
    Ok(TxResult {
        code,
        log,
        tx_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bit_emission::{FeePolicy, GenesisAllocation};
    use bit_staking::{
        consensus_address, StakingBook, StakingParameters, RECOVERY_RECEIPT_BYTES,
        TESTNET_MIN_SELF_BOND_ATOMIC,
    };
    use bit_types::{
        position_id, validator_id, Amount, CompactBlock, ExecutionSummary, MonetaryPolicy,
    };
    use decaf377::Fq;
    use tempfile::TempDir;

    fn genesis(max_block_bytes: u64) -> GenesisConfig {
        let mut native_asset_id = [0; 32];
        native_asset_id.copy_from_slice(&Fq::from(1u64).to_bytes());
        let monetary_policy = MonetaryPolicy::reference_testnet();
        GenesisConfig {
            chain_context: [1; 32],
            native_asset_id,
            protocol_version: 1,
            max_block_bytes,
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
            genesis_execution_hash: [2; 32],
            genesis_compact_hash: [3; 32],
        }
    }

    fn genesis_with_active_validator() -> (GenesisConfig, Hash32, Hash32, u64) {
        let mut genesis = genesis(1_000_000);
        genesis.monetary_policy.epoch_blocks = 2;
        let chain = genesis.chain_context;
        let operator = [21; 32];
        let validator_id = validator_id(&chain, &operator);
        let consensus_pubkey = [22; 32];
        let owner = [23; 32];
        let position_id = position_id(&chain, &owner);
        let principal = Amount::new(TESTNET_MIN_SELF_BOND_ATOMIC).unwrap();
        let mut staking = StakingBook::new(chain, StakingParameters::reference_testnet()).unwrap();
        staking
            .register_validator(validator_id, operator, consensus_pubkey, 500)
            .unwrap();
        staking
            .open_pending_delegation(
                0,
                0,
                position_id,
                owner,
                validator_id,
                principal,
                Amount::ZERO,
                true,
                vec![24; RECOVERY_RECEIPT_BYTES],
            )
            .unwrap();
        staking.activate_pending(&position_id, 1).unwrap();
        let power = staking.apply_validator_set().unwrap()[0].power;
        genesis.genesis_staking = staking;
        genesis.genesis_allocation = GenesisAllocation {
            shielded: Amount::ZERO,
            stake: principal,
            pending_delegation: Amount::ZERO,
            exits: Amount::ZERO,
            commission: Amount::ZERO,
            fee_reserve: Amount::ZERO,
            unclaimed_genesis: Amount::new(
                genesis.monetary_policy.genesis_supply.value() - principal.value(),
            )
            .unwrap(),
        };
        (genesis, validator_id, consensus_pubkey, power)
    }

    #[tokio::test]
    async fn empty_finalize_is_invisible_until_commit() {
        let dir = TempDir::new().unwrap();
        let genesis = genesis(1_000_000);
        let app = ApplicationCore::open(dir.path().to_path_buf(), genesis.clone())
            .await
            .unwrap();
        let initial = app.info().await.unwrap();
        assert_eq!(initial.last_block_height, 0);
        assert!(app.process_proposal(1, &[]).await.unwrap());

        let finalized = app
            .finalize_block(BlockRequest {
                height: 1,
                block_time_seconds: 1,
                transactions: Vec::new(),
                last_commit: None,
                byzantine_evidence: Vec::new(),
                next_validators_hash: app.expected_next_validators_hash(1).await.unwrap(),
            })
            .await
            .unwrap();
        let execution =
            ExecutionSummary::decode_canonical(&finalized.artifacts.execution_summary).unwrap();
        let compact = CompactBlock::decode_canonical(&finalized.artifacts.compact_block).unwrap();
        assert_eq!(execution.height, 1);
        assert_eq!(execution.shielded_tree_root, finalized.shielded_tree_root);
        assert!(execution.transactions.is_empty());
        assert_eq!(compact.height, 1);
        assert_eq!(compact.shielded_tree_root, finalized.shielded_tree_root);
        assert!(compact.transactions.is_empty());
        assert_eq!(execution.events, compact.events);
        assert!(app.block_artifacts(1).unwrap().is_none());
        assert_eq!(app.info().await.unwrap(), initial);
        assert!(matches!(
            app.finalize_block(BlockRequest {
                height: 1,
                block_time_seconds: 1,
                transactions: Vec::new(),
                last_commit: None,
                byzantine_evidence: Vec::new(),
                next_validators_hash: app.expected_next_validators_hash(1).await.unwrap(),
            })
            .await,
            Err(Error::PendingBlockExists)
        ));

        let committed = app.commit().await.unwrap();
        assert_eq!(committed.app_hash, finalized.app_hash);
        assert_eq!(
            app.query_latest_with_proof("execution/block/00000000000000000001")
                .await
                .unwrap()
                .value,
            Some(finalized.artifacts.execution_hash.to_vec())
        );
        assert_eq!(
            app.query_latest_with_proof("compact/hash/00000000000000000001")
                .await
                .unwrap()
                .value,
            Some(finalized.artifacts.compact_hash.to_vec())
        );
        assert_eq!(app.info().await.unwrap().last_block_height, 1);
        assert_eq!(
            app.block_artifacts(1).unwrap(),
            Some(finalized.artifacts.clone())
        );
        let proven = app.block_artifacts_with_proofs(1).await.unwrap().unwrap();
        assert_eq!(proven.artifacts, finalized.artifacts);
        assert_eq!(proven.execution_proof.storage_version, 1);
        assert_eq!(proven.compact_proof.storage_version, 1);
        proven.execution_proof.verify().unwrap();
        proven.compact_proof.verify().unwrap();
        assert!(matches!(app.commit().await, Err(Error::NoPendingBlock)));
        app.close().await;

        let reopened = ApplicationCore::open(dir.path().to_path_buf(), genesis)
            .await
            .unwrap();
        assert_eq!(
            reopened.block_artifacts(1).unwrap(),
            Some(finalized.artifacts)
        );
        reopened.close().await;
    }

    #[tokio::test]
    async fn committed_artifact_stage_is_published_after_restart() {
        let dir = TempDir::new().unwrap();
        let genesis = genesis(1_000_000);
        let app = ApplicationCore::open(dir.path().to_path_buf(), genesis.clone())
            .await
            .unwrap();
        let finalized = app
            .finalize_block(BlockRequest {
                height: 1,
                block_time_seconds: 1,
                transactions: Vec::new(),
                last_commit: None,
                byzantine_evidence: Vec::new(),
                next_validators_hash: app.expected_next_validators_hash(1).await.unwrap(),
            })
            .await
            .unwrap();

        let pending = app.pending.lock().await.take().unwrap();
        let committed = app.state.read().await.commit(pending.block).unwrap();
        assert_eq!(committed.app_hash, finalized.app_hash);
        drop(pending.artifacts);
        assert!(app.block_artifacts(1).unwrap().is_none());
        app.close().await;

        let reopened = ApplicationCore::open(dir.path().to_path_buf(), genesis)
            .await
            .unwrap();
        assert_eq!(
            reopened.block_artifacts(1).unwrap(),
            Some(finalized.artifacts)
        );
        reopened.close().await;
    }

    #[tokio::test]
    async fn uncommitted_artifact_stage_is_removed_after_restart() {
        let dir = TempDir::new().unwrap();
        let genesis = genesis(1_000_000);
        let app = ApplicationCore::open(dir.path().to_path_buf(), genesis.clone())
            .await
            .unwrap();
        app.finalize_block(BlockRequest {
            height: 1,
            block_time_seconds: 1,
            transactions: Vec::new(),
            last_commit: None,
            byzantine_evidence: Vec::new(),
            next_validators_hash: app.expected_next_validators_hash(1).await.unwrap(),
        })
        .await
        .unwrap();
        let abandoned = app.pending.lock().await.take().unwrap();
        drop(abandoned);
        app.close().await;

        let reopened = ApplicationCore::open(dir.path().to_path_buf(), genesis)
            .await
            .unwrap();
        assert_eq!(reopened.info().await.unwrap().last_block_height, 0);
        assert!(reopened.block_artifacts(1).unwrap().is_none());
        let finalized = reopened
            .finalize_block(BlockRequest {
                height: 1,
                block_time_seconds: 1,
                transactions: Vec::new(),
                last_commit: None,
                byzantine_evidence: Vec::new(),
                next_validators_hash: reopened.expected_next_validators_hash(1).await.unwrap(),
            })
            .await
            .unwrap();
        reopened.commit().await.unwrap();
        assert_eq!(
            reopened.block_artifacts(1).unwrap(),
            Some(finalized.artifacts)
        );
        reopened.close().await;
    }

    #[tokio::test]
    async fn proposal_paths_reject_invalid_transactions_without_writes() {
        let dir = TempDir::new().unwrap();
        let app = ApplicationCore::open(dir.path().to_path_buf(), genesis(4))
            .await
            .unwrap();
        let initial = app.state_summary().await.unwrap();

        let checked = app.check_tx(&[0xff]).await.unwrap();
        assert_eq!(checked.code, TxCode::InvalidEnvelope);
        let proposal = app
            .prepare_proposal(1, vec![vec![0xff], vec![1, 2, 3, 4, 5]], 100)
            .await
            .unwrap();
        assert!(proposal.transactions.is_empty());
        assert_eq!(proposal.rejected.len(), 2);
        assert_eq!(proposal.rejected[0].code, TxCode::InvalidEnvelope);
        assert_eq!(proposal.rejected[1].code, TxCode::BlockBytesExceeded);
        assert!(!app.process_proposal(1, &[vec![0xff]]).await.unwrap());
        assert!(matches!(
            app.finalize_block(BlockRequest {
                height: 1,
                block_time_seconds: 1,
                transactions: vec![vec![1, 2, 3, 4, 5]],
                last_commit: None,
                byzantine_evidence: Vec::new(),
                next_validators_hash: app.expected_next_validators_hash(1).await.unwrap(),
            })
            .await,
            Err(Error::FinalizedBlockTooLarge {
                actual: 5,
                maximum: 4
            })
        ));
        assert_eq!(app.state_summary().await.unwrap(), initial);
        app.close().await;
    }

    #[tokio::test]
    async fn finalize_reports_invalid_transaction_and_commits_clean_block() {
        let dir = TempDir::new().unwrap();
        let app = ApplicationCore::open(dir.path().to_path_buf(), genesis(1024))
            .await
            .unwrap();
        let finalized = app
            .finalize_block(BlockRequest {
                height: 1,
                block_time_seconds: 1,
                transactions: vec![vec![0xff]],
                last_commit: None,
                byzantine_evidence: Vec::new(),
                next_validators_hash: app.expected_next_validators_hash(1).await.unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(finalized.accepted_transactions, 0);
        assert_eq!(finalized.transaction_results.len(), 1);
        assert_eq!(
            finalized.transaction_results[0].code,
            TxCode::InvalidEnvelope
        );
        let receipt = app.commit().await.unwrap();
        assert_eq!(receipt.transaction_count, 0);
        assert_eq!(receipt.state_height, 1);
        app.close().await;
    }

    #[tokio::test]
    async fn actual_commits_automatically_settle_epoch_and_emit_power_update() {
        let dir = TempDir::new().unwrap();
        let (genesis, validator_id, consensus_pubkey, power) = genesis_with_active_validator();
        let app = ApplicationCore::open(dir.path().to_path_buf(), genesis.clone())
            .await
            .unwrap();
        let vote = CommitVote {
            consensus_address: consensus_address(&consensus_pubkey),
            power,
            signed: true,
        };
        for height in 1..=2 {
            let outcome = app
                .finalize_block(BlockRequest {
                    height,
                    block_time_seconds: height,
                    transactions: Vec::new(),
                    last_commit: (height > 1).then(|| LastCommit { votes: vec![vote] }),
                    byzantine_evidence: Vec::new(),
                    next_validators_hash: app.expected_next_validators_hash(height).await.unwrap(),
                })
                .await
                .unwrap();
            assert!(outcome.validator_updates.is_empty());
            app.commit().await.unwrap();
        }

        let boundary = app
            .finalize_block(BlockRequest {
                height: 3,
                block_time_seconds: 3,
                transactions: Vec::new(),
                last_commit: Some(LastCommit { votes: vec![vote] }),
                byzantine_evidence: Vec::new(),
                next_validators_hash: app.expected_next_validators_hash(3).await.unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(boundary.validator_updates.len(), 1);
        assert_eq!(
            boundary.validator_updates[0].consensus_pubkey,
            consensus_pubkey
        );
        assert!(boundary.validator_updates[0].power > power);
        let updated_power = boundary.validator_updates[0].power;
        app.commit().await.unwrap();
        assert_eq!(
            app.state_summary().await.unwrap().supply.completed_epochs,
            1
        );
        let validator = app
            .state
            .read()
            .await
            .staking_book()
            .unwrap()
            .validator(&validator_id)
            .unwrap()
            .clone();
        assert_eq!(validator.signing_window.len(), 2);
        assert_eq!(validator.signed_window_count, 2);
        assert_eq!(validator.epoch_score, 0);
        for height in [3, 4] {
            let set = app
                .state
                .read()
                .await
                .effective_validator_set_at(height)
                .await
                .unwrap();
            assert_eq!(set.validators()[0].power, power);
        }
        let h_plus_two = app
            .state
            .read()
            .await
            .effective_validator_set_at(5)
            .await
            .unwrap();
        assert_eq!(h_plus_two.validators()[0].power, updated_power);
        app.close().await;

        let reopened = ApplicationCore::open(dir.path().to_path_buf(), genesis)
            .await
            .unwrap();
        assert_eq!(
            reopened
                .state
                .read()
                .await
                .staking_book()
                .unwrap()
                .validator(&validator_id)
                .unwrap(),
            &validator
        );
        reopened.close().await;
    }

    #[tokio::test]
    async fn consensus_context_mismatch_is_rejected_without_staging_state() {
        let dir = TempDir::new().unwrap();
        let (genesis, _, consensus_pubkey, power) = genesis_with_active_validator();
        let app = ApplicationCore::open(dir.path().to_path_buf(), genesis)
            .await
            .unwrap();
        let initial = app.state_summary().await.unwrap();
        let expected_h1 = app.expected_next_validators_hash(1).await.unwrap();
        let mut wrong_hash = expected_h1;
        wrong_hash[0] ^= 1;
        assert!(matches!(
            app.finalize_block(BlockRequest {
                height: 1,
                block_time_seconds: 1,
                transactions: Vec::new(),
                last_commit: None,
                byzantine_evidence: Vec::new(),
                next_validators_hash: wrong_hash,
            })
            .await,
            Err(Error::State(bit_state::Error::NextValidatorsHashMismatch))
        ));
        assert_eq!(app.state_summary().await.unwrap(), initial);

        app.finalize_block(BlockRequest {
            height: 1,
            block_time_seconds: 1,
            transactions: Vec::new(),
            last_commit: None,
            byzantine_evidence: Vec::new(),
            next_validators_hash: expected_h1,
        })
        .await
        .unwrap();
        app.commit().await.unwrap();

        let expected_h2 = app.expected_next_validators_hash(2).await.unwrap();
        let wrong_vote = CommitVote {
            consensus_address: consensus_address(&consensus_pubkey),
            power: power + 1,
            signed: true,
        };
        assert!(matches!(
            app.finalize_block(BlockRequest {
                height: 2,
                block_time_seconds: 2,
                transactions: Vec::new(),
                last_commit: Some(LastCommit {
                    votes: vec![wrong_vote],
                }),
                byzantine_evidence: Vec::new(),
                next_validators_hash: expected_h2,
            })
            .await,
            Err(Error::State(bit_state::Error::Staking(
                bit_staking::Error::LastCommitSetMismatch
            )))
        ));
        assert_eq!(app.info().await.unwrap().last_block_height, 1);
        app.close().await;
    }
}
