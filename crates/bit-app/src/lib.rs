//! Deterministic BIT application lifecycle over the persistent consensus state.
//!
//! This crate owns transaction selection, proposal re-execution, finalization,
//! and commit ordering. The network-facing ABCI 0.38 adapter will translate
//! protobuf requests into these methods without duplicating execution rules.

pub mod abci;

use bit_state::{
    CommitReceipt, GenesisConfig, PersistentState, PreparedBlock, QueryProof, StateSummary,
};
use bit_transaction::Error as TransactionError;
use std::path::PathBuf;
use thiserror::Error;
use tokio::sync::Mutex;

pub type Hash32 = [u8; 32];

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid application configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("state operation failed: {0}")]
    State(#[from] bit_state::Error),
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
    /// Digest produced by the deterministic business-action executor.
    pub execution_hash: Hash32,
    /// Digest produced by the versioned compact-block encoder.
    pub compact_hash: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizeOutcome {
    pub height: u64,
    pub app_hash: Hash32,
    pub shielded_tree_root: Hash32,
    pub transaction_results: Vec<TxResult>,
    pub accepted_transactions: usize,
}

pub struct ApplicationCore {
    state: PersistentState,
    protocol_version: u64,
    max_block_bytes: u64,
    pending: Mutex<Option<PreparedBlock>>,
}

impl ApplicationCore {
    pub async fn open(state_path: PathBuf, genesis: GenesisConfig) -> Result<Self> {
        let protocol_version = genesis.protocol_version;
        let max_block_bytes = genesis.max_block_bytes;
        let state = PersistentState::open(state_path, genesis).await?;
        Ok(Self {
            state,
            protocol_version,
            max_block_bytes,
            pending: Mutex::new(None),
        })
    }

    pub async fn info(&self) -> Result<AppInfo> {
        let summary = self.state.summary().await?;
        Ok(AppInfo {
            protocol_version: self.protocol_version,
            last_block_height: summary.state_height,
            last_block_app_hash: summary.app_hash,
        })
    }

    pub async fn state_summary(&self) -> Result<StateSummary> {
        Ok(self.state.summary().await?)
    }

    /// Check a transaction against the latest committed state without writes.
    pub async fn check_tx(&self, transaction: &[u8]) -> Result<TxResult> {
        let height = next_height(self.state.summary().await?.state_height)?;
        let mut block = self
            .state
            .begin_block_preview(height, [0; 32], [0; 32])
            .await?;
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
        let summary = self.state.summary().await?;
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
        let limit = requested_max_tx_bytes.min(self.max_block_bytes);
        let mut block = self
            .state
            .begin_block_at(height, block_time_seconds, [0; 32], [0; 32])
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
        let summary = self.state.summary().await?;
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
        if total_bytes(transactions)? > self.max_block_bytes {
            return Ok(false);
        }
        let mut block = self
            .state
            .begin_block_at(height, block_time_seconds, [0; 32], [0; 32])
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
        let mut block = self
            .state
            .begin_block_at(
                request.height,
                request.block_time_seconds,
                request.execution_hash,
                request.compact_hash,
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
        let prepared = block.prepare().await?;
        let outcome = FinalizeOutcome {
            height: prepared.state_height,
            app_hash: prepared.app_hash,
            shielded_tree_root: prepared.shielded_tree_root,
            accepted_transactions: prepared.transaction_count,
            transaction_results,
        };
        *pending = Some(prepared);
        Ok(outcome)
    }

    /// Durably commit the block produced by the last successful finalization.
    pub async fn commit(&self) -> Result<CommitReceipt> {
        let prepared = self
            .pending
            .lock()
            .await
            .take()
            .ok_or(Error::NoPendingBlock)?;
        Ok(self.state.commit(prepared)?)
    }

    pub async fn query_latest_with_proof(&self, key: &str) -> Result<QueryProof> {
        Ok(self.state.query_latest_with_proof(key).await?)
    }

    pub async fn close(self) {
        self.state.close().await;
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
    use bit_staking::{StakingBook, StakingParameters};
    use bit_types::MonetaryPolicy;
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
            genesis_execution_hash: [2; 32],
            genesis_compact_hash: [3; 32],
        }
    }

    #[tokio::test]
    async fn empty_finalize_is_invisible_until_commit() {
        let dir = TempDir::new().unwrap();
        let app = ApplicationCore::open(dir.path().to_path_buf(), genesis(1_000_000))
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
                execution_hash: [4; 32],
                compact_hash: [5; 32],
            })
            .await
            .unwrap();
        assert_eq!(app.info().await.unwrap(), initial);
        assert!(matches!(
            app.finalize_block(BlockRequest {
                height: 1,
                block_time_seconds: 1,
                transactions: Vec::new(),
                execution_hash: [4; 32],
                compact_hash: [5; 32],
            })
            .await,
            Err(Error::PendingBlockExists)
        ));

        let committed = app.commit().await.unwrap();
        assert_eq!(committed.app_hash, finalized.app_hash);
        assert_eq!(app.info().await.unwrap().last_block_height, 1);
        assert!(matches!(app.commit().await, Err(Error::NoPendingBlock)));
        app.close().await;
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
                execution_hash: [8; 32],
                compact_hash: [9; 32],
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
                execution_hash: [6; 32],
                compact_hash: [7; 32],
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
}
