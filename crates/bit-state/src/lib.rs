//! Versioned BIT consensus state backed by Cnidarium, JMT, and RocksDB.
//!
//! A block is first prepared against an immutable snapshot. Preparing computes
//! the next JMT root but does not write to RocksDB. Committing the prepared
//! batch persists the height, execution marker, compact-block hash, shielded
//! tree, anchors, nullifiers, and transaction markers in one RocksDB batch.

use bit_emission::{
    completed_epochs_after_height, FeeClass, FeePolicy, GenesisAllocation, SupplyAudit, SupplyState,
};
use bit_staking::{
    ActivationCapacityRecord, ActivationOutcome, CommitVote, ConsensusPowerUpdate,
    EffectiveValidatorSet, PositionStatus, StakePool, StakePosition, StakingBook,
    StakingParameters, StakingTotals, Validator, ValidatorPower, ValidatorReward,
    ValidatorSetTransition, ValidatorUpdate,
};
use bit_transaction::{
    verify_staking_stateless, verify_transfer_stateless, ActionAuthorizationView,
    PendingPositionAuthorization, StatelessVerificationContext, VerifiedStakingAction,
    VerifiedStakingTransaction, VerifiedTransfer,
};
use bit_types::{Action, Amount, Envelope, MonetaryPolicy};
use cnidarium::{Snapshot, StagedWriteBatch, StateDelta, StateRead, StateWrite, Storage};
use decaf377::Fq;
use futures::StreamExt;
use ibc_types::core::commitment::{MerklePath, MerkleProof, MerkleRoot};
use penumbra_sdk_tct::{StateCommitment, Tree, Witness};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::RwLock,
};
use thiserror::Error;

pub type Hash32 = [u8; 32];

const STORAGE_SCHEMA_VERSION: u32 = 11;
const MAX_FRONTIER_BYTES: usize = 64 * 1024 * 1024;
const META_VERSION: &str = "meta/version";
const META_HEIGHT: &str = "meta/height";
const META_BLOCK_TIME_SECONDS: &str = "meta/block_time_seconds";
const META_CHAIN_CONTEXT: &str = "meta/chain_context";
const META_NATIVE_ASSET_ID: &str = "meta/native_asset_id";
const META_PROTOCOL_VERSION: &str = "meta/protocol_version";
const META_MAX_BLOCK_BYTES: &str = "meta/max_block_bytes";
const META_MAX_TX_LIFETIME: &str = "meta/max_tx_lifetime_blocks";
const META_MAX_ENVELOPE_BYTES: &str = "meta/max_envelope_bytes";
const META_ANCHOR_RETENTION: &str = "meta/anchor_retention_blocks";
const META_GENESIS_COMMITMENTS_HASH: &str = "meta/genesis_commitments_hash";
const META_MONETARY_POLICY_HASH: &str = "meta/monetary_policy_hash";
const TREE_ROOT: &str = "shielded/tree_root";
const TREE_FRONTIER: &str = "shielded/tree_frontier";
const EMISSION_POLICY: &str = "emission/policy";
const EMISSION_COMPLETED_EPOCHS: &str = "emission/completed_epochs";
const EMISSION_FORFEITED_UNISSUED: &str = "emission/forfeited_unissued";
const SUPPLY_MAX: &str = "supply/max_supply";
const SUPPLY_GENESIS: &str = "supply/genesis";
const SUPPLY_CUMULATIVE_MINTED: &str = "supply/cumulative_minted";
const SUPPLY_BURNED: &str = "supply/burned";
const SUPPLY_SHIELDED: &str = "supply/shielded_total";
const SUPPLY_STAKE: &str = "supply/stake_total";
const SUPPLY_PENDING: &str = "supply/pending_delegation_total";
const SUPPLY_EXITS: &str = "supply/exit_total";
const SUPPLY_COMMISSION: &str = "supply/commission_total";
const FEES_RESERVE: &str = "fees/reserve";
const FEES_BASE: &str = "fees/base_atomic";
const FEES_PER_KIB: &str = "fees/per_kib_atomic";
const FEES_PER_SPEND_PROOF: &str = "fees/per_spend_proof_atomic";
const FEES_PER_OUTPUT_PROOF: &str = "fees/per_output_proof_atomic";
const FEES_NEW_POSITION_SURCHARGE: &str = "fees/new_position_surcharge_atomic";
const FEES_VALIDATOR_REGISTRATION_SURCHARGE: &str = "fees/validator_registration_surcharge_atomic";
const GENESIS_UNCLAIMED: &str = "genesis/unclaimed_total";
const STAKING_PARAMETERS: &str = "staking/parameters";
const STAKING_VALIDATOR_PREFIX: &str = "staking/validators/";
const STAKING_POOL_PREFIX: &str = "staking/pools/";
const STAKING_POSITION_PREFIX: &str = "staking/positions/";
const STAKING_CAPACITY_PREFIX: &str = "staking/capacity/";
const STAKING_EFFECTIVE_SCHEDULE: &str = "staking/effective_schedule";

const SUBSTORES: &[&str] = &[
    "shielded",
    "transactions",
    "execution",
    "compact",
    "supply",
    "emission",
    "fees",
    "genesis",
    "staking",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisConfig {
    pub chain_context: Hash32,
    pub native_asset_id: Hash32,
    pub protocol_version: u64,
    pub max_block_bytes: u64,
    pub max_tx_lifetime_blocks: u64,
    pub max_envelope_bytes: usize,
    pub anchor_retention_blocks: u64,
    pub monetary_policy: MonetaryPolicy,
    pub fee_policy: FeePolicy,
    pub genesis_allocation: GenesisAllocation,
    /// Complete height-zero staking state from the signed genesis manifest.
    pub genesis_staking: StakingBook,
    /// Ordered shielded commitments assigned by the signed genesis manifest.
    pub genesis_commitments: Vec<Hash32>,
    pub genesis_execution_hash: Hash32,
    pub genesis_compact_hash: Hash32,
}

impl GenesisConfig {
    fn validate(&self) -> Result<()> {
        if self.protocol_version == 0 {
            return Err(Error::InvalidConfig(
                "protocol_version must be greater than zero",
            ));
        }
        if self.max_block_bytes == 0 {
            return Err(Error::InvalidConfig(
                "max_block_bytes must be greater than zero",
            ));
        }
        if self.max_tx_lifetime_blocks == 0 {
            return Err(Error::InvalidConfig(
                "max_tx_lifetime_blocks must be greater than zero",
            ));
        }
        if self.max_envelope_bytes == 0 {
            return Err(Error::InvalidConfig(
                "max_envelope_bytes must be greater than zero",
            ));
        }
        if self.anchor_retention_blocks == 0 {
            return Err(Error::InvalidConfig(
                "anchor_retention_blocks must be greater than zero",
            ));
        }
        SupplyState::genesis(&self.monetary_policy, self.genesis_allocation.clone())?;
        self.genesis_staking.validate()?;
        if self.genesis_staking.chain_context() != self.chain_context {
            return Err(Error::InvalidConfig(
                "genesis staking chain context differs",
            ));
        }
        let staking_totals = self.genesis_staking.totals()?;
        if staking_totals.pooled_assets != self.genesis_allocation.stake
            || staking_totals.pending_assets != self.genesis_allocation.pending_delegation
        {
            return Err(Error::InvalidConfig(
                "genesis staking totals differ from supply allocation",
            ));
        }
        for class in [
            FeeClass::Standard,
            FeeClass::NewPosition,
            FeeClass::ValidatorRegistration,
        ] {
            let maximum_minimum =
                self.fee_policy
                    .minimum_fee(self.max_envelope_bytes, 8, 8, class)?;
            if maximum_minimum.value() > self.monetary_policy.genesis_supply.value() {
                return Err(Error::InvalidConfig(
                    "maximum minimum fee exceeds genesis supply",
                ));
            }
        }
        u64::try_from(self.max_envelope_bytes)
            .map_err(|_| Error::InvalidConfig("max_envelope_bytes does not fit in u64"))?;
        let mut unique = BTreeSet::new();
        for bytes in &self.genesis_commitments {
            StateCommitment::try_from(*bytes)
                .map_err(|_| Error::InvalidConfig("invalid genesis commitment"))?;
            if !unique.insert(*bytes) {
                return Err(Error::InvalidConfig("duplicate genesis commitment"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("storage operation failed: {0}")]
    Storage(#[from] anyhow::Error),
    #[error("transaction rejected: {0}")]
    Transaction(#[from] bit_transaction::Error),
    #[error("supply accounting failed: {0}")]
    Accounting(#[from] bit_emission::Error),
    #[error("staking state failed: {0}")]
    Staking(#[from] bit_staking::Error),
    #[error("invalid state configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("stored state is corrupt or incompatible: {0}")]
    CorruptState(String),
    #[error("expected next state height {expected}, got {actual}")]
    HeightMismatch { expected: u64, actual: u64 },
    #[error("block time regressed from {previous} to {actual}")]
    BlockTimeRegression { previous: u64, actual: u64 },
    #[error("transaction anchor is not retained")]
    UnknownAnchor,
    #[error("transaction is already applied")]
    TransactionAlreadyApplied,
    #[error("nullifier is already spent")]
    NullifierAlreadySpent,
    #[error("transaction repeats a nullifier")]
    DuplicateNullifier,
    #[error("output commitment is not a canonical field element")]
    InvalidOutputCommitment,
    #[error("state commitment tree is full")]
    CommitmentTreeFull,
    #[error("invalid epoch system phase: {0}")]
    InvalidSystemPhase(&'static str),
    #[error("next_validators_hash does not match the persisted H+1 validator set")]
    NextValidatorsHashMismatch,
    #[error(
        "HALT_NO_SAFE_VALIDATOR_SET: validator updates would remove the last effective validator"
    )]
    NoSafeValidatorSet,
    #[error("effective validator set height {requested} is outside [{first}, {last}]")]
    EffectiveValidatorSetUnavailable {
        requested: u64,
        first: u64,
        last: u64,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSummary {
    pub storage_schema_version: u32,
    pub state_height: u64,
    pub block_time_seconds: u64,
    pub storage_version: u64,
    pub app_hash: Hash32,
    pub shielded_tree_root: Hash32,
    pub supply: SupplyAudit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochRewardSettlement {
    pub epoch: u64,
    pub issuance_quota: Amount,
    pub distributed: Amount,
    pub fee_reserve_remainder: Amount,
    pub validator_rewards: Vec<ValidatorReward>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemBlockOutcome {
    pub last_commit_height: Option<u64>,
    pub reward_settlement: Option<EpochRewardSettlement>,
    pub activations: Vec<(Hash32, ActivationOutcome)>,
    pub validator_set: Option<Vec<ValidatorPower>>,
    pub validator_updates: Vec<ConsensusPowerUpdate>,
}

/// Three-height rolling schedule. At committed height H it stores the exact
/// CometBFT sets for H, H+1, and H+2. Historical JMT versions retain the same
/// three-height view without copying a full set into a new key every block.
#[derive(Clone, Debug, Eq, PartialEq)]
struct EffectiveValidatorSchedule {
    base_height: u64,
    sets: [EffectiveValidatorSet; 3],
}

impl EffectiveValidatorSchedule {
    fn genesis(set: EffectiveValidatorSet) -> Self {
        Self {
            base_height: 0,
            sets: [set.clone(), set.clone(), set],
        }
    }

    fn effective_set_at(&self, height: u64) -> Result<&EffectiveValidatorSet> {
        let last = self
            .base_height
            .checked_add(2)
            .ok_or_else(|| Error::CorruptState("effective set height overflow".to_owned()))?;
        let index = height
            .checked_sub(self.base_height)
            .and_then(|offset| (offset <= 2).then_some(offset as usize));
        index
            .map(|index| &self.sets[index])
            .ok_or(Error::EffectiveValidatorSetUnavailable {
                requested: height,
                first: self.base_height,
                last,
            })
    }

    fn validate_block_context(
        &self,
        height: u64,
        last_commit: Option<&[CommitVote]>,
        next_validators_hash: Hash32,
    ) -> Result<()> {
        let expected_base = height
            .checked_sub(1)
            .ok_or(Error::InvalidSystemPhase("block height is zero"))?;
        if self.base_height != expected_base {
            return Err(Error::InvalidSystemPhase(
                "effective validator schedule is not aligned with block height",
            ));
        }
        let next_height = height
            .checked_add(1)
            .ok_or(Error::InvalidSystemPhase("next validator height overflow"))?;
        if self.effective_set_at(next_height)?.comet_hash() != next_validators_hash {
            return Err(Error::NextValidatorsHashMismatch);
        }
        if height == 1 {
            if last_commit.is_some_and(|votes| !votes.is_empty()) {
                return Err(Error::InvalidSystemPhase(
                    "height one cannot contain a previous commit",
                ));
            }
        } else {
            self.effective_set_at(height - 1)?
                .validate_last_commit(last_commit.ok_or(Error::InvalidSystemPhase(
                    "previous commit is required after height one",
                ))?)?;
        }
        Ok(())
    }

    fn advance(&mut self, committed_height: u64, h_plus_two: EffectiveValidatorSet) -> Result<()> {
        let expected = self
            .base_height
            .checked_add(1)
            .ok_or_else(|| Error::CorruptState("effective set height overflow".to_owned()))?;
        if committed_height != expected {
            return Err(Error::InvalidSystemPhase(
                "effective validator schedule advance is out of order",
            ));
        }
        self.sets = [self.sets[1].clone(), self.sets[2].clone(), h_plus_two];
        self.base_height = committed_height;
        Ok(())
    }

    fn encode_persistent(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.push(1);
        out.extend_from_slice(&self.base_height.to_be_bytes());
        for set in &self.sets {
            let bytes = set.encode_persistent()?;
            let len = u32::try_from(bytes.len()).map_err(|_| {
                Error::CorruptState("effective set encoding is too large".to_owned())
            })?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }

    fn decode_persistent(bytes: &[u8]) -> Result<Self> {
        let mut offset = 0usize;
        if take_schedule(bytes, &mut offset, 1)?[0] != 1 {
            return Err(Error::CorruptState(
                "unsupported effective validator schedule version".to_owned(),
            ));
        }
        let base_height = u64::from_be_bytes(
            take_schedule(bytes, &mut offset, 8)?
                .try_into()
                .expect("slice length is checked"),
        );
        let mut sets = Vec::with_capacity(3);
        for _ in 0..3 {
            let len = u32::from_be_bytes(
                take_schedule(bytes, &mut offset, 4)?
                    .try_into()
                    .expect("slice length is checked"),
            );
            let len = usize::try_from(len)
                .map_err(|_| Error::CorruptState("effective set length overflow".to_owned()))?;
            sets.push(EffectiveValidatorSet::decode_persistent(take_schedule(
                bytes,
                &mut offset,
                len,
            )?)?);
        }
        if offset != bytes.len() {
            return Err(Error::CorruptState(
                "trailing effective validator schedule bytes".to_owned(),
            ));
        }
        Ok(Self {
            base_height,
            sets: sets
                .try_into()
                .expect("exactly three effective sets were decoded"),
        })
    }
}

pub struct QueryProof {
    pub key: String,
    pub value: Option<Vec<u8>>,
    pub proof: MerkleProof,
    pub app_hash: Hash32,
    pub storage_version: u64,
}

impl QueryProof {
    /// Verify this membership or non-membership proof against its app hash.
    pub fn verify(&self) -> anyhow::Result<()> {
        let (path, proof_specs) = proof_path(&self.key);
        let root = MerkleRoot {
            hash: self.app_hash.to_vec(),
        };
        match &self.value {
            Some(value) => self
                .proof
                .verify_membership(&proof_specs, root, path, value.clone(), 0),
            None => self.proof.verify_non_membership(&proof_specs, root, path),
        }
    }
}

pub struct PersistentState {
    storage: Storage,
    config: GenesisConfig,
    staking: RwLock<StakingBook>,
}

impl PersistentState {
    /// Open a database, creating a height-zero state if the path is empty.
    /// Existing state is validated against every immutable configuration field.
    pub async fn open(path: PathBuf, config: GenesisConfig) -> Result<Self> {
        config.validate()?;
        let prefixes = SUBSTORES
            .iter()
            .map(|prefix| (*prefix).to_owned())
            .collect();
        let storage = Storage::load(path, prefixes).await?;

        if storage.latest_version() == u64::MAX {
            if let Err(error) = initialize_genesis(&storage, &config).await {
                storage.release().await;
                return Err(error);
            }
        }

        if let Err(error) = validate_storage(&storage, &config).await {
            storage.release().await;
            return Err(error);
        }

        let staking =
            match read_staking_book(&storage.latest_snapshot(), config.chain_context).await {
                Ok(staking) => staking,
                Err(error) => {
                    storage.release().await;
                    return Err(error);
                }
            };

        Ok(Self {
            storage,
            config,
            staking: RwLock::new(staking),
        })
    }

    pub async fn summary(&self) -> Result<StateSummary> {
        summary_from_snapshot(self.storage.latest_snapshot(), &self.config.monetary_policy).await
    }

    pub async fn begin_block(
        &self,
        height: u64,
        execution_hash: Hash32,
        compact_hash: Hash32,
    ) -> Result<BlockSession<'_>> {
        self.begin_block_preview(height, execution_hash, compact_hash)
            .await
    }

    pub async fn begin_block_preview(
        &self,
        height: u64,
        execution_hash: Hash32,
        compact_hash: Hash32,
    ) -> Result<BlockSession<'_>> {
        let current_time =
            read_u64(&self.storage.latest_snapshot(), META_BLOCK_TIME_SECONDS).await?;
        let preview_time = current_time
            .checked_add(1)
            .ok_or_else(|| Error::CorruptState("block time seconds overflow".to_owned()))?;
        self.begin_block_at(height, preview_time, execution_hash, compact_hash)
            .await
    }

    pub async fn begin_block_at(
        &self,
        height: u64,
        block_time_seconds: u64,
        execution_hash: Hash32,
        compact_hash: Hash32,
    ) -> Result<BlockSession<'_>> {
        let snapshot = self.storage.latest_snapshot();
        let current_height = read_u64(&snapshot, META_HEIGHT).await?;
        let expected = current_height
            .checked_add(1)
            .ok_or_else(|| Error::CorruptState("state height overflow".to_owned()))?;
        if height != expected {
            return Err(Error::HeightMismatch {
                expected,
                actual: height,
            });
        }
        let previous_time = read_u64(&snapshot, META_BLOCK_TIME_SECONDS).await?;
        if block_time_seconds < previous_time {
            return Err(Error::BlockTimeRegression {
                previous: previous_time,
                actual: block_time_seconds,
            });
        }

        let tree = read_tree(&snapshot).await?;
        let stored_root = read_hash32(&snapshot, TREE_ROOT).await?;
        if tree_root_bytes(&tree) != stored_root {
            return Err(Error::CorruptState(
                "shielded tree frontier does not match stored root".to_owned(),
            ));
        }
        let supply = read_supply(&snapshot).await?;
        supply.validate_at_height(&self.config.monetary_policy, current_height)?;
        let staking = self
            .staking
            .read()
            .map_err(|_| Error::CorruptState("staking memory lock is poisoned".to_owned()))?
            .clone();
        validate_staking_supply(&staking, &supply)?;
        let effective_schedule = read_effective_schedule(&snapshot).await?;
        if effective_schedule.base_height != current_height {
            return Err(Error::CorruptState(
                "effective validator schedule height differs from state height".to_owned(),
            ));
        }
        let logical_height = current_height
            .checked_add(2)
            .ok_or_else(|| Error::CorruptState("validator set height overflow".to_owned()))?;
        if effective_schedule.effective_set_at(logical_height)?
            != &staking.effective_validator_set()?
        {
            return Err(Error::CorruptState(
                "logical staking set differs from the H+2 effective set".to_owned(),
            ));
        }

        Ok(BlockSession {
            owner: self,
            delta: StateDelta::new(snapshot),
            tree,
            height,
            block_time_seconds,
            execution_hash,
            compact_hash,
            supply,
            staking,
            effective_schedule,
            staking_touches: StakingTouches::default(),
            system_phases_staged: false,
            transaction_count: 0,
        })
    }

    pub async fn query_latest_with_proof(&self, key: &str) -> Result<QueryProof> {
        if key.is_empty() {
            return Err(Error::InvalidConfig("query key must not be empty"));
        }
        let snapshot = self.storage.latest_snapshot();
        let app_hash = snapshot.root_hash().await?.0;
        let storage_version = snapshot.version();
        let (value, proof) = snapshot.get_with_proof(key.as_bytes().to_vec()).await?;
        Ok(QueryProof {
            key: key.to_owned(),
            value,
            proof,
            app_hash,
            storage_version,
        })
    }

    pub async fn supply_audit(&self) -> Result<SupplyAudit> {
        let snapshot = self.storage.latest_snapshot();
        let height = read_u64(&snapshot, META_HEIGHT).await?;
        let supply = read_supply(&snapshot).await?;
        Ok(supply.audit_at_height(&self.config.monetary_policy, height)?)
    }

    /// Return one of the three consensus sets retained at the latest state
    /// version. Older committed heights remain recoverable from historical JMT
    /// versions when the historical query surface is exposed.
    pub async fn effective_validator_set_at(&self, height: u64) -> Result<EffectiveValidatorSet> {
        Ok(read_effective_schedule(&self.storage.latest_snapshot())
            .await?
            .effective_set_at(height)?
            .clone())
    }

    /// Hash CometBFT must place in the height-H request for its H+1 set.
    pub async fn expected_next_validators_hash(&self, block_height: u64) -> Result<Hash32> {
        let snapshot = self.storage.latest_snapshot();
        let current_height = read_u64(&snapshot, META_HEIGHT).await?;
        let expected = current_height
            .checked_add(1)
            .ok_or_else(|| Error::CorruptState("state height overflow".to_owned()))?;
        if block_height != expected {
            return Err(Error::HeightMismatch {
                expected,
                actual: block_height,
            });
        }
        let set_height = block_height
            .checked_add(1)
            .ok_or_else(|| Error::CorruptState("validator set height overflow".to_owned()))?;
        Ok(read_effective_schedule(&snapshot)
            .await?
            .effective_set_at(set_height)?
            .comet_hash())
    }

    pub fn staking_book(&self) -> Result<StakingBook> {
        self.staking
            .read()
            .map(|book| book.clone())
            .map_err(|_| Error::CorruptState("staking memory lock is poisoned".to_owned()))
    }

    pub async fn anchor_is_retained(&self, anchor: &Hash32) -> Result<bool> {
        Ok(self
            .storage
            .latest_snapshot()
            .get_raw(&anchor_lookup_key(anchor))
            .await?
            .is_some())
    }

    pub async fn nullifier_is_spent(&self, nullifier: &Hash32) -> Result<bool> {
        Ok(self
            .storage
            .latest_snapshot()
            .get_raw(&nullifier_key(nullifier))
            .await?
            .is_some())
    }

    pub async fn transaction_is_applied(&self, tx_id: &Hash32) -> Result<bool> {
        Ok(self
            .storage
            .latest_snapshot()
            .get_raw(&transaction_key(tx_id))
            .await?
            .is_some())
    }

    /// Commit a previously prepared block in one durable RocksDB batch.
    pub fn commit(&self, prepared: PreparedBlock) -> Result<CommitReceipt> {
        let expected_root = prepared.app_hash;
        let committed_root = self.storage.commit_batch(prepared.batch)?.0;
        if committed_root != expected_root {
            return Err(Error::CorruptState(
                "committed JMT root differs from prepared root".to_owned(),
            ));
        }
        *self
            .staking
            .write()
            .map_err(|_| Error::CorruptState("staking memory lock is poisoned".to_owned()))? =
            prepared.staking;
        Ok(CommitReceipt {
            state_height: prepared.state_height,
            block_time_seconds: prepared.block_time_seconds,
            storage_version: prepared.storage_version,
            app_hash: committed_root,
            shielded_tree_root: prepared.shielded_tree_root,
            supply: prepared.supply,
            staking: prepared.staking_totals,
            transaction_count: prepared.transaction_count,
        })
    }

    pub async fn close(self) {
        self.storage.release().await;
    }
}

pub struct BlockSession<'a> {
    owner: &'a PersistentState,
    delta: StateDelta<Snapshot>,
    tree: Tree,
    height: u64,
    block_time_seconds: u64,
    execution_hash: Hash32,
    compact_hash: Hash32,
    supply: SupplyState,
    staking: StakingBook,
    effective_schedule: EffectiveValidatorSchedule,
    staking_touches: StakingTouches,
    system_phases_staged: bool,
    transaction_count: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct StakingTouches {
    validators: BTreeSet<Hash32>,
    pools: BTreeSet<Hash32>,
    positions: BTreeSet<Hash32>,
    capacity_epochs: BTreeSet<u64>,
}

struct StakingAuthorizationSnapshot<'a>(&'a StakingBook);

impl ActionAuthorizationView for StakingAuthorizationSnapshot<'_> {
    fn validator_operator(&self, validator_id: &Hash32) -> Option<Hash32> {
        self.0
            .validator(validator_id)
            .map(|validator| validator.operator_pubkey)
    }

    fn validator_sequence(&self, validator_id: &Hash32) -> Option<u64> {
        self.0
            .validator(validator_id)
            .map(|validator| validator.sequence)
    }

    fn pending_position(&self, position_id: &Hash32) -> Option<PendingPositionAuthorization> {
        self.0.position(position_id).and_then(|position| {
            (position.status == PositionStatus::Pending).then_some(PendingPositionAuthorization {
                owner: position.owner_pubkey,
                sequence: position.sequence,
                release: position.pending_amount,
            })
        })
    }
}

impl BlockSession<'_> {
    /// Dispatch one canonical user transaction through the verifier for its
    /// action. All enabled actions share the same block overlay.
    pub async fn verify_and_stage_transaction(&mut self, envelope_bytes: &[u8]) -> Result<Hash32> {
        let envelope = Envelope::decode_canonical(
            envelope_bytes,
            self.owner.config.max_envelope_bytes,
            self.height,
            self.owner.config.max_tx_lifetime_blocks,
        )
        .map_err(bit_transaction::Error::from)?;
        let body = envelope
            .validate(self.height, self.owner.config.max_tx_lifetime_blocks)
            .map_err(bit_transaction::Error::from)?;
        match body.action {
            Action::Transfer => Ok(self.verify_and_stage_transfer(envelope_bytes).await?.tx_id),
            Action::RegisterValidator { .. }
            | Action::Delegate { .. }
            | Action::CancelPending { .. }
            | Action::UpdateValidator { .. }
            | Action::UnjailValidator { .. }
            | Action::RotateConsensusKey { .. }
            | Action::ClaimCommission { .. } => Ok(self
                .verify_and_stage_staking_action(envelope_bytes)
                .await?
                .shielded
                .tx_id),
            _ => Err(bit_transaction::Error::UnsupportedAction.into()),
        }
    }

    /// Execute the deterministic pre-transaction consensus phases for this
    /// block. At height greater than one the supplied votes are CometBFT's
    /// actual validator set for the previous height.
    pub fn stage_consensus_system(
        &mut self,
        last_commit: Option<&[CommitVote]>,
        next_validators_hash: Hash32,
    ) -> Result<SystemBlockOutcome> {
        if self.system_phases_staged {
            return Err(Error::InvalidSystemPhase(
                "consensus system phases are already staged",
            ));
        }

        let checkpoint = (
            self.supply.clone(),
            self.staking.clone(),
            self.effective_schedule.clone(),
            self.staking_touches.clone(),
        );
        let outcome = self.stage_consensus_system_inner(last_commit, next_validators_hash);
        if outcome.is_err() {
            self.supply = checkpoint.0;
            self.staking = checkpoint.1;
            self.effective_schedule = checkpoint.2;
            self.staking_touches = checkpoint.3;
        }
        outcome
    }

    fn stage_consensus_system_inner(
        &mut self,
        last_commit: Option<&[CommitVote]>,
        next_validators_hash: Hash32,
    ) -> Result<SystemBlockOutcome> {
        self.effective_schedule.validate_block_context(
            self.height,
            last_commit,
            next_validators_hash,
        )?;

        let last_commit_height = (self.height > 1).then_some(self.height - 1);
        let mut updates = BTreeMap::new();
        if let Some(last_commit_height) = last_commit_height {
            let votes = last_commit.expect("validated above for height greater than one");
            let score_epoch =
                (last_commit_height - 1) / self.owner.config.monetary_policy.epoch_blocks;
            let commit_outcome = self.staking.record_last_commit(
                score_epoch,
                self.height,
                self.block_time_seconds,
                votes,
            )?;
            self.staking_touches
                .validators
                .extend(commit_outcome.observed_validators);
            updates.extend(
                commit_outcome
                    .validator_updates
                    .into_iter()
                    .map(|update| (update.consensus_pubkey, update.power)),
            );
        }

        let mut reward_settlement = None;
        let mut activations = Vec::new();
        let mut validator_set = None;
        if self.height > 1
            && (self.height - 1) % self.owner.config.monetary_policy.epoch_blocks == 0
        {
            let boundary_epoch = (self.height - 1) / self.owner.config.monetary_policy.epoch_blocks;
            let settled_epoch = boundary_epoch
                .checked_sub(1)
                .ok_or(Error::InvalidSystemPhase("reward epoch underflow"))?;
            let scores = self.staking.take_epoch_scores(settled_epoch)?;
            self.staking_touches
                .validators
                .extend(scores.keys().copied());
            reward_settlement = Some(self.stage_epoch_reward_settlement(&scores)?);
            activations = self.stage_epoch_staking_activation()?;
            let transition = self.stage_validator_set_transition()?;
            for update in &transition.updates {
                updates.insert(update.consensus_pubkey, update.power);
            }
            validator_set = Some(transition.selected);
        }
        let validator_updates: Vec<_> = updates
            .into_iter()
            .map(|(consensus_pubkey, power)| ConsensusPowerUpdate {
                consensus_pubkey,
                power,
            })
            .collect();
        let h_plus_one = self
            .height
            .checked_add(1)
            .ok_or(Error::InvalidSystemPhase("validator set height overflow"))?;
        let base_set = self
            .effective_schedule
            .effective_set_at(h_plus_one)?
            .clone();
        let h_plus_two = base_set.apply_updates(&validator_updates)?;
        if !base_set.validators().is_empty() && h_plus_two.validators().is_empty() {
            return Err(Error::NoSafeValidatorSet);
        }
        self.effective_schedule.advance(self.height, h_plus_two)?;
        self.system_phases_staged = true;

        Ok(SystemBlockOutcome {
            last_commit_height,
            reward_settlement,
            activations,
            validator_set,
            validator_updates,
        })
    }

    fn boundary_epoch(&self) -> Result<u64> {
        let epoch_blocks = self.owner.config.monetary_policy.epoch_blocks;
        if self.height <= 1 || (self.height - 1) % epoch_blocks != 0 {
            return Err(Error::InvalidSystemPhase(
                "operation is only valid on an epoch first block",
            ));
        }
        Ok((self.height - 1) / epoch_blocks)
    }

    /// Advance the fixed issuance schedule for the epoch that ended before
    /// this boundary block. Reward allocation is a later system subphase.
    pub fn stage_epoch_issuance(&mut self, has_eligible_stake: bool) -> Result<Amount> {
        let boundary_epoch = self.boundary_epoch()?;
        let expected = self
            .supply
            .completed_epochs
            .checked_add(1)
            .ok_or(bit_emission::Error::Overflow)?;
        if expected != boundary_epoch
            || completed_epochs_after_height(
                self.height,
                self.owner.config.monetary_policy.epoch_blocks,
            )? != boundary_epoch
        {
            return Err(Error::InvalidSystemPhase(
                "issuance settlement is missing or duplicated",
            ));
        }
        Ok(self
            .supply
            .settle_next_epoch(&self.owner.config.monetary_policy, has_eligible_stake)?)
    }

    /// Atomically settle the exact epoch issuance and all accumulated fee
    /// reserve using scores produced from that epoch's actual validator set.
    pub fn stage_epoch_reward_settlement(
        &mut self,
        scores: &BTreeMap<Hash32, u128>,
    ) -> Result<EpochRewardSettlement> {
        let boundary_epoch = self.boundary_epoch()?;
        let expected = self
            .supply
            .completed_epochs
            .checked_add(1)
            .ok_or(bit_emission::Error::Overflow)?;
        if expected != boundary_epoch {
            return Err(Error::InvalidSystemPhase(
                "reward settlement is missing or duplicated",
            ));
        }

        let mut staking = self.staking.clone();
        let mut supply = self.supply.clone();
        let has_eligible_score = staking.reward_score_total(scores)? > 0;
        let issuance_quota =
            supply.settle_next_epoch(&self.owner.config.monetary_policy, has_eligible_score)?;
        let available = supply.fee_reserve;
        let validator_rewards =
            staking.distribute_epoch_rewards(boundary_epoch, available, scores)?;
        let distributed_value = validator_rewards.iter().try_fold(0u128, |total, reward| {
            total
                .checked_add(reward.gross_reward.value())
                .ok_or(bit_emission::Error::Overflow)
        })?;
        let stake_reward_value = validator_rewards.iter().try_fold(0u128, |total, reward| {
            total
                .checked_add(reward.stake_reward.value())
                .ok_or(bit_emission::Error::Overflow)
        })?;
        let commission_reward_value =
            validator_rewards.iter().try_fold(0u128, |total, reward| {
                total
                    .checked_add(reward.commission_reward.value())
                    .ok_or(bit_emission::Error::Overflow)
            })?;
        let distributed = Amount::new(distributed_value).map_err(bit_emission::Error::from)?;
        supply.distribute_fee_reserve(
            &self.owner.config.monetary_policy,
            Amount::new(stake_reward_value).map_err(bit_emission::Error::from)?,
            Amount::new(commission_reward_value).map_err(bit_emission::Error::from)?,
        )?;
        validate_staking_supply(&staking, &supply)?;

        self.staking_touches
            .pools
            .extend(staking.pools().map(|pool| pool.validator_id));
        self.staking_touches
            .validators
            .extend(validator_rewards.iter().map(|reward| reward.validator_id));
        self.staking = staking;
        self.supply = supply;
        Ok(EpochRewardSettlement {
            epoch: boundary_epoch,
            issuance_quota,
            distributed,
            fee_reserve_remainder: self.supply.fee_reserve,
            validator_rewards,
        })
    }

    /// Stage a validator registration after the execution layer has verified
    /// operator authorization, consensus-key proof of possession, and fee inputs.
    pub fn stage_authorized_validator_registration(
        &mut self,
        validator_id: Hash32,
        operator_pubkey: Hash32,
        consensus_pubkey: Hash32,
        commission_bps: u16,
        fee: Amount,
    ) -> Result<()> {
        self.stage_authorized_validator_registration_with_metadata(
            validator_id,
            operator_pubkey,
            consensus_pubkey,
            commission_bps,
            "validator".to_owned(),
            String::new(),
            String::new(),
            fee,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn stage_authorized_validator_registration_with_metadata(
        &mut self,
        validator_id: Hash32,
        operator_pubkey: Hash32,
        consensus_pubkey: Hash32,
        commission_bps: u16,
        display_name: String,
        website: String,
        description: String,
        fee: Amount,
    ) -> Result<()> {
        let mut staking = self.staking.clone();
        let mut supply = self.supply.clone();
        staking.register_validator_with_metadata_at(
            validator_id,
            operator_pubkey,
            consensus_pubkey,
            commission_bps,
            display_name,
            website,
            description,
            self.height,
            self.block_time_seconds,
        )?;
        supply.charge_shielded_fee(&self.owner.config.monetary_policy, fee)?;
        validate_staking_supply(&staking, &supply)?;
        self.staking = staking;
        self.supply = supply;
        self.staking_touches.validators.insert(validator_id);
        self.staking_touches.pools.insert(validator_id);
        Ok(())
    }

    /// Stage a Delegate after Spend, owner, and conditional operator signatures
    /// have been verified against the final transaction effect.
    #[allow(clippy::too_many_arguments)]
    pub fn stage_authorized_pending_delegation(
        &mut self,
        current_epoch: u64,
        position_id: Hash32,
        owner_pubkey: Hash32,
        validator_id: Hash32,
        deposit: Amount,
        min_shares: Amount,
        self_bond: bool,
        recovery_receipt: Vec<u8>,
        fee: Amount,
    ) -> Result<()> {
        let mut staking = self.staking.clone();
        let mut supply = self.supply.clone();
        staking.open_pending_delegation(
            current_epoch,
            self.height,
            position_id,
            owner_pubkey,
            validator_id,
            deposit,
            min_shares,
            self_bond,
            recovery_receipt,
        )?;
        supply.open_pending_delegation(&self.owner.config.monetary_policy, deposit, fee)?;
        validate_staking_supply(&staking, &supply)?;
        self.staking = staking;
        self.supply = supply;
        self.staking_touches.positions.insert(position_id);
        self.staking_touches.pools.insert(validator_id);
        self.staking_touches.capacity_epochs.insert(
            current_epoch
                .checked_add(1)
                .ok_or(bit_staking::Error::Overflow)?,
        );
        Ok(())
    }

    /// Settle all due activation records in their canonical order. Principal
    /// enters P only for successful activations; refundable entries remain in D.
    pub fn stage_epoch_staking_activation(&mut self) -> Result<Vec<(Hash32, ActivationOutcome)>> {
        let current_epoch = self.boundary_epoch()?;
        if self.supply.completed_epochs != current_epoch {
            return Err(Error::InvalidSystemPhase(
                "issuance must settle before staking activation",
            ));
        }
        if self
            .staking
            .pools()
            .any(|pool| pool.last_settled_epoch != current_epoch)
        {
            return Err(Error::InvalidSystemPhase(
                "rewards must settle before staking activation",
            ));
        }
        let due: BTreeMap<Hash32, (Amount, Hash32, bool)> = self
            .staking
            .positions()
            .filter(|position| {
                position.status == PositionStatus::Pending
                    && position.activation_epoch <= current_epoch
            })
            .map(|position| {
                (
                    position.position_id,
                    (
                        position.pending_amount,
                        position.validator_id,
                        position.self_bond,
                    ),
                )
            })
            .collect();
        let mut staking = self.staking.clone();
        let mut supply = self.supply.clone();
        let outcomes = staking.activate_epoch(current_epoch)?;
        for (id, outcome) in &outcomes {
            let (deposit, validator_id, self_bond) = due
                .get(id)
                .copied()
                .ok_or_else(|| Error::CorruptState("activation outcome was not due".to_owned()))?;
            if matches!(outcome, ActivationOutcome::Activated { .. }) {
                supply.activate_pending_delegation(&self.owner.config.monetary_policy, deposit)?;
            }
            self.staking_touches.positions.insert(*id);
            self.staking_touches.pools.insert(validator_id);
            if self_bond {
                self.staking_touches.validators.insert(validator_id);
            }
        }
        validate_staking_supply(&staking, &supply)?;
        self.staking = staking;
        self.supply = supply;
        Ok(outcomes)
    }

    pub fn stage_authorized_pending_cancel(
        &mut self,
        position_id: Hash32,
        expected_sequence: u64,
        fee: Amount,
    ) -> Result<Amount> {
        let position = self
            .staking
            .position(&position_id)
            .ok_or(bit_staking::Error::PositionNotFound)?
            .clone();
        let mut staking = self.staking.clone();
        let mut supply = self.supply.clone();
        let released = staking.cancel_pending(&position_id, expected_sequence)?;
        supply.release_pending_delegation(&self.owner.config.monetary_policy, released, fee)?;
        validate_staking_supply(&staking, &supply)?;
        self.staking = staking;
        self.supply = supply;
        self.staking_touches.positions.insert(position_id);
        self.staking_touches.pools.insert(position.validator_id);
        self.staking_touches
            .capacity_epochs
            .insert(position.activation_epoch);
        Ok(released)
    }

    pub fn stage_authorized_pending_refund(
        &mut self,
        position_id: Hash32,
        expected_sequence: u64,
        fee: Amount,
    ) -> Result<Amount> {
        let mut staking = self.staking.clone();
        let mut supply = self.supply.clone();
        let released = staking.refund_pending(&position_id, expected_sequence)?;
        supply.release_pending_delegation(&self.owner.config.monetary_policy, released, fee)?;
        validate_staking_supply(&staking, &supply)?;
        self.staking = staking;
        self.supply = supply;
        self.staking_touches.positions.insert(position_id);
        Ok(released)
    }

    pub fn stage_validator_set_selection(&mut self) -> Result<Vec<ValidatorPower>> {
        Ok(self.stage_validator_set_transition()?.selected)
    }

    /// Apply scheduled validator changes and return the exact key/power delta
    /// required by CometBFT. Removed or rotated-out keys receive power zero.
    pub fn stage_validator_set_transition(&mut self) -> Result<ValidatorSetTransition> {
        let previous_records: BTreeMap<Hash32, (bit_staking::ValidatorStatus, u64)> = self
            .staking
            .validators()
            .map(|validator| {
                (
                    validator.validator_id,
                    (validator.status, validator.voting_power),
                )
            })
            .collect();
        let previous_set: BTreeMap<[u8; 32], u64> = self
            .staking
            .validators()
            .filter(|validator| validator.voting_power != 0)
            .map(|validator| (validator.consensus_pubkey, validator.voting_power))
            .collect();
        let mut staking = self.staking.clone();
        let current_epoch = self.boundary_epoch()?;
        let scheduled = staking.apply_scheduled_validator_changes(
            current_epoch,
            self.height,
            self.block_time_seconds,
        )?;
        let selected = staking.apply_validator_set()?;
        let next_set: BTreeMap<[u8; 32], u64> = selected
            .iter()
            .map(|validator| (validator.consensus_pubkey, validator.power))
            .collect();
        let keys: BTreeSet<[u8; 32]> = previous_set
            .keys()
            .chain(next_set.keys())
            .copied()
            .collect();
        let updates = keys
            .into_iter()
            .filter_map(|consensus_pubkey| {
                let previous = previous_set.get(&consensus_pubkey).copied().unwrap_or(0);
                let next = next_set.get(&consensus_pubkey).copied().unwrap_or(0);
                (previous != next).then_some(ConsensusPowerUpdate {
                    consensus_pubkey,
                    power: next,
                })
            })
            .collect();
        for validator in staking.validators() {
            if previous_records.get(&validator.validator_id)
                != Some(&(validator.status, validator.voting_power))
            {
                self.staking_touches
                    .validators
                    .insert(validator.validator_id);
            }
        }
        self.staking_touches.validators.extend(scheduled);
        self.staking = staking;
        Ok(ValidatorSetTransition { selected, updates })
    }

    /// Verify and stage a canonical Transfer against the current block overlay.
    pub async fn verify_and_stage_transfer(
        &mut self,
        envelope_bytes: &[u8],
    ) -> Result<VerifiedTransfer> {
        // Decode once for cheap anchor and replay checks before proof verification.
        let envelope = Envelope::decode_canonical(
            envelope_bytes,
            self.owner.config.max_envelope_bytes,
            self.height,
            self.owner.config.max_tx_lifetime_blocks,
        )
        .map_err(bit_transaction::Error::from)?;
        let body = envelope
            .validate(self.height, self.owner.config.max_tx_lifetime_blocks)
            .map_err(bit_transaction::Error::from)?;
        if body.chain_context != self.owner.config.chain_context {
            return Err(bit_transaction::Error::WrongChainContext.into());
        }
        if !matches!(body.action, Action::Transfer) {
            return Err(bit_transaction::Error::UnsupportedAction.into());
        }
        if self
            .delta
            .get_raw(&anchor_lookup_key(&body.anchor))
            .await?
            .is_none()
        {
            return Err(bit_transaction::Error::UnknownAnchor.into());
        }
        let tx_id = envelope
            .tx_id(self.height, self.owner.config.max_tx_lifetime_blocks)
            .map_err(bit_transaction::Error::from)?;
        if self
            .delta
            .get_raw(&transaction_key(&tx_id))
            .await?
            .is_some()
        {
            return Err(bit_transaction::Error::TransactionAlreadyApplied.into());
        }

        let verified = verify_transfer_stateless(
            envelope_bytes,
            &StatelessVerificationContext {
                expected_chain_context: self.owner.config.chain_context,
                current_height: self.height,
                max_lifetime: self.owner.config.max_tx_lifetime_blocks,
                max_envelope_bytes: self.owner.config.max_envelope_bytes,
                native_asset_id: self.owner.config.native_asset_id,
                fee_policy: self.owner.config.fee_policy,
            },
        )?;
        self.stage_verified(&verified).await?;
        Ok(verified)
    }

    /// Verify and atomically stage any currently enabled staking action
    /// against the current block overlay and staking snapshot.
    pub async fn verify_and_stage_staking_action(
        &mut self,
        envelope_bytes: &[u8],
    ) -> Result<VerifiedStakingTransaction> {
        let envelope = Envelope::decode_canonical(
            envelope_bytes,
            self.owner.config.max_envelope_bytes,
            self.height,
            self.owner.config.max_tx_lifetime_blocks,
        )
        .map_err(bit_transaction::Error::from)?;
        let body = envelope
            .validate(self.height, self.owner.config.max_tx_lifetime_blocks)
            .map_err(bit_transaction::Error::from)?;
        if body.chain_context != self.owner.config.chain_context {
            return Err(bit_transaction::Error::WrongChainContext.into());
        }
        if !matches!(
            &body.action,
            Action::RegisterValidator { .. }
                | Action::Delegate { .. }
                | Action::CancelPending { .. }
                | Action::UpdateValidator { .. }
                | Action::UnjailValidator { .. }
                | Action::RotateConsensusKey { .. }
                | Action::ClaimCommission { .. }
        ) {
            return Err(bit_transaction::Error::UnsupportedAction.into());
        }
        if self
            .delta
            .get_raw(&anchor_lookup_key(&body.anchor))
            .await?
            .is_none()
        {
            return Err(bit_transaction::Error::UnknownAnchor.into());
        }
        let tx_id = envelope
            .tx_id(self.height, self.owner.config.max_tx_lifetime_blocks)
            .map_err(bit_transaction::Error::from)?;
        if self
            .delta
            .get_raw(&transaction_key(&tx_id))
            .await?
            .is_some()
        {
            return Err(bit_transaction::Error::TransactionAlreadyApplied.into());
        }

        let verified = verify_staking_stateless(
            envelope_bytes,
            &StatelessVerificationContext {
                expected_chain_context: self.owner.config.chain_context,
                current_height: self.height,
                max_lifetime: self.owner.config.max_tx_lifetime_blocks,
                max_envelope_bytes: self.owner.config.max_envelope_bytes,
                native_asset_id: self.owner.config.native_asset_id,
                fee_policy: self.owner.config.fee_policy,
            },
            &StakingAuthorizationSnapshot(&self.staking),
        )?;
        self.stage_verified_staking(&verified).await?;
        Ok(verified)
    }

    async fn stage_verified(&mut self, verified: &VerifiedTransfer) -> Result<()> {
        let candidate_tree = self.validated_candidate_tree(verified).await?;
        let mut candidate_supply = self.supply.clone();
        candidate_supply.charge_transfer_fee(&self.owner.config.monetary_policy, verified.fee)?;
        self.record_verified(verified, candidate_tree);
        self.supply = candidate_supply;
        Ok(())
    }

    async fn stage_verified_staking(
        &mut self,
        verified: &VerifiedStakingTransaction,
    ) -> Result<()> {
        let candidate_tree = self.validated_candidate_tree(&verified.shielded).await?;
        let mut candidate_staking = self.staking.clone();
        let mut candidate_supply = self.supply.clone();
        let mut touches = StakingTouches::default();
        match &verified.action {
            VerifiedStakingAction::RegisterValidator {
                validator_id,
                operator,
                consensus,
                commission_bps,
                display_name,
                website,
                description,
            } => {
                candidate_staking.register_validator_with_metadata_at(
                    *validator_id,
                    *operator,
                    *consensus,
                    *commission_bps,
                    display_name.clone(),
                    website.clone(),
                    description.clone(),
                    self.height,
                    self.block_time_seconds,
                )?;
                candidate_supply.charge_shielded_fee(
                    &self.owner.config.monetary_policy,
                    verified.shielded.fee,
                )?;
                touches.validators.insert(*validator_id);
                touches.pools.insert(*validator_id);
            }
            VerifiedStakingAction::Delegate {
                position_id,
                owner,
                validator_id,
                deposit,
                min_shares,
                self_bond,
                recovery,
            } => {
                let current_epoch =
                    self.height.saturating_sub(1) / self.owner.config.monetary_policy.epoch_blocks;
                candidate_staking.open_pending_delegation(
                    current_epoch,
                    self.height,
                    *position_id,
                    *owner,
                    *validator_id,
                    *deposit,
                    *min_shares,
                    *self_bond,
                    recovery.clone(),
                )?;
                candidate_supply.open_pending_delegation(
                    &self.owner.config.monetary_policy,
                    *deposit,
                    verified.shielded.fee,
                )?;
                touches.positions.insert(*position_id);
                touches.pools.insert(*validator_id);
                touches.capacity_epochs.insert(
                    current_epoch
                        .checked_add(1)
                        .ok_or(bit_staking::Error::Overflow)?,
                );
            }
            VerifiedStakingAction::CancelPending {
                position_id,
                expected_sequence,
                expected_release,
                fee_source,
            } => {
                let position = candidate_staking
                    .position(position_id)
                    .ok_or(bit_staking::Error::PositionNotFound)?
                    .clone();
                let released = candidate_staking.cancel_pending(position_id, *expected_sequence)?;
                if released != *expected_release {
                    return Err(bit_transaction::Error::StaleStateQuote("pending release").into());
                }
                candidate_supply.release_pending_delegation_with_fee_source(
                    &self.owner.config.monetary_policy,
                    released,
                    verified.shielded.fee,
                    *fee_source,
                )?;
                touches.positions.insert(*position_id);
                touches.pools.insert(position.validator_id);
                touches.capacity_epochs.insert(position.activation_epoch);
            }
            VerifiedStakingAction::UpdateValidator {
                validator_id,
                expected_sequence,
                display_name,
                website,
                description,
                commission_bps,
                request_disable,
            } => {
                let current_epoch =
                    self.height.saturating_sub(1) / self.owner.config.monetary_policy.epoch_blocks;
                candidate_staking.update_validator(
                    validator_id,
                    *expected_sequence,
                    current_epoch,
                    self.height,
                    self.block_time_seconds,
                    ValidatorUpdate {
                        display_name: display_name.clone(),
                        website: website.clone(),
                        description: description.clone(),
                        commission_bps: *commission_bps,
                        request_disable: *request_disable,
                    },
                )?;
                candidate_supply.charge_shielded_fee(
                    &self.owner.config.monetary_policy,
                    verified.shielded.fee,
                )?;
                touches.validators.insert(*validator_id);
            }
            VerifiedStakingAction::UnjailValidator {
                validator_id,
                expected_sequence,
            } => {
                candidate_staking.unjail_validator(
                    validator_id,
                    *expected_sequence,
                    self.height,
                    self.block_time_seconds,
                )?;
                candidate_supply.charge_shielded_fee(
                    &self.owner.config.monetary_policy,
                    verified.shielded.fee,
                )?;
                touches.validators.insert(*validator_id);
            }
            VerifiedStakingAction::RotateConsensusKey {
                validator_id,
                expected_sequence,
                new_consensus,
            } => {
                let current_epoch =
                    self.height.saturating_sub(1) / self.owner.config.monetary_policy.epoch_blocks;
                candidate_staking.rotate_consensus_key(
                    validator_id,
                    *expected_sequence,
                    *new_consensus,
                    current_epoch,
                )?;
                candidate_supply.charge_shielded_fee(
                    &self.owner.config.monetary_policy,
                    verified.shielded.fee,
                )?;
                touches.validators.insert(*validator_id);
            }
            VerifiedStakingAction::ClaimCommission {
                validator_id,
                expected_sequence,
                requested_amount,
                fee_source,
            } => {
                let released = candidate_staking.claim_commission(
                    validator_id,
                    *expected_sequence,
                    *requested_amount,
                )?;
                candidate_supply.release_commission(
                    &self.owner.config.monetary_policy,
                    released,
                    verified.shielded.fee,
                    *fee_source,
                )?;
                touches.validators.insert(*validator_id);
            }
        }
        validate_staking_supply(&candidate_staking, &candidate_supply)?;

        self.record_verified(&verified.shielded, candidate_tree);
        self.staking = candidate_staking;
        self.supply = candidate_supply;
        self.staking_touches.validators.extend(touches.validators);
        self.staking_touches.pools.extend(touches.pools);
        self.staking_touches.positions.extend(touches.positions);
        self.staking_touches
            .capacity_epochs
            .extend(touches.capacity_epochs);
        Ok(())
    }

    async fn validated_candidate_tree(&self, verified: &VerifiedTransfer) -> Result<Tree> {
        if self
            .delta
            .get_raw(&anchor_lookup_key(&verified.anchor))
            .await?
            .is_none()
        {
            return Err(Error::UnknownAnchor);
        }
        if self
            .delta
            .get_raw(&transaction_key(&verified.tx_id))
            .await?
            .is_some()
        {
            return Err(Error::TransactionAlreadyApplied);
        }
        let mut transaction_nullifiers = BTreeSet::new();
        for nullifier in &verified.nullifiers {
            if !transaction_nullifiers.insert(*nullifier) {
                return Err(Error::DuplicateNullifier);
            }
            if self
                .delta
                .get_raw(&nullifier_key(nullifier))
                .await?
                .is_some()
            {
                return Err(Error::NullifierAlreadySpent);
            }
        }

        // Build the candidate tree first so a malformed commitment cannot leave
        // part of this transaction in the block overlay.
        let mut candidate_tree = self.tree.clone();
        for bytes in &verified.output_commitments {
            let commitment =
                StateCommitment::try_from(*bytes).map_err(|_| Error::InvalidOutputCommitment)?;
            candidate_tree
                .insert(Witness::Forget, commitment)
                .map_err(|_| Error::CommitmentTreeFull)?;
        }
        Ok(candidate_tree)
    }

    fn record_verified(&mut self, verified: &VerifiedTransfer, candidate_tree: Tree) {
        let transaction_value = transaction_record(self.height, verified);
        self.delta
            .put_raw(transaction_key(&verified.tx_id), transaction_value);
        for nullifier in &verified.nullifiers {
            self.delta.put_raw(
                nullifier_key(nullifier),
                nullifier_record(self.height, &verified.tx_id),
            );
        }
        self.tree = candidate_tree;
        self.transaction_count += 1;
    }

    /// Seal the shielded block and compute the next app hash without writing it.
    pub async fn prepare(mut self) -> Result<PreparedBlock> {
        if !self.system_phases_staged {
            return Err(Error::InvalidSystemPhase(
                "consensus system phases were not staged",
            ));
        }
        self.staking.validate()?;
        validate_staking_supply(&self.staking, &self.supply)?;
        let logical_height = self
            .height
            .checked_add(2)
            .ok_or(Error::InvalidSystemPhase("validator set height overflow"))?;
        if self.effective_schedule.effective_set_at(logical_height)?
            != &self.staking.effective_validator_set()?
        {
            return Err(Error::InvalidSystemPhase(
                "logical staking set differs from the H+2 effective set",
            ));
        }
        let staking_totals = self.staking.totals()?;
        let supply = self
            .supply
            .audit_at_height(&self.owner.config.monetary_policy, self.height)?;
        self.tree
            .end_block()
            .map_err(|_| Error::CommitmentTreeFull)?;
        let shielded_tree_root = tree_root_bytes(&self.tree);
        let frontier = bincode::serialize(&self.tree).map_err(|error| {
            Error::CorruptState(format!("cannot encode tree frontier: {error}"))
        })?;
        if frontier.len() > MAX_FRONTIER_BYTES {
            return Err(Error::CorruptState(format!(
                "tree frontier exceeds {MAX_FRONTIER_BYTES} bytes"
            )));
        }

        self.delta
            .put_raw(META_HEIGHT.to_owned(), u64_bytes(self.height));
        self.delta.put_raw(
            META_BLOCK_TIME_SECONDS.to_owned(),
            u64_bytes(self.block_time_seconds),
        );
        self.delta
            .put_raw(TREE_ROOT.to_owned(), shielded_tree_root.to_vec());
        self.delta.put_raw(TREE_FRONTIER.to_owned(), frontier);
        self.delta
            .put_raw(anchor_height_key(self.height), shielded_tree_root.to_vec());
        self.delta.put_raw(
            anchor_lookup_key(&shielded_tree_root),
            u64_bytes(self.height),
        );
        self.delta
            .put_raw(execution_key(self.height), self.execution_hash.to_vec());
        self.delta
            .put_raw(compact_key(self.height), self.compact_hash.to_vec());
        write_supply(&mut self.delta, &self.supply);
        write_staking_updates(&mut self.delta, &self.staking, &self.staking_touches)?;
        self.delta.put_raw(
            STAKING_EFFECTIVE_SCHEDULE.to_owned(),
            self.effective_schedule.encode_persistent()?,
        );

        if self.height >= self.owner.config.anchor_retention_blocks {
            let prune_height = self.height - self.owner.config.anchor_retention_blocks;
            let old_anchor_key = anchor_height_key(prune_height);
            if let Some(old_anchor) = self.delta.get_raw(&old_anchor_key).await? {
                let old_anchor = exact_hash32(&old_anchor, &old_anchor_key)?;
                let old_lookup_key = anchor_lookup_key(&old_anchor);
                if self.delta.get_raw(&old_lookup_key).await? == Some(u64_bytes(prune_height)) {
                    self.delta.delete(old_lookup_key);
                }
                self.delta.delete(old_anchor_key);
            }
        }

        let batch = self.owner.storage.prepare_commit(self.delta).await?;
        let storage_version = batch.version();
        if storage_version != self.height {
            return Err(Error::CorruptState(format!(
                "prepared storage version {storage_version} differs from state height {}",
                self.height
            )));
        }
        let app_hash = batch.root_hash().0;
        Ok(PreparedBlock {
            batch,
            state_height: self.height,
            block_time_seconds: self.block_time_seconds,
            storage_version,
            app_hash,
            shielded_tree_root,
            supply,
            staking: self.staking,
            staking_totals,
            transaction_count: self.transaction_count,
        })
    }
}

pub struct PreparedBlock {
    batch: StagedWriteBatch,
    pub state_height: u64,
    pub block_time_seconds: u64,
    pub storage_version: u64,
    pub app_hash: Hash32,
    pub shielded_tree_root: Hash32,
    pub supply: SupplyAudit,
    staking: StakingBook,
    pub staking_totals: StakingTotals,
    pub transaction_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    pub state_height: u64,
    pub block_time_seconds: u64,
    pub storage_version: u64,
    pub app_hash: Hash32,
    pub shielded_tree_root: Hash32,
    pub supply: SupplyAudit,
    pub staking: StakingTotals,
    pub transaction_count: usize,
}

async fn initialize_genesis(storage: &Storage, config: &GenesisConfig) -> Result<()> {
    let supply = SupplyState::genesis(&config.monetary_policy, config.genesis_allocation.clone())?;
    let mut tree = Tree::new();
    for bytes in &config.genesis_commitments {
        let commitment = StateCommitment::try_from(*bytes)
            .map_err(|_| Error::InvalidConfig("invalid genesis commitment"))?;
        tree.insert(Witness::Forget, commitment)
            .map_err(|_| Error::CommitmentTreeFull)?;
    }
    tree.end_block().map_err(|_| Error::CommitmentTreeFull)?;
    let tree_root = tree_root_bytes(&tree);
    let frontier = bincode::serialize(&tree)
        .map_err(|error| Error::CorruptState(format!("cannot encode genesis tree: {error}")))?;
    let mut delta = StateDelta::new(storage.latest_snapshot());
    delta.put_raw(
        META_VERSION.to_owned(),
        STORAGE_SCHEMA_VERSION.to_be_bytes().to_vec(),
    );
    delta.put_raw(META_HEIGHT.to_owned(), u64_bytes(0));
    delta.put_raw(META_BLOCK_TIME_SECONDS.to_owned(), u64_bytes(0));
    delta.put_raw(META_CHAIN_CONTEXT.to_owned(), config.chain_context.to_vec());
    delta.put_raw(
        META_NATIVE_ASSET_ID.to_owned(),
        config.native_asset_id.to_vec(),
    );
    delta.put_raw(
        META_PROTOCOL_VERSION.to_owned(),
        u64_bytes(config.protocol_version),
    );
    delta.put_raw(
        META_MAX_BLOCK_BYTES.to_owned(),
        u64_bytes(config.max_block_bytes),
    );
    delta.put_raw(
        META_MAX_TX_LIFETIME.to_owned(),
        u64_bytes(config.max_tx_lifetime_blocks),
    );
    delta.put_raw(
        META_MAX_ENVELOPE_BYTES.to_owned(),
        u64_bytes(config.max_envelope_bytes as u64),
    );
    delta.put_raw(
        META_ANCHOR_RETENTION.to_owned(),
        u64_bytes(config.anchor_retention_blocks),
    );
    delta.put_raw(
        META_GENESIS_COMMITMENTS_HASH.to_owned(),
        genesis_commitments_hash(&config.genesis_commitments).to_vec(),
    );
    delta.put_raw(
        META_MONETARY_POLICY_HASH.to_owned(),
        supply.monetary_policy_hash.to_vec(),
    );
    delta.put_raw(
        EMISSION_POLICY.to_owned(),
        config
            .monetary_policy
            .encode_canonical()
            .map_err(bit_emission::Error::from)?,
    );
    write_fee_policy(&mut delta, config.fee_policy);
    write_supply(&mut delta, &supply);
    write_staking_genesis(&mut delta, &config.genesis_staking)?;
    delta.put_raw(
        STAKING_EFFECTIVE_SCHEDULE.to_owned(),
        EffectiveValidatorSchedule::genesis(config.genesis_staking.effective_validator_set()?)
            .encode_persistent()?,
    );
    delta.put_raw(TREE_ROOT.to_owned(), tree_root.to_vec());
    delta.put_raw(TREE_FRONTIER.to_owned(), frontier);
    delta.put_raw(anchor_height_key(0), tree_root.to_vec());
    delta.put_raw(anchor_lookup_key(&tree_root), u64_bytes(0));
    delta.put_raw(execution_key(0), config.genesis_execution_hash.to_vec());
    delta.put_raw(compact_key(0), config.genesis_compact_hash.to_vec());
    let root = storage.commit(delta).await?;
    if storage.latest_version() != 0 || root.0 == [0; 32] {
        return Err(Error::CorruptState(
            "genesis commit did not produce version zero and a nonzero root".to_owned(),
        ));
    }
    Ok(())
}

async fn validate_storage(storage: &Storage, config: &GenesisConfig) -> Result<()> {
    let snapshot = storage.latest_snapshot();
    let schema = read_u32(&snapshot, META_VERSION).await?;
    if schema != STORAGE_SCHEMA_VERSION {
        return Err(Error::CorruptState(format!(
            "storage schema {schema} is not supported"
        )));
    }
    let height = read_u64(&snapshot, META_HEIGHT).await?;
    read_u64(&snapshot, META_BLOCK_TIME_SECONDS).await?;
    if snapshot.version() != height {
        return Err(Error::CorruptState(format!(
            "storage version {} differs from state height {height}",
            snapshot.version()
        )));
    }
    require_equal_hash(&snapshot, META_CHAIN_CONTEXT, &config.chain_context).await?;
    require_equal_hash(&snapshot, META_NATIVE_ASSET_ID, &config.native_asset_id).await?;
    require_equal_u64(&snapshot, META_PROTOCOL_VERSION, config.protocol_version).await?;
    require_equal_u64(&snapshot, META_MAX_BLOCK_BYTES, config.max_block_bytes).await?;
    require_equal_u64(
        &snapshot,
        META_MAX_TX_LIFETIME,
        config.max_tx_lifetime_blocks,
    )
    .await?;
    require_equal_u64(
        &snapshot,
        META_MAX_ENVELOPE_BYTES,
        config.max_envelope_bytes as u64,
    )
    .await?;
    require_equal_u64(
        &snapshot,
        META_ANCHOR_RETENTION,
        config.anchor_retention_blocks,
    )
    .await?;
    require_equal_hash(
        &snapshot,
        META_GENESIS_COMMITMENTS_HASH,
        &genesis_commitments_hash(&config.genesis_commitments),
    )
    .await?;
    let policy_hash = config
        .monetary_policy
        .hash()
        .map_err(bit_emission::Error::from)?;
    require_equal_hash(&snapshot, META_MONETARY_POLICY_HASH, &policy_hash).await?;
    let stored_policy = required(&snapshot, EMISSION_POLICY).await?;
    if stored_policy
        != config
            .monetary_policy
            .encode_canonical()
            .map_err(bit_emission::Error::from)?
    {
        return Err(Error::CorruptState(
            "immutable monetary policy bytes differ".to_owned(),
        ));
    }
    if read_fee_policy(&snapshot).await? != config.fee_policy {
        return Err(Error::CorruptState(
            "immutable fee policy differs".to_owned(),
        ));
    }
    let supply = read_supply(&snapshot).await?;
    supply.validate_at_height(&config.monetary_policy, height)?;
    let staking = read_staking_book(&snapshot, config.chain_context).await?;
    if staking.parameters() != config.genesis_staking.parameters() {
        return Err(Error::CorruptState(
            "immutable staking parameters differ".to_owned(),
        ));
    }
    validate_staking_supply(&staking, &supply)?;
    let effective_schedule = read_effective_schedule(&snapshot).await?;
    if effective_schedule.base_height != height {
        return Err(Error::CorruptState(
            "effective validator schedule height differs from state height".to_owned(),
        ));
    }
    let logical_height = height
        .checked_add(2)
        .ok_or_else(|| Error::CorruptState("validator set height overflow".to_owned()))?;
    if effective_schedule.effective_set_at(logical_height)? != &staking.effective_validator_set()? {
        return Err(Error::CorruptState(
            "logical staking set differs from the H+2 effective set".to_owned(),
        ));
    }

    let tree = read_tree(&snapshot).await?;
    let tree_root = tree_root_bytes(&tree);
    if read_hash32(&snapshot, TREE_ROOT).await? != tree_root {
        return Err(Error::CorruptState(
            "stored tree root does not match the recoverable frontier".to_owned(),
        ));
    }
    if read_hash32(&snapshot, &anchor_height_key(height)).await? != tree_root {
        return Err(Error::CorruptState(
            "current-height anchor does not match the shielded tree".to_owned(),
        ));
    }
    if read_u64(&snapshot, &anchor_lookup_key(&tree_root)).await? != height {
        return Err(Error::CorruptState(
            "current shielded root is absent from the anchor lookup".to_owned(),
        ));
    }
    read_hash32(&snapshot, &execution_key(height)).await?;
    read_hash32(&snapshot, &compact_key(height)).await?;
    snapshot.root_hash().await?;
    Ok(())
}

async fn summary_from_snapshot(
    snapshot: Snapshot,
    monetary_policy: &MonetaryPolicy,
) -> Result<StateSummary> {
    let state_height = read_u64(&snapshot, META_HEIGHT).await?;
    let block_time_seconds = read_u64(&snapshot, META_BLOCK_TIME_SECONDS).await?;
    let supply = read_supply(&snapshot).await?;
    Ok(StateSummary {
        storage_schema_version: read_u32(&snapshot, META_VERSION).await?,
        state_height,
        block_time_seconds,
        storage_version: snapshot.version(),
        app_hash: snapshot.root_hash().await?.0,
        shielded_tree_root: read_hash32(&snapshot, TREE_ROOT).await?,
        supply: supply.audit_at_height(monetary_policy, state_height)?,
    })
}

fn write_supply(delta: &mut StateDelta<Snapshot>, supply: &SupplyState) {
    for (key, value) in [
        (SUPPLY_MAX, supply.max_supply),
        (SUPPLY_GENESIS, supply.genesis_supply),
        (SUPPLY_CUMULATIVE_MINTED, supply.cumulative_minted),
        (SUPPLY_BURNED, supply.burned),
        (SUPPLY_SHIELDED, supply.shielded_total),
        (SUPPLY_STAKE, supply.stake_total),
        (SUPPLY_PENDING, supply.pending_delegation_total),
        (SUPPLY_EXITS, supply.exit_total),
        (SUPPLY_COMMISSION, supply.commission_total),
        (FEES_RESERVE, supply.fee_reserve),
        (GENESIS_UNCLAIMED, supply.unclaimed_genesis_total),
        (EMISSION_FORFEITED_UNISSUED, supply.forfeited_unissued),
    ] {
        delta.put_raw(key.to_owned(), value.to_be_bytes().to_vec());
    }
    delta.put_raw(
        EMISSION_COMPLETED_EPOCHS.to_owned(),
        u64_bytes(supply.completed_epochs),
    );
}

fn write_fee_policy(delta: &mut StateDelta<Snapshot>, policy: FeePolicy) {
    for (key, value) in [
        (FEES_BASE, policy.base),
        (FEES_PER_KIB, policy.per_kib),
        (FEES_PER_SPEND_PROOF, policy.per_spend_proof),
        (FEES_PER_OUTPUT_PROOF, policy.per_output_proof),
        (FEES_NEW_POSITION_SURCHARGE, policy.new_position_surcharge),
        (
            FEES_VALIDATOR_REGISTRATION_SURCHARGE,
            policy.validator_registration_surcharge,
        ),
    ] {
        delta.put_raw(key.to_owned(), value.to_be_bytes().to_vec());
    }
}

fn write_staking_genesis(delta: &mut StateDelta<Snapshot>, staking: &StakingBook) -> Result<()> {
    delta.put_raw(
        STAKING_PARAMETERS.to_owned(),
        staking.parameters().encode_persistent(),
    );
    for validator in staking.validators() {
        delta.put_raw(
            staking_validator_key(&validator.validator_id),
            validator.encode_persistent()?,
        );
    }
    for pool in staking.pools() {
        delta.put_raw(
            staking_pool_key(&pool.validator_id),
            pool.encode_persistent(),
        );
    }
    for position in staking.positions() {
        delta.put_raw(
            staking_position_key(&position.position_id),
            position.encode_persistent()?,
        );
    }
    for capacity in staking.capacity_records() {
        delta.put_raw(
            staking_capacity_key(capacity.activation_epoch),
            capacity.encode_persistent(),
        );
    }
    Ok(())
}

fn write_staking_updates(
    delta: &mut StateDelta<Snapshot>,
    staking: &StakingBook,
    touches: &StakingTouches,
) -> Result<()> {
    for id in &touches.validators {
        let validator = staking
            .validator(id)
            .ok_or_else(|| Error::CorruptState("touched validator is missing".to_owned()))?;
        delta.put_raw(staking_validator_key(id), validator.encode_persistent()?);
    }
    for id in &touches.pools {
        let pool = staking
            .pool(id)
            .ok_or_else(|| Error::CorruptState("touched staking pool is missing".to_owned()))?;
        delta.put_raw(staking_pool_key(id), pool.encode_persistent());
    }
    for id in &touches.positions {
        let position = staking
            .position(id)
            .ok_or_else(|| Error::CorruptState("touched stake position is missing".to_owned()))?;
        delta.put_raw(staking_position_key(id), position.encode_persistent()?);
    }
    for epoch in &touches.capacity_epochs {
        let capacity = staking.capacity_record(*epoch).ok_or_else(|| {
            Error::CorruptState("touched activation capacity is missing".to_owned())
        })?;
        delta.put_raw(staking_capacity_key(*epoch), capacity.encode_persistent());
    }
    Ok(())
}

async fn read_effective_schedule(snapshot: &Snapshot) -> Result<EffectiveValidatorSchedule> {
    EffectiveValidatorSchedule::decode_persistent(
        &required(snapshot, STAKING_EFFECTIVE_SCHEDULE).await?,
    )
}

fn take_schedule<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| Error::CorruptState("effective schedule length overflow".to_owned()))?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| Error::CorruptState("truncated effective validator schedule".to_owned()))?;
    *offset = end;
    Ok(value)
}

async fn read_staking_book(snapshot: &Snapshot, chain_context: Hash32) -> Result<StakingBook> {
    let parameters =
        StakingParameters::decode_persistent(&required(snapshot, STAKING_PARAMETERS).await?)?;
    let mut validators = Vec::new();
    let mut validator_stream = snapshot.prefix_raw(STAKING_VALIDATOR_PREFIX);
    while let Some(entry) = validator_stream.next().await {
        let (key, value) = entry?;
        let validator = Validator::decode_persistent(&value)?;
        require_hash_key(&key, STAKING_VALIDATOR_PREFIX, &validator.validator_id)?;
        validators.push(validator);
    }
    let mut pools = Vec::new();
    let mut pool_stream = snapshot.prefix_raw(STAKING_POOL_PREFIX);
    while let Some(entry) = pool_stream.next().await {
        let (key, value) = entry?;
        let pool = StakePool::decode_persistent(&value)?;
        require_hash_key(&key, STAKING_POOL_PREFIX, &pool.validator_id)?;
        pools.push(pool);
    }
    let mut positions = Vec::new();
    let mut position_stream = snapshot.prefix_raw(STAKING_POSITION_PREFIX);
    while let Some(entry) = position_stream.next().await {
        let (key, value) = entry?;
        let position = StakePosition::decode_persistent(&value)?;
        require_hash_key(&key, STAKING_POSITION_PREFIX, &position.position_id)?;
        positions.push(position);
    }
    let mut capacity = Vec::new();
    let mut capacity_stream = snapshot.prefix_raw(STAKING_CAPACITY_PREFIX);
    while let Some(entry) = capacity_stream.next().await {
        let (key, value) = entry?;
        let record = ActivationCapacityRecord::decode_persistent(&value)?;
        if key != staking_capacity_key(record.activation_epoch) {
            return Err(Error::CorruptState(format!(
                "staking capacity key does not match encoded epoch: {key}"
            )));
        }
        capacity.push(record);
    }
    Ok(StakingBook::from_records(
        chain_context,
        parameters,
        validators,
        pools,
        positions,
        capacity,
    )?)
}

fn validate_staking_supply(staking: &StakingBook, supply: &SupplyState) -> Result<()> {
    let totals = staking.totals()?;
    if totals.pooled_assets != supply.stake_total {
        return Err(Error::CorruptState(
            "staking pools do not equal the P supply container".to_owned(),
        ));
    }
    if totals.pending_assets != supply.pending_delegation_total {
        return Err(Error::CorruptState(
            "staking pending positions do not equal the D supply container".to_owned(),
        ));
    }
    if totals.commission_assets != supply.commission_total {
        return Err(Error::CorruptState(
            "validator commissions do not equal the C supply container".to_owned(),
        ));
    }
    Ok(())
}

fn require_hash_key(key: &str, prefix: &str, id: &Hash32) -> Result<()> {
    if key != format!("{prefix}{}", hex::encode(id)) {
        return Err(Error::CorruptState(format!(
            "staking record key does not match encoded identifier: {key}"
        )));
    }
    Ok(())
}

pub fn staking_validator_key(id: &Hash32) -> String {
    hash_key("staking/validators", id)
}

pub fn staking_pool_key(id: &Hash32) -> String {
    hash_key("staking/pools", id)
}

pub fn staking_position_key(id: &Hash32) -> String {
    hash_key("staking/positions", id)
}

pub fn staking_capacity_key(epoch: u64) -> String {
    format!("{STAKING_CAPACITY_PREFIX}{epoch:016x}")
}

async fn read_fee_policy(snapshot: &Snapshot) -> Result<FeePolicy> {
    Ok(FeePolicy {
        base: read_amount(snapshot, FEES_BASE).await?,
        per_kib: read_amount(snapshot, FEES_PER_KIB).await?,
        per_spend_proof: read_amount(snapshot, FEES_PER_SPEND_PROOF).await?,
        per_output_proof: read_amount(snapshot, FEES_PER_OUTPUT_PROOF).await?,
        new_position_surcharge: read_amount(snapshot, FEES_NEW_POSITION_SURCHARGE).await?,
        validator_registration_surcharge: read_amount(
            snapshot,
            FEES_VALIDATOR_REGISTRATION_SURCHARGE,
        )
        .await?,
    })
}

async fn read_supply(snapshot: &Snapshot) -> Result<SupplyState> {
    Ok(SupplyState {
        max_supply: read_amount(snapshot, SUPPLY_MAX).await?,
        genesis_supply: read_amount(snapshot, SUPPLY_GENESIS).await?,
        cumulative_minted: read_amount(snapshot, SUPPLY_CUMULATIVE_MINTED).await?,
        burned: read_amount(snapshot, SUPPLY_BURNED).await?,
        shielded_total: read_amount(snapshot, SUPPLY_SHIELDED).await?,
        stake_total: read_amount(snapshot, SUPPLY_STAKE).await?,
        pending_delegation_total: read_amount(snapshot, SUPPLY_PENDING).await?,
        exit_total: read_amount(snapshot, SUPPLY_EXITS).await?,
        commission_total: read_amount(snapshot, SUPPLY_COMMISSION).await?,
        fee_reserve: read_amount(snapshot, FEES_RESERVE).await?,
        unclaimed_genesis_total: read_amount(snapshot, GENESIS_UNCLAIMED).await?,
        completed_epochs: read_u64(snapshot, EMISSION_COMPLETED_EPOCHS).await?,
        forfeited_unissued: read_amount(snapshot, EMISSION_FORFEITED_UNISSUED).await?,
        monetary_policy_hash: read_hash32(snapshot, META_MONETARY_POLICY_HASH).await?,
    })
}

async fn read_amount(snapshot: &Snapshot, key: &str) -> Result<Amount> {
    let bytes = required(snapshot, key).await?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptState(format!("{key} must contain exactly 16 bytes")))?;
    Amount::from_be_bytes(bytes)
        .map_err(|_| Error::CorruptState(format!("{key} contains an invalid amount")))
}

async fn read_tree(snapshot: &Snapshot) -> Result<Tree> {
    let bytes = required(snapshot, TREE_FRONTIER).await?;
    if bytes.len() > MAX_FRONTIER_BYTES {
        return Err(Error::CorruptState(format!(
            "stored tree frontier exceeds {MAX_FRONTIER_BYTES} bytes"
        )));
    }
    bincode::deserialize(&bytes)
        .map_err(|error| Error::CorruptState(format!("cannot decode tree frontier: {error}")))
}

async fn required(snapshot: &Snapshot, key: &str) -> Result<Vec<u8>> {
    snapshot
        .get_raw(key)
        .await?
        .ok_or_else(|| Error::CorruptState(format!("missing required key {key}")))
}

async fn read_hash32(snapshot: &Snapshot, key: &str) -> Result<Hash32> {
    let bytes = required(snapshot, key).await?;
    exact_hash32(&bytes, key)
}

fn exact_hash32(bytes: &[u8], key: &str) -> Result<Hash32> {
    bytes
        .try_into()
        .map_err(|_| Error::CorruptState(format!("{key} must contain exactly 32 bytes")))
}

async fn read_u64(snapshot: &Snapshot, key: &str) -> Result<u64> {
    let bytes = required(snapshot, key).await?;
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| Error::CorruptState(format!("{key} must contain exactly 8 bytes")))?;
    Ok(u64::from_be_bytes(bytes))
}

async fn read_u32(snapshot: &Snapshot, key: &str) -> Result<u32> {
    let bytes = required(snapshot, key).await?;
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| Error::CorruptState(format!("{key} must contain exactly 4 bytes")))?;
    Ok(u32::from_be_bytes(bytes))
}

async fn require_equal_hash(snapshot: &Snapshot, key: &str, expected: &Hash32) -> Result<()> {
    if read_hash32(snapshot, key).await? != *expected {
        return Err(Error::CorruptState(format!(
            "immutable configuration mismatch at {key}"
        )));
    }
    Ok(())
}

async fn require_equal_u64(snapshot: &Snapshot, key: &str, expected: u64) -> Result<()> {
    if read_u64(snapshot, key).await? != expected {
        return Err(Error::CorruptState(format!(
            "immutable configuration mismatch at {key}"
        )));
    }
    Ok(())
}

fn tree_root_bytes(tree: &Tree) -> Hash32 {
    let root: Fq = tree.root().into();
    root.to_bytes()
}

fn genesis_commitments_hash(commitments: &[Hash32]) -> Hash32 {
    let mut hash = Sha256::new();
    hash.update(b"BIT-GENESIS-COMMITMENTS-V1");
    hash.update((commitments.len() as u64).to_be_bytes());
    for commitment in commitments {
        hash.update(commitment);
    }
    hash.finalize().into()
}

fn u64_bytes(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn hash_key(prefix: &str, hash: &Hash32) -> String {
    format!("{prefix}/{}", hex::encode(hash))
}

fn anchor_height_key(height: u64) -> String {
    format!("shielded/anchor/{height:020}")
}

fn anchor_lookup_key(anchor: &Hash32) -> String {
    hash_key("shielded/anchor_by_root", anchor)
}

fn nullifier_key(nullifier: &Hash32) -> String {
    hash_key("shielded/nullifier", nullifier)
}

fn transaction_key(tx_id: &Hash32) -> String {
    hash_key("transactions/applied", tx_id)
}

fn execution_key(height: u64) -> String {
    format!("execution/block/{height:020}")
}

fn compact_key(height: u64) -> String {
    format!("compact/hash/{height:020}")
}

fn transaction_record(height: u64, verified: &VerifiedTransfer) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 64 + 32 + 16 + 16 + 4 + 4);
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(&verified.effect_hash);
    out.extend_from_slice(&verified.anchor);
    out.extend_from_slice(&verified.fee.to_be_bytes());
    out.extend_from_slice(&verified.minimum_fee.to_be_bytes());
    out.extend_from_slice(&(verified.nullifiers.len() as u32).to_be_bytes());
    out.extend_from_slice(&(verified.output_commitments.len() as u32).to_be_bytes());
    out
}

fn nullifier_record(height: u64, tx_id: &Hash32) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(tx_id);
    out
}

fn proof_path(key: &str) -> (MerklePath, Vec<ics23::ProofSpec>) {
    for prefix in SUBSTORES {
        if let Some(remainder) = key.strip_prefix(&format!("{prefix}/")) {
            return (
                MerklePath {
                    key_path: vec![(*prefix).to_owned(), remainder.to_owned()],
                },
                vec![cnidarium::ics23_spec(), cnidarium::ics23_spec()],
            );
        }
    }
    (
        MerklePath {
            key_path: vec![key.to_owned()],
        },
        vec![cnidarium::ics23_spec()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bit_staking::StakingParameters;
    use bit_types::{
        chain_context, ed25519_authorization_message, position_id, proof_hash, validator_id,
        Action, Amount, Authorization, Envelope, Role, TxBody,
    };
    use decaf377::Fr;
    use decaf377_rdsa::{Binding, SigningKey};
    use ed25519_consensus::SigningKey as Ed25519SigningKey;
    use penumbra_sdk_asset::{asset, Balance, Value};
    use penumbra_sdk_keys::{
        keys::{Bip44Path, SeedPhrase, SpendKey},
        symmetric::{PayloadKind, WrappedMemoKey},
    };
    use penumbra_sdk_num::Amount as PenumbraAmount;
    use penumbra_sdk_proof_params as proof_params;
    use penumbra_sdk_proto::{penumbra::core::component::shielded_pool::v1 as pb, DomainType};
    use penumbra_sdk_sct::Nullifier;
    use penumbra_sdk_shielded_pool::{
        output::{Body as OutputBody, OutputProofPrivate, OutputProofPublic},
        spend::{Body as SpendBody, SpendProofPrivate, SpendProofPublic},
        EncryptedBackref, Note, OutputProof, Rseed, SpendProof,
    };
    use rand_core::{OsRng, RngCore};
    use std::path::Path;
    use tempfile::TempDir;

    fn random_bytes() -> [u8; 32] {
        let mut bytes = [0; 32];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    fn random_fr() -> Fr {
        Fr::from_le_bytes_mod_order(&random_bytes())
    }

    fn random_fq() -> Fq {
        Fq::from_le_bytes_mod_order(&random_bytes())
    }

    fn spend_key() -> SpendKey {
        SpendKey::from_seed_phrase_bip44(
            SeedPhrase::from_randomness(&random_bytes()),
            &Bip44Path::new(0),
        )
    }

    fn value(amount: u128) -> Value {
        Value {
            amount: PenumbraAmount::from(amount),
            asset_id: asset::Id(Fq::from(1u64)),
        }
    }

    fn load_proving_key(path: &Path, name: &str, expected_sha256: &str) -> Vec<u8> {
        let bytes = std::fs::read(path.join(name)).unwrap_or_else(|error| {
            panic!("missing {name}; run feasibility/scripts/bootstrap_tools.py first: {error}")
        });
        assert_eq!(hex::encode(Sha256::digest(&bytes)), expected_sha256);
        bytes
    }

    #[derive(Clone, Copy)]
    enum RealActionKind {
        Transfer,
        RegisterValidator,
        Delegate,
        UpdateValidator,
        UnjailValidator,
        RotateConsensusKey,
        ClaimCommission,
    }

    fn real_action_fixture(kind: RealActionKind) -> (GenesisConfig, Vec<u8>) {
        let parameter_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../feasibility/.tools/downloads");
        let spend_pk = load_proving_key(
            &parameter_dir,
            "spend_pk.bin",
            "87eca85bef562803fb9684c56c0a6db84aa6d0791b1c00b909e6f2a5c2cff452",
        );
        let output_pk = load_proving_key(
            &parameter_dir,
            "output_pk.bin",
            "c9e97866edd6c815a7bcb2f3b5493713794369692bb96e5a2e682613c330e4a8",
        );
        proof_params::SPEND_PROOF_PROVING_KEY
            .try_load(&spend_pk)
            .unwrap();
        proof_params::OUTPUT_PROOF_PROVING_KEY
            .try_load(&output_pk)
            .unwrap();

        let chain = chain_context([0x33; 32]);
        let mut genesis_staking =
            StakingBook::new(chain, StakingParameters::reference_testnet()).unwrap();
        let (
            action,
            fee_atomic,
            public_lock,
            public_release,
            role_keys,
            genesis_stake,
            genesis_commission,
        ) = match kind {
            RealActionKind::Transfer => (Action::Transfer, 1_000_000, 0, 0, Vec::new(), 0, 0),
            RealActionKind::RegisterValidator => {
                let operator_key = Ed25519SigningKey::from([0x61; 32]);
                let consensus_key = Ed25519SigningKey::from([0x62; 32]);
                let operator = operator_key.verification_key().to_bytes();
                let consensus = consensus_key.verification_key().to_bytes();
                (
                    Action::RegisterValidator {
                        validator_id: validator_id(&chain, &operator),
                        operator,
                        consensus,
                        commission_bps: 600,
                        display_name: "BIT validator".to_owned(),
                        website: "https://validator.invalid".to_owned(),
                        description: "role-authenticated registration".to_owned(),
                    },
                    101_000_000,
                    0,
                    0,
                    vec![
                        (Role::Operator, operator_key),
                        (Role::ConsensusPop, consensus_key),
                    ],
                    0,
                    0,
                )
            }
            RealActionKind::Delegate => {
                let operator_key = Ed25519SigningKey::from([0x71; 32]);
                let consensus_key = Ed25519SigningKey::from([0x72; 32]);
                let owner_key = Ed25519SigningKey::from([0x73; 32]);
                let operator = operator_key.verification_key().to_bytes();
                let consensus = consensus_key.verification_key().to_bytes();
                let owner = owner_key.verification_key().to_bytes();
                let target = validator_id(&chain, &operator);
                genesis_staking
                    .register_validator_with_metadata(
                        target,
                        operator,
                        consensus,
                        500,
                        "genesis validator".to_owned(),
                        String::new(),
                        String::new(),
                    )
                    .unwrap();
                (
                    Action::Delegate {
                        position_id: position_id(&chain, &owner),
                        owner,
                        validator_id: target,
                        deposit: Amount::new(bit_staking::TESTNET_MIN_DELEGATION_ATOMIC).unwrap(),
                        min_shares: Amount::new(bit_staking::TESTNET_MIN_DELEGATION_ATOMIC)
                            .unwrap(),
                        self_bond: false,
                        recovery: vec![0x74; bit_staking::RECOVERY_RECEIPT_BYTES],
                    },
                    1_000_000,
                    bit_staking::TESTNET_MIN_DELEGATION_ATOMIC,
                    0,
                    vec![(Role::PositionOwner, owner_key)],
                    0,
                    0,
                )
            }
            RealActionKind::UpdateValidator => {
                let operator_key = Ed25519SigningKey::from([0x81; 32]);
                let consensus_key = Ed25519SigningKey::from([0x82; 32]);
                let operator = operator_key.verification_key().to_bytes();
                let consensus = consensus_key.verification_key().to_bytes();
                let target = validator_id(&chain, &operator);
                genesis_staking
                    .register_validator_with_metadata(
                        target,
                        operator,
                        consensus,
                        500,
                        "before update".to_owned(),
                        String::new(),
                        String::new(),
                    )
                    .unwrap();
                (
                    Action::UpdateValidator {
                        validator_id: target,
                        expected_sequence: 0,
                        display_name: Some("after update".to_owned()),
                        website: Some("https://updated.invalid".to_owned()),
                        description: Some("scheduled commission decrease".to_owned()),
                        commission_bps: Some(400),
                        request_disable: None,
                    },
                    1_000_000,
                    0,
                    0,
                    vec![(Role::Operator, operator_key)],
                    0,
                    0,
                )
            }
            RealActionKind::RotateConsensusKey => {
                let operator_key = Ed25519SigningKey::from([0x83; 32]);
                let consensus_key = Ed25519SigningKey::from([0x84; 32]);
                let new_consensus_key = Ed25519SigningKey::from([0x85; 32]);
                let operator = operator_key.verification_key().to_bytes();
                let consensus = consensus_key.verification_key().to_bytes();
                let target = validator_id(&chain, &operator);
                genesis_staking
                    .register_validator(target, operator, consensus, 500)
                    .unwrap();
                (
                    Action::RotateConsensusKey {
                        validator_id: target,
                        expected_sequence: 0,
                        new_consensus: new_consensus_key.verification_key().to_bytes(),
                    },
                    1_000_000,
                    0,
                    0,
                    vec![
                        (Role::Operator, operator_key),
                        (Role::ConsensusPop, new_consensus_key),
                    ],
                    0,
                    0,
                )
            }
            RealActionKind::UnjailValidator => {
                let operator_key = Ed25519SigningKey::from([0x86; 32]);
                let consensus_key = Ed25519SigningKey::from([0x87; 32]);
                let owner = [0x88; 32];
                let operator = operator_key.verification_key().to_bytes();
                let consensus = consensus_key.verification_key().to_bytes();
                let target = validator_id(&chain, &operator);
                let self_bond = bit_staking::TESTNET_MIN_SELF_BOND_ATOMIC;
                let mut parameters = StakingParameters::reference_testnet();
                parameters.jail_blocks = 1;
                parameters.jail_seconds = 1;
                genesis_staking = StakingBook::new(chain, parameters).unwrap();
                genesis_staking
                    .register_validator(target, operator, consensus, 500)
                    .unwrap();
                let position = position_id(&chain, &owner);
                genesis_staking
                    .open_pending_delegation(
                        0,
                        0,
                        position,
                        owner,
                        target,
                        Amount::new(self_bond).unwrap(),
                        Amount::ZERO,
                        true,
                        vec![0x89; bit_staking::RECOVERY_RECEIPT_BYTES],
                    )
                    .unwrap();
                genesis_staking.activate_pending(&position, 1).unwrap();
                genesis_staking.apply_validator_set().unwrap();
                genesis_staking
                    .jail_validator_for_downtime(&target, 0, 0)
                    .unwrap();
                (
                    Action::UnjailValidator {
                        validator_id: target,
                        expected_sequence: 0,
                    },
                    1_000_000,
                    0,
                    0,
                    vec![(Role::Operator, operator_key)],
                    self_bond,
                    0,
                )
            }
            RealActionKind::ClaimCommission => {
                let operator_key = Ed25519SigningKey::from([0x8a; 32]);
                let consensus_key = Ed25519SigningKey::from([0x8b; 32]);
                let operator = operator_key.verification_key().to_bytes();
                let consensus = consensus_key.verification_key().to_bytes();
                let target = validator_id(&chain, &operator);
                let accrued = 100_000_000u128;
                genesis_staking
                    .register_validator(target, operator, consensus, 500)
                    .unwrap();
                let mut validator = genesis_staking.validator(&target).unwrap().clone();
                validator.commission_accrued = Amount::new(accrued).unwrap();
                let pool = genesis_staking.pool(&target).unwrap().clone();
                genesis_staking = StakingBook::from_records(
                    chain,
                    StakingParameters::reference_testnet(),
                    [validator],
                    [pool],
                    [],
                    [],
                )
                .unwrap();
                (
                    Action::ClaimCommission {
                        validator_id: target,
                        expected_sequence: 0,
                        requested_amount: Amount::new(accrued).unwrap(),
                        fee_source: bit_types::FeeSource::ReleasedValue,
                    },
                    1_000_000,
                    0,
                    accrued,
                    vec![(Role::Operator, operator_key)],
                    0,
                    accrued,
                )
            }
        };

        let sender = spend_key();
        let receiver = spend_key();
        let full_viewing_key = sender.full_viewing_key();
        let (sender_address, _) = full_viewing_key.incoming().payment_address(0u32.into());
        let (receiver_address, _) = receiver
            .full_viewing_key()
            .incoming()
            .payment_address(0u32.into());
        let input_notes: Vec<Note> = (0..2)
            .map(|_| {
                Note::from_parts(
                    sender_address.clone(),
                    value(7_500_000_000),
                    Rseed(random_bytes()),
                )
                .unwrap()
            })
            .collect();
        let genesis_commitments = input_notes
            .iter()
            .map(|note| note.commit().into())
            .collect::<Vec<_>>();
        let mut proof_tree = Tree::new();
        for note in &input_notes {
            proof_tree.insert(Witness::Keep, note.commit()).unwrap();
        }
        proof_tree.end_block().unwrap();
        let anchor = tree_root_bytes(&proof_tree);

        let memo_key = penumbra_sdk_keys::PayloadKey::random_key(&mut OsRng);
        let mut spend_bodies = Vec::with_capacity(2);
        let mut spend_proofs = Vec::with_capacity(2);
        let mut spend_randomizers = Vec::with_capacity(2);
        let mut output_bodies = Vec::with_capacity(2);
        let mut output_proofs = Vec::with_capacity(2);
        let mut synthetic_blinding_factor = Fr::from(0u64);

        for note in &input_notes {
            let witness = proof_tree.witness(note.commit()).unwrap();
            let randomizer = random_fr();
            let blinding = random_fr();
            synthetic_blinding_factor += blinding;
            let public = SpendProofPublic {
                anchor: proof_tree.root(),
                balance_commitment: note.value().commit(blinding),
                nullifier: Nullifier::derive(
                    sender.nullifier_key(),
                    witness.position(),
                    &note.commit(),
                ),
                rk: sender.spend_auth_key().randomize(&randomizer).into(),
            };
            let private = SpendProofPrivate {
                state_commitment_proof: witness,
                note: note.clone(),
                v_blinding: blinding,
                spend_auth_randomizer: randomizer,
                ak: sender.spend_auth_key().into(),
                nk: *sender.nullifier_key(),
            };
            let proof = SpendProof::prove(
                random_fq(),
                random_fq(),
                &proof_params::SPEND_PROOF_PROVING_KEY,
                public.clone(),
                private,
            )
            .unwrap();
            let encoded: pb::ZkSpendProof = proof.into();
            spend_bodies.push(
                SpendBody {
                    balance_commitment: public.balance_commitment,
                    nullifier: public.nullifier,
                    rk: public.rk,
                    encrypted_backref: EncryptedBackref::dummy(),
                }
                .encode_to_vec(),
            );
            spend_proofs.push(encoded.inner);
            spend_randomizers.push(randomizer);
        }

        let output_total = 15_000_000_000u128
            .checked_add(public_release)
            .and_then(|value| value.checked_sub(fee_atomic))
            .and_then(|value| value.checked_sub(public_lock))
            .unwrap();
        for (destination, amount) in [
            (receiver_address, 10_000_000_000u128),
            (sender_address.clone(), output_total - 10_000_000_000),
        ] {
            let note = Note::from_parts(destination, value(amount), Rseed(random_bytes())).unwrap();
            let blinding = random_fr();
            synthetic_blinding_factor += blinding;
            let public = OutputProofPublic {
                note_commitment: note.commit(),
                balance_commitment: (-Balance::from(note.value())).commit(blinding),
            };
            let proof = OutputProof::prove(
                random_fq(),
                random_fq(),
                &proof_params::OUTPUT_PROOF_PROVING_KEY,
                public.clone(),
                OutputProofPrivate {
                    note: note.clone(),
                    balance_blinding: blinding,
                },
            )
            .unwrap();
            let encoded: pb::ZkOutputProof = proof.into();
            output_bodies.push(
                OutputBody {
                    note_payload: note.payload(),
                    balance_commitment: public.balance_commitment,
                    ovk_wrapped_key: note
                        .encrypt_key(full_viewing_key.outgoing(), public.balance_commitment),
                    wrapped_memo_key: WrappedMemoKey::encrypt(
                        &memo_key,
                        note.ephemeral_secret_key(),
                        note.transmission_key(),
                        &note.diversified_generator(),
                    ),
                }
                .encode_to_vec(),
            );
            output_proofs.push(encoded.inner);
        }

        let mut proofs = spend_proofs;
        proofs.extend(output_proofs);
        let mut memo_plaintext = vec![0u8; 512];
        let return_address = sender_address.to_vec();
        memo_plaintext[..return_address.len()].copy_from_slice(&return_address);
        let body = TxBody {
            version: 1,
            chain_context: chain,
            expiry_height: 100,
            anchor,
            fee: Amount::new(fee_atomic).unwrap(),
            spends: spend_bodies,
            outputs: output_bodies,
            action,
            proof_hashes: proofs.iter().map(|proof| proof_hash(proof)).collect(),
            memo_ciphertext: Some(memo_key.encrypt(memo_plaintext, PayloadKind::Memo)),
        };
        let effect_hash = body.effect_hash().unwrap();
        let mut authorizations: Vec<_> = spend_randomizers
            .iter()
            .enumerate()
            .map(|(index, randomizer)| Authorization {
                role: Role::Spend,
                index: index as u32,
                signature: sender
                    .spend_auth_key()
                    .randomize(randomizer)
                    .sign_deterministic(&effect_hash)
                    .to_bytes()
                    .to_vec(),
            })
            .collect();
        authorizations.extend(role_keys.into_iter().map(|(role, key)| {
            let message = ed25519_authorization_message(role, &effect_hash).unwrap();
            Authorization {
                role,
                index: 0,
                signature: key.sign(&message).to_bytes().to_vec(),
            }
        }));
        let envelope = Envelope {
            envelope_version: 1,
            canonical_body: body.encode_canonical().unwrap(),
            proofs,
            authorizations,
            binding_signature: SigningKey::<Binding>::from(synthetic_blinding_factor)
                .sign_deterministic(&effect_hash)
                .to_bytes()
                .to_vec(),
        }
        .encode_canonical(1, 100)
        .unwrap();
        let native_asset_id = asset::Id(Fq::from(1u64)).to_bytes();
        let monetary_policy = MonetaryPolicy {
            genesis_supply: Amount::new(15_000_000_000 + genesis_stake + genesis_commission)
                .unwrap(),
            epoch_blocks: 720,
            halving_interval_epochs: 35_040,
        };
        (
            GenesisConfig {
                chain_context: chain,
                native_asset_id,
                protocol_version: 1,
                max_block_bytes: 1_000_000,
                max_tx_lifetime_blocks: 100,
                max_envelope_bytes: 65_536,
                anchor_retention_blocks: 8,
                genesis_allocation: GenesisAllocation {
                    shielded: Amount::new(15_000_000_000).unwrap(),
                    stake: Amount::new(genesis_stake).unwrap(),
                    pending_delegation: Amount::ZERO,
                    exits: Amount::ZERO,
                    commission: Amount::new(genesis_commission).unwrap(),
                    fee_reserve: Amount::ZERO,
                    unclaimed_genesis: Amount::ZERO,
                },
                fee_policy: FeePolicy::reference_testnet(),
                monetary_policy,
                genesis_staking,
                genesis_commitments,
                genesis_execution_hash: [0x11; 32],
                genesis_compact_hash: [0x12; 32],
            },
            envelope,
        )
    }

    fn real_transfer_fixture() -> (GenesisConfig, Vec<u8>) {
        real_action_fixture(RealActionKind::Transfer)
    }

    fn real_cancel_pending_fixture() -> (GenesisConfig, Vec<u8>) {
        let parameter_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../feasibility/.tools/downloads");
        let output_pk = load_proving_key(
            &parameter_dir,
            "output_pk.bin",
            "c9e97866edd6c815a7bcb2f3b5493713794369692bb96e5a2e682613c330e4a8",
        );
        proof_params::OUTPUT_PROOF_PROVING_KEY
            .try_load(&output_pk)
            .unwrap();

        let chain = chain_context([0x43; 32]);
        let operator_key = Ed25519SigningKey::from([0x91; 32]);
        let consensus_key = Ed25519SigningKey::from([0x92; 32]);
        let owner_key = Ed25519SigningKey::from([0x93; 32]);
        let operator = operator_key.verification_key().to_bytes();
        let consensus = consensus_key.verification_key().to_bytes();
        let owner = owner_key.verification_key().to_bytes();
        let validator = validator_id(&chain, &operator);
        let position = position_id(&chain, &owner);
        let release = Amount::new(bit_staking::TESTNET_MIN_DELEGATION_ATOMIC).unwrap();
        let fee = Amount::new(1_000_000).unwrap();

        let mut genesis_staking =
            StakingBook::new(chain, StakingParameters::reference_testnet()).unwrap();
        genesis_staking
            .register_validator_with_metadata(
                validator,
                operator,
                consensus,
                500,
                "cancel target".to_owned(),
                String::new(),
                String::new(),
            )
            .unwrap();
        genesis_staking
            .open_pending_delegation(
                0,
                0,
                position,
                owner,
                validator,
                release,
                Amount::ZERO,
                false,
                vec![0x94; bit_staking::RECOVERY_RECEIPT_BYTES],
            )
            .unwrap();

        let receiver = spend_key();
        let receiver_fvk = receiver.full_viewing_key();
        let (receiver_address, _) = receiver_fvk.incoming().payment_address(0u32.into());
        let output_note = Note::from_parts(
            receiver_address,
            value(release.value() - fee.value()),
            Rseed(random_bytes()),
        )
        .unwrap();
        let output_blinding = random_fr();
        let output_public = OutputProofPublic {
            note_commitment: output_note.commit(),
            balance_commitment: (-Balance::from(output_note.value())).commit(output_blinding),
        };
        let output_proof = OutputProof::prove(
            random_fq(),
            random_fq(),
            &proof_params::OUTPUT_PROOF_PROVING_KEY,
            output_public.clone(),
            OutputProofPrivate {
                note: output_note.clone(),
                balance_blinding: output_blinding,
            },
        )
        .unwrap();
        let encoded_proof: pb::ZkOutputProof = output_proof.into();
        let proof = encoded_proof.inner;
        let memo_key = penumbra_sdk_keys::PayloadKey::random_key(&mut OsRng);
        let output_body = OutputBody {
            note_payload: output_note.payload(),
            balance_commitment: output_public.balance_commitment,
            ovk_wrapped_key: output_note
                .encrypt_key(receiver_fvk.outgoing(), output_public.balance_commitment),
            wrapped_memo_key: WrappedMemoKey::encrypt(
                &memo_key,
                output_note.ephemeral_secret_key(),
                output_note.transmission_key(),
                &output_note.diversified_generator(),
            ),
        }
        .encode_to_vec();
        let shielded_note = Note::from_parts(
            receiver_fvk.incoming().payment_address(1u32.into()).0,
            value(15_000_000_000 - release.value()),
            Rseed(random_bytes()),
        )
        .unwrap();
        let genesis_commitment = shielded_note.commit();
        let mut genesis_tree = Tree::new();
        genesis_tree
            .insert(Witness::Forget, genesis_commitment)
            .unwrap();
        genesis_tree.end_block().unwrap();
        let anchor = tree_root_bytes(&genesis_tree);
        let body = TxBody {
            version: 1,
            chain_context: chain,
            expiry_height: 100,
            anchor,
            fee,
            spends: vec![],
            outputs: vec![output_body],
            action: Action::CancelPending {
                position_id: position,
                expected_sequence: 0,
                expected_release: release,
                fee_source: bit_types::FeeSource::ReleasedValue,
            },
            proof_hashes: vec![proof_hash(&proof)],
            memo_ciphertext: Some(memo_key.encrypt(vec![0; 512], PayloadKind::Memo)),
        };
        let effect_hash = body.effect_hash().unwrap();
        let owner_message =
            ed25519_authorization_message(Role::PositionOwner, &effect_hash).unwrap();
        let envelope = Envelope {
            envelope_version: 1,
            canonical_body: body.encode_canonical().unwrap(),
            proofs: vec![proof],
            authorizations: vec![Authorization {
                role: Role::PositionOwner,
                index: 0,
                signature: owner_key.sign(&owner_message).to_bytes().to_vec(),
            }],
            binding_signature: SigningKey::<Binding>::from(output_blinding)
                .sign_deterministic(&effect_hash)
                .to_bytes()
                .to_vec(),
        }
        .encode_canonical(1, 100)
        .unwrap();
        let monetary_policy = MonetaryPolicy {
            genesis_supply: Amount::new(15_000_000_000).unwrap(),
            epoch_blocks: 720,
            halving_interval_epochs: 35_040,
        };
        let shielded =
            Amount::new(monetary_policy.genesis_supply.value() - release.value()).unwrap();
        (
            GenesisConfig {
                chain_context: chain,
                native_asset_id: asset::Id(Fq::from(1u64)).to_bytes(),
                protocol_version: 1,
                max_block_bytes: 1_000_000,
                max_tx_lifetime_blocks: 100,
                max_envelope_bytes: 65_536,
                anchor_retention_blocks: 8,
                monetary_policy,
                fee_policy: FeePolicy::reference_testnet(),
                genesis_allocation: GenesisAllocation {
                    shielded,
                    stake: Amount::ZERO,
                    pending_delegation: release,
                    exits: Amount::ZERO,
                    commission: Amount::ZERO,
                    fee_reserve: Amount::ZERO,
                    unclaimed_genesis: Amount::ZERO,
                },
                genesis_staking,
                genesis_commitments: vec![genesis_commitment.into()],
                genesis_execution_hash: [0xa1; 32],
                genesis_compact_hash: [0xa2; 32],
            },
            envelope,
        )
    }

    fn config(retention: u64) -> GenesisConfig {
        let monetary_policy = MonetaryPolicy::reference_testnet();
        GenesisConfig {
            chain_context: [1; 32],
            native_asset_id: {
                let mut id = [0; 32];
                id[0] = 1;
                id
            },
            protocol_version: 1,
            max_block_bytes: 1_000_000,
            max_tx_lifetime_blocks: 20,
            max_envelope_bytes: 65_536,
            anchor_retention_blocks: retention,
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

    async fn stage_empty_consensus(
        state: &PersistentState,
        block: &mut BlockSession<'_>,
        height: u64,
    ) {
        let next_hash = state.expected_next_validators_hash(height).await.unwrap();
        let empty = [];
        block
            .stage_consensus_system((height > 1).then_some(empty.as_slice()), next_hash)
            .unwrap();
    }

    fn active_validator_config(
        retention: u64,
        parameters: StakingParameters,
    ) -> (GenesisConfig, Hash32, Hash32, u64) {
        let mut genesis = config(retention);
        let chain = genesis.chain_context;
        let operator = [0x91; 32];
        let validator = validator_id(&chain, &operator);
        let consensus_pubkey = [0x92; 32];
        let owner = [0x93; 32];
        let position = position_id(&chain, &owner);
        let principal = Amount::new(bit_staking::TESTNET_MIN_SELF_BOND_ATOMIC).unwrap();
        let mut staking = StakingBook::new(chain, parameters).unwrap();
        staking
            .register_validator(validator, operator, consensus_pubkey, 500)
            .unwrap();
        staking
            .open_pending_delegation(
                0,
                0,
                position,
                owner,
                validator,
                principal,
                Amount::ZERO,
                true,
                vec![0x94; bit_staking::RECOVERY_RECEIPT_BYTES],
            )
            .unwrap();
        staking.activate_pending(&position, 1).unwrap();
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
        (genesis, validator, consensus_pubkey, power)
    }

    fn verified(tx: u8, anchor: Hash32, nullifier: u8, commitment: u64) -> VerifiedTransfer {
        VerifiedTransfer {
            tx_id: [tx; 32],
            effect_hash: [tx; 64],
            anchor,
            nullifiers: vec![[nullifier; 32]],
            output_commitments: vec![Fq::from(commitment).to_bytes()],
            fee: Amount::ZERO,
            minimum_fee: Amount::ZERO,
        }
    }

    fn empty_verified_staking(
        tx: u8,
        anchor: Hash32,
        action: VerifiedStakingAction,
    ) -> VerifiedStakingTransaction {
        VerifiedStakingTransaction {
            shielded: VerifiedTransfer {
                tx_id: [tx; 32],
                effect_hash: [tx; 64],
                anchor,
                nullifiers: Vec::new(),
                output_commitments: Vec::new(),
                fee: Amount::ZERO,
                minimum_fee: Amount::ZERO,
            },
            action,
        }
    }

    #[tokio::test]
    async fn prepare_is_not_durable_and_replay_is_deterministic() {
        let dir = TempDir::new().unwrap();
        let genesis_config = config(8);
        let state = PersistentState::open(dir.path().to_path_buf(), genesis_config.clone())
            .await
            .unwrap();
        let genesis = state.summary().await.unwrap();
        assert_eq!(genesis.state_height, 0);
        assert_eq!(genesis.storage_version, 0);
        assert_eq!(
            genesis.supply.unclaimed_genesis_total,
            genesis.supply.genesis_supply
        );

        let transfer = verified(4, genesis.shielded_tree_root, 5, 6);
        let mut block = state.begin_block(1, [7; 32], [8; 32]).await.unwrap();
        stage_empty_consensus(&state, &mut block, 1).await;
        block.stage_verified(&transfer).await.unwrap();
        let first_prepared = block.prepare().await.unwrap();
        let expected_root = first_prepared.app_hash;
        drop(first_prepared);
        assert_eq!(state.summary().await.unwrap(), genesis);

        state.close().await;
        let state = PersistentState::open(dir.path().to_path_buf(), genesis_config.clone())
            .await
            .unwrap();
        assert_eq!(state.summary().await.unwrap(), genesis);
        let mut replay = state.begin_block(1, [7; 32], [8; 32]).await.unwrap();
        stage_empty_consensus(&state, &mut replay, 1).await;
        replay.stage_verified(&transfer).await.unwrap();
        let replay = replay.prepare().await.unwrap();
        assert_eq!(replay.app_hash, expected_root);
        let receipt = state.commit(replay).unwrap();
        assert_eq!(receipt.app_hash, expected_root);
        assert_eq!(receipt.state_height, 1);
        assert!(state
            .nullifier_is_spent(&transfer.nullifiers[0])
            .await
            .unwrap());
        assert!(state.transaction_is_applied(&transfer.tx_id).await.unwrap());

        let member = state
            .query_latest_with_proof(&nullifier_key(&transfer.nullifiers[0]))
            .await
            .unwrap();
        assert!(member.value.is_some());
        member.verify().unwrap();
        let absent = state
            .query_latest_with_proof(&nullifier_key(&[99; 32]))
            .await
            .unwrap();
        assert!(absent.value.is_none());
        absent.verify().unwrap();
        let main_store = state.query_latest_with_proof(META_HEIGHT).await.unwrap();
        assert_eq!(main_store.value, Some(u64_bytes(1)));
        main_store.verify().unwrap();

        state.close().await;
        let state = PersistentState::open(dir.path().to_path_buf(), genesis_config)
            .await
            .unwrap();
        let reopened = state.summary().await.unwrap();
        assert_eq!(reopened.state_height, 1);
        assert_eq!(reopened.app_hash, expected_root);
        assert!(state
            .nullifier_is_spent(&transfer.nullifiers[0])
            .await
            .unwrap());
        state.close().await;
    }

    #[tokio::test]
    async fn epoch_boundary_cannot_commit_without_the_required_system_settlement() {
        let dir = TempDir::new().unwrap();
        let mut genesis_config = config(8);
        genesis_config.monetary_policy.epoch_blocks = 2;
        let state = PersistentState::open(dir.path().to_path_buf(), genesis_config.clone())
            .await
            .unwrap();

        for height in 1..=2 {
            let mut block = state
                .begin_block(height, [height as u8; 32], [height as u8 + 10; 32])
                .await
                .unwrap();
            stage_empty_consensus(&state, &mut block, height).await;
            state.commit(block.prepare().await.unwrap()).unwrap();
        }
        let before_boundary = state.summary().await.unwrap();
        assert_eq!(before_boundary.state_height, 2);
        assert_eq!(before_boundary.supply.completed_epochs, 0);

        let boundary = state.begin_block(3, [3; 32], [13; 32]).await.unwrap();
        assert!(matches!(
            boundary.prepare().await,
            Err(Error::InvalidSystemPhase(
                "consensus system phases were not staged"
            ))
        ));
        assert_eq!(state.summary().await.unwrap(), before_boundary);
        state.close().await;

        let reopened = PersistentState::open(dir.path().to_path_buf(), genesis_config.clone())
            .await
            .unwrap();
        assert_eq!(reopened.summary().await.unwrap(), before_boundary);
        reopened.close().await;
    }

    #[tokio::test]
    async fn removing_the_last_effective_validator_halts_atomically() {
        let dir = TempDir::new().unwrap();
        let mut parameters = StakingParameters::reference_testnet();
        parameters.downtime_window = 1;
        parameters.min_signed_bps = 10_000;
        let (genesis, validator, consensus_pubkey, power) = active_validator_config(8, parameters);
        let state = PersistentState::open(dir.path().to_path_buf(), genesis)
            .await
            .unwrap();

        let first_hash = state.expected_next_validators_hash(1).await.unwrap();
        let mut first = state.begin_block(1, [0xa1; 32], [0xa2; 32]).await.unwrap();
        first.stage_consensus_system(None, first_hash).unwrap();
        state.commit(first.prepare().await.unwrap()).unwrap();

        let second_hash = state.expected_next_validators_hash(2).await.unwrap();
        let mut second = state.begin_block(2, [0xa3; 32], [0xa4; 32]).await.unwrap();
        let missed = CommitVote {
            consensus_address: bit_staking::consensus_address(&consensus_pubkey),
            power,
            signed: false,
        };
        assert!(matches!(
            second.stage_consensus_system(Some(&[missed]), second_hash),
            Err(Error::NoSafeValidatorSet)
        ));
        assert_eq!(
            second.staking.validator(&validator).unwrap().status,
            bit_staking::ValidatorStatus::Active
        );

        let signed = CommitVote {
            signed: true,
            ..missed
        };
        let outcome = second
            .stage_consensus_system(Some(&[signed]), second_hash)
            .unwrap();
        assert!(outcome.validator_updates.is_empty());
        state.commit(second.prepare().await.unwrap()).unwrap();
        assert_eq!(state.summary().await.unwrap().state_height, 2);
        assert_eq!(
            state
                .staking_book()
                .unwrap()
                .validator(&validator)
                .unwrap()
                .status,
            bit_staking::ValidatorStatus::Active
        );
    }

    #[tokio::test]
    async fn staking_records_commit_with_supply_and_survive_restart() {
        let dir = TempDir::new().unwrap();
        let mut genesis_config = config(8);
        genesis_config.monetary_policy.epoch_blocks = 2;
        genesis_config.genesis_allocation =
            GenesisAllocation::shielded_only(genesis_config.monetary_policy.genesis_supply);
        let chain = genesis_config.chain_context;
        let operator = [41; 32];
        let validator = validator_id(&chain, &operator);
        let owner = [42; 32];
        let position = position_id(&chain, &owner);
        let deposit = Amount::new(bit_staking::TESTNET_MIN_SELF_BOND_ATOMIC).unwrap();

        let state = PersistentState::open(dir.path().to_path_buf(), genesis_config.clone())
            .await
            .unwrap();
        let mut first = state.begin_block(1, [51; 32], [52; 32]).await.unwrap();
        stage_empty_consensus(&state, &mut first, 1).await;
        first
            .stage_authorized_validator_registration(
                validator,
                operator,
                [43; 32],
                500,
                Amount::ZERO,
            )
            .unwrap();
        first
            .stage_authorized_pending_delegation(
                0,
                position,
                owner,
                validator,
                deposit,
                Amount::ZERO,
                true,
                vec![44; bit_staking::RECOVERY_RECEIPT_BYTES],
                Amount::ZERO,
            )
            .unwrap();
        let first_receipt = state.commit(first.prepare().await.unwrap()).unwrap();
        assert_eq!(first_receipt.staking.pending_assets, deposit);
        assert_eq!(first_receipt.supply.pending_delegation_total, deposit);
        for key in [
            staking_validator_key(&validator),
            staking_pool_key(&validator),
            staking_position_key(&position),
            staking_capacity_key(1),
        ] {
            let proof = state.query_latest_with_proof(&key).await.unwrap();
            assert!(proof.value.is_some(), "missing staking key {key}");
            proof.verify().unwrap();
        }

        let mut second = state.begin_block(2, [53; 32], [54; 32]).await.unwrap();
        stage_empty_consensus(&state, &mut second, 2).await;
        state.commit(second.prepare().await.unwrap()).unwrap();
        let mut boundary = state.begin_block(3, [55; 32], [56; 32]).await.unwrap();
        let boundary_hash = state.expected_next_validators_hash(3).await.unwrap();
        let system = boundary
            .stage_consensus_system(Some(&[]), boundary_hash)
            .unwrap();
        let settlement = system.reward_settlement.unwrap();
        assert_eq!(settlement.distributed, Amount::ZERO);
        let outcomes = system.activations;
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(outcomes[0].1, ActivationOutcome::Activated { .. }));
        let selected = system.validator_set.unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].validator_id, validator);
        let receipt = state.commit(boundary.prepare().await.unwrap()).unwrap();
        assert_eq!(receipt.staking.pooled_assets, deposit);
        assert_eq!(receipt.staking.pending_assets, Amount::ZERO);
        assert_eq!(receipt.supply.stake_total, deposit);
        assert_eq!(receipt.supply.pending_delegation_total, Amount::ZERO);
        assert_eq!(receipt.supply.completed_epochs, 1);
        let position_proof = state
            .query_latest_with_proof(&staking_position_key(&position))
            .await
            .unwrap();
        let stored_position = StakePosition::decode_persistent(
            position_proof
                .value
                .as_deref()
                .expect("position must exist"),
        )
        .unwrap();
        assert_eq!(stored_position.status, PositionStatus::Active);
        position_proof.verify().unwrap();
        state.close().await;

        let reopened = PersistentState::open(dir.path().to_path_buf(), genesis_config.clone())
            .await
            .unwrap();
        let staking = reopened.staking_book().unwrap();
        assert_eq!(staking.position(&position).unwrap(), &stored_position);
        assert_eq!(
            staking.validator(&validator).unwrap().status,
            bit_staking::ValidatorStatus::Active
        );
        assert_eq!(reopened.supply_audit().await.unwrap().stake_total, deposit);
        let summary = reopened.summary().await.unwrap();
        let mut tampered_pool = staking.pool(&validator).unwrap().clone();
        tampered_pool.assets = Amount::new(deposit.value() + 1).unwrap();
        reopened.close().await;

        let prefixes = SUBSTORES
            .iter()
            .map(|prefix| (*prefix).to_owned())
            .collect();
        let storage = Storage::load(dir.path().to_path_buf(), prefixes)
            .await
            .unwrap();
        let mut delta = StateDelta::new(storage.latest_snapshot());
        delta.put_raw(
            staking_pool_key(&validator),
            tampered_pool.encode_persistent(),
        );
        delta.put_raw(META_HEIGHT.to_owned(), u64_bytes(4));
        delta.put_raw(anchor_height_key(4), summary.shielded_tree_root.to_vec());
        delta.put_raw(anchor_lookup_key(&summary.shielded_tree_root), u64_bytes(4));
        delta.put_raw(execution_key(4), [61; 32].to_vec());
        delta.put_raw(compact_key(4), [62; 32].to_vec());
        storage.commit(delta).await.unwrap();
        storage.release().await;
        let error = PersistentState::open(dir.path().to_path_buf(), genesis_config)
            .await
            .err()
            .expect("tampered staking pool must be rejected");
        assert!(error.to_string().contains("P supply container"));
    }

    #[tokio::test]
    async fn epoch_rewards_move_fee_reserve_into_old_pools_and_commission_atomically() {
        let dir = TempDir::new().unwrap();
        let mut genesis_config = config(8);
        genesis_config.monetary_policy.epoch_blocks = 2;
        let chain = genesis_config.chain_context;
        let operator = [0x71; 32];
        let validator_id = validator_id(&chain, &operator);
        let owner = [0x72; 32];
        let position = position_id(&chain, &owner);
        let principal = Amount::new(bit_staking::TESTNET_MIN_SELF_BOND_ATOMIC).unwrap();
        let initial_fees = Amount::new(101).unwrap();

        let mut staking = StakingBook::new(chain, StakingParameters::reference_testnet()).unwrap();
        let consensus_pubkey = [0x73; 32];
        staking
            .register_validator(validator_id, operator, consensus_pubkey, 500)
            .unwrap();
        staking
            .open_pending_delegation(
                0,
                0,
                position,
                owner,
                validator_id,
                principal,
                Amount::ZERO,
                true,
                vec![0x74; bit_staking::RECOVERY_RECEIPT_BYTES],
            )
            .unwrap();
        staking.activate_pending(&position, 1).unwrap();
        let power = staking.apply_validator_set().unwrap()[0].power;
        genesis_config.genesis_staking = staking;
        genesis_config.genesis_allocation = GenesisAllocation {
            shielded: Amount::ZERO,
            stake: principal,
            pending_delegation: Amount::ZERO,
            exits: Amount::ZERO,
            commission: Amount::ZERO,
            fee_reserve: initial_fees,
            unclaimed_genesis: Amount::new(
                genesis_config.monetary_policy.genesis_supply.value()
                    - principal.value()
                    - initial_fees.value(),
            )
            .unwrap(),
        };

        let state = PersistentState::open(dir.path().to_path_buf(), genesis_config.clone())
            .await
            .unwrap();
        let first_next_hash = state.expected_next_validators_hash(1).await.unwrap();
        let mut first = state.begin_block(1, [1; 32], [3; 32]).await.unwrap();
        first.stage_consensus_system(None, first_next_hash).unwrap();
        state.commit(first.prepare().await.unwrap()).unwrap();
        let commit_vote = CommitVote {
            consensus_address: bit_staking::consensus_address(&consensus_pubkey),
            power,
            signed: true,
        };
        let second_next_hash = state.expected_next_validators_hash(2).await.unwrap();
        let mut second = state.begin_block(2, [2; 32], [4; 32]).await.unwrap();
        second
            .stage_consensus_system(Some(&[commit_vote]), second_next_hash)
            .unwrap();
        state.commit(second.prepare().await.unwrap()).unwrap();
        let boundary_next_hash = state.expected_next_validators_hash(3).await.unwrap();
        let mut boundary = state.begin_block(3, [3; 32], [5; 32]).await.unwrap();
        let system = boundary
            .stage_consensus_system(Some(&[commit_vote]), boundary_next_hash)
            .unwrap();
        let settlement = system.reward_settlement.unwrap();
        let available = initial_fees.value() + settlement.issuance_quota.value();
        let expected_commission = available * 500 / 10_000;
        assert_eq!(settlement.distributed.value(), available);
        assert_eq!(settlement.fee_reserve_remainder, Amount::ZERO);
        assert_eq!(
            settlement.validator_rewards[0].commission_reward.value(),
            expected_commission
        );
        assert_eq!(settlement.validator_rewards[0].score, u128::from(power) * 2);
        assert!(system.activations.is_empty());
        assert_eq!(system.validator_set.unwrap()[0].validator_id, validator_id);
        assert_eq!(system.validator_updates.len(), 1);
        let receipt = state.commit(boundary.prepare().await.unwrap()).unwrap();
        assert_eq!(receipt.supply.fee_reserve, Amount::ZERO);
        assert_eq!(receipt.supply.commission_total.value(), expected_commission);
        assert_eq!(
            receipt.supply.stake_total.value(),
            principal.value() + available - expected_commission
        );
        assert_eq!(
            state
                .staking_book()
                .unwrap()
                .validator(&validator_id)
                .unwrap()
                .commission_accrued
                .value(),
            expected_commission
        );
        let h3 = state.summary().await.unwrap();
        let claim_next_hash = state.expected_next_validators_hash(4).await.unwrap();
        let mut claim_block = state.begin_block(4, [4; 32], [6; 32]).await.unwrap();
        claim_block
            .stage_consensus_system(Some(&[commit_vote]), claim_next_hash)
            .unwrap();
        claim_block
            .stage_verified_staking(&empty_verified_staking(
                0x75,
                h3.shielded_tree_root,
                VerifiedStakingAction::ClaimCommission {
                    validator_id,
                    expected_sequence: 0,
                    requested_amount: Amount::new(expected_commission).unwrap(),
                    fee_source: bit_types::FeeSource::ReleasedValue,
                },
            ))
            .await
            .unwrap();
        let claim_receipt = state.commit(claim_block.prepare().await.unwrap()).unwrap();
        assert_eq!(claim_receipt.supply.commission_total, Amount::ZERO);
        assert_eq!(
            claim_receipt.supply.shielded_total.value(),
            expected_commission
        );
        assert_eq!(
            state
                .staking_book()
                .unwrap()
                .validator(&validator_id)
                .unwrap()
                .sequence,
            1
        );
        state.close().await;

        let reopened = PersistentState::open(dir.path().to_path_buf(), genesis_config)
            .await
            .unwrap();
        assert_eq!(
            reopened
                .staking_book()
                .unwrap()
                .totals()
                .unwrap()
                .commission_assets,
            Amount::ZERO
        );
        reopened.close().await;
    }

    #[tokio::test]
    async fn conflicts_do_not_partially_change_the_block_overlay() {
        let dir = TempDir::new().unwrap();
        let state = PersistentState::open(dir.path().to_path_buf(), config(8))
            .await
            .unwrap();
        let genesis = state.summary().await.unwrap();
        let first = verified(10, genesis.shielded_tree_root, 11, 12);
        let conflict = verified(13, genesis.shielded_tree_root, 11, 14);
        let after_conflict = verified(15, genesis.shielded_tree_root, 16, 17);
        let mut internally_duplicated = verified(23, genesis.shielded_tree_root, 24, 25);
        internally_duplicated.nullifiers.push([24; 32]);
        let mut malformed_commitment = verified(26, genesis.shielded_tree_root, 27, 28);
        malformed_commitment.output_commitments[0] = [0xff; 32];
        let mut block = state.begin_block(1, [18; 32], [19; 32]).await.unwrap();
        stage_empty_consensus(&state, &mut block, 1).await;
        block.stage_verified(&first).await.unwrap();
        assert!(matches!(
            block.stage_verified(&first).await,
            Err(Error::TransactionAlreadyApplied)
        ));
        assert!(matches!(
            block.stage_verified(&conflict).await,
            Err(Error::NullifierAlreadySpent)
        ));
        assert!(matches!(
            block.stage_verified(&internally_duplicated).await,
            Err(Error::DuplicateNullifier)
        ));
        assert!(matches!(
            block.stage_verified(&malformed_commitment).await,
            Err(Error::InvalidOutputCommitment)
        ));
        block.stage_verified(&after_conflict).await.unwrap();
        let receipt = state.commit(block.prepare().await.unwrap()).unwrap();
        assert_eq!(receipt.transaction_count, 2);
        assert!(!state.transaction_is_applied(&conflict.tx_id).await.unwrap());
        assert!(!state
            .transaction_is_applied(&internally_duplicated.tx_id)
            .await
            .unwrap());
        assert!(!state
            .transaction_is_applied(&malformed_commitment.tx_id)
            .await
            .unwrap());
        assert!(state
            .transaction_is_applied(&after_conflict.tx_id)
            .await
            .unwrap());

        let mut next = state.begin_block(2, [20; 32], [21; 32]).await.unwrap();
        let replay_nullifier = verified(22, receipt.shielded_tree_root, 11, 23);
        assert!(matches!(
            next.stage_verified(&replay_nullifier).await,
            Err(Error::NullifierAlreadySpent)
        ));
        state.close().await;
    }

    #[tokio::test]
    async fn anchor_window_is_pruned_but_current_state_remains_valid() {
        let dir = TempDir::new().unwrap();
        let state = PersistentState::open(dir.path().to_path_buf(), config(2))
            .await
            .unwrap();
        let anchor0 = state.summary().await.unwrap().shielded_tree_root;

        let mut block1 = state.begin_block(1, [1; 32], [1; 32]).await.unwrap();
        stage_empty_consensus(&state, &mut block1, 1).await;
        let receipt1 = state.commit(block1.prepare().await.unwrap()).unwrap();
        let mut block2 = state.begin_block(2, [2; 32], [2; 32]).await.unwrap();
        stage_empty_consensus(&state, &mut block2, 2).await;
        let receipt2 = state.commit(block2.prepare().await.unwrap()).unwrap();
        assert!(!state.anchor_is_retained(&anchor0).await.unwrap());
        assert!(state
            .anchor_is_retained(&receipt1.shielded_tree_root)
            .await
            .unwrap());
        assert!(state
            .anchor_is_retained(&receipt2.shielded_tree_root)
            .await
            .unwrap());

        let mut block3 = state.begin_block(3, [3; 32], [3; 32]).await.unwrap();
        stage_empty_consensus(&state, &mut block3, 3).await;
        let receipt3 = state.commit(block3.prepare().await.unwrap()).unwrap();
        assert!(!state
            .anchor_is_retained(&receipt1.shielded_tree_root)
            .await
            .unwrap());
        assert!(state
            .anchor_is_retained(&receipt2.shielded_tree_root)
            .await
            .unwrap());
        assert!(state
            .anchor_is_retained(&receipt3.shielded_tree_root)
            .await
            .unwrap());
        state.close().await;
    }

    #[tokio::test]
    async fn immutable_configuration_mismatch_stops_open() {
        let dir = TempDir::new().unwrap();
        let original = config(8);
        let state = PersistentState::open(dir.path().to_path_buf(), original.clone())
            .await
            .unwrap();
        state.close().await;

        let mut wrong_chain = original.clone();
        wrong_chain.chain_context = [9; 32];
        wrong_chain.genesis_staking =
            StakingBook::new([9; 32], StakingParameters::reference_testnet()).unwrap();
        let error = PersistentState::open(dir.path().to_path_buf(), wrong_chain)
            .await
            .err()
            .expect("mismatched configuration must be rejected");
        assert!(error
            .to_string()
            .contains("immutable configuration mismatch"));

        let mut wrong_block_limit = original.clone();
        wrong_block_limit.max_block_bytes += 1;
        let error = PersistentState::open(dir.path().to_path_buf(), wrong_block_limit)
            .await
            .err()
            .expect("mismatched block limit must be rejected");
        assert!(error
            .to_string()
            .contains("immutable configuration mismatch"));

        let mut wrong_policy = original.clone();
        wrong_policy.monetary_policy.halving_interval_epochs += 1;
        let error = PersistentState::open(dir.path().to_path_buf(), wrong_policy)
            .await
            .err()
            .expect("mismatched monetary policy must be rejected");
        assert!(error
            .to_string()
            .contains("immutable configuration mismatch"));

        let mut wrong_fee_policy = original.clone();
        wrong_fee_policy.fee_policy.base = Amount::new(1_001).unwrap();
        let error = PersistentState::open(dir.path().to_path_buf(), wrong_fee_policy)
            .await
            .err()
            .expect("mismatched fee policy must be rejected");
        assert!(error.to_string().contains("immutable fee policy differs"));

        let mut wrong_staking_parameters = original.clone();
        let mut parameters = StakingParameters::reference_testnet();
        parameters.max_validators -= 1;
        wrong_staking_parameters.genesis_staking =
            StakingBook::new(original.chain_context, parameters).unwrap();
        let error = PersistentState::open(dir.path().to_path_buf(), wrong_staking_parameters)
            .await
            .err()
            .expect("mismatched staking parameters must be rejected");
        assert!(error
            .to_string()
            .contains("immutable staking parameters differ"));

        let mut wrong_commitments = original;
        wrong_commitments.genesis_commitments = vec![Fq::from(7u64).to_bytes()];
        let error = PersistentState::open(dir.path().to_path_buf(), wrong_commitments)
            .await
            .err()
            .expect("mismatched genesis commitments must be rejected");
        assert!(error
            .to_string()
            .contains("immutable configuration mismatch"));
    }

    #[tokio::test]
    async fn rolled_back_schema_and_corrupt_frontier_stop_open() {
        let schema_dir = TempDir::new().unwrap();
        let genesis_config = config(8);
        let state = PersistentState::open(schema_dir.path().to_path_buf(), genesis_config.clone())
            .await
            .unwrap();
        state.close().await;
        let prefixes = SUBSTORES
            .iter()
            .map(|prefix| (*prefix).to_owned())
            .collect();
        let storage = Storage::load(schema_dir.path().to_path_buf(), prefixes)
            .await
            .unwrap();
        let mut delta = StateDelta::new(storage.latest_snapshot());
        delta.put_raw(META_VERSION.to_owned(), 1u32.to_be_bytes().to_vec());
        delta.put_raw(META_HEIGHT.to_owned(), u64_bytes(1));
        storage.commit(delta).await.unwrap();
        storage.release().await;
        let error = PersistentState::open(schema_dir.path().to_path_buf(), genesis_config.clone())
            .await
            .err()
            .expect("rolled-back schema must be rejected");
        assert!(error.to_string().contains("storage schema 1"));

        let frontier_dir = TempDir::new().unwrap();
        let state =
            PersistentState::open(frontier_dir.path().to_path_buf(), genesis_config.clone())
                .await
                .unwrap();
        state.close().await;
        let prefixes = SUBSTORES
            .iter()
            .map(|prefix| (*prefix).to_owned())
            .collect();
        let storage = Storage::load(frontier_dir.path().to_path_buf(), prefixes)
            .await
            .unwrap();
        let snapshot = storage.latest_snapshot();
        let mut schedule = read_effective_schedule(&snapshot).await.unwrap();
        let unchanged = schedule.effective_set_at(2).unwrap().clone();
        schedule.advance(1, unchanged).unwrap();
        let mut delta = StateDelta::new(snapshot);
        delta.put_raw(META_HEIGHT.to_owned(), u64_bytes(1));
        delta.put_raw(
            STAKING_EFFECTIVE_SCHEDULE.to_owned(),
            schedule.encode_persistent().unwrap(),
        );
        delta.put_raw(TREE_FRONTIER.to_owned(), vec![0xff]);
        storage.commit(delta).await.unwrap();
        storage.release().await;
        let error = PersistentState::open(frontier_dir.path().to_path_buf(), genesis_config)
            .await
            .err()
            .expect("corrupt frontier must be rejected");
        assert!(error.to_string().contains("cannot decode tree frontier"));

        let duplicate_dir = TempDir::new().unwrap();
        let mut duplicate_config = config(8);
        let commitment = Fq::from(7u64).to_bytes();
        duplicate_config.genesis_commitments = vec![commitment, commitment];
        assert!(matches!(
            PersistentState::open(duplicate_dir.path().to_path_buf(), duplicate_config).await,
            Err(Error::InvalidConfig("duplicate genesis commitment"))
        ));
    }

    #[tokio::test]
    async fn real_enabled_staking_envelopes_persist_atomically() {
        for kind in [
            RealActionKind::RegisterValidator,
            RealActionKind::Delegate,
            RealActionKind::UpdateValidator,
            RealActionKind::UnjailValidator,
            RealActionKind::RotateConsensusKey,
            RealActionKind::ClaimCommission,
        ] {
            let (genesis_config, envelope_bytes) = real_action_fixture(kind);
            let decoded = Envelope::decode_canonical(&envelope_bytes, 65_536, 1, 100).unwrap();
            let body = decoded.validate(1, 100).unwrap();
            let action = body.action.clone();
            let dir = TempDir::new().unwrap();
            let state = PersistentState::open(dir.path().to_path_buf(), genesis_config.clone())
                .await
                .unwrap();
            let genesis = state.summary().await.unwrap();
            let mut block = state.begin_block(1, [0x81; 32], [0x82; 32]).await.unwrap();
            stage_empty_consensus(&state, &mut block, 1).await;
            let tx_id = block
                .verify_and_stage_transaction(&envelope_bytes)
                .await
                .unwrap();
            let fee_class = match &action {
                Action::RegisterValidator { .. } => FeeClass::ValidatorRegistration,
                Action::Delegate { .. } => FeeClass::NewPosition,
                Action::UpdateValidator { .. }
                | Action::UnjailValidator { .. }
                | Action::RotateConsensusKey { .. }
                | Action::ClaimCommission { .. } => FeeClass::Standard,
                _ => unreachable!(),
            };
            assert!(
                body.fee
                    >= genesis_config
                        .fee_policy
                        .minimum_fee(
                            envelope_bytes.len(),
                            body.spends.len(),
                            body.outputs.len(),
                            fee_class,
                        )
                        .unwrap()
            );
            let receipt = state.commit(block.prepare().await.unwrap()).unwrap();
            assert_eq!(receipt.transaction_count, 1);
            assert!(state.transaction_is_applied(&tx_id).await.unwrap());

            match action {
                Action::RegisterValidator {
                    validator_id,
                    operator,
                    consensus,
                    display_name,
                    website,
                    description,
                    ..
                } => {
                    let validator = state
                        .staking_book()
                        .unwrap()
                        .validator(&validator_id)
                        .unwrap()
                        .clone();
                    assert_eq!(validator.operator_pubkey, operator);
                    assert_eq!(validator.consensus_pubkey, consensus);
                    assert_eq!(validator.display_name, display_name);
                    assert_eq!(validator.website, website);
                    assert_eq!(validator.description, description);
                    assert_eq!(
                        receipt.supply.shielded_total.value(),
                        genesis.supply.shielded_total.value() - body.fee.value()
                    );
                    assert_eq!(receipt.supply.fee_reserve, body.fee);
                    let proof = state
                        .query_latest_with_proof(&staking_validator_key(&validator_id))
                        .await
                        .unwrap();
                    assert!(proof.value.is_some());
                    proof.verify().unwrap();
                }
                Action::Delegate {
                    position_id,
                    validator_id,
                    deposit,
                    recovery,
                    ..
                } => {
                    let position = state
                        .staking_book()
                        .unwrap()
                        .position(&position_id)
                        .unwrap()
                        .clone();
                    assert_eq!(position.status, PositionStatus::Pending);
                    assert_eq!(position.pending_amount, deposit);
                    assert_eq!(position.recovery_receipt, recovery);
                    assert_eq!(receipt.supply.pending_delegation_total, deposit);
                    assert_eq!(
                        receipt.supply.shielded_total.value(),
                        genesis.supply.shielded_total.value() - deposit.value() - body.fee.value()
                    );
                    assert_eq!(
                        state
                            .staking_book()
                            .unwrap()
                            .pool(&validator_id)
                            .unwrap()
                            .pending_total,
                        deposit
                    );
                    for key in [
                        staking_position_key(&position_id),
                        staking_pool_key(&validator_id),
                        staking_capacity_key(1),
                    ] {
                        let proof = state.query_latest_with_proof(&key).await.unwrap();
                        assert!(proof.value.is_some());
                        proof.verify().unwrap();
                    }
                }
                Action::UpdateValidator {
                    validator_id,
                    display_name,
                    website,
                    description,
                    commission_bps,
                    ..
                } => {
                    let validator = state
                        .staking_book()
                        .unwrap()
                        .validator(&validator_id)
                        .unwrap()
                        .clone();
                    assert_eq!(validator.display_name, display_name.unwrap());
                    assert_eq!(validator.website, website.unwrap());
                    assert_eq!(validator.description, description.unwrap());
                    assert_eq!(validator.sequence, 1);
                    assert_eq!(
                        validator.pending_commission.unwrap().commission_bps,
                        commission_bps.unwrap()
                    );
                    assert_eq!(
                        receipt.supply.shielded_total.value(),
                        genesis.supply.shielded_total.value() - body.fee.value()
                    );
                    state
                        .query_latest_with_proof(&staking_validator_key(&validator_id))
                        .await
                        .unwrap()
                        .verify()
                        .unwrap();
                }
                Action::UnjailValidator { validator_id, .. } => {
                    let validator = state
                        .staking_book()
                        .unwrap()
                        .validator(&validator_id)
                        .unwrap()
                        .clone();
                    assert_eq!(validator.status, bit_staking::ValidatorStatus::Candidate);
                    assert_eq!(validator.sequence, 1);
                    assert_eq!(validator.jailed_at_height, None);
                    assert_eq!(
                        receipt.supply.shielded_total.value(),
                        genesis.supply.shielded_total.value() - body.fee.value()
                    );
                }
                Action::RotateConsensusKey {
                    validator_id,
                    new_consensus,
                    ..
                } => {
                    let validator = state
                        .staking_book()
                        .unwrap()
                        .validator(&validator_id)
                        .unwrap()
                        .clone();
                    assert_ne!(validator.consensus_pubkey, new_consensus);
                    assert_eq!(validator.sequence, 1);
                    assert_eq!(validator.consensus_key_history.len(), 1);
                    assert_eq!(
                        validator.pending_consensus_key.unwrap().consensus_pubkey,
                        new_consensus
                    );
                    assert_eq!(
                        receipt.supply.shielded_total.value(),
                        genesis.supply.shielded_total.value() - body.fee.value()
                    );
                }
                Action::ClaimCommission {
                    validator_id,
                    requested_amount,
                    ..
                } => {
                    let validator = state
                        .staking_book()
                        .unwrap()
                        .validator(&validator_id)
                        .unwrap()
                        .clone();
                    assert_eq!(validator.sequence, 1);
                    assert_eq!(validator.commission_accrued, Amount::ZERO);
                    assert_eq!(receipt.supply.commission_total, Amount::ZERO);
                    assert_eq!(receipt.supply.fee_reserve, body.fee);
                    assert_eq!(
                        receipt.supply.shielded_total.value(),
                        genesis.supply.shielded_total.value() + requested_amount.value()
                            - body.fee.value()
                    );
                    state
                        .query_latest_with_proof(&staking_validator_key(&validator_id))
                        .await
                        .unwrap()
                        .verify()
                        .unwrap();
                }
                _ => unreachable!(),
            }
            state.close().await;

            let reopened = PersistentState::open(dir.path().to_path_buf(), genesis_config)
                .await
                .unwrap();
            assert_eq!(reopened.summary().await.unwrap().state_height, 1);
            assert!(reopened.transaction_is_applied(&tx_id).await.unwrap());
            reopened.close().await;
        }
    }

    #[tokio::test]
    async fn real_cancel_pending_releases_exact_value_and_fee() {
        let (genesis_config, envelope_bytes) = real_cancel_pending_fixture();
        let decoded = Envelope::decode_canonical(&envelope_bytes, 65_536, 1, 100).unwrap();
        let body = decoded.validate(1, 100).unwrap();
        let (position_id, release) = match body.action {
            Action::CancelPending {
                position_id,
                expected_release,
                ..
            } => (position_id, expected_release),
            _ => unreachable!(),
        };
        let dir = TempDir::new().unwrap();
        let state = PersistentState::open(dir.path().to_path_buf(), genesis_config.clone())
            .await
            .unwrap();
        let genesis = state.summary().await.unwrap();
        assert_eq!(genesis.supply.pending_delegation_total, release);

        let mut block = state.begin_block(1, [0xb1; 32], [0xb2; 32]).await.unwrap();
        stage_empty_consensus(&state, &mut block, 1).await;
        let mut wrong_source_body = body.clone();
        if let Action::CancelPending { fee_source, .. } = &mut wrong_source_body.action {
            *fee_source = bit_types::FeeSource::Shielded;
        }
        let mut wrong_source = decoded;
        wrong_source.canonical_body = wrong_source_body.encode_canonical().unwrap();
        let wrong_source_bytes = wrong_source.encode_canonical(1, 100).unwrap();
        assert!(matches!(
            block
                .verify_and_stage_transaction(&wrong_source_bytes)
                .await,
            Err(Error::Transaction(
                bit_transaction::Error::InvalidFeeSource(
                    "SHIELDED requires at least one private Spend"
                )
            ))
        ));

        let tx_id = block
            .verify_and_stage_transaction(&envelope_bytes)
            .await
            .unwrap();
        let receipt = state.commit(block.prepare().await.unwrap()).unwrap();
        assert_eq!(receipt.transaction_count, 1);
        assert_eq!(receipt.supply.pending_delegation_total, Amount::ZERO);
        assert_eq!(receipt.supply.fee_reserve, body.fee);
        assert_eq!(
            receipt.supply.shielded_total.value(),
            genesis.supply.shielded_total.value() + release.value() - body.fee.value()
        );
        let staking = state.staking_book().unwrap();
        let position = staking.position(&position_id).unwrap();
        assert_eq!(position.status, PositionStatus::Closed);
        assert_eq!(position.pending_amount, Amount::ZERO);
        assert_eq!(position.sequence, 1);
        let capacity = staking.capacity_record(1).unwrap();
        assert_eq!(capacity.accepted, 1);
        assert_eq!(capacity.canceled_before_processing, 1);
        assert!(state.transaction_is_applied(&tx_id).await.unwrap());
        state.close().await;

        let reopened = PersistentState::open(dir.path().to_path_buf(), genesis_config)
            .await
            .unwrap();
        assert_eq!(
            reopened
                .staking_book()
                .unwrap()
                .position(&position_id)
                .unwrap()
                .status,
            PositionStatus::Closed
        );
        reopened.close().await;
    }

    #[tokio::test]
    async fn real_two_spend_two_output_transfer_survives_restart() {
        let (genesis_config, envelope) = real_transfer_fixture();
        let dir = TempDir::new().unwrap();
        let state = PersistentState::open(dir.path().to_path_buf(), genesis_config.clone())
            .await
            .unwrap();
        let genesis = state.summary().await.unwrap();
        let decoded = Envelope::decode_canonical(&envelope, 65_536, 1, 100).unwrap();
        let body = decoded.validate(1, 100).unwrap();
        assert_eq!(genesis.shielded_tree_root, body.anchor);
        assert_eq!(genesis.supply.shielded_total.value(), 15_000_000_000);
        assert_eq!(genesis.supply.fee_reserve, Amount::ZERO);

        let mut block = state.begin_block(1, [0x21; 32], [0x22; 32]).await.unwrap();
        stage_empty_consensus(&state, &mut block, 1).await;
        let mut underpriced_body = body.clone();
        underpriced_body.fee = Amount::ZERO;
        let mut underpriced_envelope = decoded.clone();
        underpriced_envelope.canonical_body = underpriced_body.encode_canonical().unwrap();
        let underpriced_bytes = underpriced_envelope.encode_canonical(1, 100).unwrap();
        assert!(matches!(
            block.verify_and_stage_transfer(&underpriced_bytes).await,
            Err(Error::Transaction(bit_transaction::Error::FeeTooLow {
                provided: Amount::ZERO,
                ..
            }))
        ));
        let verified = block.verify_and_stage_transfer(&envelope).await.unwrap();
        assert_eq!(verified.nullifiers.len(), 2);
        assert_eq!(verified.output_commitments.len(), 2);
        assert_eq!(
            verified.minimum_fee,
            genesis_config
                .fee_policy
                .minimum_fee(envelope.len(), 2, 2, FeeClass::Standard)
                .unwrap()
        );
        assert!(verified.fee >= verified.minimum_fee);
        let prepared = block.prepare().await.unwrap();
        let expected_app_hash = prepared.app_hash;
        let expected_tree_root = prepared.shielded_tree_root;
        assert_eq!(prepared.supply.shielded_total.value(), 14_999_000_000);
        assert_eq!(prepared.supply.fee_reserve.value(), 1_000_000);
        assert_eq!(prepared.supply.current_supply.value(), 15_000_000_000);
        assert_eq!(state.summary().await.unwrap(), genesis);
        assert!(!state.transaction_is_applied(&verified.tx_id).await.unwrap());

        let receipt = state.commit(prepared).unwrap();
        assert_eq!(receipt.transaction_count, 1);
        assert_eq!(receipt.supply.fee_reserve.value(), 1_000_000);
        assert_ne!(receipt.shielded_tree_root, genesis.shielded_tree_root);
        assert_eq!(receipt.shielded_tree_root, expected_tree_root);
        for nullifier in &verified.nullifiers {
            assert!(state.nullifier_is_spent(nullifier).await.unwrap());
            let proof = state
                .query_latest_with_proof(&nullifier_key(nullifier))
                .await
                .unwrap();
            assert!(proof.value.is_some());
            proof.verify().unwrap();
        }
        let transaction_proof = state
            .query_latest_with_proof(&transaction_key(&verified.tx_id))
            .await
            .unwrap();
        assert!(transaction_proof.value.is_some());
        transaction_proof.verify().unwrap();
        let fee_proof = state.query_latest_with_proof(FEES_RESERVE).await.unwrap();
        assert_eq!(
            fee_proof.value,
            Some(Amount::new(1_000_000).unwrap().to_be_bytes().to_vec())
        );
        fee_proof.verify().unwrap();
        let fee_base_proof = state.query_latest_with_proof(FEES_BASE).await.unwrap();
        assert_eq!(
            fee_base_proof.value,
            Some(FeePolicy::reference_testnet().base.to_be_bytes().to_vec())
        );
        fee_base_proof.verify().unwrap();
        state.close().await;

        let state = PersistentState::open(dir.path().to_path_buf(), genesis_config)
            .await
            .unwrap();
        let reopened = state.summary().await.unwrap();
        assert_eq!(reopened.state_height, 1);
        assert_eq!(reopened.app_hash, expected_app_hash);
        assert_eq!(reopened.shielded_tree_root, expected_tree_root);
        assert_eq!(reopened.supply, receipt.supply);
        assert!(state.transaction_is_applied(&verified.tx_id).await.unwrap());
        let reopened_transaction_proof = state
            .query_latest_with_proof(&transaction_key(&verified.tx_id))
            .await
            .unwrap();
        assert!(reopened_transaction_proof.value.is_some());
        reopened_transaction_proof.verify().unwrap();
        for nullifier in &verified.nullifiers {
            assert!(state.nullifier_is_spent(nullifier).await.unwrap());
            let reopened_proof = state
                .query_latest_with_proof(&nullifier_key(nullifier))
                .await
                .unwrap();
            assert!(reopened_proof.value.is_some());
            reopened_proof.verify().unwrap();
        }

        let mut replay = state.begin_block(2, [0x31; 32], [0x32; 32]).await.unwrap();
        assert!(matches!(
            replay.verify_and_stage_transfer(&envelope).await,
            Err(Error::Transaction(
                bit_transaction::Error::TransactionAlreadyApplied
            ))
        ));
        drop(replay);
        state.close().await;
    }

    #[tokio::test]
    async fn fee_accounting_failure_is_atomic_and_persisted_tampering_stops_open() {
        let dir = TempDir::new().unwrap();
        let genesis_config = config(8);
        let state = PersistentState::open(dir.path().to_path_buf(), genesis_config.clone())
            .await
            .unwrap();
        let genesis = state.summary().await.unwrap();
        let mut transfer = verified(41, genesis.shielded_tree_root, 42, 43);
        transfer.fee = Amount::new(1).unwrap();
        let mut block = state.begin_block(1, [44; 32], [45; 32]).await.unwrap();
        stage_empty_consensus(&state, &mut block, 1).await;
        assert!(matches!(
            block.stage_verified(&transfer).await,
            Err(Error::Accounting(bit_emission::Error::Insufficient(
                "shielded total"
            )))
        ));
        let receipt = state.commit(block.prepare().await.unwrap()).unwrap();
        assert_eq!(receipt.transaction_count, 0);
        assert_eq!(receipt.supply, genesis.supply);
        assert!(!state.transaction_is_applied(&transfer.tx_id).await.unwrap());
        state.close().await;

        let prefixes = SUBSTORES
            .iter()
            .map(|prefix| (*prefix).to_owned())
            .collect();
        let storage = Storage::load(dir.path().to_path_buf(), prefixes)
            .await
            .unwrap();
        let mut delta = StateDelta::new(storage.latest_snapshot());
        delta.put_raw(
            FEES_RESERVE.to_owned(),
            Amount::new(1).unwrap().to_be_bytes().to_vec(),
        );
        delta.put_raw(META_HEIGHT.to_owned(), u64_bytes(2));
        storage.commit(delta).await.unwrap();
        storage.release().await;

        let error = PersistentState::open(dir.path().to_path_buf(), genesis_config)
            .await
            .err()
            .expect("tampered supply accounting must be rejected");
        assert!(error.to_string().contains("asset containers"));
    }

    #[tokio::test]
    async fn validator_mutations_stage_atomically_and_survive_restart() {
        let mut genesis_config = config(8);
        let chain = genesis_config.chain_context;
        let operator = [0x41; 32];
        let validator_id = validator_id(&chain, &operator);
        let self_bond_owner = [0x42; 32];
        let self_bond_id = position_id(&chain, &self_bond_owner);
        let self_bond = Amount::new(bit_staking::TESTNET_MIN_SELF_BOND_ATOMIC).unwrap();
        let mut parameters = StakingParameters::reference_testnet();
        parameters.jail_blocks = 1;
        parameters.jail_seconds = 1;
        let mut staking = StakingBook::new(chain, parameters).unwrap();
        staking
            .register_validator_with_metadata_at(
                validator_id,
                operator,
                [0x43; 32],
                500,
                "genesis validator".to_owned(),
                String::new(),
                String::new(),
                0,
                0,
            )
            .unwrap();
        staking
            .open_pending_delegation(
                0,
                0,
                self_bond_id,
                self_bond_owner,
                validator_id,
                self_bond,
                Amount::ZERO,
                true,
                vec![0x44; bit_staking::RECOVERY_RECEIPT_BYTES],
            )
            .unwrap();
        staking.activate_pending(&self_bond_id, 1).unwrap();
        staking.apply_validator_set().unwrap();
        staking
            .jail_validator_for_downtime(&validator_id, 0, 0)
            .unwrap();
        genesis_config.genesis_staking = staking;
        genesis_config.genesis_allocation = GenesisAllocation {
            shielded: Amount::ZERO,
            stake: self_bond,
            pending_delegation: Amount::ZERO,
            exits: Amount::ZERO,
            commission: Amount::ZERO,
            fee_reserve: Amount::ZERO,
            unclaimed_genesis: Amount::new(
                genesis_config.monetary_policy.genesis_supply.value() - self_bond.value(),
            )
            .unwrap(),
        };

        let dir = TempDir::new().unwrap();
        let state = PersistentState::open(dir.path().to_path_buf(), genesis_config.clone())
            .await
            .unwrap();
        let genesis = state.summary().await.unwrap();
        let mut block = state
            .begin_block_at(1, 1, [0xc1; 32], [0xc2; 32])
            .await
            .unwrap();
        stage_empty_consensus(&state, &mut block, 1).await;
        block
            .stage_verified_staking(&empty_verified_staking(
                0xd1,
                genesis.shielded_tree_root,
                VerifiedStakingAction::UpdateValidator {
                    validator_id,
                    expected_sequence: 0,
                    display_name: Some("updated validator".to_owned()),
                    website: Some("https://validator.invalid".to_owned()),
                    description: None,
                    commission_bps: Some(400),
                    request_disable: None,
                },
            ))
            .await
            .unwrap();
        block
            .stage_verified_staking(&empty_verified_staking(
                0xd2,
                genesis.shielded_tree_root,
                VerifiedStakingAction::RotateConsensusKey {
                    validator_id,
                    expected_sequence: 1,
                    new_consensus: [0x45; 32],
                },
            ))
            .await
            .unwrap();
        block
            .stage_verified_staking(&empty_verified_staking(
                0xd3,
                genesis.shielded_tree_root,
                VerifiedStakingAction::UnjailValidator {
                    validator_id,
                    expected_sequence: 2,
                },
            ))
            .await
            .unwrap();
        let receipt = state.commit(block.prepare().await.unwrap()).unwrap();
        assert_eq!(receipt.transaction_count, 3);
        assert_eq!(receipt.block_time_seconds, 1);
        assert_eq!(receipt.supply, genesis.supply);
        let validator = state
            .staking_book()
            .unwrap()
            .validator(&validator_id)
            .unwrap()
            .clone();
        assert_eq!(validator.sequence, 3);
        assert_eq!(validator.status, bit_staking::ValidatorStatus::Candidate);
        assert_eq!(validator.display_name, "updated validator");
        assert_ne!(validator.consensus_pubkey, [0x45; 32]);
        assert_eq!(validator.consensus_key_history.len(), 1);
        assert_eq!(
            validator.pending_consensus_key.unwrap().consensus_pubkey,
            [0x45; 32]
        );
        assert_eq!(validator.pending_commission.unwrap().commission_bps, 400);
        assert!(matches!(
            state.begin_block_at(2, 0, [1; 32], [2; 32]).await,
            Err(Error::BlockTimeRegression {
                previous: 1,
                actual: 0
            })
        ));
        state.close().await;

        let reopened = PersistentState::open(dir.path().to_path_buf(), genesis_config)
            .await
            .unwrap();
        assert_eq!(reopened.summary().await.unwrap().block_time_seconds, 1);
        let validator = reopened
            .staking_book()
            .unwrap()
            .validator(&validator_id)
            .unwrap()
            .clone();
        assert_eq!(validator.sequence, 3);
        assert_eq!(validator.consensus_key_history.len(), 1);
        assert_eq!(
            validator.pending_consensus_key.unwrap().consensus_pubkey,
            [0x45; 32]
        );
        reopened.close().await;
    }
}
