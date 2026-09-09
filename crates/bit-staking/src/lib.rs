//! Deterministic native staking state transitions for BIT.
//!
//! This crate owns validator, pool, and position rules. Authorization checks,
//! persistent storage, exit cohorts, slashing, and reward distribution are
//! connected by later layers; no method here treats a caller as authorized.

use bit_types::{position_id, validator_id, Amount};
use primitive_types::U256;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub type Hash32 = [u8; 32];
pub type PubKey32 = [u8; 32];

pub const ATOMIC_PER_BIT: u128 = 100_000_000;
pub const TESTNET_MIN_DELEGATION_ATOMIC: u128 = ATOMIC_PER_BIT;
pub const TESTNET_MIN_SELF_BOND_ATOMIC: u128 = 1_000 * ATOMIC_PER_BIT;
pub const COMETBFT_SAFE_TOTAL_POWER: u64 = (1u64 << 60) - 1;
pub const RECOVERY_RECEIPT_BYTES: usize = 512;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid staking parameters: {0}")]
    InvalidParameters(&'static str),
    #[error("staking arithmetic overflow")]
    Overflow,
    #[error("division by zero")]
    DivisionByZero,
    #[error("validator already exists")]
    ValidatorAlreadyExists,
    #[error("validator not found")]
    ValidatorNotFound,
    #[error("validator identifier does not match its operator key")]
    ValidatorIdMismatch,
    #[error("consensus key is already assigned to another validator")]
    ConsensusKeyAlreadyInUse,
    #[error("invalid validator metadata: {0}")]
    InvalidMetadata(&'static str),
    #[error("validator does not accept this delegation")]
    ValidatorNotAcceptingDelegation,
    #[error("commission exceeds the configured maximum")]
    CommissionTooHigh,
    #[error("position already exists")]
    PositionAlreadyExists,
    #[error("position not found")]
    PositionNotFound,
    #[error("position identifier does not match its owner key")]
    PositionIdMismatch,
    #[error("delegation recovery receipt must be exactly 512 bytes")]
    InvalidRecoveryReceipt,
    #[error("delegation is below the configured minimum")]
    DelegationBelowMinimum,
    #[error("self bond is below the configured minimum")]
    SelfBondBelowMinimum,
    #[error("activation capacity is exhausted for this epoch")]
    ActivationCapacity,
    #[error("position is not pending")]
    PositionNotPending,
    #[error("position is not refundable")]
    PositionNotRefundable,
    #[error("position sequence does not match the expected value")]
    PositionSequenceMismatch,
    #[error("position cannot activate before its activation epoch")]
    ActivationTooEarly,
    #[error("stake pool is insolvent and requires a new generation")]
    InsolventPool,
    #[error("stake pool has assets without shares")]
    InconsistentPool,
    #[error("share amount is zero or exceeds the pool")]
    InvalidShares,
    #[error("voting power exceeds the configured safe bound")]
    VotingPowerExceeded,
    #[error("staking invariant failed: {0}")]
    Invariant(&'static str),
    #[error("invalid staking state encoding: {0}")]
    InvalidEncoding(&'static str),
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StakingParameters {
    pub min_delegation: Amount,
    pub min_self_bond: Amount,
    pub max_validators: u16,
    pub power_unit_atomic: Amount,
    pub max_total_voting_power: u64,
    pub max_pending_per_epoch: u32,
    pub max_commission_bps: u16,
    pub default_commission_bps: u16,
    pub max_commission_increase_bps: u16,
}

impl StakingParameters {
    pub fn reference_testnet() -> Self {
        Self {
            min_delegation: amount(TESTNET_MIN_DELEGATION_ATOMIC),
            min_self_bond: amount(TESTNET_MIN_SELF_BOND_ATOMIC),
            max_validators: 64,
            power_unit_atomic: amount(ATOMIC_PER_BIT),
            max_total_voting_power: COMETBFT_SAFE_TOTAL_POWER,
            max_pending_per_epoch: 1_000,
            max_commission_bps: 2_000,
            default_commission_bps: 500,
            max_commission_increase_bps: 100,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_delegation == Amount::ZERO {
            return Err(Error::InvalidParameters("minimum delegation is zero"));
        }
        if self.min_self_bond < self.min_delegation {
            return Err(Error::InvalidParameters(
                "minimum self bond is below minimum delegation",
            ));
        }
        if self.max_validators == 0 {
            return Err(Error::InvalidParameters("validator set is empty"));
        }
        if self.power_unit_atomic == Amount::ZERO {
            return Err(Error::InvalidParameters("power unit is zero"));
        }
        if self.max_total_voting_power == 0
            || self.max_total_voting_power > COMETBFT_SAFE_TOTAL_POWER
        {
            return Err(Error::InvalidParameters("unsafe total voting power"));
        }
        if self.max_pending_per_epoch == 0 {
            return Err(Error::InvalidParameters("pending capacity is zero"));
        }
        if self.max_commission_bps > 10_000
            || self.default_commission_bps > self.max_commission_bps
            || self.max_commission_increase_bps > self.max_commission_bps
        {
            return Err(Error::InvalidParameters("invalid commission limits"));
        }
        Ok(())
    }

    pub fn encode_persistent(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.u8(1);
        writer.amount(self.min_delegation);
        writer.amount(self.min_self_bond);
        writer.u16(self.max_validators);
        writer.amount(self.power_unit_atomic);
        writer.u64(self.max_total_voting_power);
        writer.u32(self.max_pending_per_epoch);
        writer.u16(self.max_commission_bps);
        writer.u16(self.default_commission_bps);
        writer.u16(self.max_commission_increase_bps);
        writer.finish()
    }

    pub fn decode_persistent(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.version(1)?;
        let parameters = Self {
            min_delegation: reader.amount()?,
            min_self_bond: reader.amount()?,
            max_validators: reader.u16()?,
            power_unit_atomic: reader.amount()?,
            max_total_voting_power: reader.u64()?,
            max_pending_per_epoch: reader.u32()?,
            max_commission_bps: reader.u16()?,
            default_commission_bps: reader.u16()?,
            max_commission_increase_bps: reader.u16()?,
        };
        reader.finish()?;
        parameters.validate()?;
        Ok(parameters)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorStatus {
    Candidate,
    Active,
    Disabled,
    Jailed,
    Tombstoned,
}

impl ValidatorStatus {
    fn may_receive_delegation(self) -> bool {
        matches!(self, Self::Candidate | Self::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Validator {
    pub validator_id: Hash32,
    pub operator_pubkey: PubKey32,
    pub consensus_pubkey: PubKey32,
    pub display_name: String,
    pub website: String,
    pub description: String,
    pub status: ValidatorStatus,
    pub accepts_delegation: bool,
    pub commission_bps: u16,
    pub self_bond_positions: BTreeSet<Hash32>,
    pub voting_power: u64,
    pub sequence: u64,
}

impl Validator {
    pub fn encode_persistent(&self) -> Result<Vec<u8>> {
        validate_metadata(&self.display_name, &self.website, &self.description)?;
        let count = u32::try_from(self.self_bond_positions.len()).map_err(|_| Error::Overflow)?;
        let mut writer = Writer::new();
        writer.u8(2);
        writer.hash32(&self.validator_id);
        writer.hash32(&self.operator_pubkey);
        writer.hash32(&self.consensus_pubkey);
        writer.string(&self.display_name)?;
        writer.string(&self.website)?;
        writer.string(&self.description)?;
        writer.u8(match self.status {
            ValidatorStatus::Candidate => 0,
            ValidatorStatus::Active => 1,
            ValidatorStatus::Disabled => 2,
            ValidatorStatus::Jailed => 3,
            ValidatorStatus::Tombstoned => 4,
        });
        writer.boolean(self.accepts_delegation);
        writer.u16(self.commission_bps);
        writer.u32(count);
        for id in &self.self_bond_positions {
            writer.hash32(id);
        }
        writer.u64(self.voting_power);
        writer.u64(self.sequence);
        Ok(writer.finish())
    }

    pub fn decode_persistent(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.version(2)?;
        let validator_id = reader.hash32()?;
        let operator_pubkey = reader.hash32()?;
        let consensus_pubkey = reader.hash32()?;
        let display_name = reader.string(1, 64, "display name")?;
        let website = reader.string(0, 256, "website")?;
        let description = reader.string(0, 512, "description")?;
        let status = match reader.u8()? {
            0 => ValidatorStatus::Candidate,
            1 => ValidatorStatus::Active,
            2 => ValidatorStatus::Disabled,
            3 => ValidatorStatus::Jailed,
            4 => ValidatorStatus::Tombstoned,
            _ => return Err(Error::InvalidEncoding("unknown validator status")),
        };
        let accepts_delegation = reader.boolean()?;
        let commission_bps = reader.u16()?;
        let count = reader.u32()?;
        let required = usize::try_from(count)
            .map_err(|_| Error::Overflow)?
            .checked_mul(32)
            .ok_or(Error::Overflow)?;
        if reader.remaining() < required + 16 {
            return Err(Error::InvalidEncoding("truncated self bond index"));
        }
        let mut self_bond_positions = BTreeSet::new();
        for _ in 0..count {
            if !self_bond_positions.insert(reader.hash32()?) {
                return Err(Error::InvalidEncoding("duplicate self bond position"));
            }
        }
        let voting_power = reader.u64()?;
        let sequence = reader.u64()?;
        reader.finish()?;
        Ok(Self {
            validator_id,
            operator_pubkey,
            consensus_pubkey,
            display_name,
            website,
            description,
            status,
            accepts_delegation,
            commission_bps,
            self_bond_positions,
            voting_power,
            sequence,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StakePool {
    pub validator_id: Hash32,
    pub generation: u64,
    pub assets: Amount,
    pub total_shares: Amount,
    pub pending_total: Amount,
    pub last_settled_epoch: u64,
}

impl StakePool {
    pub fn empty(validator_id: Hash32) -> Self {
        Self {
            validator_id,
            generation: 0,
            assets: Amount::ZERO,
            total_shares: Amount::ZERO,
            pending_total: Amount::ZERO,
            last_settled_epoch: 0,
        }
    }

    pub fn quote_minted_shares(&self, deposit: Amount) -> Result<Amount> {
        match (self.assets.value(), self.total_shares.value()) {
            (0, 0) => Ok(deposit),
            (0, _) => Err(Error::InsolventPool),
            (_, 0) => Err(Error::InconsistentPool),
            (assets, shares) => floor_mul_div(deposit.value(), shares, assets),
        }
    }

    pub fn position_value(&self, shares: Amount) -> Result<Amount> {
        let shares = shares.value();
        let total_shares = self.total_shares.value();
        if shares > total_shares || (shares > 0 && total_shares == 0) {
            return Err(Error::InvalidShares);
        }
        if shares == 0 {
            return Ok(Amount::ZERO);
        }
        if shares == total_shares {
            return Ok(self.assets);
        }
        floor_mul_div(shares, self.assets.value(), total_shares)
    }

    /// Burn shares and return their gross assets. Burning the final share takes
    /// every remaining atom so integer rounding cannot strand pool value.
    pub fn redeem(&mut self, shares: Amount) -> Result<Amount> {
        if shares == Amount::ZERO || shares > self.total_shares {
            return Err(Error::InvalidShares);
        }
        let gross = self.position_value(shares)?;
        self.assets = checked_sub(self.assets, gross, "stake pool")?;
        self.total_shares = checked_sub(self.total_shares, shares, "stake shares")?;
        Ok(gross)
    }

    pub fn credit_rewards(&mut self, rewards: Amount, settled_epoch: u64) -> Result<()> {
        if settled_epoch <= self.last_settled_epoch {
            return Err(Error::Invariant("pool settlement epoch did not advance"));
        }
        if rewards != Amount::ZERO && self.total_shares == Amount::ZERO {
            return Err(Error::Invariant("cannot reward a pool without shares"));
        }
        self.assets = checked_add(self.assets, rewards)?;
        self.last_settled_epoch = settled_epoch;
        Ok(())
    }

    pub fn encode_persistent(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.u8(1);
        writer.hash32(&self.validator_id);
        writer.u64(self.generation);
        writer.amount(self.assets);
        writer.amount(self.total_shares);
        writer.amount(self.pending_total);
        writer.u64(self.last_settled_epoch);
        writer.finish()
    }

    pub fn decode_persistent(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.version(1)?;
        let pool = Self {
            validator_id: reader.hash32()?,
            generation: reader.u64()?,
            assets: reader.amount()?,
            total_shares: reader.amount()?,
            pending_total: reader.amount()?,
            last_settled_epoch: reader.u64()?,
        };
        reader.finish()?;
        Ok(pool)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PositionStatus {
    Pending,
    Active,
    RefundablePending,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StakePosition {
    pub position_id: Hash32,
    pub owner_pubkey: PubKey32,
    pub validator_id: Hash32,
    pub generation: u64,
    pub shares: Amount,
    pub pending_amount: Amount,
    pub min_shares: Amount,
    pub status: PositionStatus,
    pub sequence: u64,
    pub created_height: u64,
    pub activation_epoch: u64,
    pub self_bond: bool,
    pub recovery_receipt: Vec<u8>,
}

impl StakePosition {
    pub fn encode_persistent(&self) -> Result<Vec<u8>> {
        if self.recovery_receipt.len() != RECOVERY_RECEIPT_BYTES {
            return Err(Error::InvalidEncoding(
                "recovery receipt must be exactly 512 bytes",
            ));
        }
        let receipt_len =
            u32::try_from(self.recovery_receipt.len()).map_err(|_| Error::Overflow)?;
        let mut writer = Writer::new();
        writer.u8(1);
        writer.hash32(&self.position_id);
        writer.hash32(&self.owner_pubkey);
        writer.hash32(&self.validator_id);
        writer.u64(self.generation);
        writer.amount(self.shares);
        writer.amount(self.pending_amount);
        writer.amount(self.min_shares);
        writer.u8(match self.status {
            PositionStatus::Pending => 0,
            PositionStatus::Active => 1,
            PositionStatus::RefundablePending => 2,
            PositionStatus::Closed => 3,
        });
        writer.u64(self.sequence);
        writer.u64(self.created_height);
        writer.u64(self.activation_epoch);
        writer.boolean(self.self_bond);
        writer.u32(receipt_len);
        writer.bytes(&self.recovery_receipt);
        Ok(writer.finish())
    }

    pub fn decode_persistent(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.version(1)?;
        let position_id = reader.hash32()?;
        let owner_pubkey = reader.hash32()?;
        let validator_id = reader.hash32()?;
        let generation = reader.u64()?;
        let shares = reader.amount()?;
        let pending_amount = reader.amount()?;
        let min_shares = reader.amount()?;
        let status = match reader.u8()? {
            0 => PositionStatus::Pending,
            1 => PositionStatus::Active,
            2 => PositionStatus::RefundablePending,
            3 => PositionStatus::Closed,
            _ => return Err(Error::InvalidEncoding("unknown position status")),
        };
        let sequence = reader.u64()?;
        let created_height = reader.u64()?;
        let activation_epoch = reader.u64()?;
        let self_bond = reader.boolean()?;
        let receipt_len = usize::try_from(reader.u32()?).map_err(|_| Error::Overflow)?;
        if receipt_len != RECOVERY_RECEIPT_BYTES {
            return Err(Error::InvalidEncoding(
                "recovery receipt must be exactly 512 bytes",
            ));
        }
        let recovery_receipt = reader.take(receipt_len)?.to_vec();
        reader.finish()?;
        Ok(Self {
            position_id,
            owner_pubkey,
            validator_id,
            generation,
            shares,
            pending_amount,
            min_shares,
            status,
            sequence,
            created_height,
            activation_epoch,
            self_bond,
            recovery_receipt,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefundReason {
    ValidatorIneligible,
    PoolInsolvent,
    ZeroShares,
    MinimumSharesNotMet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationOutcome {
    Activated {
        minted_shares: Amount,
    },
    Refundable {
        amount: Amount,
        reason: RefundReason,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CapacityLedger {
    accepted: u32,
    canceled_before_processing: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationCapacityRecord {
    pub activation_epoch: u64,
    pub accepted: u32,
    pub canceled_before_processing: u32,
}

impl ActivationCapacityRecord {
    pub fn encode_persistent(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.u8(1);
        writer.u64(self.activation_epoch);
        writer.u32(self.accepted);
        writer.u32(self.canceled_before_processing);
        writer.finish()
    }

    pub fn decode_persistent(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.version(1)?;
        let record = Self {
            activation_epoch: reader.u64()?,
            accepted: reader.u32()?,
            canceled_before_processing: reader.u32()?,
        };
        reader.finish()?;
        CapacityLedger {
            accepted: record.accepted,
            canceled_before_processing: record.canceled_before_processing,
        }
        .occupied()?;
        Ok(record)
    }
}

impl CapacityLedger {
    fn occupied(self) -> Result<u32> {
        self.accepted
            .checked_sub(self.canceled_before_processing)
            .ok_or(Error::Invariant("pending capacity underflow"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatorPower {
    pub validator_id: Hash32,
    pub consensus_pubkey: PubKey32,
    pub stake: Amount,
    pub power: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StakingTotals {
    pub pooled_assets: Amount,
    pub pending_assets: Amount,
    pub total_shares: Amount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StakingBook {
    chain_context: Hash32,
    parameters: StakingParameters,
    validators: BTreeMap<Hash32, Validator>,
    pools: BTreeMap<Hash32, StakePool>,
    positions: BTreeMap<Hash32, StakePosition>,
    capacity: BTreeMap<u64, CapacityLedger>,
}

impl StakingBook {
    pub fn new(chain_context: Hash32, parameters: StakingParameters) -> Result<Self> {
        parameters.validate()?;
        Ok(Self {
            chain_context,
            parameters,
            validators: BTreeMap::new(),
            pools: BTreeMap::new(),
            positions: BTreeMap::new(),
            capacity: BTreeMap::new(),
        })
    }

    pub fn chain_context(&self) -> Hash32 {
        self.chain_context
    }

    pub fn parameters(&self) -> &StakingParameters {
        &self.parameters
    }

    pub fn from_records(
        chain_context: Hash32,
        parameters: StakingParameters,
        validators: impl IntoIterator<Item = Validator>,
        pools: impl IntoIterator<Item = StakePool>,
        positions: impl IntoIterator<Item = StakePosition>,
        capacity: impl IntoIterator<Item = ActivationCapacityRecord>,
    ) -> Result<Self> {
        parameters.validate()?;
        let mut book = Self {
            chain_context,
            parameters,
            validators: BTreeMap::new(),
            pools: BTreeMap::new(),
            positions: BTreeMap::new(),
            capacity: BTreeMap::new(),
        };
        for validator in validators {
            let id = validator.validator_id;
            if book.validators.insert(id, validator).is_some() {
                return Err(Error::InvalidEncoding("duplicate validator record"));
            }
        }
        for pool in pools {
            let id = pool.validator_id;
            if book.pools.insert(id, pool).is_some() {
                return Err(Error::InvalidEncoding("duplicate pool record"));
            }
        }
        for position in positions {
            let id = position.position_id;
            if book.positions.insert(id, position).is_some() {
                return Err(Error::InvalidEncoding("duplicate position record"));
            }
        }
        for record in capacity {
            let ledger = CapacityLedger {
                accepted: record.accepted,
                canceled_before_processing: record.canceled_before_processing,
            };
            ledger.occupied()?;
            if book
                .capacity
                .insert(record.activation_epoch, ledger)
                .is_some()
            {
                return Err(Error::InvalidEncoding("duplicate capacity record"));
            }
        }
        book.validate()?;
        Ok(book)
    }

    pub fn validators(&self) -> impl Iterator<Item = &Validator> {
        self.validators.values()
    }

    pub fn pools(&self) -> impl Iterator<Item = &StakePool> {
        self.pools.values()
    }

    pub fn positions(&self) -> impl Iterator<Item = &StakePosition> {
        self.positions.values()
    }

    pub fn capacity_records(&self) -> impl Iterator<Item = ActivationCapacityRecord> + '_ {
        self.capacity
            .iter()
            .map(|(epoch, ledger)| ActivationCapacityRecord {
                activation_epoch: *epoch,
                accepted: ledger.accepted,
                canceled_before_processing: ledger.canceled_before_processing,
            })
    }

    pub fn validator(&self, id: &Hash32) -> Option<&Validator> {
        self.validators.get(id)
    }

    pub fn pool(&self, id: &Hash32) -> Option<&StakePool> {
        self.pools.get(id)
    }

    pub fn position(&self, id: &Hash32) -> Option<&StakePosition> {
        self.positions.get(id)
    }

    pub fn register_validator(
        &mut self,
        id: Hash32,
        operator_pubkey: PubKey32,
        consensus_pubkey: PubKey32,
        commission_bps: u16,
    ) -> Result<()> {
        self.register_validator_with_metadata(
            id,
            operator_pubkey,
            consensus_pubkey,
            commission_bps,
            "validator".to_owned(),
            String::new(),
            String::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_validator_with_metadata(
        &mut self,
        id: Hash32,
        operator_pubkey: PubKey32,
        consensus_pubkey: PubKey32,
        commission_bps: u16,
        display_name: String,
        website: String,
        description: String,
    ) -> Result<()> {
        self.transact(|next| {
            if validator_id(&next.chain_context, &operator_pubkey) != id {
                return Err(Error::ValidatorIdMismatch);
            }
            if commission_bps > next.parameters.max_commission_bps {
                return Err(Error::CommissionTooHigh);
            }
            validate_metadata(&display_name, &website, &description)?;
            if next.validators.contains_key(&id) {
                return Err(Error::ValidatorAlreadyExists);
            }
            if next
                .validators
                .values()
                .any(|validator| validator.consensus_pubkey == consensus_pubkey)
            {
                return Err(Error::ConsensusKeyAlreadyInUse);
            }
            next.validators.insert(
                id,
                Validator {
                    validator_id: id,
                    operator_pubkey,
                    consensus_pubkey,
                    display_name,
                    website,
                    description,
                    status: ValidatorStatus::Candidate,
                    accepts_delegation: true,
                    commission_bps,
                    self_bond_positions: BTreeSet::new(),
                    voting_power: 0,
                    sequence: 0,
                },
            );
            next.pools.insert(id, StakePool::empty(id));
            Ok(())
        })
    }

    pub fn capacity_record(&self, activation_epoch: u64) -> Option<ActivationCapacityRecord> {
        self.capacity
            .get(&activation_epoch)
            .map(|ledger| ActivationCapacityRecord {
                activation_epoch,
                accepted: ledger.accepted,
                canceled_before_processing: ledger.canceled_before_processing,
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_pending_delegation(
        &mut self,
        current_epoch: u64,
        created_height: u64,
        id: Hash32,
        owner_pubkey: PubKey32,
        validator: Hash32,
        deposit: Amount,
        min_shares: Amount,
        self_bond: bool,
        recovery_receipt: Vec<u8>,
    ) -> Result<()> {
        self.transact(|next| {
            if position_id(&next.chain_context, &owner_pubkey) != id {
                return Err(Error::PositionIdMismatch);
            }
            if next.positions.contains_key(&id) {
                return Err(Error::PositionAlreadyExists);
            }
            if recovery_receipt.len() != RECOVERY_RECEIPT_BYTES {
                return Err(Error::InvalidRecoveryReceipt);
            }
            if deposit < next.parameters.min_delegation {
                return Err(Error::DelegationBelowMinimum);
            }
            if self_bond && deposit < next.parameters.min_self_bond {
                return Err(Error::SelfBondBelowMinimum);
            }
            let validator_state = next
                .validators
                .get(&validator)
                .ok_or(Error::ValidatorNotFound)?;
            if !validator_state.accepts_delegation
                || !validator_state.status.may_receive_delegation()
            {
                return Err(Error::ValidatorNotAcceptingDelegation);
            }
            let activation_epoch = current_epoch.checked_add(1).ok_or(Error::Overflow)?;
            let capacity = next.capacity.entry(activation_epoch).or_default();
            if capacity.occupied()? >= next.parameters.max_pending_per_epoch {
                return Err(Error::ActivationCapacity);
            }
            capacity.accepted = capacity.accepted.checked_add(1).ok_or(Error::Overflow)?;

            let pool = next
                .pools
                .get_mut(&validator)
                .ok_or(Error::Invariant("validator pool missing"))?;
            pool.pending_total = checked_add(pool.pending_total, deposit)?;
            let generation = pool.generation;
            next.positions.insert(
                id,
                StakePosition {
                    position_id: id,
                    owner_pubkey,
                    validator_id: validator,
                    generation,
                    shares: Amount::ZERO,
                    pending_amount: deposit,
                    min_shares,
                    status: PositionStatus::Pending,
                    sequence: 0,
                    created_height,
                    activation_epoch,
                    self_bond,
                    recovery_receipt,
                },
            );
            Ok(())
        })
    }

    pub fn activate_pending(
        &mut self,
        id: &Hash32,
        current_epoch: u64,
    ) -> Result<ActivationOutcome> {
        self.transact(|next| next.activate_pending_inner(id, current_epoch))
    }

    /// Activate all due positions in a consensus-stable order. Self bonds run
    /// first so a validator registered in the preceding epoch can establish
    /// eligibility before its ordinary delegations are considered. Each group
    /// is ordered by position identifier bytes.
    pub fn activate_epoch(
        &mut self,
        current_epoch: u64,
    ) -> Result<Vec<(Hash32, ActivationOutcome)>> {
        self.transact(|next| {
            let mut due: Vec<(bool, Hash32)> = next
                .positions
                .values()
                .filter(|position| {
                    position.status == PositionStatus::Pending
                        && position.activation_epoch <= current_epoch
                })
                .map(|position| (position.self_bond, position.position_id))
                .collect();
            due.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
            due.into_iter()
                .map(|(_, id)| {
                    let outcome = next.activate_pending_inner(&id, current_epoch)?;
                    Ok((id, outcome))
                })
                .collect()
        })
    }

    fn activate_pending_inner(
        &mut self,
        id: &Hash32,
        current_epoch: u64,
    ) -> Result<ActivationOutcome> {
        let position = self.positions.get(id).ok_or(Error::PositionNotFound)?;
        if position.status != PositionStatus::Pending {
            return Err(Error::PositionNotPending);
        }
        if current_epoch < position.activation_epoch {
            return Err(Error::ActivationTooEarly);
        }

        let validator_id = position.validator_id;
        let deposit = position.pending_amount;
        let min_shares = position.min_shares;
        let self_bond = position.self_bond;
        let generation = position.generation;
        let status_eligible = self.validators.get(&validator_id).is_some_and(|validator| {
            validator.accepts_delegation && validator.status.may_receive_delegation()
        });
        let pool = self
            .pools
            .get(&validator_id)
            .ok_or(Error::Invariant("validator pool missing"))?;
        if pool.generation != generation {
            self.mark_refundable(id)?;
            return Ok(ActivationOutcome::Refundable {
                amount: deposit,
                reason: RefundReason::ValidatorIneligible,
            });
        }
        if pool.assets == Amount::ZERO && pool.total_shares != Amount::ZERO {
            self.mark_refundable(id)?;
            return Ok(ActivationOutcome::Refundable {
                amount: deposit,
                reason: RefundReason::PoolInsolvent,
            });
        }
        let eligible =
            status_eligible && (self_bond || self.has_minimum_self_bond(&validator_id)?);
        if !eligible {
            self.mark_refundable(id)?;
            return Ok(ActivationOutcome::Refundable {
                amount: deposit,
                reason: RefundReason::ValidatorIneligible,
            });
        }
        let minted_shares = pool.quote_minted_shares(deposit)?;
        if minted_shares == Amount::ZERO || minted_shares < min_shares {
            let reason = if minted_shares == Amount::ZERO {
                RefundReason::ZeroShares
            } else {
                RefundReason::MinimumSharesNotMet
            };
            self.mark_refundable(id)?;
            return Ok(ActivationOutcome::Refundable {
                amount: deposit,
                reason,
            });
        }

        let pool = self
            .pools
            .get_mut(&validator_id)
            .ok_or(Error::Invariant("validator pool missing"))?;
        pool.pending_total = checked_sub(pool.pending_total, deposit, "pending pool")?;
        pool.assets = checked_add(pool.assets, deposit)?;
        pool.total_shares = checked_add(pool.total_shares, minted_shares)?;

        let position = self.positions.get_mut(id).ok_or(Error::PositionNotFound)?;
        position.pending_amount = Amount::ZERO;
        position.shares = minted_shares;
        position.status = PositionStatus::Active;
        position.sequence = position.sequence.checked_add(1).ok_or(Error::Overflow)?;
        if self_bond {
            self.validators
                .get_mut(&validator_id)
                .ok_or(Error::ValidatorNotFound)?
                .self_bond_positions
                .insert(*id);
        }
        Ok(ActivationOutcome::Activated { minted_shares })
    }

    fn mark_refundable(&mut self, id: &Hash32) -> Result<()> {
        let position = self.positions.get_mut(id).ok_or(Error::PositionNotFound)?;
        let pool = self
            .pools
            .get_mut(&position.validator_id)
            .ok_or(Error::Invariant("validator pool missing"))?;
        pool.pending_total =
            checked_sub(pool.pending_total, position.pending_amount, "pending pool")?;
        // Refundable principal remains in the global pending-delegation supply
        // container, but is no longer queued against an individual pool.
        position.status = PositionStatus::RefundablePending;
        position.sequence = position.sequence.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    }

    /// Cancel an unprocessed pending position. Its epoch capacity is released.
    pub fn cancel_pending(&mut self, id: &Hash32, expected_sequence: u64) -> Result<Amount> {
        self.transact(|next| {
            let position = next.positions.get(id).ok_or(Error::PositionNotFound)?;
            if position.status != PositionStatus::Pending {
                return Err(Error::PositionNotPending);
            }
            if position.sequence != expected_sequence {
                return Err(Error::PositionSequenceMismatch);
            }
            let release = position.pending_amount;
            let validator = position.validator_id;
            let activation_epoch = position.activation_epoch;
            let pool = next
                .pools
                .get_mut(&validator)
                .ok_or(Error::Invariant("validator pool missing"))?;
            pool.pending_total = checked_sub(pool.pending_total, release, "pending pool")?;
            let capacity = next
                .capacity
                .get_mut(&activation_epoch)
                .ok_or(Error::Invariant("pending capacity reservation missing"))?;
            capacity.canceled_before_processing = capacity
                .canceled_before_processing
                .checked_add(1)
                .ok_or(Error::Overflow)?;
            let position = next.positions.get_mut(id).ok_or(Error::PositionNotFound)?;
            position.pending_amount = Amount::ZERO;
            position.status = PositionStatus::Closed;
            position.sequence = position.sequence.checked_add(1).ok_or(Error::Overflow)?;
            Ok(release)
        })
    }

    /// Release principal after an activation-time failure.
    pub fn refund_pending(&mut self, id: &Hash32, expected_sequence: u64) -> Result<Amount> {
        self.transact(|next| {
            let position = next.positions.get_mut(id).ok_or(Error::PositionNotFound)?;
            if position.status != PositionStatus::RefundablePending {
                return Err(Error::PositionNotRefundable);
            }
            if position.sequence != expected_sequence {
                return Err(Error::PositionSequenceMismatch);
            }
            let release = position.pending_amount;
            position.pending_amount = Amount::ZERO;
            position.status = PositionStatus::Closed;
            position.sequence = position.sequence.checked_add(1).ok_or(Error::Overflow)?;
            Ok(release)
        })
    }

    pub fn position_value(&self, id: &Hash32) -> Result<Amount> {
        let position = self.positions.get(id).ok_or(Error::PositionNotFound)?;
        if position.status != PositionStatus::Active {
            return Ok(Amount::ZERO);
        }
        self.pools
            .get(&position.validator_id)
            .ok_or(Error::Invariant("validator pool missing"))?
            .position_value(position.shares)
    }

    pub fn candidate_set(&self) -> Result<Vec<ValidatorPower>> {
        let mut candidates = Vec::new();
        for (id, validator) in &self.validators {
            if !validator.accepts_delegation
                || !validator.status.may_receive_delegation()
                || !self.has_minimum_self_bond(id)?
            {
                continue;
            }
            let pool = self
                .pools
                .get(id)
                .ok_or(Error::Invariant("validator pool missing"))?;
            let power = self.power_for_assets(pool.assets)?;
            if power == 0 {
                continue;
            }
            candidates.push(ValidatorPower {
                validator_id: *id,
                consensus_pubkey: validator.consensus_pubkey,
                stake: pool.assets,
                power,
            });
        }
        candidates.sort_by(|left, right| {
            right
                .stake
                .cmp(&left.stake)
                .then_with(|| left.validator_id.cmp(&right.validator_id))
        });
        candidates.truncate(usize::from(self.parameters.max_validators));
        let total = candidates.iter().try_fold(0u64, |sum, candidate| {
            sum.checked_add(candidate.power).ok_or(Error::Overflow)
        })?;
        if total > self.parameters.max_total_voting_power {
            return Err(Error::VotingPowerExceeded);
        }
        Ok(candidates)
    }

    /// Apply the deterministic candidate selection to the validator records.
    /// The returned entries are the exact CometBFT update plan for the caller.
    pub fn apply_validator_set(&mut self) -> Result<Vec<ValidatorPower>> {
        self.transact(|next| {
            let selected = next.candidate_set()?;
            let powers: BTreeMap<Hash32, u64> = selected
                .iter()
                .map(|entry| (entry.validator_id, entry.power))
                .collect();
            for validator in next.validators.values_mut() {
                if matches!(
                    validator.status,
                    ValidatorStatus::Candidate | ValidatorStatus::Active
                ) {
                    validator.voting_power =
                        powers.get(&validator.validator_id).copied().unwrap_or(0);
                    validator.status = if validator.voting_power == 0 {
                        ValidatorStatus::Candidate
                    } else {
                        ValidatorStatus::Active
                    };
                } else {
                    validator.voting_power = 0;
                }
            }
            Ok(selected)
        })
    }

    pub fn totals(&self) -> Result<StakingTotals> {
        let pooled_assets = sum_amounts(self.pools.values().map(|pool| pool.assets))?;
        let pending_assets = sum_amounts(
            self.positions
                .values()
                .filter(|position| {
                    matches!(
                        position.status,
                        PositionStatus::Pending | PositionStatus::RefundablePending
                    )
                })
                .map(|position| position.pending_amount),
        )?;
        let total_shares = sum_amounts(self.pools.values().map(|pool| pool.total_shares))?;
        Ok(StakingTotals {
            pooled_assets,
            pending_assets,
            total_shares,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.parameters.validate()?;
        if self.validators.len() != self.pools.len() {
            return Err(Error::Invariant("validator and pool counts differ"));
        }
        let mut consensus_keys = BTreeSet::new();
        for (id, validator) in &self.validators {
            if validator.validator_id != *id
                || validator_id(&self.chain_context, &validator.operator_pubkey) != *id
            {
                return Err(Error::Invariant("validator identity mismatch"));
            }
            if validator.commission_bps > self.parameters.max_commission_bps {
                return Err(Error::Invariant("validator commission is out of range"));
            }
            validate_metadata(
                &validator.display_name,
                &validator.website,
                &validator.description,
            )?;
            if !consensus_keys.insert(validator.consensus_pubkey) {
                return Err(Error::Invariant("duplicate validator consensus key"));
            }
            let pool = self
                .pools
                .get(id)
                .ok_or(Error::Invariant("validator pool missing"))?;
            if pool.validator_id != *id {
                return Err(Error::Invariant("pool validator mismatch"));
            }
            if pool.assets != Amount::ZERO && pool.total_shares == Amount::ZERO {
                return Err(Error::Invariant("pool assets exist without shares"));
            }
            match validator.status {
                ValidatorStatus::Active => {
                    if validator.voting_power == 0
                        || validator.voting_power != self.power_for_assets(pool.assets)?
                    {
                        return Err(Error::Invariant("active validator power is inconsistent"));
                    }
                }
                _ if validator.voting_power != 0 => {
                    return Err(Error::Invariant("inactive validator has voting power"));
                }
                _ => {}
            }
        }

        let mut active_shares: BTreeMap<(Hash32, u64), u128> = BTreeMap::new();
        let mut active_self_bonds: BTreeMap<Hash32, BTreeSet<Hash32>> = BTreeMap::new();
        let mut queued_pending: BTreeMap<Hash32, u128> = BTreeMap::new();
        let mut queued_by_epoch: BTreeMap<u64, u32> = BTreeMap::new();
        for (id, position) in &self.positions {
            if position.recovery_receipt.len() != RECOVERY_RECEIPT_BYTES {
                return Err(Error::Invariant(
                    "recovery receipt must be exactly 512 bytes",
                ));
            }
            if position.position_id != *id
                || position_id(&self.chain_context, &position.owner_pubkey) != *id
            {
                return Err(Error::Invariant("position identity mismatch"));
            }
            let pool = self
                .pools
                .get(&position.validator_id)
                .ok_or(Error::Invariant("position validator missing"))?;
            match position.status {
                PositionStatus::Pending => {
                    if position.shares != Amount::ZERO || position.pending_amount == Amount::ZERO {
                        return Err(Error::Invariant("invalid pending position amounts"));
                    }
                    add_u128(
                        queued_pending.entry(position.validator_id).or_default(),
                        position.pending_amount.value(),
                    )?;
                    let count = queued_by_epoch
                        .entry(position.activation_epoch)
                        .or_default();
                    *count = count.checked_add(1).ok_or(Error::Overflow)?;
                }
                PositionStatus::RefundablePending => {
                    if position.shares != Amount::ZERO || position.pending_amount == Amount::ZERO {
                        return Err(Error::Invariant("invalid refundable position amounts"));
                    }
                }
                PositionStatus::Active => {
                    if position.shares == Amount::ZERO || position.pending_amount != Amount::ZERO {
                        return Err(Error::Invariant("invalid active position amounts"));
                    }
                    add_u128(
                        active_shares
                            .entry((position.validator_id, position.generation))
                            .or_default(),
                        position.shares.value(),
                    )?;
                    if position.self_bond {
                        active_self_bonds
                            .entry(position.validator_id)
                            .or_default()
                            .insert(*id);
                    }
                }
                PositionStatus::Closed => {
                    if position.shares != Amount::ZERO || position.pending_amount != Amount::ZERO {
                        return Err(Error::Invariant("closed position still has value"));
                    }
                }
            }
            if position.generation != pool.generation
                && !matches!(position.status, PositionStatus::Closed)
            {
                return Err(Error::Invariant("live position uses old generation"));
            }
        }

        for (id, pool) in &self.pools {
            if active_shares
                .get(&(*id, pool.generation))
                .copied()
                .unwrap_or(0)
                != pool.total_shares.value()
            {
                return Err(Error::Invariant("position shares do not equal pool shares"));
            }
            if queued_pending.get(id).copied().unwrap_or(0) != pool.pending_total.value() {
                return Err(Error::Invariant(
                    "pending positions do not equal pool pending",
                ));
            }
            if self
                .validators
                .get(id)
                .ok_or(Error::Invariant("validator missing"))?
                .self_bond_positions
                != active_self_bonds.get(id).cloned().unwrap_or_default()
            {
                return Err(Error::Invariant("self bond index is inconsistent"));
            }
        }
        for (epoch, ledger) in &self.capacity {
            let occupied = ledger.occupied()?;
            if queued_by_epoch.get(epoch).copied().unwrap_or(0) > occupied {
                return Err(Error::Invariant(
                    "pending positions exceed reserved capacity",
                ));
            }
        }
        let _ = self.totals()?;
        let _ = self.candidate_set()?;
        Ok(())
    }

    fn has_minimum_self_bond(&self, validator_id: &Hash32) -> Result<bool> {
        let validator = self
            .validators
            .get(validator_id)
            .ok_or(Error::ValidatorNotFound)?;
        let pool = self
            .pools
            .get(validator_id)
            .ok_or(Error::Invariant("validator pool missing"))?;
        let self_bond_shares =
            validator
                .self_bond_positions
                .iter()
                .try_fold(0u128, |sum, id| {
                    let position = self
                        .positions
                        .get(id)
                        .ok_or(Error::Invariant("self bond position missing"))?;
                    if position.validator_id != *validator_id
                        || !position.self_bond
                        || position.status != PositionStatus::Active
                    {
                        return Err(Error::Invariant("invalid self bond position"));
                    }
                    sum.checked_add(position.shares.value())
                        .ok_or(Error::Overflow)
                })?;
        if self_bond_shares == 0 {
            return Ok(false);
        }
        let self_bond_shares = Amount::new(self_bond_shares).map_err(|_| Error::Overflow)?;
        Ok(pool.position_value(self_bond_shares)? >= self.parameters.min_self_bond)
    }

    fn power_for_assets(&self, assets: Amount) -> Result<u64> {
        let power = assets.value() / self.parameters.power_unit_atomic.value();
        if power > u128::from(self.parameters.max_total_voting_power)
            || power > u128::from(u64::MAX)
        {
            return Err(Error::VotingPowerExceeded);
        }
        Ok(power as u64)
    }

    fn transact<T>(&mut self, operation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let mut next = self.clone();
        let result = operation(&mut next)?;
        next.validate()?;
        *self = next;
        Ok(result)
    }
}

fn floor_mul_div(left: u128, right: u128, divisor: u128) -> Result<Amount> {
    if divisor == 0 {
        return Err(Error::DivisionByZero);
    }
    let quotient = U256::from(left)
        .checked_mul(U256::from(right))
        .ok_or(Error::Overflow)?
        / U256::from(divisor);
    if quotient > U256::from(u128::MAX) {
        return Err(Error::Overflow);
    }
    Amount::new(quotient.as_u128()).map_err(|_| Error::Overflow)
}

fn checked_add(left: Amount, right: Amount) -> Result<Amount> {
    Amount::new(
        left.value()
            .checked_add(right.value())
            .ok_or(Error::Overflow)?,
    )
    .map_err(|_| Error::Overflow)
}

fn checked_sub(left: Amount, right: Amount, name: &'static str) -> Result<Amount> {
    let value = left
        .value()
        .checked_sub(right.value())
        .ok_or(Error::Invariant(name))?;
    Amount::new(value).map_err(|_| Error::Overflow)
}

fn sum_amounts(mut values: impl Iterator<Item = Amount>) -> Result<Amount> {
    let sum = values.try_fold(0u128, |sum, value| {
        sum.checked_add(value.value()).ok_or(Error::Overflow)
    })?;
    Amount::new(sum).map_err(|_| Error::Overflow)
}

fn add_u128(target: &mut u128, value: u128) -> Result<()> {
    *target = target.checked_add(value).ok_or(Error::Overflow)?;
    Ok(())
}

fn amount(value: u128) -> Amount {
    Amount::new(value).expect("testnet staking constants and validated arithmetic fit Amount")
}

fn validate_metadata(display_name: &str, website: &str, description: &str) -> Result<()> {
    if display_name.is_empty() || display_name.len() > 64 {
        return Err(Error::InvalidMetadata("display name length outside 1..64"));
    }
    if website.len() > 256 {
        return Err(Error::InvalidMetadata("website exceeds 256 bytes"));
    }
    if description.len() > 512 {
        return Err(Error::InvalidMetadata("description exceeds 512 bytes"));
    }
    Ok(())
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn hash32(&mut self, value: &Hash32) {
        self.bytes.extend_from_slice(value);
    }

    fn amount(&mut self, value: Amount) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn string(&mut self, value: &str) -> Result<()> {
        let length = u16::try_from(value.len()).map_err(|_| Error::Overflow)?;
        self.u16(length);
        self.bytes(value.as_bytes());
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn version(&mut self, expected: u8) -> Result<()> {
        if self.u8()? != expected {
            return Err(Error::InvalidEncoding("unsupported record version"));
        }
        Ok(())
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(count).ok_or(Error::Overflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::InvalidEncoding("truncated record"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| Error::InvalidEncoding("invalid u16"))?,
        ))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| Error::InvalidEncoding("invalid u32"))?,
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| Error::InvalidEncoding("invalid u64"))?,
        ))
    }

    fn boolean(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidEncoding("invalid boolean")),
        }
    }

    fn hash32(&mut self) -> Result<Hash32> {
        self.take(32)?
            .try_into()
            .map_err(|_| Error::InvalidEncoding("invalid 32-byte value"))
    }

    fn amount(&mut self) -> Result<Amount> {
        let bytes = self
            .take(16)?
            .try_into()
            .map_err(|_| Error::InvalidEncoding("invalid amount width"))?;
        Amount::from_be_bytes(bytes).map_err(|_| Error::InvalidEncoding("invalid amount"))
    }

    fn string(&mut self, min: usize, max: usize, name: &'static str) -> Result<String> {
        let length = usize::from(self.u16()?);
        if length < min || length > max {
            return Err(Error::InvalidEncoding(name));
        }
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidEncoding("invalid UTF-8"))
    }

    fn finish(&self) -> Result<()> {
        if self.remaining() != 0 {
            return Err(Error::InvalidEncoding("trailing record bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn book_with_validator() -> (StakingBook, Hash32) {
        let chain = key(1);
        let operator = key(2);
        let id = validator_id(&chain, &operator);
        let mut book = StakingBook::new(chain, StakingParameters::reference_testnet()).unwrap();
        book.register_validator(id, operator, key(3), 500).unwrap();
        (book, id)
    }

    fn open(
        book: &mut StakingBook,
        validator: Hash32,
        owner: PubKey32,
        deposit: u128,
        min_shares: u128,
        self_bond: bool,
    ) -> Hash32 {
        let id = position_id(&book.chain_context(), &owner);
        book.open_pending_delegation(
            0,
            10,
            id,
            owner,
            validator,
            amount(deposit),
            amount(min_shares),
            self_bond,
            vec![9; RECOVERY_RECEIPT_BYTES],
        )
        .unwrap();
        id
    }

    #[test]
    fn registration_and_position_ids_are_enforced() {
        let chain = key(1);
        let operator = key(2);
        let mut book = StakingBook::new(chain, StakingParameters::reference_testnet()).unwrap();
        assert_eq!(
            book.register_validator(key(99), operator, key(3), 500),
            Err(Error::ValidatorIdMismatch)
        );
        let validator = validator_id(&chain, &operator);
        book.register_validator(validator, operator, key(3), 500)
            .unwrap();
        assert_eq!(
            book.open_pending_delegation(
                0,
                1,
                key(98),
                key(4),
                validator,
                amount(TESTNET_MIN_DELEGATION_ATOMIC),
                Amount::ZERO,
                false,
                vec![0; RECOVERY_RECEIPT_BYTES],
            ),
            Err(Error::PositionIdMismatch)
        );
        assert!(book.validate().is_ok());
    }

    #[test]
    fn pending_activates_after_epoch_and_does_not_receive_old_reward() {
        let (mut book, validator) = book_with_validator();
        let self_bond = open(
            &mut book,
            validator,
            key(4),
            TESTNET_MIN_SELF_BOND_ATOMIC,
            0,
            true,
        );
        assert_eq!(
            book.activate_pending(&self_bond, 0),
            Err(Error::ActivationTooEarly)
        );
        assert_eq!(
            book.activate_pending(&self_bond, 1).unwrap(),
            ActivationOutcome::Activated {
                minted_shares: amount(TESTNET_MIN_SELF_BOND_ATOMIC)
            }
        );

        let delegator = open(
            &mut book,
            validator,
            key(5),
            TESTNET_MIN_DELEGATION_ATOMIC,
            0,
            false,
        );
        book.pools
            .get_mut(&validator)
            .unwrap()
            .credit_rewards(amount(333_333_333), 1)
            .unwrap();
        let expected = floor_mul_div(
            TESTNET_MIN_DELEGATION_ATOMIC,
            TESTNET_MIN_SELF_BOND_ATOMIC,
            TESTNET_MIN_SELF_BOND_ATOMIC + 333_333_333,
        )
        .unwrap();
        assert_eq!(
            book.activate_pending(&delegator, 1).unwrap(),
            ActivationOutcome::Activated {
                minted_shares: expected
            }
        );
        assert!(expected < amount(TESTNET_MIN_DELEGATION_ATOMIC));
        assert!(book.validate().is_ok());
    }

    #[test]
    fn activation_slippage_failure_becomes_refundable() {
        let (mut book, validator) = book_with_validator();
        let self_bond = open(
            &mut book,
            validator,
            key(4),
            TESTNET_MIN_SELF_BOND_ATOMIC,
            0,
            true,
        );
        book.activate_pending(&self_bond, 1).unwrap();
        let deposit = TESTNET_MIN_DELEGATION_ATOMIC;
        let delegator = open(&mut book, validator, key(5), deposit, deposit, false);
        book.pools
            .get_mut(&validator)
            .unwrap()
            .credit_rewards(amount(1), 1)
            .unwrap();
        assert_eq!(
            book.activate_pending(&delegator, 1).unwrap(),
            ActivationOutcome::Refundable {
                amount: amount(deposit),
                reason: RefundReason::MinimumSharesNotMet,
            }
        );
        assert_eq!(
            book.position(&delegator).unwrap().status,
            PositionStatus::RefundablePending
        );
        assert_eq!(book.refund_pending(&delegator, 1).unwrap(), amount(deposit));
        assert!(book.validate().is_ok());
    }

    #[test]
    fn epoch_batch_activates_self_bond_before_ordinary_delegation() {
        let (mut book, validator) = book_with_validator();
        let ordinary = open(
            &mut book,
            validator,
            key(4),
            TESTNET_MIN_DELEGATION_ATOMIC,
            0,
            false,
        );
        let self_bond = open(
            &mut book,
            validator,
            key(5),
            TESTNET_MIN_SELF_BOND_ATOMIC,
            0,
            true,
        );
        let outcomes = book.activate_epoch(1).unwrap();
        assert_eq!(outcomes[0].0, self_bond);
        assert!(matches!(outcomes[0].1, ActivationOutcome::Activated { .. }));
        assert_eq!(outcomes[1].0, ordinary);
        assert!(matches!(outcomes[1].1, ActivationOutcome::Activated { .. }));
        assert!(book.validate().is_ok());
    }

    #[test]
    fn ineligible_validator_makes_pending_refundable() {
        let (mut book, validator) = book_with_validator();
        let self_bond = open(
            &mut book,
            validator,
            key(4),
            TESTNET_MIN_SELF_BOND_ATOMIC,
            0,
            true,
        );
        book.validators.get_mut(&validator).unwrap().status = ValidatorStatus::Disabled;
        assert_eq!(
            book.activate_pending(&self_bond, 1).unwrap(),
            ActivationOutcome::Refundable {
                amount: amount(TESTNET_MIN_SELF_BOND_ATOMIC),
                reason: RefundReason::ValidatorIneligible,
            }
        );
        assert_eq!(book.pool(&validator).unwrap().pending_total, Amount::ZERO);
    }

    #[test]
    fn insolvent_pool_does_not_trap_an_accepted_pending_deposit() {
        let (mut book, validator) = book_with_validator();
        let self_bond = open(
            &mut book,
            validator,
            key(4),
            TESTNET_MIN_SELF_BOND_ATOMIC,
            0,
            true,
        );
        book.activate_pending(&self_bond, 1).unwrap();
        let delegator = open(
            &mut book,
            validator,
            key(5),
            TESTNET_MIN_DELEGATION_ATOMIC,
            0,
            false,
        );
        book.pools.get_mut(&validator).unwrap().assets = Amount::ZERO;
        assert_eq!(
            book.activate_pending(&delegator, 1).unwrap(),
            ActivationOutcome::Refundable {
                amount: amount(TESTNET_MIN_DELEGATION_ATOMIC),
                reason: RefundReason::PoolInsolvent,
            }
        );
    }

    #[test]
    fn zero_share_quote_becomes_refundable() {
        let (mut book, validator) = book_with_validator();
        let self_bond = open(
            &mut book,
            validator,
            key(4),
            TESTNET_MIN_SELF_BOND_ATOMIC,
            0,
            true,
        );
        let delegator = open(
            &mut book,
            validator,
            key(5),
            TESTNET_MIN_DELEGATION_ATOMIC,
            0,
            false,
        );
        book.activate_pending(&self_bond, 1).unwrap();
        let reward =
            u128::from(COMETBFT_SAFE_TOTAL_POWER) * ATOMIC_PER_BIT - TESTNET_MIN_SELF_BOND_ATOMIC;
        book.pools
            .get_mut(&validator)
            .unwrap()
            .credit_rewards(amount(reward), 1)
            .unwrap();
        assert_eq!(
            book.activate_pending(&delegator, 1).unwrap(),
            ActivationOutcome::Refundable {
                amount: amount(TESTNET_MIN_DELEGATION_ATOMIC),
                reason: RefundReason::ZeroShares,
            }
        );
    }

    #[test]
    fn canceled_pending_releases_epoch_capacity() {
        let (mut book, validator) = book_with_validator();
        book.parameters.max_pending_per_epoch = 1;
        let first = open(
            &mut book,
            validator,
            key(4),
            TESTNET_MIN_SELF_BOND_ATOMIC,
            0,
            true,
        );
        let second_owner = key(5);
        let second = position_id(&book.chain_context(), &second_owner);
        assert_eq!(
            book.open_pending_delegation(
                0,
                11,
                second,
                second_owner,
                validator,
                amount(TESTNET_MIN_DELEGATION_ATOMIC),
                Amount::ZERO,
                false,
                vec![0; RECOVERY_RECEIPT_BYTES],
            ),
            Err(Error::ActivationCapacity)
        );
        assert_eq!(
            book.cancel_pending(&first, 1),
            Err(Error::PositionSequenceMismatch)
        );
        assert_eq!(
            book.cancel_pending(&first, 0).unwrap(),
            amount(TESTNET_MIN_SELF_BOND_ATOMIC)
        );
        book.open_pending_delegation(
            0,
            11,
            second,
            second_owner,
            validator,
            amount(TESTNET_MIN_DELEGATION_ATOMIC),
            Amount::ZERO,
            false,
            vec![0; RECOVERY_RECEIPT_BYTES],
        )
        .unwrap();
    }

    #[test]
    fn pool_math_uses_u256_and_final_redemption_drains_residual() {
        let validator = key(7);
        let mut pool = StakePool {
            validator_id: validator,
            generation: 0,
            assets: amount((1u128 << 119) + 7),
            total_shares: amount((1u128 << 119) + 3),
            pending_total: Amount::ZERO,
            last_settled_epoch: 0,
        };
        let quote = pool.quote_minted_shares(amount(1u128 << 118)).unwrap();
        assert!(quote > Amount::ZERO);

        pool.assets = amount(10);
        pool.total_shares = amount(3);
        assert_eq!(pool.redeem(amount(1)).unwrap(), amount(3));
        assert_eq!(pool.assets, amount(7));
        assert_eq!(pool.redeem(amount(2)).unwrap(), amount(7));
        assert_eq!(pool.assets, Amount::ZERO);
        assert_eq!(pool.total_shares, Amount::ZERO);
    }

    #[test]
    fn zero_value_and_inconsistent_pools_fail_closed() {
        let mut pool = StakePool::empty(key(1));
        pool.total_shares = amount(1);
        assert_eq!(
            pool.quote_minted_shares(amount(1)),
            Err(Error::InsolventPool)
        );
        pool.assets = amount(1);
        pool.total_shares = Amount::ZERO;
        assert_eq!(
            pool.quote_minted_shares(amount(1)),
            Err(Error::InconsistentPool)
        );
    }

    #[test]
    fn candidate_set_sorts_stake_then_identifier_and_checks_power() {
        let chain = key(1);
        let mut parameters = StakingParameters::reference_testnet();
        parameters.max_validators = 2;
        let mut book = StakingBook::new(chain, parameters).unwrap();
        let mut validators = Vec::new();
        for byte in 2..=4 {
            let operator = key(byte);
            let validator = validator_id(&chain, &operator);
            book.register_validator(validator, operator, key(byte + 10), 500)
                .unwrap();
            let self_bond = open(
                &mut book,
                validator,
                key(byte + 20),
                TESTNET_MIN_SELF_BOND_ATOMIC,
                0,
                true,
            );
            book.activate_pending(&self_bond, 1).unwrap();
            validators.push(validator);
        }
        let selected = book.candidate_set().unwrap();
        let mut sorted_ids = validators.clone();
        sorted_ids.sort();
        assert_eq!(
            selected
                .iter()
                .map(|entry| entry.validator_id)
                .collect::<Vec<_>>(),
            sorted_ids[..2]
        );
        let applied = book.apply_validator_set().unwrap();
        assert_eq!(applied, selected);
        assert_eq!(
            book.validators
                .values()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .count(),
            2
        );
        book.parameters.max_total_voting_power = 1;
        assert_eq!(book.candidate_set(), Err(Error::VotingPowerExceeded));
    }

    #[test]
    fn failed_mutation_does_not_leave_partial_state() {
        let (mut book, validator) = book_with_validator();
        let before = book.clone();
        let owner = key(4);
        let id = position_id(&book.chain_context(), &owner);
        assert_eq!(
            book.open_pending_delegation(
                0,
                10,
                id,
                owner,
                validator,
                amount(1),
                Amount::ZERO,
                false,
                vec![0; RECOVERY_RECEIPT_BYTES],
            ),
            Err(Error::DelegationBelowMinimum)
        );
        assert_eq!(book, before);
    }

    #[test]
    fn persistent_records_roundtrip_and_reject_noncanonical_bytes() {
        let (mut book, validator_id) = book_with_validator();
        let self_bond = open(
            &mut book,
            validator_id,
            key(4),
            TESTNET_MIN_SELF_BOND_ATOMIC,
            0,
            true,
        );
        book.activate_pending(&self_bond, 1).unwrap();
        book.apply_validator_set().unwrap();

        let parameters =
            StakingParameters::decode_persistent(&book.parameters().encode_persistent()).unwrap();
        let validators: Vec<_> = book
            .validators()
            .map(|value| Validator::decode_persistent(&value.encode_persistent().unwrap()).unwrap())
            .collect();
        let pools: Vec<_> = book
            .pools()
            .map(|value| StakePool::decode_persistent(&value.encode_persistent()).unwrap())
            .collect();
        let positions: Vec<_> = book
            .positions()
            .map(|value| {
                StakePosition::decode_persistent(&value.encode_persistent().unwrap()).unwrap()
            })
            .collect();
        let capacity: Vec<_> = book
            .capacity_records()
            .map(|value| {
                ActivationCapacityRecord::decode_persistent(&value.encode_persistent()).unwrap()
            })
            .collect();
        let rebuilt = StakingBook::from_records(
            book.chain_context(),
            parameters,
            validators,
            pools,
            positions,
            capacity,
        )
        .unwrap();
        assert_eq!(rebuilt, book);

        let mut trailing = book.pool(&validator_id).unwrap().encode_persistent();
        trailing.push(0);
        assert_eq!(
            StakePool::decode_persistent(&trailing),
            Err(Error::InvalidEncoding("trailing record bytes"))
        );
        let mut bad_bool = book
            .position(&self_bond)
            .unwrap()
            .encode_persistent()
            .unwrap();
        let bool_offset = bad_bool.len() - 4 - RECOVERY_RECEIPT_BYTES - 1;
        bad_bool[bool_offset] = 2;
        assert_eq!(
            StakePosition::decode_persistent(&bad_bool),
            Err(Error::InvalidEncoding("invalid boolean"))
        );
    }

    #[test]
    fn invariant_detects_share_tampering() {
        let (mut book, validator) = book_with_validator();
        let self_bond = open(
            &mut book,
            validator,
            key(4),
            TESTNET_MIN_SELF_BOND_ATOMIC,
            0,
            true,
        );
        book.activate_pending(&self_bond, 1).unwrap();
        book.pools.get_mut(&validator).unwrap().total_shares = amount(1);
        assert_eq!(
            book.validate(),
            Err(Error::Invariant("position shares do not equal pool shares"))
        );
    }
}
