//! Deterministic native staking state transitions for BIT.
//!
//! This crate owns validator, pool, and position rules. Authorization checks,
//! persistent storage, exit cohorts, and slashing are connected by later
//! layers; no method here treats a caller as authorized.

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
    #[error("commission increase exceeds the configured per-change maximum")]
    CommissionIncreaseTooLarge,
    #[error("validator sequence does not match the expected value")]
    ValidatorSequenceMismatch,
    #[error("validator update does not change any field")]
    EmptyValidatorUpdate,
    #[error("validator is permanently tombstoned")]
    ValidatorTombstoned,
    #[error("validator is not jailed")]
    ValidatorNotJailed,
    #[error("validator jail period has not elapsed")]
    JailPeriodNotElapsed,
    #[error("only an active validator can be jailed for downtime")]
    ValidatorNotActive,
    #[error("new consensus key is unchanged")]
    ConsensusKeyUnchanged,
    #[error("reward score references an unknown validator")]
    UnknownRewardValidator,
    #[error("commission claim must be nonzero and no greater than accrued commission")]
    InvalidCommissionClaim,
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
    pub jail_seconds: u64,
    pub jail_blocks: u64,
    pub commission_notice_seconds: u64,
    pub commission_notice_blocks: u64,
    pub evidence_max_age_seconds: u64,
    pub evidence_max_age_blocks: u64,
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
            jail_seconds: 7_200,
            jail_blocks: 1_440,
            commission_notice_seconds: 604_800,
            commission_notice_blocks: 120_960,
            evidence_max_age_seconds: 604_800,
            evidence_max_age_blocks: 120_960,
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
        if self.jail_seconds == 0
            || self.jail_blocks == 0
            || self.commission_notice_seconds == 0
            || self.commission_notice_blocks == 0
            || self.evidence_max_age_seconds == 0
            || self.evidence_max_age_blocks == 0
        {
            return Err(Error::InvalidParameters(
                "staking time windows must be nonzero",
            ));
        }
        Ok(())
    }

    pub fn encode_persistent(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.u8(2);
        writer.amount(self.min_delegation);
        writer.amount(self.min_self_bond);
        writer.u16(self.max_validators);
        writer.amount(self.power_unit_atomic);
        writer.u64(self.max_total_voting_power);
        writer.u32(self.max_pending_per_epoch);
        writer.u16(self.max_commission_bps);
        writer.u16(self.default_commission_bps);
        writer.u16(self.max_commission_increase_bps);
        writer.u64(self.jail_seconds);
        writer.u64(self.jail_blocks);
        writer.u64(self.commission_notice_seconds);
        writer.u64(self.commission_notice_blocks);
        writer.u64(self.evidence_max_age_seconds);
        writer.u64(self.evidence_max_age_blocks);
        writer.finish()
    }

    pub fn decode_persistent(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.version(2)?;
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
            jail_seconds: reader.u64()?,
            jail_blocks: reader.u64()?,
            commission_notice_seconds: reader.u64()?,
            commission_notice_blocks: reader.u64()?,
            evidence_max_age_seconds: reader.u64()?,
            evidence_max_age_blocks: reader.u64()?,
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
    pub commission_accrued: Amount,
    pub pending_commission: Option<PendingCommissionChange>,
    pub pending_consensus_key: Option<PendingConsensusKey>,
    pub consensus_key_history: Vec<ConsensusKeyRecord>,
    pub jailed_at_height: Option<u64>,
    pub jailed_at_time_seconds: Option<u64>,
    pub self_bond_positions: BTreeSet<Hash32>,
    pub voting_power: u64,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingCommissionChange {
    pub commission_bps: u16,
    pub effective_epoch: u64,
    pub earliest_height: u64,
    pub earliest_time_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingConsensusKey {
    pub consensus_pubkey: PubKey32,
    pub effective_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusKeyRecord {
    pub consensus_pubkey: PubKey32,
    pub activated_height: u64,
    pub activated_time_seconds: u64,
    pub retired_height: Option<u64>,
    pub retired_time_seconds: Option<u64>,
    pub responsibility_end_height: Option<u64>,
    pub responsibility_end_time_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorUpdate {
    pub display_name: Option<String>,
    pub website: Option<String>,
    pub description: Option<String>,
    pub commission_bps: Option<u16>,
    pub request_disable: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatorReward {
    pub validator_id: Hash32,
    pub score: u128,
    pub gross_reward: Amount,
    pub stake_reward: Amount,
    pub commission_reward: Amount,
}

impl Validator {
    pub fn encode_persistent(&self) -> Result<Vec<u8>> {
        validate_metadata(&self.display_name, &self.website, &self.description)?;
        let history_count =
            u32::try_from(self.consensus_key_history.len()).map_err(|_| Error::Overflow)?;
        let self_bond_count =
            u32::try_from(self.self_bond_positions.len()).map_err(|_| Error::Overflow)?;
        let mut writer = Writer::new();
        writer.u8(4);
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
        writer.amount(self.commission_accrued);
        writer.boolean(self.pending_commission.is_some());
        if let Some(pending) = self.pending_commission {
            writer.u16(pending.commission_bps);
            writer.u64(pending.effective_epoch);
            writer.u64(pending.earliest_height);
            writer.u64(pending.earliest_time_seconds);
        }
        writer.boolean(self.pending_consensus_key.is_some());
        if let Some(pending) = self.pending_consensus_key {
            writer.hash32(&pending.consensus_pubkey);
            writer.u64(pending.effective_epoch);
        }
        match (self.jailed_at_height, self.jailed_at_time_seconds) {
            (Some(height), Some(time)) => {
                writer.boolean(true);
                writer.u64(height);
                writer.u64(time);
            }
            (None, None) => writer.boolean(false),
            _ => return Err(Error::Invariant("partial validator jail marker")),
        }
        writer.u32(history_count);
        for record in &self.consensus_key_history {
            writer.hash32(&record.consensus_pubkey);
            writer.u64(record.activated_height);
            writer.u64(record.activated_time_seconds);
            match (
                record.retired_height,
                record.retired_time_seconds,
                record.responsibility_end_height,
                record.responsibility_end_time_seconds,
            ) {
                (Some(height), Some(time), Some(end_height), Some(end_time)) => {
                    writer.boolean(true);
                    writer.u64(height);
                    writer.u64(time);
                    writer.u64(end_height);
                    writer.u64(end_time);
                }
                (None, None, None, None) => writer.boolean(false),
                _ => return Err(Error::Invariant("partial consensus key retirement record")),
            }
        }
        writer.u32(self_bond_count);
        for id in &self.self_bond_positions {
            writer.hash32(id);
        }
        writer.u64(self.voting_power);
        writer.u64(self.sequence);
        Ok(writer.finish())
    }

    pub fn decode_persistent(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.version(4)?;
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
        let commission_accrued = reader.amount()?;
        let pending_commission = if reader.boolean()? {
            Some(PendingCommissionChange {
                commission_bps: reader.u16()?,
                effective_epoch: reader.u64()?,
                earliest_height: reader.u64()?,
                earliest_time_seconds: reader.u64()?,
            })
        } else {
            None
        };
        let pending_consensus_key = if reader.boolean()? {
            Some(PendingConsensusKey {
                consensus_pubkey: reader.hash32()?,
                effective_epoch: reader.u64()?,
            })
        } else {
            None
        };
        let (jailed_at_height, jailed_at_time_seconds) = if reader.boolean()? {
            (Some(reader.u64()?), Some(reader.u64()?))
        } else {
            (None, None)
        };
        let history_count = reader.u32()?;
        let mut consensus_key_history = Vec::new();
        for _ in 0..history_count {
            let consensus_pubkey = reader.hash32()?;
            let activated_height = reader.u64()?;
            let activated_time_seconds = reader.u64()?;
            let (
                retired_height,
                retired_time_seconds,
                responsibility_end_height,
                responsibility_end_time_seconds,
            ) = if reader.boolean()? {
                (
                    Some(reader.u64()?),
                    Some(reader.u64()?),
                    Some(reader.u64()?),
                    Some(reader.u64()?),
                )
            } else {
                (None, None, None, None)
            };
            consensus_key_history.push(ConsensusKeyRecord {
                consensus_pubkey,
                activated_height,
                activated_time_seconds,
                retired_height,
                retired_time_seconds,
                responsibility_end_height,
                responsibility_end_time_seconds,
            });
        }
        let self_bond_count = reader.u32()?;
        let required = usize::try_from(self_bond_count)
            .map_err(|_| Error::Overflow)?
            .checked_mul(32)
            .ok_or(Error::Overflow)?;
        if reader.remaining() < required + 16 {
            return Err(Error::InvalidEncoding("truncated self bond index"));
        }
        let mut self_bond_positions = BTreeSet::new();
        for _ in 0..self_bond_count {
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
            commission_accrued,
            pending_commission,
            pending_consensus_key,
            consensus_key_history,
            jailed_at_height,
            jailed_at_time_seconds,
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
    pub commission_assets: Amount,
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
        self.register_validator_with_metadata_at(
            id,
            operator_pubkey,
            consensus_pubkey,
            commission_bps,
            display_name,
            website,
            description,
            0,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_validator_with_metadata_at(
        &mut self,
        id: Hash32,
        operator_pubkey: PubKey32,
        consensus_pubkey: PubKey32,
        commission_bps: u16,
        display_name: String,
        website: String,
        description: String,
        activated_height: u64,
        activated_time_seconds: u64,
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
            if next.validators.values().any(|validator| {
                validator
                    .consensus_key_history
                    .iter()
                    .any(|record| record.consensus_pubkey == consensus_pubkey)
                    || validator
                        .pending_consensus_key
                        .is_some_and(|pending| pending.consensus_pubkey == consensus_pubkey)
            }) {
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
                    commission_accrued: Amount::ZERO,
                    pending_commission: None,
                    pending_consensus_key: None,
                    consensus_key_history: vec![ConsensusKeyRecord {
                        consensus_pubkey,
                        activated_height,
                        activated_time_seconds,
                        retired_height: None,
                        retired_time_seconds: None,
                        responsibility_end_height: None,
                        responsibility_end_time_seconds: None,
                    }],
                    jailed_at_height: None,
                    jailed_at_time_seconds: None,
                    self_bond_positions: BTreeSet::new(),
                    voting_power: 0,
                    sequence: 0,
                },
            );
            next.pools.insert(id, StakePool::empty(id));
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_validator(
        &mut self,
        id: &Hash32,
        expected_sequence: u64,
        current_epoch: u64,
        current_height: u64,
        current_time_seconds: u64,
        update: ValidatorUpdate,
    ) -> Result<()> {
        self.transact(|next| {
            let parameters = next.parameters.clone();
            let validator = next
                .validators
                .get_mut(id)
                .ok_or(Error::ValidatorNotFound)?;
            if validator.status == ValidatorStatus::Tombstoned {
                return Err(Error::ValidatorTombstoned);
            }
            if validator.sequence != expected_sequence {
                return Err(Error::ValidatorSequenceMismatch);
            }
            if update.display_name.is_none()
                && update.website.is_none()
                && update.description.is_none()
                && update.commission_bps.is_none()
                && update.request_disable.is_none()
            {
                return Err(Error::EmptyValidatorUpdate);
            }

            let mut changed = false;
            if let Some(display_name) = update.display_name {
                validate_metadata(&display_name, &validator.website, &validator.description)?;
                if validator.display_name != display_name {
                    validator.display_name = display_name;
                    changed = true;
                }
            }
            if let Some(website) = update.website {
                validate_metadata(&validator.display_name, &website, &validator.description)?;
                if validator.website != website {
                    validator.website = website;
                    changed = true;
                }
            }
            if let Some(description) = update.description {
                validate_metadata(&validator.display_name, &validator.website, &description)?;
                if validator.description != description {
                    validator.description = description;
                    changed = true;
                }
            }
            if let Some(commission_bps) = update.commission_bps {
                if commission_bps > parameters.max_commission_bps {
                    return Err(Error::CommissionTooHigh);
                }
                if commission_bps == validator.commission_bps {
                    if validator.pending_commission.take().is_some() {
                        changed = true;
                    }
                } else {
                    let effective_epoch = current_epoch.checked_add(1).ok_or(Error::Overflow)?;
                    let (earliest_height, earliest_time_seconds) =
                        if commission_bps > validator.commission_bps {
                            if commission_bps - validator.commission_bps
                                > parameters.max_commission_increase_bps
                            {
                                return Err(Error::CommissionIncreaseTooLarge);
                            }
                            (
                                current_height
                                    .checked_add(parameters.commission_notice_blocks)
                                    .ok_or(Error::Overflow)?,
                                current_time_seconds
                                    .checked_add(parameters.commission_notice_seconds)
                                    .ok_or(Error::Overflow)?,
                            )
                        } else {
                            (current_height, current_time_seconds)
                        };
                    let pending = PendingCommissionChange {
                        commission_bps,
                        effective_epoch,
                        earliest_height,
                        earliest_time_seconds,
                    };
                    if validator.pending_commission != Some(pending) {
                        validator.pending_commission = Some(pending);
                        changed = true;
                    }
                }
            }
            if let Some(disable) = update.request_disable {
                let accepts_delegation = !disable;
                if validator.accepts_delegation != accepts_delegation {
                    validator.accepts_delegation = accepts_delegation;
                    if !disable && validator.status == ValidatorStatus::Disabled {
                        validator.status = ValidatorStatus::Candidate;
                    }
                    changed = true;
                }
            }
            if !changed {
                return Err(Error::EmptyValidatorUpdate);
            }
            validator.sequence = validator.sequence.checked_add(1).ok_or(Error::Overflow)?;
            Ok(())
        })
    }

    pub fn jail_validator_for_downtime(
        &mut self,
        id: &Hash32,
        current_height: u64,
        current_time_seconds: u64,
    ) -> Result<()> {
        self.transact(|next| {
            let validator = next
                .validators
                .get_mut(id)
                .ok_or(Error::ValidatorNotFound)?;
            if validator.status == ValidatorStatus::Tombstoned {
                return Err(Error::ValidatorTombstoned);
            }
            if validator.status != ValidatorStatus::Active {
                return Err(Error::ValidatorNotActive);
            }
            validator.status = ValidatorStatus::Jailed;
            validator.voting_power = 0;
            validator.jailed_at_height = Some(current_height);
            validator.jailed_at_time_seconds = Some(current_time_seconds);
            Ok(())
        })
    }

    pub fn unjail_validator(
        &mut self,
        id: &Hash32,
        expected_sequence: u64,
        current_height: u64,
        current_time_seconds: u64,
    ) -> Result<()> {
        self.transact(|next| {
            let parameters = next.parameters.clone();
            let validator = next
                .validators
                .get_mut(id)
                .ok_or(Error::ValidatorNotFound)?;
            if validator.status == ValidatorStatus::Tombstoned {
                return Err(Error::ValidatorTombstoned);
            }
            if validator.sequence != expected_sequence {
                return Err(Error::ValidatorSequenceMismatch);
            }
            if validator.status != ValidatorStatus::Jailed {
                return Err(Error::ValidatorNotJailed);
            }
            let jailed_height = validator
                .jailed_at_height
                .ok_or(Error::Invariant("jailed validator is missing height"))?;
            let jailed_time = validator
                .jailed_at_time_seconds
                .ok_or(Error::Invariant("jailed validator is missing time"))?;
            let earliest_height = jailed_height
                .checked_add(parameters.jail_blocks)
                .ok_or(Error::Overflow)?;
            let earliest_time = jailed_time
                .checked_add(parameters.jail_seconds)
                .ok_or(Error::Overflow)?;
            if current_height < earliest_height || current_time_seconds < earliest_time {
                return Err(Error::JailPeriodNotElapsed);
            }
            validator.status = ValidatorStatus::Candidate;
            validator.voting_power = 0;
            validator.jailed_at_height = None;
            validator.jailed_at_time_seconds = None;
            validator.sequence = validator.sequence.checked_add(1).ok_or(Error::Overflow)?;
            Ok(())
        })
    }

    pub fn rotate_consensus_key(
        &mut self,
        id: &Hash32,
        expected_sequence: u64,
        new_consensus_pubkey: PubKey32,
        current_epoch: u64,
    ) -> Result<()> {
        self.transact(|next| {
            let validator = next.validators.get(id).ok_or(Error::ValidatorNotFound)?;
            if validator.status == ValidatorStatus::Tombstoned {
                return Err(Error::ValidatorTombstoned);
            }
            if validator.sequence != expected_sequence {
                return Err(Error::ValidatorSequenceMismatch);
            }
            if validator.consensus_pubkey == new_consensus_pubkey
                || validator
                    .pending_consensus_key
                    .is_some_and(|pending| pending.consensus_pubkey == new_consensus_pubkey)
            {
                return Err(Error::ConsensusKeyUnchanged);
            }
            if next.validators.values().any(|candidate| {
                candidate
                    .consensus_key_history
                    .iter()
                    .any(|record| record.consensus_pubkey == new_consensus_pubkey)
                    || candidate
                        .pending_consensus_key
                        .is_some_and(|pending| pending.consensus_pubkey == new_consensus_pubkey)
            }) {
                return Err(Error::ConsensusKeyAlreadyInUse);
            }
            let validator = next
                .validators
                .get_mut(id)
                .ok_or(Error::ValidatorNotFound)?;
            validator.pending_consensus_key = Some(PendingConsensusKey {
                consensus_pubkey: new_consensus_pubkey,
                effective_epoch: current_epoch.checked_add(1).ok_or(Error::Overflow)?,
            });
            validator.sequence = validator.sequence.checked_add(1).ok_or(Error::Overflow)?;
            Ok(())
        })
    }

    pub fn apply_scheduled_validator_changes(
        &mut self,
        current_epoch: u64,
        current_height: u64,
        current_time_seconds: u64,
    ) -> Result<BTreeSet<Hash32>> {
        self.transact(|next| {
            let mut changed = BTreeSet::new();
            let evidence_max_age_blocks = next.parameters.evidence_max_age_blocks;
            let evidence_max_age_seconds = next.parameters.evidence_max_age_seconds;
            for validator in next.validators.values_mut() {
                if let Some(pending) = validator.pending_commission {
                    if current_epoch >= pending.effective_epoch
                        && current_height >= pending.earliest_height
                        && current_time_seconds >= pending.earliest_time_seconds
                    {
                        validator.commission_bps = pending.commission_bps;
                        validator.pending_commission = None;
                        changed.insert(validator.validator_id);
                    }
                }
                if let Some(pending) = validator.pending_consensus_key {
                    if current_epoch >= pending.effective_epoch {
                        let responsibility_end_height = current_height
                            .checked_add(evidence_max_age_blocks)
                            .ok_or(Error::Overflow)?;
                        let responsibility_end_time = current_time_seconds
                            .checked_add(evidence_max_age_seconds)
                            .ok_or(Error::Overflow)?;
                        let current = validator
                            .consensus_key_history
                            .last_mut()
                            .ok_or(Error::Invariant("validator consensus key history is empty"))?;
                        if current.consensus_pubkey != validator.consensus_pubkey
                            || current.retired_height.is_some()
                        {
                            return Err(Error::Invariant(
                                "validator current consensus key is inconsistent",
                            ));
                        }
                        current.retired_height = Some(current_height);
                        current.retired_time_seconds = Some(current_time_seconds);
                        current.responsibility_end_height = Some(responsibility_end_height);
                        current.responsibility_end_time_seconds = Some(responsibility_end_time);
                        validator.consensus_key_history.push(ConsensusKeyRecord {
                            consensus_pubkey: pending.consensus_pubkey,
                            activated_height: current_height,
                            activated_time_seconds: current_time_seconds,
                            retired_height: None,
                            retired_time_seconds: None,
                            responsibility_end_height: None,
                            responsibility_end_time_seconds: None,
                        });
                        validator.consensus_pubkey = pending.consensus_pubkey;
                        validator.pending_consensus_key = None;
                        changed.insert(validator.validator_id);
                    }
                }
            }
            Ok(changed)
        })
    }

    /// Split the available fee reserve across validators by their exact epoch
    /// scores, then split each validator's gross reward between its existing
    /// stake pool and accrued operator commission. Integer remainders are not
    /// assigned here and remain in the caller's fee reserve.
    pub fn distribute_epoch_rewards(
        &mut self,
        settled_epoch: u64,
        available: Amount,
        scores: &BTreeMap<Hash32, u128>,
    ) -> Result<Vec<ValidatorReward>> {
        self.transact(|next| {
            let total_score = next.reward_score_total(scores)?;
            let eligible: BTreeMap<Hash32, u128> = scores
                .iter()
                .filter_map(|(id, score)| next.reward_eligible(id, *score).then_some((*id, *score)))
                .collect();

            let mut rewards = Vec::with_capacity(eligible.len());
            for (id, score) in eligible {
                let gross_reward = floor_mul_div(available.value(), score, total_score)?;
                let commission_bps = next
                    .validators
                    .get(&id)
                    .ok_or(Error::ValidatorNotFound)?
                    .commission_bps;
                let commission_reward =
                    floor_mul_div(gross_reward.value(), u128::from(commission_bps), 10_000)?;
                let stake_reward = checked_sub(gross_reward, commission_reward, "reward split")?;
                next.pools
                    .get_mut(&id)
                    .ok_or(Error::ValidatorNotFound)?
                    .credit_rewards(stake_reward, settled_epoch)?;
                let validator = next
                    .validators
                    .get_mut(&id)
                    .ok_or(Error::ValidatorNotFound)?;
                validator.commission_accrued =
                    checked_add(validator.commission_accrued, commission_reward)?;
                rewards.push(ValidatorReward {
                    validator_id: id,
                    score,
                    gross_reward,
                    stake_reward,
                    commission_reward,
                });
            }

            let rewarded: BTreeSet<_> = rewards.iter().map(|reward| reward.validator_id).collect();
            for (id, pool) in &mut next.pools {
                if !rewarded.contains(id) {
                    pool.credit_rewards(Amount::ZERO, settled_epoch)?;
                }
            }
            Ok(rewards)
        })
    }

    pub fn reward_score_total(&self, scores: &BTreeMap<Hash32, u128>) -> Result<u128> {
        for id in scores.keys() {
            if !self.validators.contains_key(id) {
                return Err(Error::UnknownRewardValidator);
            }
        }
        scores.iter().try_fold(0u128, |total, (id, score)| {
            if self.reward_eligible(id, *score) {
                total.checked_add(*score).ok_or(Error::Overflow)
            } else {
                Ok(total)
            }
        })
    }

    pub fn claim_commission(
        &mut self,
        id: &Hash32,
        expected_sequence: u64,
        requested_amount: Amount,
    ) -> Result<Amount> {
        self.transact(|next| {
            let validator = next
                .validators
                .get_mut(id)
                .ok_or(Error::ValidatorNotFound)?;
            if validator.status == ValidatorStatus::Tombstoned {
                return Err(Error::ValidatorTombstoned);
            }
            if validator.sequence != expected_sequence {
                return Err(Error::ValidatorSequenceMismatch);
            }
            if requested_amount == Amount::ZERO || requested_amount > validator.commission_accrued {
                return Err(Error::InvalidCommissionClaim);
            }
            validator.commission_accrued = checked_sub(
                validator.commission_accrued,
                requested_amount,
                "validator commission",
            )?;
            validator.sequence = validator.sequence.checked_add(1).ok_or(Error::Overflow)?;
            Ok(requested_amount)
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
                ) && validator.accepts_delegation
                {
                    validator.voting_power =
                        powers.get(&validator.validator_id).copied().unwrap_or(0);
                    validator.status = if validator.voting_power == 0 {
                        ValidatorStatus::Candidate
                    } else {
                        ValidatorStatus::Active
                    };
                } else if matches!(
                    validator.status,
                    ValidatorStatus::Candidate | ValidatorStatus::Active
                ) {
                    validator.status = ValidatorStatus::Disabled;
                    validator.voting_power = 0;
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
        let commission_assets = sum_amounts(
            self.validators
                .values()
                .map(|validator| validator.commission_accrued),
        )?;
        Ok(StakingTotals {
            pooled_assets,
            pending_assets,
            commission_assets,
            total_shares,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.parameters.validate()?;
        if self.validators.len() != self.pools.len() {
            return Err(Error::Invariant("validator and pool counts differ"));
        }
        let mut consensus_keys = BTreeSet::new();
        let mut active_power_total = 0u64;
        for (id, validator) in &self.validators {
            if validator.validator_id != *id
                || validator_id(&self.chain_context, &validator.operator_pubkey) != *id
            {
                return Err(Error::Invariant("validator identity mismatch"));
            }
            if validator.commission_bps > self.parameters.max_commission_bps {
                return Err(Error::Invariant("validator commission is out of range"));
            }
            if let Some(pending) = validator.pending_commission {
                if pending.commission_bps > self.parameters.max_commission_bps
                    || pending.commission_bps == validator.commission_bps
                {
                    return Err(Error::Invariant("pending commission is invalid"));
                }
            }
            if let Some(pending) = validator.pending_consensus_key {
                if pending.consensus_pubkey == validator.consensus_pubkey {
                    return Err(Error::Invariant("pending consensus key is unchanged"));
                }
            }
            validate_metadata(
                &validator.display_name,
                &validator.website,
                &validator.description,
            )?;
            if validator.consensus_key_history.is_empty() {
                return Err(Error::Invariant("validator consensus key history is empty"));
            }
            for (index, record) in validator.consensus_key_history.iter().enumerate() {
                if !consensus_keys.insert(record.consensus_pubkey) {
                    return Err(Error::Invariant("duplicate validator consensus key"));
                }
                let is_current = index + 1 == validator.consensus_key_history.len();
                match (
                    record.retired_height,
                    record.retired_time_seconds,
                    record.responsibility_end_height,
                    record.responsibility_end_time_seconds,
                ) {
                    (None, None, None, None) if is_current => {
                        if record.consensus_pubkey != validator.consensus_pubkey {
                            return Err(Error::Invariant(
                                "current consensus history key does not match validator",
                            ));
                        }
                    }
                    (
                        Some(retired_height),
                        Some(retired_time),
                        Some(end_height),
                        Some(end_time),
                    ) if !is_current => {
                        if retired_height < record.activated_height
                            || retired_time < record.activated_time_seconds
                            || end_height < retired_height
                            || end_time < retired_time
                        {
                            return Err(Error::Invariant("consensus key history range is invalid"));
                        }
                        let next = &validator.consensus_key_history[index + 1];
                        if next.activated_height != retired_height
                            || next.activated_time_seconds != retired_time
                        {
                            return Err(Error::Invariant(
                                "consensus key history ranges are not contiguous",
                            ));
                        }
                    }
                    _ => {
                        return Err(Error::Invariant(
                            "consensus key retirement record is incomplete",
                        ));
                    }
                }
            }
            if let Some(pending) = validator.pending_consensus_key {
                if !consensus_keys.insert(pending.consensus_pubkey) {
                    return Err(Error::Invariant("duplicate validator consensus key"));
                }
            }
            match (
                validator.status,
                validator.jailed_at_height,
                validator.jailed_at_time_seconds,
            ) {
                (ValidatorStatus::Jailed, Some(_), Some(_)) => {}
                (ValidatorStatus::Jailed, _, _) => {
                    return Err(Error::Invariant("jailed validator is missing jail markers"));
                }
                (_, None, None) => {}
                _ => return Err(Error::Invariant("non-jailed validator has jail markers")),
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
                    if validator.voting_power == 0 {
                        return Err(Error::Invariant("active validator power is inconsistent"));
                    }
                    active_power_total = active_power_total
                        .checked_add(validator.voting_power)
                        .ok_or(Error::VotingPowerExceeded)?;
                }
                _ if validator.voting_power != 0 => {
                    return Err(Error::Invariant("inactive validator has voting power"));
                }
                _ => {}
            }
        }
        if active_power_total > self.parameters.max_total_voting_power {
            return Err(Error::VotingPowerExceeded);
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

    fn reward_eligible(&self, validator_id: &Hash32, score: u128) -> bool {
        let Some(validator) = self.validators.get(validator_id) else {
            return false;
        };
        let Some(pool) = self.pools.get(validator_id) else {
            return false;
        };
        score > 0
            && validator.status != ValidatorStatus::Tombstoned
            && pool.assets != Amount::ZERO
            && pool.total_shares != Amount::ZERO
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

    #[test]
    fn validator_updates_enforce_sequence_notice_and_disable_state() {
        let (mut book, validator_id) = book_with_validator();
        book.update_validator(
            &validator_id,
            0,
            0,
            10,
            100,
            ValidatorUpdate {
                display_name: Some("updated validator".to_owned()),
                commission_bps: Some(600),
                ..ValidatorUpdate::default()
            },
        )
        .unwrap();
        let validator = book.validator(&validator_id).unwrap();
        assert_eq!(validator.display_name, "updated validator");
        assert_eq!(validator.sequence, 1);
        assert_eq!(validator.commission_bps, 500);
        assert_eq!(
            validator.pending_commission,
            Some(PendingCommissionChange {
                commission_bps: 600,
                effective_epoch: 1,
                earliest_height: 120_970,
                earliest_time_seconds: 604_900,
            })
        );

        assert!(book
            .apply_scheduled_validator_changes(1, 120_970, 604_899)
            .unwrap()
            .is_empty());
        assert!(book
            .apply_scheduled_validator_changes(1, 120_969, 604_900)
            .unwrap()
            .is_empty());
        assert_eq!(
            book.apply_scheduled_validator_changes(1, 120_970, 604_900)
                .unwrap(),
            BTreeSet::from([validator_id])
        );
        assert_eq!(book.validator(&validator_id).unwrap().commission_bps, 600);

        let before = book.clone();
        assert_eq!(
            book.update_validator(
                &validator_id,
                1,
                1,
                200_000,
                700_000,
                ValidatorUpdate {
                    commission_bps: Some(701),
                    ..ValidatorUpdate::default()
                },
            ),
            Err(Error::CommissionIncreaseTooLarge)
        );
        assert_eq!(book, before);

        book.update_validator(
            &validator_id,
            1,
            1,
            200_000,
            700_000,
            ValidatorUpdate {
                commission_bps: Some(400),
                ..ValidatorUpdate::default()
            },
        )
        .unwrap();
        assert!(book
            .apply_scheduled_validator_changes(1, u64::MAX, u64::MAX)
            .unwrap()
            .is_empty());
        book.apply_scheduled_validator_changes(2, 200_000, 700_000)
            .unwrap();
        assert_eq!(book.validator(&validator_id).unwrap().commission_bps, 400);

        book.update_validator(
            &validator_id,
            2,
            2,
            200_001,
            700_001,
            ValidatorUpdate {
                request_disable: Some(true),
                ..ValidatorUpdate::default()
            },
        )
        .unwrap();
        book.apply_validator_set().unwrap();
        assert_eq!(
            book.validator(&validator_id).unwrap().status,
            ValidatorStatus::Disabled
        );
        book.update_validator(
            &validator_id,
            3,
            2,
            200_002,
            700_002,
            ValidatorUpdate {
                request_disable: Some(false),
                ..ValidatorUpdate::default()
            },
        )
        .unwrap();
        assert_eq!(
            book.validator(&validator_id).unwrap().status,
            ValidatorStatus::Candidate
        );
        assert!(book.validate().is_ok());
    }

    #[test]
    fn unjail_requires_both_chain_time_and_block_waits() {
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
        book.jail_validator_for_downtime(&validator_id, 100, 1_000)
            .unwrap();

        assert_eq!(
            book.unjail_validator(&validator_id, 0, 1_540, 8_199),
            Err(Error::JailPeriodNotElapsed)
        );
        assert_eq!(
            book.unjail_validator(&validator_id, 0, 1_539, 8_200),
            Err(Error::JailPeriodNotElapsed)
        );
        book.unjail_validator(&validator_id, 0, 1_540, 8_200)
            .unwrap();
        let validator = book.validator(&validator_id).unwrap();
        assert_eq!(validator.status, ValidatorStatus::Candidate);
        assert_eq!(validator.sequence, 1);
        assert_eq!(validator.jailed_at_height, None);
        assert_eq!(validator.jailed_at_time_seconds, None);
        assert!(book.validate().is_ok());
    }

    #[test]
    fn consensus_rotation_preserves_responsibility_history_and_key_uniqueness() {
        let (mut book, validator_id) = book_with_validator();
        book.rotate_consensus_key(&validator_id, 0, key(4), 0)
            .unwrap();
        let validator = book.validator(&validator_id).unwrap();
        assert_eq!(validator.consensus_pubkey, key(3));
        assert_eq!(validator.sequence, 1);
        assert_eq!(validator.consensus_key_history.len(), 1);
        assert_eq!(
            validator.pending_consensus_key,
            Some(PendingConsensusKey {
                consensus_pubkey: key(4),
                effective_epoch: 1,
            })
        );
        assert!(book
            .apply_scheduled_validator_changes(0, 10, 20)
            .unwrap()
            .is_empty());
        assert_eq!(
            book.apply_scheduled_validator_changes(1, 10, 20).unwrap(),
            BTreeSet::from([validator_id])
        );
        let validator = book.validator(&validator_id).unwrap();
        assert_eq!(validator.consensus_pubkey, key(4));
        assert_eq!(validator.pending_consensus_key, None);
        assert_eq!(validator.consensus_key_history.len(), 2);
        assert_eq!(validator.consensus_key_history[0].retired_height, Some(10));
        assert_eq!(
            validator.consensus_key_history[0].responsibility_end_height,
            Some(120_970)
        );
        assert_eq!(
            validator.consensus_key_history[0].responsibility_end_time_seconds,
            Some(604_820)
        );

        let other_operator = key(5);
        let other_id = bit_types::validator_id(&book.chain_context(), &other_operator);
        assert_eq!(
            book.register_validator(other_id, other_operator, key(3), 500),
            Err(Error::ConsensusKeyAlreadyInUse)
        );
        assert_eq!(
            book.rotate_consensus_key(&validator_id, 0, key(6), 1),
            Err(Error::ValidatorSequenceMismatch)
        );
        assert_eq!(
            book.rotate_consensus_key(&validator_id, 1, key(4), 1),
            Err(Error::ConsensusKeyUnchanged)
        );

        let encoded = book
            .validator(&validator_id)
            .unwrap()
            .encode_persistent()
            .unwrap();
        assert_eq!(
            Validator::decode_persistent(&encoded).unwrap(),
            *book.validator(&validator_id).unwrap()
        );
        assert!(book.validate().is_ok());
    }

    #[test]
    fn epoch_rewards_split_by_score_and_commission_with_remainder_retained() {
        let (mut book, first_id) = book_with_validator();
        let second_operator = key(5);
        let second_id = validator_id(&book.chain_context(), &second_operator);
        book.register_validator(second_id, second_operator, key(6), 1_000)
            .unwrap();

        let first_bond = open(
            &mut book,
            first_id,
            key(4),
            TESTNET_MIN_SELF_BOND_ATOMIC,
            0,
            true,
        );
        let second_bond = open(
            &mut book,
            second_id,
            key(7),
            TESTNET_MIN_SELF_BOND_ATOMIC,
            0,
            true,
        );
        book.activate_pending(&first_bond, 1).unwrap();
        book.activate_pending(&second_bond, 1).unwrap();

        let rewards = book
            .distribute_epoch_rewards(
                1,
                amount(101),
                &BTreeMap::from([(first_id, 1), (second_id, 3)]),
            )
            .unwrap();
        assert_eq!(rewards.len(), 2);
        assert_eq!(rewards[0].gross_reward, amount(25));
        assert_eq!(rewards[0].stake_reward, amount(24));
        assert_eq!(rewards[0].commission_reward, amount(1));
        assert_eq!(rewards[1].gross_reward, amount(75));
        assert_eq!(rewards[1].stake_reward, amount(68));
        assert_eq!(rewards[1].commission_reward, amount(7));
        assert_eq!(book.totals().unwrap().commission_assets, amount(8));
        assert_eq!(book.pool(&first_id).unwrap().last_settled_epoch, 1);
        assert_eq!(book.pool(&second_id).unwrap().last_settled_epoch, 1);

        let before = book.clone();
        assert_eq!(
            book.claim_commission(&first_id, 0, amount(2)),
            Err(Error::InvalidCommissionClaim)
        );
        assert_eq!(book, before);
        assert_eq!(
            book.claim_commission(&first_id, 0, amount(1)),
            Ok(amount(1))
        );
        assert_eq!(book.validator(&first_id).unwrap().sequence, 1);
        assert_eq!(book.totals().unwrap().commission_assets, amount(7));
        assert!(book.validate().is_ok());
    }
}
