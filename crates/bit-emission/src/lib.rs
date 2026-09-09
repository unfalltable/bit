//! Fixed-cap supply accounting for BIT.
//!
//! This crate owns integer conservation rules and epoch issuance transitions.
//! It deliberately does not define the unresolved `supply/audit_snapshot` wire
//! encoding from SPEC-04; persistence stores the individual consensus fields.

use bit_types::{Amount, MonetaryPolicy, MAX_SUPPLY_ATOMIC};
use thiserror::Error;

pub type Hash32 = [u8; 32];

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid monetary policy: {0}")]
    Policy(#[from] bit_types::Error),
    #[error("invalid genesis accounting: {0}")]
    InvalidGenesis(&'static str),
    #[error("supply accounting overflow")]
    Overflow,
    #[error("insufficient value in {0}")]
    Insufficient(&'static str),
    #[error("supply invariant failed: {0}")]
    Invariant(&'static str),
    #[error("invalid fee calculation input: {0}")]
    InvalidFeeInput(&'static str),
    #[error("invalid emission schedule input: {0}")]
    InvalidScheduleInput(&'static str),
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisAllocation {
    pub shielded: Amount,
    pub stake: Amount,
    pub pending_delegation: Amount,
    pub exits: Amount,
    pub commission: Amount,
    pub fee_reserve: Amount,
    pub unclaimed_genesis: Amount,
}

impl GenesisAllocation {
    pub fn shielded_only(genesis_supply: Amount) -> Self {
        Self {
            shielded: genesis_supply,
            stake: Amount::ZERO,
            pending_delegation: Amount::ZERO,
            exits: Amount::ZERO,
            commission: Amount::ZERO,
            fee_reserve: Amount::ZERO,
            unclaimed_genesis: Amount::ZERO,
        }
    }

    pub fn unclaimed_only(genesis_supply: Amount) -> Self {
        Self {
            shielded: Amount::ZERO,
            stake: Amount::ZERO,
            pending_delegation: Amount::ZERO,
            exits: Amount::ZERO,
            commission: Amount::ZERO,
            fee_reserve: Amount::ZERO,
            unclaimed_genesis: genesis_supply,
        }
    }

    fn total(&self) -> Result<u128> {
        checked_sum([
            self.shielded.value(),
            self.stake.value(),
            self.pending_delegation.value(),
            self.exits.value(),
            self.commission.value(),
            self.fee_reserve.value(),
            self.unclaimed_genesis.value(),
        ])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeeClass {
    Standard,
    NewPosition,
    ValidatorRegistration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeePolicy {
    pub base: Amount,
    pub per_kib: Amount,
    pub per_spend_proof: Amount,
    pub per_output_proof: Amount,
    pub new_position_surcharge: Amount,
    pub validator_registration_surcharge: Amount,
}

impl FeePolicy {
    pub fn reference_testnet() -> Self {
        Self {
            base: Amount::new(1_000).expect("reference fee must fit Amount"),
            per_kib: Amount::new(200).expect("reference fee must fit Amount"),
            per_spend_proof: Amount::new(500).expect("reference fee must fit Amount"),
            per_output_proof: Amount::new(500).expect("reference fee must fit Amount"),
            new_position_surcharge: Amount::new(100_000).expect("reference fee must fit Amount"),
            validator_registration_surcharge: Amount::new(100_000_000)
                .expect("reference fee must fit Amount"),
        }
    }

    /// Calculate the exact minimum fee from the complete canonical envelope size.
    pub fn minimum_fee(
        &self,
        canonical_envelope_bytes: usize,
        spend_count: usize,
        output_count: usize,
        class: FeeClass,
    ) -> Result<Amount> {
        if canonical_envelope_bytes == 0 {
            return Err(Error::InvalidFeeInput(
                "canonical envelope size must be positive",
            ));
        }
        let kibibytes = canonical_envelope_bytes
            .checked_add(1023)
            .ok_or(Error::Overflow)?
            / 1024;
        let mut total = self.base.value();
        total = add(total, multiply(self.per_kib.value(), kibibytes as u128)?)?;
        total = add(
            total,
            multiply(self.per_spend_proof.value(), spend_count as u128)?,
        )?;
        total = add(
            total,
            multiply(self.per_output_proof.value(), output_count as u128)?,
        )?;
        let surcharge = match class {
            FeeClass::Standard => Amount::ZERO,
            FeeClass::NewPosition => self.new_position_surcharge,
            FeeClass::ValidatorRegistration => self.validator_registration_surcharge,
        };
        amount(add(total, surcharge.value())?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupplyContainer {
    Shielded,
    Stake,
    PendingDelegation,
    Exits,
    Commission,
    FeeReserve,
    UnclaimedGenesis,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupplyState {
    pub max_supply: Amount,
    pub genesis_supply: Amount,
    pub cumulative_minted: Amount,
    pub burned: Amount,
    pub shielded_total: Amount,
    pub stake_total: Amount,
    pub pending_delegation_total: Amount,
    pub exit_total: Amount,
    pub commission_total: Amount,
    pub fee_reserve: Amount,
    pub unclaimed_genesis_total: Amount,
    pub completed_epochs: u64,
    pub forfeited_unissued: Amount,
    pub monetary_policy_hash: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupplyAudit {
    pub max_supply: Amount,
    pub genesis_supply: Amount,
    pub cumulative_minted: Amount,
    pub burned: Amount,
    pub issued_total: Amount,
    pub current_supply: Amount,
    pub scheduled_to_date: Amount,
    pub forfeited_unissued: Amount,
    pub future_issuance_budget: Amount,
    pub shielded_total: Amount,
    pub stake_total: Amount,
    pub pending_delegation_total: Amount,
    pub exit_total: Amount,
    pub commission_total: Amount,
    pub fee_reserve: Amount,
    pub unclaimed_genesis_total: Amount,
    pub completed_epochs: u64,
    pub monetary_policy_hash: Hash32,
}

impl SupplyState {
    pub fn genesis(policy: &MonetaryPolicy, allocation: GenesisAllocation) -> Result<Self> {
        policy.validate()?;
        if allocation.total()? != policy.genesis_supply.value() {
            return Err(Error::InvalidGenesis(
                "asset containers do not sum to genesis supply",
            ));
        }
        let state = Self {
            max_supply: amount(MAX_SUPPLY_ATOMIC)?,
            genesis_supply: policy.genesis_supply,
            cumulative_minted: Amount::ZERO,
            burned: Amount::ZERO,
            shielded_total: allocation.shielded,
            stake_total: allocation.stake,
            pending_delegation_total: allocation.pending_delegation,
            exit_total: allocation.exits,
            commission_total: allocation.commission,
            fee_reserve: allocation.fee_reserve,
            unclaimed_genesis_total: allocation.unclaimed_genesis,
            completed_epochs: 0,
            forfeited_unissued: Amount::ZERO,
            monetary_policy_hash: policy.hash()?,
        };
        state.validate(policy)?;
        Ok(state)
    }

    pub fn validate(&self, policy: &MonetaryPolicy) -> Result<()> {
        policy.validate()?;
        if self.max_supply.value() != MAX_SUPPLY_ATOMIC {
            return Err(Error::Invariant("max supply differs from fixed constant"));
        }
        if self.genesis_supply != policy.genesis_supply {
            return Err(Error::Invariant("genesis supply differs from policy"));
        }
        if self.monetary_policy_hash != policy.hash()? {
            return Err(Error::Invariant("monetary policy hash differs"));
        }

        let issued = add(self.genesis_supply.value(), self.cumulative_minted.value())?;
        if issued > self.max_supply.value() {
            return Err(Error::Invariant("historical issuance exceeds hard cap"));
        }
        if self.burned.value() > issued {
            return Err(Error::Invariant("burned amount exceeds issued amount"));
        }
        let current = issued - self.burned.value();
        if self.container_total()? != current {
            return Err(Error::Invariant(
                "asset containers do not equal issued minus burned",
            ));
        }

        let scheduled = policy.scheduled(self.completed_epochs)?;
        if add(
            self.cumulative_minted.value(),
            self.forfeited_unissued.value(),
        )? != scheduled
        {
            return Err(Error::Invariant(
                "minted plus forfeited does not equal scheduled issuance",
            ));
        }
        let budget = policy.future_budget();
        if scheduled > budget {
            return Err(Error::Invariant("scheduled issuance exceeds future budget"));
        }
        let future = budget - scheduled;
        if checked_sum([issued, self.forfeited_unissued.value(), future])?
            != self.max_supply.value()
        {
            return Err(Error::Invariant(
                "issued, forfeited, and future budget do not equal hard cap",
            ));
        }
        Ok(())
    }

    /// Validate both monetary identities and the height-derived settlement count.
    pub fn validate_at_height(&self, policy: &MonetaryPolicy, height: u64) -> Result<()> {
        self.validate(policy)?;
        let expected = completed_epochs_after_height(height, policy.epoch_blocks)?;
        if self.completed_epochs != expected {
            return Err(Error::Invariant(
                "completed epochs differ from committed height",
            ));
        }
        Ok(())
    }

    pub fn audit(&self, policy: &MonetaryPolicy) -> Result<SupplyAudit> {
        self.validate(policy)?;
        let issued = add(self.genesis_supply.value(), self.cumulative_minted.value())?;
        let scheduled = policy.scheduled(self.completed_epochs)?;
        Ok(SupplyAudit {
            max_supply: self.max_supply,
            genesis_supply: self.genesis_supply,
            cumulative_minted: self.cumulative_minted,
            burned: self.burned,
            issued_total: amount(issued)?,
            current_supply: amount(issued - self.burned.value())?,
            scheduled_to_date: amount(scheduled)?,
            forfeited_unissued: self.forfeited_unissued,
            future_issuance_budget: amount(policy.future_budget() - scheduled)?,
            shielded_total: self.shielded_total,
            stake_total: self.stake_total,
            pending_delegation_total: self.pending_delegation_total,
            exit_total: self.exit_total,
            commission_total: self.commission_total,
            fee_reserve: self.fee_reserve,
            unclaimed_genesis_total: self.unclaimed_genesis_total,
            completed_epochs: self.completed_epochs,
            monetary_policy_hash: self.monetary_policy_hash,
        })
    }

    pub fn audit_at_height(&self, policy: &MonetaryPolicy, height: u64) -> Result<SupplyAudit> {
        self.validate_at_height(policy, height)?;
        self.audit(policy)
    }

    /// Move a Transfer fee from the private pool to the fee reserve.
    pub fn charge_transfer_fee(&mut self, policy: &MonetaryPolicy, fee: Amount) -> Result<()> {
        self.charge_shielded_fee(policy, fee)
    }

    /// Move a fee paid by private Spend inputs from Q into F.
    pub fn charge_shielded_fee(&mut self, policy: &MonetaryPolicy, fee: Amount) -> Result<()> {
        let mut next = self.clone();
        next.shielded_total = subtract(next.shielded_total, fee, "shielded total")?;
        next.fee_reserve = amount(add(next.fee_reserve.value(), fee.value())?)?;
        next.validate(policy)?;
        *self = next;
        Ok(())
    }

    /// Lock a new delegation principal in D and charge its fee into F.
    pub fn open_pending_delegation(
        &mut self,
        policy: &MonetaryPolicy,
        deposit: Amount,
        fee: Amount,
    ) -> Result<()> {
        let debit = amount(add(deposit.value(), fee.value())?)?;
        let mut next = self.clone();
        next.shielded_total = subtract(next.shielded_total, debit, "shielded total")?;
        next.pending_delegation_total =
            amount(add(next.pending_delegation_total.value(), deposit.value())?)?;
        next.fee_reserve = amount(add(next.fee_reserve.value(), fee.value())?)?;
        next.validate(policy)?;
        *self = next;
        Ok(())
    }

    /// Move an accepted pending principal from D into the active stake pool P.
    pub fn activate_pending_delegation(
        &mut self,
        policy: &MonetaryPolicy,
        deposit: Amount,
    ) -> Result<()> {
        let mut next = self.clone();
        next.pending_delegation_total = subtract(
            next.pending_delegation_total,
            deposit,
            "pending delegation total",
        )?;
        next.stake_total = amount(add(next.stake_total.value(), deposit.value())?)?;
        next.validate(policy)?;
        *self = next;
        Ok(())
    }

    /// Return canceled or refundable pending principal to Q and charge F.
    pub fn release_pending_delegation(
        &mut self,
        policy: &MonetaryPolicy,
        released: Amount,
        fee: Amount,
    ) -> Result<()> {
        if fee > released {
            return Err(Error::Insufficient("released pending delegation"));
        }
        let mut next = self.clone();
        next.pending_delegation_total = subtract(
            next.pending_delegation_total,
            released,
            "pending delegation total",
        )?;
        next.shielded_total = amount(add(
            next.shielded_total.value(),
            released.value() - fee.value(),
        )?)?;
        next.fee_reserve = amount(add(next.fee_reserve.value(), fee.value())?)?;
        next.validate(policy)?;
        *self = next;
        Ok(())
    }

    /// Release one genesis allocation into the private pool and optionally pay its fee.
    pub fn claim_genesis(
        &mut self,
        policy: &MonetaryPolicy,
        released: Amount,
        fee: Amount,
    ) -> Result<()> {
        if fee.value() > released.value() {
            return Err(Error::Insufficient("released genesis value"));
        }
        let mut next = self.clone();
        next.unclaimed_genesis_total = subtract(
            next.unclaimed_genesis_total,
            released,
            "unclaimed genesis total",
        )?;
        next.shielded_total = amount(add(
            next.shielded_total.value(),
            released.value() - fee.value(),
        )?)?;
        next.fee_reserve = amount(add(next.fee_reserve.value(), fee.value())?)?;
        next.validate(policy)?;
        *self = next;
        Ok(())
    }

    /// Settle exactly the next scheduled epoch. Eligible issuance first enters F.
    pub fn settle_next_epoch(
        &mut self,
        policy: &MonetaryPolicy,
        has_eligible_stake: bool,
    ) -> Result<Amount> {
        self.validate(policy)?;
        let quota = amount(policy.quota(self.completed_epochs)?)?;
        let mut next = self.clone();
        next.completed_epochs = next
            .completed_epochs
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        if has_eligible_stake {
            next.cumulative_minted = amount(add(next.cumulative_minted.value(), quota.value())?)?;
            next.fee_reserve = amount(add(next.fee_reserve.value(), quota.value())?)?;
        } else {
            next.forfeited_unissued = amount(add(next.forfeited_unissued.value(), quota.value())?)?;
        }
        next.validate(policy)?;
        *self = next;
        Ok(quota)
    }

    pub fn distribute_fee_reserve(
        &mut self,
        policy: &MonetaryPolicy,
        stake_reward: Amount,
        commission_reward: Amount,
    ) -> Result<()> {
        let distributed = amount(add(stake_reward.value(), commission_reward.value())?)?;
        let mut next = self.clone();
        next.fee_reserve = subtract(next.fee_reserve, distributed, "fee reserve")?;
        next.stake_total = amount(add(next.stake_total.value(), stake_reward.value())?)?;
        next.commission_total = amount(add(
            next.commission_total.value(),
            commission_reward.value(),
        )?)?;
        next.validate(policy)?;
        *self = next;
        Ok(())
    }

    pub fn burn_from(
        &mut self,
        policy: &MonetaryPolicy,
        container: SupplyContainer,
        value: Amount,
    ) -> Result<()> {
        let mut next = self.clone();
        let source = match container {
            SupplyContainer::Shielded => &mut next.shielded_total,
            SupplyContainer::Stake => &mut next.stake_total,
            SupplyContainer::PendingDelegation => &mut next.pending_delegation_total,
            SupplyContainer::Exits => &mut next.exit_total,
            SupplyContainer::Commission => &mut next.commission_total,
            SupplyContainer::FeeReserve => &mut next.fee_reserve,
            SupplyContainer::UnclaimedGenesis => &mut next.unclaimed_genesis_total,
        };
        *source = subtract(*source, value, "burn source container")?;
        next.burned = amount(add(next.burned.value(), value.value())?)?;
        next.validate(policy)?;
        *self = next;
        Ok(())
    }

    fn container_total(&self) -> Result<u128> {
        checked_sum([
            self.shielded_total.value(),
            self.stake_total.value(),
            self.pending_delegation_total.value(),
            self.exit_total.value(),
            self.commission_total.value(),
            self.fee_reserve.value(),
            self.unclaimed_genesis_total.value(),
        ])
    }
}

/// Number of epochs that must be settled after committing `height`.
pub fn completed_epochs_after_height(height: u64, epoch_blocks: u64) -> Result<u64> {
    if epoch_blocks == 0 {
        return Err(Error::InvalidScheduleInput(
            "epoch block count must be positive",
        ));
    }
    Ok(height.saturating_sub(1) / epoch_blocks)
}

fn amount(value: u128) -> Result<Amount> {
    Amount::new(value).map_err(Error::Policy)
}

fn add(left: u128, right: u128) -> Result<u128> {
    left.checked_add(right).ok_or(Error::Overflow)
}

fn multiply(left: u128, right: u128) -> Result<u128> {
    left.checked_mul(right).ok_or(Error::Overflow)
}

fn subtract(left: Amount, right: Amount, name: &'static str) -> Result<Amount> {
    let value = left
        .value()
        .checked_sub(right.value())
        .ok_or(Error::Insufficient(name))?;
    amount(value)
}

fn checked_sum<const N: usize>(values: [u128; N]) -> Result<u128> {
    values.into_iter().try_fold(0u128, add)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> MonetaryPolicy {
        MonetaryPolicy::reference_testnet()
    }

    #[test]
    fn genesis_requires_exact_container_sum() {
        let policy = policy();
        let state = SupplyState::genesis(
            &policy,
            GenesisAllocation::shielded_only(policy.genesis_supply),
        )
        .unwrap();
        let audit = state.audit(&policy).unwrap();
        assert_eq!(audit.issued_total, policy.genesis_supply);
        assert_eq!(audit.current_supply, policy.genesis_supply);
        assert_eq!(audit.future_issuance_budget.value(), policy.future_budget());

        let invalid = GenesisAllocation::shielded_only(Amount::new(1).unwrap());
        assert!(matches!(
            SupplyState::genesis(&policy, invalid),
            Err(Error::InvalidGenesis(_))
        ));
    }

    #[test]
    fn reference_fee_policy_uses_ceiling_kibibytes_and_action_surcharges() {
        let fees = FeePolicy::reference_testnet();
        assert_eq!(
            fees.minimum_fee(1, 0, 0, FeeClass::Standard)
                .unwrap()
                .value(),
            1_200
        );
        assert_eq!(
            fees.minimum_fee(1024, 2, 2, FeeClass::Standard)
                .unwrap()
                .value(),
            3_200
        );
        assert_eq!(
            fees.minimum_fee(1025, 2, 2, FeeClass::Standard)
                .unwrap()
                .value(),
            3_400
        );
        assert_eq!(
            fees.minimum_fee(1025, 0, 0, FeeClass::NewPosition)
                .unwrap()
                .value(),
            101_400
        );
        assert_eq!(
            fees.minimum_fee(1025, 0, 0, FeeClass::ValidatorRegistration)
                .unwrap()
                .value(),
            100_001_400
        );
        assert!(matches!(
            fees.minimum_fee(0, 0, 0, FeeClass::Standard),
            Err(Error::InvalidFeeInput(_))
        ));
    }

    #[test]
    fn completed_epoch_count_changes_only_on_the_next_epoch_first_block() {
        assert_eq!(completed_epochs_after_height(0, 720).unwrap(), 0);
        assert_eq!(completed_epochs_after_height(1, 720).unwrap(), 0);
        assert_eq!(completed_epochs_after_height(720, 720).unwrap(), 0);
        assert_eq!(completed_epochs_after_height(721, 720).unwrap(), 1);
        assert_eq!(completed_epochs_after_height(1_440, 720).unwrap(), 1);
        assert_eq!(completed_epochs_after_height(1_441, 720).unwrap(), 2);
        assert!(matches!(
            completed_epochs_after_height(1, 0),
            Err(Error::InvalidScheduleInput(_))
        ));

        let policy = policy();
        let state = SupplyState::genesis(
            &policy,
            GenesisAllocation::shielded_only(policy.genesis_supply),
        )
        .unwrap();
        assert!(state.validate_at_height(&policy, 720).is_ok());
        assert!(matches!(
            state.validate_at_height(&policy, 721),
            Err(Error::Invariant(
                "completed epochs differ from committed height"
            ))
        ));
    }

    #[test]
    fn transfer_fee_is_an_atomic_container_move() {
        let policy = policy();
        let mut state = SupplyState::genesis(
            &policy,
            GenesisAllocation::shielded_only(policy.genesis_supply),
        )
        .unwrap();
        state
            .charge_transfer_fee(&policy, Amount::new(1_000).unwrap())
            .unwrap();
        let audit = state.audit(&policy).unwrap();
        assert_eq!(
            audit.shielded_total.value(),
            policy.genesis_supply.value() - 1_000
        );
        assert_eq!(audit.fee_reserve.value(), 1_000);
        assert_eq!(audit.current_supply, policy.genesis_supply);

        let before = state.clone();
        assert!(matches!(
            state.charge_transfer_fee(&policy, policy.genesis_supply),
            Err(Error::Insufficient("shielded total"))
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn delegation_moves_follow_q_d_p_and_f_accounting() {
        let policy = policy();
        let mut state = SupplyState::genesis(
            &policy,
            GenesisAllocation::shielded_only(policy.genesis_supply),
        )
        .unwrap();
        let deposit = Amount::new(100_000_000_000).unwrap();
        let open_fee = Amount::new(101_200).unwrap();
        state
            .open_pending_delegation(&policy, deposit, open_fee)
            .unwrap();
        let pending = state.audit(&policy).unwrap();
        assert_eq!(pending.pending_delegation_total, deposit);
        assert_eq!(pending.fee_reserve, open_fee);
        assert_eq!(
            pending.shielded_total.value(),
            policy.genesis_supply.value() - deposit.value() - open_fee.value()
        );

        state.activate_pending_delegation(&policy, deposit).unwrap();
        let active = state.audit(&policy).unwrap();
        assert_eq!(active.pending_delegation_total, Amount::ZERO);
        assert_eq!(active.stake_total, deposit);
        assert_eq!(active.current_supply, policy.genesis_supply);

        let second = Amount::new(200_000_000).unwrap();
        state
            .open_pending_delegation(&policy, second, open_fee)
            .unwrap();
        let release_fee = Amount::new(1_200).unwrap();
        state
            .release_pending_delegation(&policy, second, release_fee)
            .unwrap();
        let released = state.audit(&policy).unwrap();
        assert_eq!(released.pending_delegation_total, Amount::ZERO);
        assert_eq!(released.stake_total, deposit);
        assert_eq!(
            released.fee_reserve.value(),
            open_fee.value() * 2 + release_fee.value()
        );
        assert_eq!(released.current_supply, policy.genesis_supply);
    }

    #[test]
    fn failed_delegation_accounting_is_atomic() {
        let policy = policy();
        let mut state = SupplyState::genesis(
            &policy,
            GenesisAllocation::shielded_only(policy.genesis_supply),
        )
        .unwrap();
        let before = state.clone();
        assert!(matches!(
            state.open_pending_delegation(&policy, policy.genesis_supply, Amount::new(1).unwrap()),
            Err(Error::Insufficient("shielded total"))
        ));
        assert_eq!(state, before);
        assert!(matches!(
            state.release_pending_delegation(
                &policy,
                Amount::new(1).unwrap(),
                Amount::new(2).unwrap()
            ),
            Err(Error::Insufficient("released pending delegation"))
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn issuance_and_forfeiture_follow_the_exact_schedule_without_catchup() {
        let policy = policy();
        let mut state = SupplyState::genesis(
            &policy,
            GenesisAllocation::shielded_only(policy.genesis_supply),
        )
        .unwrap();
        let first = state.settle_next_epoch(&policy, true).unwrap();
        assert_eq!(first.value(), policy.quota(0).unwrap());
        assert_eq!(state.cumulative_minted, first);
        assert_eq!(state.fee_reserve, first);

        let second = state.settle_next_epoch(&policy, false).unwrap();
        assert_eq!(second.value(), policy.quota(1).unwrap());
        assert_eq!(state.cumulative_minted, first);
        assert_eq!(state.forfeited_unissued, second);
        assert_eq!(
            state.audit(&policy).unwrap().scheduled_to_date.value(),
            policy.scheduled(2).unwrap()
        );
    }

    #[test]
    fn burn_does_not_reopen_issuance_and_tampering_is_detected() {
        let policy = policy();
        let mut state = SupplyState::genesis(
            &policy,
            GenesisAllocation::shielded_only(policy.genesis_supply),
        )
        .unwrap();
        state
            .burn_from(
                &policy,
                SupplyContainer::Shielded,
                Amount::new(500).unwrap(),
            )
            .unwrap();
        let audit = state.audit(&policy).unwrap();
        assert_eq!(audit.burned.value(), 500);
        assert_eq!(audit.future_issuance_budget.value(), policy.future_budget());

        state.fee_reserve = Amount::new(1).unwrap();
        assert!(matches!(state.validate(&policy), Err(Error::Invariant(_))));
    }
}
