use crate::{
    cbor::{Cursor, Writer},
    Amount, Error, Result, MAX_SUPPLY_ATOMIC,
};
use sha2::{Digest, Sha256};

pub const POLICY_ID: &str = "BUDGET_HALVING_EPOCH_V1";
pub const EMPTY_SET_POLICY: &str = "FORFEIT_UNISSUED_NO_CATCHUP";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonetaryPolicy {
    pub genesis_supply: Amount,
    pub epoch_blocks: u64,
    pub halving_interval_epochs: u64,
}

impl MonetaryPolicy {
    pub fn reference_testnet() -> Self {
        Self {
            genesis_supply: Amount::new(10_000_000_000_000_000).unwrap(),
            epoch_blocks: 720,
            halving_interval_epochs: 35040,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.genesis_supply.value() == 0 || self.genesis_supply.value() >= MAX_SUPPLY_ATOMIC {
            return Err(Error::InvalidPolicy("genesis supply outside 0 < G0 < M"));
        }
        if self.epoch_blocks == 0 || self.halving_interval_epochs == 0 {
            return Err(Error::InvalidPolicy(
                "epoch and halving intervals must be positive",
            ));
        }
        self.epoch_blocks
            .checked_mul(self.halving_interval_epochs)
            .ok_or(Error::InvalidPolicy("halving block interval overflow"))?;
        Ok(())
    }
    pub fn future_budget(&self) -> u128 {
        MAX_SUPPLY_ATOMIC - self.genesis_supply.value()
    }
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut w = Writer::new();
        w.array(9);
        w.text(POLICY_ID);
        w.bytes(&Amount::new(MAX_SUPPLY_ATOMIC)?.to_be_bytes());
        w.uint(8);
        w.bytes(&self.genesis_supply.to_be_bytes());
        w.uint(self.epoch_blocks);
        w.uint(self.halving_interval_epochs);
        w.text(EMPTY_SET_POLICY);
        w.boolean(false);
        w.boolean(false);
        Ok(w.finish())
    }
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(bytes);
        if c.array()? != 9 {
            return Err(Error::InvalidPolicy("policy must have nine fields"));
        }
        if c.text()? != POLICY_ID {
            return Err(Error::InvalidPolicy("unknown policy id"));
        }
        if Amount::from_be_bytes(c.bytes()?.try_into().map_err(|_| Error::InvalidAmount)?)?.value()
            != MAX_SUPPLY_ATOMIC
        {
            return Err(Error::InvalidPolicy("max supply mismatch"));
        }
        if c.uint() != Ok(8) {
            return Err(Error::InvalidPolicy("decimals must equal 8"));
        }
        let genesis_supply =
            Amount::from_be_bytes(c.bytes()?.try_into().map_err(|_| Error::InvalidAmount)?)?;
        let epoch_blocks = c.uint()?;
        let halving_interval_epochs = c.uint()?;
        if c.text()? != EMPTY_SET_POLICY {
            return Err(Error::InvalidPolicy("empty-set policy mismatch"));
        }
        if c.boolean()? || c.boolean()? {
            return Err(Error::InvalidPolicy(
                "burn reopening and tail emission must be false",
            ));
        }
        c.finish()?;
        let policy = Self {
            genesis_supply,
            epoch_blocks,
            halving_interval_epochs,
        };
        policy.validate()?;
        if policy.encode_canonical()?.as_slice() != bytes {
            return Err(Error::InvalidPolicy(
                "policy does not round-trip canonically",
            ));
        }
        Ok(policy)
    }
    pub fn hash(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.encode_canonical()?).into())
    }
    pub fn scheduled(&self, completed_epochs: u64) -> Result<u128> {
        scheduled_issuance(
            self.future_budget(),
            self.halving_interval_epochs,
            completed_epochs,
        )
    }
    pub fn quota(&self, epoch: u64) -> Result<u128> {
        quota(self.future_budget(), self.halving_interval_epochs, epoch)
    }
}

pub fn scheduled_issuance(budget: u128, interval: u64, completed: u64) -> Result<u128> {
    if budget > MAX_SUPPLY_ATOMIC || interval == 0 {
        return Err(Error::InvalidPolicy("invalid budget or interval"));
    }
    let era = completed / interval;
    let offset = completed % interval;
    let remaining = if era >= 128 { 0 } else { budget >> era };
    let tranche = remaining - remaining / 2;
    let progress = tranche.checked_mul(offset as u128).ok_or(Error::Overflow)? / interval as u128;
    budget
        .checked_sub(remaining)
        .and_then(|v| v.checked_add(progress))
        .ok_or(Error::Overflow)
}
pub fn quota(budget: u128, interval: u64, epoch: u64) -> Result<u128> {
    let next = epoch.checked_add(1).ok_or(Error::Overflow)?;
    scheduled_issuance(budget, interval, next)?
        .checked_sub(scheduled_issuance(budget, interval, epoch)?)
        .ok_or(Error::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reference_policy_matches_frozen_vector() {
        let p = MonetaryPolicy::reference_testnet();
        let bytes = p.encode_canonical().unwrap();
        assert_eq!(hex::encode(&bytes),"89774255444745545f48414c56494e475f45504f43485f56315000000000000000008e1bc9bf0400000008500000000000000000002386f26fc100001902d01988e0781b464f52464549545f554e4953535545445f4e4f5f43415443485550f4f4");
        assert_eq!(
            hex::encode(p.hash().unwrap()),
            "1f30a6e87b17cfafdf8e3265beb24cf1fc366307f62ac9475e5a558fdeddddcc"
        );
        assert_eq!(MonetaryPolicy::decode_canonical(&bytes).unwrap(), p);
    }
    #[test]
    fn golden_issuance_points() {
        let p = MonetaryPolicy::reference_testnet();
        for (e, u, q) in [
            (0, 0, 145976027397260),
            (35039, 5114854023972602739, 145976027397261),
            (35040, 5115000000000000000, 72988013698630),
            (70080, 7672500000000000000, 36494006849315),
            (2242559, 10229999999999999999, 1),
            (2242560, 10230000000000000000, 0),
        ] {
            assert_eq!(p.scheduled(e).unwrap(), u);
            assert_eq!(p.quota(e).unwrap(), q);
        }
    }
    #[test]
    fn small_budget_exhaustion() {
        for budget in 1..100 {
            for interval in 1..8 {
                let mut sum = 0;
                for epoch in 0..interval * 130 {
                    sum += quota(budget, interval, epoch).unwrap();
                    assert_eq!(
                        sum,
                        scheduled_issuance(budget, interval, epoch + 1).unwrap()
                    );
                }
                assert_eq!(sum, budget);
            }
        }
    }
}
