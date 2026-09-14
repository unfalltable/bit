use crate::{cbor::Cursor, cbor::Writer, Amount, Error, Result, MAX_SUPPLY_ATOMIC};

const SUPPLY_AUDIT_VERSION: u64 = 1;
const SUPPLY_AUDIT_FIELDS: usize = 19;

/// Complete, proof-bearing supply view stored under `supply/audit_snapshot`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupplyAuditSnapshot {
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
    pub monetary_policy_hash: [u8; 32],
}

impl SupplyAuditSnapshot {
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.array(SUPPLY_AUDIT_FIELDS);
        writer.uint(SUPPLY_AUDIT_VERSION);
        for value in [
            self.max_supply,
            self.genesis_supply,
            self.cumulative_minted,
            self.burned,
            self.issued_total,
            self.current_supply,
            self.scheduled_to_date,
            self.forfeited_unissued,
            self.future_issuance_budget,
            self.shielded_total,
            self.stake_total,
            self.pending_delegation_total,
            self.exit_total,
            self.commission_total,
            self.fee_reserve,
            self.unclaimed_genesis_total,
        ] {
            writer.bytes(&value.to_be_bytes());
        }
        writer.uint(self.completed_epochs);
        writer.bytes(&self.monetary_policy_hash);
        Ok(writer.finish())
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        if cursor.array()? != SUPPLY_AUDIT_FIELDS || cursor.uint()? != SUPPLY_AUDIT_VERSION {
            return Err(Error::InvalidSupplyAudit(
                "unsupported supply audit version or arity",
            ));
        }
        let snapshot = Self {
            max_supply: read_amount(&mut cursor)?,
            genesis_supply: read_amount(&mut cursor)?,
            cumulative_minted: read_amount(&mut cursor)?,
            burned: read_amount(&mut cursor)?,
            issued_total: read_amount(&mut cursor)?,
            current_supply: read_amount(&mut cursor)?,
            scheduled_to_date: read_amount(&mut cursor)?,
            forfeited_unissued: read_amount(&mut cursor)?,
            future_issuance_budget: read_amount(&mut cursor)?,
            shielded_total: read_amount(&mut cursor)?,
            stake_total: read_amount(&mut cursor)?,
            pending_delegation_total: read_amount(&mut cursor)?,
            exit_total: read_amount(&mut cursor)?,
            commission_total: read_amount(&mut cursor)?,
            fee_reserve: read_amount(&mut cursor)?,
            unclaimed_genesis_total: read_amount(&mut cursor)?,
            completed_epochs: cursor.uint()?,
            monetary_policy_hash: cursor
                .bytes()?
                .try_into()
                .map_err(|_| Error::InvalidSupplyAudit("policy hash must be 32 bytes"))?,
        };
        cursor.finish()?;
        snapshot.validate()?;
        if snapshot.encode_canonical()?.as_slice() != bytes {
            return Err(Error::InvalidSupplyAudit(
                "supply audit does not round-trip canonically",
            ));
        }
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_supply.value() != MAX_SUPPLY_ATOMIC {
            return Err(Error::InvalidSupplyAudit(
                "max supply differs from the fixed constant",
            ));
        }
        let issued = checked_add(self.genesis_supply.value(), self.cumulative_minted.value())?;
        if self.issued_total.value() != issued {
            return Err(Error::InvalidSupplyAudit(
                "issued total differs from genesis plus minted",
            ));
        }
        let current = issued
            .checked_sub(self.burned.value())
            .ok_or(Error::InvalidSupplyAudit("burned exceeds issued"))?;
        if self.current_supply.value() != current {
            return Err(Error::InvalidSupplyAudit(
                "current supply differs from issued minus burned",
            ));
        }
        if checked_add(
            self.cumulative_minted.value(),
            self.forfeited_unissued.value(),
        )? != self.scheduled_to_date.value()
        {
            return Err(Error::InvalidSupplyAudit(
                "minted plus forfeited differs from scheduled issuance",
            ));
        }
        if checked_sum([
            issued,
            self.forfeited_unissued.value(),
            self.future_issuance_budget.value(),
        ])? != self.max_supply.value()
        {
            return Err(Error::InvalidSupplyAudit(
                "issued, forfeited, and future budget do not equal max supply",
            ));
        }
        if checked_sum([
            self.shielded_total.value(),
            self.stake_total.value(),
            self.pending_delegation_total.value(),
            self.exit_total.value(),
            self.commission_total.value(),
            self.fee_reserve.value(),
            self.unclaimed_genesis_total.value(),
        ])? != current
        {
            return Err(Error::InvalidSupplyAudit(
                "asset containers do not equal current supply",
            ));
        }
        Ok(())
    }
}

fn read_amount(cursor: &mut Cursor<'_>) -> Result<Amount> {
    let bytes: [u8; 16] = cursor
        .bytes()?
        .try_into()
        .map_err(|_| Error::InvalidSupplyAudit("amount must be 16 bytes"))?;
    Amount::from_be_bytes(bytes)
}

fn checked_add(left: u128, right: u128) -> Result<u128> {
    left.checked_add(right)
        .ok_or(Error::InvalidSupplyAudit("supply arithmetic overflow"))
}

fn checked_sum(values: impl IntoIterator<Item = u128>) -> Result<u128> {
    values.into_iter().try_fold(0u128, checked_add)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amount(value: u128) -> Amount {
        Amount::new(value).unwrap()
    }

    fn snapshot() -> SupplyAuditSnapshot {
        let genesis = 10_000_000_000_000_000u128;
        let minted = 20u128;
        let issued = genesis + minted;
        let burned = 5u128;
        SupplyAuditSnapshot {
            max_supply: amount(MAX_SUPPLY_ATOMIC),
            genesis_supply: amount(genesis),
            cumulative_minted: amount(minted),
            burned: amount(burned),
            issued_total: amount(issued),
            current_supply: amount(issued - burned),
            scheduled_to_date: amount(30),
            forfeited_unissued: amount(10),
            future_issuance_budget: amount(MAX_SUPPLY_ATOMIC - issued - 10),
            shielded_total: amount(issued - burned),
            stake_total: Amount::ZERO,
            pending_delegation_total: Amount::ZERO,
            exit_total: Amount::ZERO,
            commission_total: Amount::ZERO,
            fee_reserve: Amount::ZERO,
            unclaimed_genesis_total: Amount::ZERO,
            completed_epochs: 2,
            monetary_policy_hash: [0x44; 32],
        }
    }

    #[test]
    fn supply_audit_round_trips_and_rejects_identity_changes() {
        let snapshot = snapshot();
        let encoded = snapshot.encode_canonical().unwrap();
        assert_eq!(
            SupplyAuditSnapshot::decode_canonical(&encoded).unwrap(),
            snapshot
        );

        let mut invalid = snapshot;
        invalid.current_supply = amount(invalid.current_supply.value() - 1);
        assert!(invalid.encode_canonical().is_err());
    }

    #[test]
    fn supply_audit_matches_shared_vector() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/supply-audit-vectors.json"
        ))
        .unwrap();
        let vector = &vectors["complete_snapshot"];
        let read_amount = |name: &str| {
            amount(
                vector[format!("{name}_atomic")]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
            )
        };
        let snapshot = SupplyAuditSnapshot {
            max_supply: read_amount("max_supply"),
            genesis_supply: read_amount("genesis_supply"),
            cumulative_minted: read_amount("cumulative_minted"),
            burned: read_amount("burned"),
            issued_total: read_amount("issued_total"),
            current_supply: read_amount("current_supply"),
            scheduled_to_date: read_amount("scheduled_to_date"),
            forfeited_unissued: read_amount("forfeited_unissued"),
            future_issuance_budget: read_amount("future_issuance_budget"),
            shielded_total: read_amount("shielded_total"),
            stake_total: read_amount("stake_total"),
            pending_delegation_total: read_amount("pending_delegation_total"),
            exit_total: read_amount("exit_total"),
            commission_total: read_amount("commission_total"),
            fee_reserve: read_amount("fee_reserve"),
            unclaimed_genesis_total: read_amount("unclaimed_genesis_total"),
            completed_epochs: vector["completed_epochs"].as_u64().unwrap(),
            monetary_policy_hash: hex::decode(vector["monetary_policy_hash_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let encoded = snapshot.encode_canonical().unwrap();
        assert_eq!(
            encoded,
            hex::decode(vector["canonical_cbor_hex"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            SupplyAuditSnapshot::decode_canonical(&encoded).unwrap(),
            snapshot
        );
    }
}
