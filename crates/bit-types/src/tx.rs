use crate::{
    cbor::{Cursor, Writer},
    Amount, Error, Result,
};
use blake2::{Blake2b512, Digest as BlakeDigest};
use sha2::Sha256;

pub type Hash32 = [u8; 32];
pub type PubKey32 = [u8; 32];

const EFFECT_DOMAIN: &[u8] = b"bit/effect/v1";
const CHAIN_DOMAIN: &[u8] = b"bit/chain/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeeSource {
    Shielded,
    ReleasedValue,
}

impl FeeSource {
    fn encode(self, writer: &mut Writer) {
        writer.uint(match self {
            Self::Shielded => 0,
            Self::ReleasedValue => 1,
        });
    }
    fn decode(cursor: &mut Cursor<'_>) -> Result<Self> {
        match cursor.uint()? {
            0 => Ok(Self::Shielded),
            1 => Ok(Self::ReleasedValue),
            _ => Err(Error::InvalidTransaction("unknown fee source")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Transfer,
    Delegate {
        position_id: Hash32,
        owner: PubKey32,
        validator_id: Hash32,
        deposit: Amount,
        min_shares: Amount,
        self_bond: bool,
        recovery: Vec<u8>,
    },
    CancelPending {
        position_id: Hash32,
        expected_sequence: u64,
        expected_release: Amount,
        fee_source: FeeSource,
    },
    Unbond {
        position_id: Hash32,
        expected_sequence: u64,
        shares: Amount,
        min_gross: Amount,
        max_fee: Amount,
        fee_source: FeeSource,
    },
    ClaimExit {
        ticket_id: Hash32,
        expected_sequence: u64,
        expected_release: Amount,
        fee_source: FeeSource,
    },
    RegisterValidator {
        validator_id: Hash32,
        operator: PubKey32,
        consensus: PubKey32,
        commission_bps: u16,
        display_name: String,
        website: String,
        description: String,
    },
    UpdateValidator {
        validator_id: Hash32,
        expected_sequence: u64,
        display_name: Option<String>,
        website: Option<String>,
        description: Option<String>,
        commission_bps: Option<u16>,
        request_disable: Option<bool>,
    },
    UnjailValidator {
        validator_id: Hash32,
        expected_sequence: u64,
    },
    RotateConsensusKey {
        validator_id: Hash32,
        expected_sequence: u64,
        new_consensus: PubKey32,
    },
    ClaimCommission {
        validator_id: Hash32,
        expected_sequence: u64,
        requested_amount: Amount,
        fee_source: FeeSource,
    },
    ClaimGenesis {
        claim_id: Hash32,
        expected_amount: Amount,
        fee_source: FeeSource,
    },
}

impl Action {
    pub fn tag(&self) -> u8 {
        match self {
            Self::Transfer => 0,
            Self::Delegate { .. } => 1,
            Self::CancelPending { .. } => 2,
            Self::Unbond { .. } => 3,
            Self::ClaimExit { .. } => 4,
            Self::RegisterValidator { .. } => 5,
            Self::UpdateValidator { .. } => 6,
            Self::UnjailValidator { .. } => 7,
            Self::RotateConsensusKey { .. } => 8,
            Self::ClaimCommission { .. } => 9,
            Self::ClaimGenesis { .. } => 10,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Delegate { recovery, .. } if recovery.len() != 512 => Err(
                Error::InvalidTransaction("delegate recovery receipt must be 512 bytes"),
            ),
            Self::RegisterValidator {
                commission_bps,
                display_name,
                website,
                description,
                ..
            } => {
                valid_commission(*commission_bps)?;
                valid_text(display_name, 1, 64, "display name")?;
                valid_text(website, 0, 256, "website")?;
                valid_text(description, 0, 512, "description")
            }
            Self::UpdateValidator {
                display_name,
                website,
                description,
                commission_bps,
                request_disable,
                ..
            } => {
                if display_name.is_none()
                    && website.is_none()
                    && description.is_none()
                    && commission_bps.is_none()
                    && request_disable.is_none()
                {
                    return Err(Error::InvalidTransaction("validator update is empty"));
                }
                if let Some(value) = display_name {
                    valid_text(value, 1, 64, "display name")?;
                }
                if let Some(value) = website {
                    valid_text(value, 0, 256, "website")?;
                }
                if let Some(value) = description {
                    valid_text(value, 0, 512, "description")?;
                }
                if let Some(value) = commission_bps {
                    valid_commission(*value)?;
                }
                Ok(())
            }
            Self::ClaimCommission {
                requested_amount, ..
            } if *requested_amount == Amount::ZERO => {
                Err(Error::InvalidTransaction("commission claim is zero"))
            }
            Self::Unbond { shares, .. } if *shares == Amount::ZERO => {
                Err(Error::InvalidTransaction("unbond shares are zero"))
            }
            Self::ClaimExit {
                expected_release, ..
            } if *expected_release == Amount::ZERO => {
                Err(Error::InvalidTransaction("exit claim is zero"))
            }
            _ => Ok(()),
        }
    }

    fn encode(&self, w: &mut Writer) -> Result<()> {
        self.validate()?;
        match self {
            Self::Transfer => {
                w.array(1);
                w.uint(0);
            }
            Self::Delegate {
                position_id,
                owner,
                validator_id,
                deposit,
                min_shares,
                self_bond,
                recovery,
            } => {
                w.array(8);
                w.uint(1);
                bytes32(w, position_id);
                bytes32(w, owner);
                bytes32(w, validator_id);
                amount(w, *deposit);
                amount(w, *min_shares);
                w.boolean(*self_bond);
                w.bytes(recovery);
            }
            Self::CancelPending {
                position_id,
                expected_sequence,
                expected_release,
                fee_source,
            } => {
                w.array(5);
                w.uint(2);
                bytes32(w, position_id);
                w.uint(*expected_sequence);
                amount(w, *expected_release);
                fee_source.encode(w);
            }
            Self::Unbond {
                position_id,
                expected_sequence,
                shares,
                min_gross,
                max_fee,
                fee_source,
            } => {
                w.array(7);
                w.uint(3);
                bytes32(w, position_id);
                w.uint(*expected_sequence);
                amount(w, *shares);
                amount(w, *min_gross);
                amount(w, *max_fee);
                fee_source.encode(w);
            }
            Self::ClaimExit {
                ticket_id,
                expected_sequence,
                expected_release,
                fee_source,
            } => {
                w.array(5);
                w.uint(4);
                bytes32(w, ticket_id);
                w.uint(*expected_sequence);
                amount(w, *expected_release);
                fee_source.encode(w);
            }
            Self::RegisterValidator {
                validator_id,
                operator,
                consensus,
                commission_bps,
                display_name,
                website,
                description,
            } => {
                w.array(8);
                w.uint(5);
                bytes32(w, validator_id);
                bytes32(w, operator);
                bytes32(w, consensus);
                w.uint((*commission_bps).into());
                w.text(display_name);
                w.text(website);
                w.text(description);
            }
            Self::UpdateValidator {
                validator_id,
                expected_sequence,
                display_name,
                website,
                description,
                commission_bps,
                request_disable,
            } => {
                w.array(8);
                w.uint(6);
                bytes32(w, validator_id);
                w.uint(*expected_sequence);
                optional(w, display_name.as_ref(), |w, v| w.text(v));
                optional(w, website.as_ref(), |w, v| w.text(v));
                optional(w, description.as_ref(), |w, v| w.text(v));
                optional(w, commission_bps.as_ref(), |w, v| w.uint((*v).into()));
                optional(w, request_disable.as_ref(), |w, v| w.boolean(*v));
            }
            Self::UnjailValidator {
                validator_id,
                expected_sequence,
            } => {
                w.array(3);
                w.uint(7);
                bytes32(w, validator_id);
                w.uint(*expected_sequence);
            }
            Self::RotateConsensusKey {
                validator_id,
                expected_sequence,
                new_consensus,
            } => {
                w.array(4);
                w.uint(8);
                bytes32(w, validator_id);
                w.uint(*expected_sequence);
                bytes32(w, new_consensus);
            }
            Self::ClaimCommission {
                validator_id,
                expected_sequence,
                requested_amount,
                fee_source,
            } => {
                w.array(5);
                w.uint(9);
                bytes32(w, validator_id);
                w.uint(*expected_sequence);
                amount(w, *requested_amount);
                fee_source.encode(w);
            }
            Self::ClaimGenesis {
                claim_id,
                expected_amount,
                fee_source,
            } => {
                w.array(4);
                w.uint(10);
                bytes32(w, claim_id);
                amount(w, *expected_amount);
                fee_source.encode(w);
            }
        }
        Ok(())
    }

    fn decode(c: &mut Cursor<'_>) -> Result<Self> {
        let len = c.array()?;
        let tag = c.uint()?;
        let action = match tag {
            0 if len == 1 => Self::Transfer,
            1 if len == 8 => Self::Delegate {
                position_id: read32(c)?,
                owner: read32(c)?,
                validator_id: read32(c)?,
                deposit: read_amount(c)?,
                min_shares: read_amount(c)?,
                self_bond: c.boolean()?,
                recovery: c.bytes()?,
            },
            2 if len == 5 => Self::CancelPending {
                position_id: read32(c)?,
                expected_sequence: c.uint()?,
                expected_release: read_amount(c)?,
                fee_source: FeeSource::decode(c)?,
            },
            3 if len == 7 => Self::Unbond {
                position_id: read32(c)?,
                expected_sequence: c.uint()?,
                shares: read_amount(c)?,
                min_gross: read_amount(c)?,
                max_fee: read_amount(c)?,
                fee_source: FeeSource::decode(c)?,
            },
            4 if len == 5 => Self::ClaimExit {
                ticket_id: read32(c)?,
                expected_sequence: c.uint()?,
                expected_release: read_amount(c)?,
                fee_source: FeeSource::decode(c)?,
            },
            5 if len == 8 => Self::RegisterValidator {
                validator_id: read32(c)?,
                operator: read32(c)?,
                consensus: read32(c)?,
                commission_bps: read_bps(c)?,
                display_name: c.text()?,
                website: c.text()?,
                description: c.text()?,
            },
            6 if len == 8 => Self::UpdateValidator {
                validator_id: read32(c)?,
                expected_sequence: c.uint()?,
                display_name: c.nullable(|c| c.text())?,
                website: c.nullable(|c| c.text())?,
                description: c.nullable(|c| c.text())?,
                commission_bps: c.nullable(read_bps)?,
                request_disable: c.nullable(|c| c.boolean())?,
            },
            7 if len == 3 => Self::UnjailValidator {
                validator_id: read32(c)?,
                expected_sequence: c.uint()?,
            },
            8 if len == 4 => Self::RotateConsensusKey {
                validator_id: read32(c)?,
                expected_sequence: c.uint()?,
                new_consensus: read32(c)?,
            },
            9 if len == 5 => Self::ClaimCommission {
                validator_id: read32(c)?,
                expected_sequence: c.uint()?,
                requested_amount: read_amount(c)?,
                fee_source: FeeSource::decode(c)?,
            },
            10 if len == 4 => Self::ClaimGenesis {
                claim_id: read32(c)?,
                expected_amount: read_amount(c)?,
                fee_source: FeeSource::decode(c)?,
            },
            _ => return Err(Error::InvalidTransaction("unknown action tag or arity")),
        };
        action.validate()?;
        Ok(action)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxBody {
    pub version: u8,
    pub chain_context: Hash32,
    pub expiry_height: u64,
    pub anchor: Hash32,
    pub fee: Amount,
    pub spends: Vec<Vec<u8>>,
    pub outputs: Vec<Vec<u8>>,
    pub action: Action,
    pub proof_hashes: Vec<Hash32>,
    pub memo_ciphertext: Option<Vec<u8>>,
}

impl TxBody {
    pub fn validate_structure(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::InvalidTransaction("body version must be 1"));
        }
        if self.spends.len() > 8 || self.outputs.len() > 8 {
            return Err(Error::InvalidTransaction("Spend/Output count exceeds 8"));
        }
        if self
            .spends
            .iter()
            .chain(&self.outputs)
            .any(|body| body.is_empty() || body.len() > 8192)
        {
            return Err(Error::InvalidTransaction(
                "upstream body length outside 1..8192",
            ));
        }
        if self.proof_hashes.len() != self.spends.len() + self.outputs.len() {
            return Err(Error::InvalidTransaction("proof hash cardinality mismatch"));
        }
        match (&self.memo_ciphertext, self.outputs.is_empty()) {
            (None, true) => {}
            (Some(memo), false) if memo.len() == 528 => {}
            (Some(_), _) => {
                return Err(Error::InvalidTransaction(
                    "memo ciphertext must be 528 bytes and requires an Output",
                ))
            }
            (None, false) => {
                return Err(Error::InvalidTransaction(
                    "an Output requires a transaction memo",
                ))
            }
        }
        self.action.validate()
    }

    pub fn validate_at_height(&self, current_height: u64, max_lifetime: u64) -> Result<()> {
        self.validate_structure()?;
        let last = current_height
            .checked_add(max_lifetime)
            .ok_or(Error::Overflow)?;
        if self.expiry_height < current_height || self.expiry_height > last {
            return Err(Error::InvalidTransaction(
                "expiry height outside allowed window",
            ));
        }
        Ok(())
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        let mut w = Writer::new();
        w.array(10);
        w.uint(self.version.into());
        bytes32(&mut w, &self.chain_context);
        w.uint(self.expiry_height);
        bytes32(&mut w, &self.anchor);
        amount(&mut w, self.fee);
        w.array(self.spends.len());
        for body in &self.spends {
            w.bytes(body);
        }
        w.array(self.outputs.len());
        for body in &self.outputs {
            w.bytes(body);
        }
        self.action.encode(&mut w)?;
        w.array(self.proof_hashes.len());
        for hash in &self.proof_hashes {
            bytes32(&mut w, hash);
        }
        match &self.memo_ciphertext {
            Some(memo) => w.bytes(memo),
            None => w.null(),
        }
        Ok(w.finish())
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(bytes);
        if c.array()? != 10 {
            return Err(Error::InvalidTransaction("body must have ten fields"));
        }
        let version = u8::try_from(c.uint()?)
            .map_err(|_| Error::InvalidTransaction("body version overflow"))?;
        let chain_context = read32(&mut c)?;
        let expiry_height = c.uint()?;
        let anchor = read32(&mut c)?;
        let fee = read_amount(&mut c)?;
        let spend_count = c.array()?;
        if spend_count > 8 {
            return Err(Error::InvalidTransaction("too many Spends"));
        }
        let mut spends = Vec::with_capacity(spend_count);
        for _ in 0..spend_count {
            spends.push(c.bytes()?);
        }
        let output_count = c.array()?;
        if output_count > 8 {
            return Err(Error::InvalidTransaction("too many Outputs"));
        }
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(c.bytes()?);
        }
        let action = Action::decode(&mut c)?;
        let proof_count = c.array()?;
        if proof_count > 16 {
            return Err(Error::InvalidTransaction("too many proof hashes"));
        }
        let mut proof_hashes = Vec::with_capacity(proof_count);
        for _ in 0..proof_count {
            proof_hashes.push(read32(&mut c)?);
        }
        let memo_ciphertext = c.nullable(|c| c.bytes())?;
        c.finish()?;
        let body = Self {
            version,
            chain_context,
            expiry_height,
            anchor,
            fee,
            spends,
            outputs,
            action,
            proof_hashes,
            memo_ciphertext,
        };
        body.validate_structure()?;
        if body.encode_canonical()?.as_slice() != bytes {
            return Err(Error::InvalidCbor("body does not round-trip canonically"));
        }
        Ok(body)
    }

    pub fn effect_hash(&self) -> Result<[u8; 64]> {
        Ok(effect_hash(&self.encode_canonical()?))
    }
}

pub fn chain_context(genesis_manifest_hash: Hash32) -> Hash32 {
    hash32(&[CHAIN_DOMAIN, &genesis_manifest_hash])
}
pub fn proof_hash(proof: &[u8]) -> Hash32 {
    hash32(&[proof])
}
pub fn effect_hash(body: &[u8]) -> [u8; 64] {
    let mut h = Blake2b512::new();
    h.update(EFFECT_DOMAIN);
    h.update((body.len() as u64).to_be_bytes());
    h.update(body);
    h.finalize().into()
}
pub fn position_id(chain: &Hash32, owner: &PubKey32) -> Hash32 {
    hash32(&[b"bit/position/v1", chain, owner])
}
pub fn validator_id(chain: &Hash32, operator: &PubKey32) -> Hash32 {
    hash32(&[b"bit/validator/v1", chain, operator])
}
pub fn cohort_id(chain: &Hash32, validator: &Hash32, exit_epoch: u64) -> Hash32 {
    hash32(&[
        b"bit/cohort/v1",
        chain,
        validator,
        &exit_epoch.to_be_bytes(),
    ])
}
pub fn ticket_id(chain: &Hash32, position: &Hash32, sequence: u64) -> Hash32 {
    hash32(&[b"bit/ticket/v1", chain, position, &sequence.to_be_bytes()])
}

fn hash32(parts: &[&[u8]]) -> Hash32 {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn bytes32(w: &mut Writer, bytes: &Hash32) {
    w.bytes(bytes);
}
fn amount(w: &mut Writer, value: Amount) {
    w.bytes(&value.to_be_bytes());
}
fn read32(c: &mut Cursor<'_>) -> Result<Hash32> {
    c.bytes()?
        .try_into()
        .map_err(|_| Error::InvalidTransaction("expected 32-byte value"))
}
fn read_amount(c: &mut Cursor<'_>) -> Result<Amount> {
    Amount::from_be_bytes(c.bytes()?.try_into().map_err(|_| Error::InvalidAmount)?)
}
fn read_bps(c: &mut Cursor<'_>) -> Result<u16> {
    let value =
        u16::try_from(c.uint()?).map_err(|_| Error::InvalidTransaction("commission overflow"))?;
    valid_commission(value)?;
    Ok(value)
}
fn valid_commission(value: u16) -> Result<()> {
    if value <= 2000 {
        Ok(())
    } else {
        Err(Error::InvalidTransaction("commission exceeds 2000 bps"))
    }
}
fn valid_text(value: &str, min: usize, max: usize, name: &'static str) -> Result<()> {
    if (min..=max).contains(&value.len()) {
        Ok(())
    } else {
        Err(Error::InvalidTransaction(name))
    }
}
fn optional<T>(w: &mut Writer, value: Option<&T>, encode: impl FnOnce(&mut Writer, &T)) {
    match value {
        Some(value) => encode(w, value),
        None => w.null(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> TxBody {
        let proofs = [vec![7; 192], vec![8; 192]];
        TxBody {
            version: 1,
            chain_context: [0; 32],
            expiry_height: 10,
            anchor: [0x11; 32],
            fee: Amount::new(100).unwrap(),
            spends: vec![vec![1, 2, 3]],
            outputs: vec![vec![4, 5]],
            action: Action::Transfer,
            proof_hashes: proofs.iter().map(|p| proof_hash(p)).collect(),
            memo_ciphertext: Some(vec![9; 528]),
        }
    }

    #[test]
    fn canonical_body_roundtrip_and_rejects_non_shortest() {
        let body = body();
        let encoded = body.encode_canonical().unwrap();
        assert_eq!(TxBody::decode_canonical(&encoded).unwrap(), body);
        let mut changed = encoded;
        assert_eq!(changed[0], 0x8a);
        changed.splice(1..2, [0x18, 0x01]);
        assert!(TxBody::decode_canonical(&changed).is_err());
    }

    #[test]
    fn all_action_shapes_roundtrip() {
        let id = [3; 32];
        let key = [4; 32];
        let amount = Amount::new(55).unwrap();
        let actions = vec![
            Action::Transfer,
            Action::Delegate {
                position_id: id,
                owner: key,
                validator_id: id,
                deposit: amount,
                min_shares: amount,
                self_bond: true,
                recovery: vec![1; 512],
            },
            Action::CancelPending {
                position_id: id,
                expected_sequence: 1,
                expected_release: amount,
                fee_source: FeeSource::ReleasedValue,
            },
            Action::Unbond {
                position_id: id,
                expected_sequence: 2,
                shares: amount,
                min_gross: amount,
                max_fee: amount,
                fee_source: FeeSource::Shielded,
            },
            Action::ClaimExit {
                ticket_id: id,
                expected_sequence: 3,
                expected_release: amount,
                fee_source: FeeSource::ReleasedValue,
            },
            Action::RegisterValidator {
                validator_id: id,
                operator: key,
                consensus: key,
                commission_bps: 2000,
                display_name: "v".into(),
                website: "".into(),
                description: "ok".into(),
            },
            Action::UpdateValidator {
                validator_id: id,
                expected_sequence: 4,
                display_name: None,
                website: Some("https://example.invalid".into()),
                description: None,
                commission_bps: Some(10),
                request_disable: Some(false),
            },
            Action::UnjailValidator {
                validator_id: id,
                expected_sequence: 5,
            },
            Action::RotateConsensusKey {
                validator_id: id,
                expected_sequence: 6,
                new_consensus: key,
            },
            Action::ClaimCommission {
                validator_id: id,
                expected_sequence: 7,
                requested_amount: amount,
                fee_source: FeeSource::Shielded,
            },
            Action::ClaimGenesis {
                claim_id: id,
                expected_amount: amount,
                fee_source: FeeSource::ReleasedValue,
            },
        ];
        for action in actions {
            let mut tx = body();
            tx.action = action;
            let encoded = tx.encode_canonical().unwrap();
            assert_eq!(TxBody::decode_canonical(&encoded).unwrap(), tx);
        }
    }

    #[test]
    fn structure_and_expiry_fail_closed() {
        let mut tx = body();
        tx.proof_hashes.pop();
        assert!(tx.encode_canonical().is_err());
        let mut tx = body();
        tx.memo_ciphertext = None;
        assert!(tx.encode_canonical().is_err());
        assert!(body().validate_at_height(11, 120).is_err());
        assert!(body().validate_at_height(1, 8).is_err());

        let mut tx = body();
        tx.action = Action::UpdateValidator {
            validator_id: [3; 32],
            expected_sequence: 0,
            display_name: None,
            website: None,
            description: None,
            commission_bps: None,
            request_disable: None,
        };
        assert_eq!(
            tx.validate_at_height(1, 120),
            Err(Error::InvalidTransaction("validator update is empty"))
        );

        let mut tx = body();
        tx.action = Action::ClaimCommission {
            validator_id: [3; 32],
            expected_sequence: 0,
            requested_amount: Amount::ZERO,
            fee_source: FeeSource::ReleasedValue,
        };
        assert_eq!(
            tx.validate_at_height(1, 120),
            Err(Error::InvalidTransaction("commission claim is zero"))
        );
    }

    #[test]
    fn identifiers_are_domain_separated() {
        let chain = chain_context([7; 32]);
        let key = [8; 32];
        let position = position_id(&chain, &key);
        let validator = validator_id(&chain, &key);
        assert_ne!(position, validator);
        assert_ne!(
            cohort_id(&chain, &validator, 1),
            ticket_id(&chain, &position, 1)
        );
        assert_ne!(effect_hash(b"abc"), effect_hash(b"abcd"));
    }

    #[test]
    fn structural_body_matches_cross_language_vector() {
        let tx = TxBody {
            version: 1,
            chain_context: [0; 32],
            expiry_height: 10,
            anchor: [0x11; 32],
            fee: Amount::ZERO,
            spends: vec![],
            outputs: vec![],
            action: Action::Transfer,
            proof_hashes: vec![],
            memo_ciphertext: None,
        };
        let bytes = tx.encode_canonical().unwrap();
        assert_eq!(hex::encode(&bytes),"8a01582000000000000000000000000000000000000000000000000000000000000000000a5820111111111111111111111111111111111111111111111111111111111111111150000000000000000000000000000000008080810080f6");
        assert_eq!(hex::encode(tx.effect_hash().unwrap()),"c241b57f883e3fc006cbc7cc17cff03c4f5262fad2b30182463fdcdbdeab12e8b5b90617d23a2325fe08a7b7c4d6e075e1fc7517b951e8191de36da07d79de69");
    }
}
