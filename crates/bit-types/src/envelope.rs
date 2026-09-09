use crate::{proof_hash, Action, Error, Result, TxBody};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    Spend = 1,
    PositionOwner = 2,
    Operator = 3,
    ConsensusPop = 4,
    GenesisClaim = 5,
}

impl Role {
    /// Domain separator for the Ed25519 authorization roles carried after all
    /// Spend authorizations. Spend uses the upstream randomized RDSA scheme.
    pub fn ed25519_domain(self) -> Option<&'static [u8]> {
        match self {
            Self::Spend => None,
            Self::PositionOwner => Some(b"bit/owner/v1"),
            Self::Operator => Some(b"bit/operator/v1"),
            Self::ConsensusPop => Some(b"bit/consensus-pop/v1"),
            Self::GenesisClaim => Some(b"bit/genesis-claim/v1"),
        }
    }
}

/// Build the exact message signed by a non-Spend Ed25519 authorization.
/// Every role binds the complete 64-byte transaction effect hash.
pub fn ed25519_authorization_message(role: Role, effect_hash: &[u8; 64]) -> Option<Vec<u8>> {
    let domain = role.ed25519_domain()?;
    let mut message = Vec::with_capacity(domain.len() + effect_hash.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(effect_hash);
    Some(message)
}

impl TryFrom<u64> for Role {
    type Error = Error;
    fn try_from(value: u64) -> Result<Self> {
        match value {
            1 => Ok(Self::Spend),
            2 => Ok(Self::PositionOwner),
            3 => Ok(Self::Operator),
            4 => Ok(Self::ConsensusPop),
            5 => Ok(Self::GenesisClaim),
            _ => Err(Error::InvalidEnvelope("unknown authorization role")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authorization {
    pub role: Role,
    pub index: u32,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub envelope_version: u32,
    pub canonical_body: Vec<u8>,
    pub proofs: Vec<Vec<u8>>,
    pub authorizations: Vec<Authorization>,
    pub binding_signature: Vec<u8>,
}

impl Envelope {
    pub fn validate(&self, current_height: u64, max_lifetime: u64) -> Result<TxBody> {
        if self.envelope_version != 1 {
            return Err(Error::InvalidEnvelope("envelope version must be 1"));
        }
        let body = TxBody::decode_canonical(&self.canonical_body)?;
        body.validate_at_height(current_height, max_lifetime)?;
        if self.proofs.len() != body.proof_hashes.len() {
            return Err(Error::InvalidEnvelope("proof cardinality mismatch"));
        }
        if self.proofs.iter().any(|proof| proof.len() != 192) {
            return Err(Error::InvalidEnvelope("proof must be 192 bytes"));
        }
        for (proof, expected) in self.proofs.iter().zip(&body.proof_hashes) {
            if proof_hash(proof) != *expected {
                return Err(Error::InvalidEnvelope("proof hash mismatch"));
            }
        }
        if self.binding_signature.len() != 64 {
            return Err(Error::InvalidEnvelope("binding signature must be 64 bytes"));
        }
        let expected = expected_roles(&body);
        if self.authorizations.len() != expected.len() {
            return Err(Error::InvalidEnvelope("authorization cardinality mismatch"));
        }
        for (actual, expected) in self.authorizations.iter().zip(expected) {
            if actual.role != expected.0 || actual.index != expected.1 {
                return Err(Error::InvalidEnvelope(
                    "authorization role or order mismatch",
                ));
            }
            if actual.signature.len() != 64 {
                return Err(Error::InvalidEnvelope(
                    "authorization signature must be 64 bytes",
                ));
            }
        }
        Ok(body)
    }

    pub fn encode_canonical(&self, current_height: u64, max_lifetime: u64) -> Result<Vec<u8>> {
        self.validate(current_height, max_lifetime)?;
        let mut out = Vec::new();
        field_varint(&mut out, 1, self.envelope_version.into());
        field_bytes(&mut out, 2, &self.canonical_body);
        for proof in &self.proofs {
            field_bytes(&mut out, 3, proof);
        }
        for authorization in &self.authorizations {
            field_bytes(&mut out, 4, &encode_authorization(authorization));
        }
        field_bytes(&mut out, 5, &self.binding_signature);
        Ok(out)
    }

    pub fn decode_canonical(
        bytes: &[u8],
        max_bytes: usize,
        current_height: u64,
        max_lifetime: u64,
    ) -> Result<Self> {
        if bytes.len() > max_bytes {
            return Err(Error::InvalidEnvelope("envelope exceeds size limit"));
        }
        let mut c = ProtoCursor::new(bytes);
        let mut previous = 0;
        let mut version = None;
        let mut body = None;
        let mut proofs = vec![];
        let mut authorizations = vec![];
        let mut binding = None;
        while !c.finished() {
            let key = c.varint()?;
            let field = u32::try_from(key >> 3)
                .map_err(|_| Error::InvalidEnvelope("field number overflow"))?;
            let wire = (key & 7) as u8;
            if field == 0 || field < previous {
                return Err(Error::InvalidEnvelope("fields out of canonical order"));
            }
            previous = field;
            match (field, wire) {
                (1, 0) if version.is_none() => {
                    version = Some(
                        u32::try_from(c.varint()?)
                            .map_err(|_| Error::InvalidEnvelope("version overflow"))?,
                    )
                }
                (2, 2) if body.is_none() => body = Some(c.bytes()?.to_vec()),
                (3, 2) => proofs.push(c.bytes()?.to_vec()),
                (4, 2) => authorizations.push(decode_authorization(c.bytes()?)?),
                (5, 2) if binding.is_none() => binding = Some(c.bytes()?.to_vec()),
                (1 | 2 | 5, _) => {
                    return Err(Error::InvalidEnvelope("duplicate field or wrong wire type"))
                }
                _ => return Err(Error::InvalidEnvelope("unknown field or wrong wire type")),
            }
        }
        let envelope = Self {
            envelope_version: version.ok_or(Error::InvalidEnvelope("missing envelope version"))?,
            canonical_body: body.ok_or(Error::InvalidEnvelope("missing canonical body"))?,
            proofs,
            authorizations,
            binding_signature: binding
                .ok_or(Error::InvalidEnvelope("missing binding signature"))?,
        };
        envelope.validate(current_height, max_lifetime)?;
        if envelope
            .encode_canonical(current_height, max_lifetime)?
            .as_slice()
            != bytes
        {
            return Err(Error::InvalidEnvelope(
                "envelope does not round-trip canonically",
            ));
        }
        Ok(envelope)
    }

    pub fn tx_id(&self, current_height: u64, max_lifetime: u64) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.encode_canonical(current_height, max_lifetime)?).into())
    }
}

fn expected_roles(body: &TxBody) -> Vec<(Role, u32)> {
    let mut roles: Vec<_> = (0..body.spends.len())
        .map(|index| (Role::Spend, index as u32))
        .collect();
    match &body.action {
        Action::Transfer => {}
        Action::Delegate { self_bond, .. } => {
            roles.push((Role::PositionOwner, 0));
            if *self_bond {
                roles.push((Role::Operator, 0));
            }
        }
        Action::CancelPending { .. } | Action::Unbond { .. } | Action::ClaimExit { .. } => {
            roles.push((Role::PositionOwner, 0))
        }
        Action::RegisterValidator { .. } => {
            roles.push((Role::Operator, 0));
            roles.push((Role::ConsensusPop, 0));
        }
        Action::UpdateValidator { .. }
        | Action::UnjailValidator { .. }
        | Action::ClaimCommission { .. } => roles.push((Role::Operator, 0)),
        Action::RotateConsensusKey { .. } => {
            roles.push((Role::Operator, 0));
            roles.push((Role::ConsensusPop, 0));
        }
        Action::ClaimGenesis { .. } => roles.push((Role::GenesisClaim, 0)),
    }
    roles
}

fn encode_authorization(auth: &Authorization) -> Vec<u8> {
    let mut out = Vec::new();
    field_varint(&mut out, 1, auth.role as u64);
    if auth.index != 0 {
        field_varint(&mut out, 2, auth.index.into());
    }
    field_bytes(&mut out, 3, &auth.signature);
    out
}

fn decode_authorization(bytes: &[u8]) -> Result<Authorization> {
    let mut c = ProtoCursor::new(bytes);
    let mut previous = 0;
    let mut role = None;
    let mut index = None;
    let mut signature = None;
    while !c.finished() {
        let key = c.varint()?;
        let field = u32::try_from(key >> 3)
            .map_err(|_| Error::InvalidEnvelope("authorization field overflow"))?;
        let wire = (key & 7) as u8;
        if field == 0 || field < previous {
            return Err(Error::InvalidEnvelope("authorization fields out of order"));
        }
        previous = field;
        match (field, wire) {
            (1, 0) if role.is_none() => role = Some(Role::try_from(c.varint()?)?),
            (2, 0) if index.is_none() => {
                let value = u32::try_from(c.varint()?)
                    .map_err(|_| Error::InvalidEnvelope("authorization index overflow"))?;
                if value == 0 {
                    return Err(Error::InvalidEnvelope("default index must be omitted"));
                }
                index = Some(value);
            }
            (3, 2) if signature.is_none() => signature = Some(c.bytes()?.to_vec()),
            (1..=3, _) => {
                return Err(Error::InvalidEnvelope(
                    "duplicate authorization field or wrong wire type",
                ))
            }
            _ => return Err(Error::InvalidEnvelope("unknown authorization field")),
        }
    }
    let auth = Authorization {
        role: role.ok_or(Error::InvalidEnvelope("missing authorization role"))?,
        index: index.unwrap_or(0),
        signature: signature.ok_or(Error::InvalidEnvelope("missing authorization signature"))?,
    };
    if encode_authorization(&auth).as_slice() != bytes {
        return Err(Error::InvalidEnvelope("authorization is not canonical"));
    }
    Ok(auth)
}

fn field_varint(out: &mut Vec<u8>, field: u32, value: u64) {
    put_varint(out, (field as u64) << 3);
    put_varint(out, value);
}
fn field_bytes(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    put_varint(out, ((field as u64) << 3) | 2);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}
fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}
fn varint_size(mut value: u64) -> usize {
    let mut n = 1;
    while value >= 0x80 {
        n += 1;
        value >>= 7;
    }
    n
}

struct ProtoCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> ProtoCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        let start = self.offset;
        for index in 0..10 {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or(Error::InvalidEnvelope("truncated varint"))?;
            self.offset += 1;
            if index == 9 && byte > 1 {
                return Err(Error::InvalidEnvelope("varint overflow"));
            }
            value |= ((byte & 0x7f) as u64) << (index * 7);
            if byte & 0x80 == 0 {
                if self.offset - start != varint_size(value) {
                    return Err(Error::InvalidEnvelope("non-minimal varint"));
                }
                return Ok(value);
            }
        }
        Err(Error::InvalidEnvelope("varint overflow"))
    }
    fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.varint()?)
            .map_err(|_| Error::InvalidEnvelope("length overflow"))?;
        let end = self
            .offset
            .checked_add(len)
            .ok_or(Error::InvalidEnvelope("length overflow"))?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::InvalidEnvelope("truncated bytes"))?;
        self.offset = end;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, Amount};
    fn fixture() -> Envelope {
        let proofs = vec![vec![7; 192], vec![8; 192]];
        let body = TxBody {
            version: 1,
            chain_context: [0; 32],
            expiry_height: 10,
            anchor: [1; 32],
            fee: Amount::new(100).unwrap(),
            spends: vec![vec![1]],
            outputs: vec![vec![2]],
            action: Action::Transfer,
            proof_hashes: proofs.iter().map(|p| proof_hash(p)).collect(),
            memo_ciphertext: Some(vec![3; 528]),
        };
        Envelope {
            envelope_version: 1,
            canonical_body: body.encode_canonical().unwrap(),
            proofs,
            authorizations: vec![Authorization {
                role: Role::Spend,
                index: 0,
                signature: vec![4; 64],
            }],
            binding_signature: vec![5; 64],
        }
    }
    #[test]
    fn envelope_roundtrip_and_tx_id() {
        let envelope = fixture();
        let bytes = envelope.encode_canonical(1, 20).unwrap();
        assert_eq!(
            Envelope::decode_canonical(&bytes, 65536, 1, 20).unwrap(),
            envelope
        );
        assert_eq!(
            envelope.tx_id(1, 20).unwrap(),
            Sha256::digest(bytes).as_slice()
        );
    }
    #[test]
    fn rejects_proof_role_and_wire_changes() {
        let mut envelope = fixture();
        envelope.proofs[0][0] ^= 1;
        assert!(envelope.validate(1, 20).is_err());
        let mut envelope = fixture();
        envelope.authorizations[0].role = Role::Operator;
        assert!(envelope.validate(1, 20).is_err());
        let canonical = fixture().encode_canonical(1, 20).unwrap();
        let mut nonminimal = canonical;
        assert_eq!(nonminimal[0], 8);
        nonminimal.splice(0..1, [0x88, 0]);
        assert!(Envelope::decode_canonical(&nonminimal, 65536, 1, 20).is_err());
    }
    #[test]
    fn role_plan_includes_action_authorities() {
        let mut envelope = fixture();
        let mut body = TxBody::decode_canonical(&envelope.canonical_body).unwrap();
        body.action = Action::ClaimGenesis {
            claim_id: [9; 32],
            expected_amount: Amount::new(1).unwrap(),
            fee_source: crate::FeeSource::Shielded,
        };
        envelope.canonical_body = body.encode_canonical().unwrap();
        assert!(envelope.validate(1, 20).is_err());
        envelope.authorizations.push(Authorization {
            role: Role::GenesisClaim,
            index: 0,
            signature: vec![6; 64],
        });
        assert!(envelope.validate(1, 20).is_ok());
    }
    #[test]
    fn ed25519_role_messages_bind_domain_and_full_effect_hash() {
        let effect = [0x5a; 64];
        assert_eq!(
            ed25519_authorization_message(Role::PositionOwner, &effect).unwrap(),
            [b"bit/owner/v1".as_slice(), effect.as_slice()].concat()
        );
        assert_eq!(
            ed25519_authorization_message(Role::Operator, &effect).unwrap(),
            [b"bit/operator/v1".as_slice(), effect.as_slice()].concat()
        );
        assert_eq!(
            ed25519_authorization_message(Role::ConsensusPop, &effect).unwrap(),
            [b"bit/consensus-pop/v1".as_slice(), effect.as_slice()].concat()
        );
        assert_eq!(
            ed25519_authorization_message(Role::GenesisClaim, &effect).unwrap(),
            [b"bit/genesis-claim/v1".as_slice(), effect.as_slice()].concat()
        );
        assert!(ed25519_authorization_message(Role::Spend, &effect).is_none());
    }
    #[test]
    fn structural_envelope_matches_cross_language_vector() {
        let body = TxBody {
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
        let envelope = Envelope {
            envelope_version: 1,
            canonical_body: body.encode_canonical().unwrap(),
            proofs: vec![],
            authorizations: vec![],
            binding_signature: vec![5; 64],
        };
        let bytes = envelope.encode_canonical(1, 20).unwrap();
        assert_eq!(hex::encode(&bytes),"0801125e8a01582000000000000000000000000000000000000000000000000000000000000000000a5820111111111111111111111111111111111111111111111111111111111111111150000000000000000000000000000000008080810080f62a4005050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505");
        assert_eq!(
            hex::encode(envelope.tx_id(1, 20).unwrap()),
            "30e2596a12700e462abb88d3ec7148b4e9f6b8a1af6fc276761bf5f9a5ccc631"
        );
    }
}
