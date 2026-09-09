//! Narrow BIT adapter over the frozen Penumbra Spend/Output primitives.
//!
//! All external proof and upstream body bytes enter through checked,
//! canonical parsers before upstream verification. This crate intentionally
//! exposes no Penumbra application actions, DEX, IBC, mint, or asset routes.

use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use decaf377::{Bls12_377, Fr};
use decaf377_rdsa::{Binding, Signature, VerificationKey, VerificationKeyBytes};
use penumbra_sdk_asset::{asset, Balance, Value};
use penumbra_sdk_num::Amount;
use penumbra_sdk_proof_params::{OUTPUT_PROOF_VERIFICATION_KEY, SPEND_PROOF_VERIFICATION_KEY};
use penumbra_sdk_proto::{
    penumbra::{core::component::shielded_pool::v1 as pb, crypto::tct::v1 as tct_pb},
    DomainType,
};
use penumbra_sdk_shielded_pool::{
    output::{Body as OutputBody, OutputProofPublic},
    spend::{Body as SpendBody, SpendProofPublic},
    OutputProof, SpendProof,
};
use penumbra_sdk_tct::Root;
use std::fmt;

pub const PROOF_LENGTH: usize = 192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShieldedError {
    InvalidProofEncoding,
    NonCanonicalProof,
    InvalidSpendBody,
    NonCanonicalSpendBody,
    InvalidOutputBody,
    NonCanonicalOutputBody,
    SpendProofRejected,
    OutputProofRejected,
    InvalidAnchor,
    InvalidNativeAssetId,
    InvalidSpendAuthorization,
    InvalidBindingSignature,
    CardinalityMismatch,
}

impl fmt::Display for ShieldedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidProofEncoding => "invalid checked Groth16 proof encoding",
            Self::NonCanonicalProof => "non-canonical Groth16 proof encoding",
            Self::InvalidSpendBody => "invalid upstream Spend body",
            Self::NonCanonicalSpendBody => "non-canonical upstream Spend body",
            Self::InvalidOutputBody => "invalid upstream Output body",
            Self::NonCanonicalOutputBody => "non-canonical upstream Output body",
            Self::SpendProofRejected => "Spend proof rejected",
            Self::OutputProofRejected => "Output proof rejected",
            Self::InvalidAnchor => "invalid commitment-tree anchor encoding",
            Self::InvalidNativeAssetId => "invalid native asset ID encoding",
            Self::InvalidSpendAuthorization => "Spend authorization rejected",
            Self::InvalidBindingSignature => "binding signature rejected",
            Self::CardinalityMismatch => "shielded item cardinality mismatch",
        })
    }
}

impl std::error::Error for ShieldedError {}
pub type Result<T> = core::result::Result<T, ShieldedError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedShieldedTransfer {
    pub nullifiers: Vec<[u8; 32]>,
    pub output_commitments: Vec<[u8; 32]>,
}

/// Public native-asset flow included in the transaction binding equation.
/// `locked` moves value out of the shielded pool, while `released` moves value
/// back into it. Fees are always consumed from the transaction balance.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShieldedPublicBalance {
    pub locked: u128,
    pub released: u128,
    pub fee: u128,
}

pub fn validate_proof_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.len() != PROOF_LENGTH {
        return Err(ShieldedError::InvalidProofEncoding);
    }
    let proof = Proof::<Bls12_377>::deserialize_compressed(bytes)
        .map_err(|_| ShieldedError::InvalidProofEncoding)?;
    let mut canonical = Vec::with_capacity(PROOF_LENGTH);
    proof
        .serialize_compressed(&mut canonical)
        .map_err(|_| ShieldedError::InvalidProofEncoding)?;
    if canonical != bytes {
        return Err(ShieldedError::NonCanonicalProof);
    }
    Ok(())
}

pub fn decode_spend_body(bytes: &[u8]) -> Result<SpendBody> {
    let body = SpendBody::decode(bytes).map_err(|_| ShieldedError::InvalidSpendBody)?;
    if body.encode_to_vec() != bytes {
        return Err(ShieldedError::NonCanonicalSpendBody);
    }
    Ok(body)
}

pub fn decode_output_body(bytes: &[u8]) -> Result<OutputBody> {
    let body = OutputBody::decode(bytes).map_err(|_| ShieldedError::InvalidOutputBody)?;
    if body.encode_to_vec() != bytes {
        return Err(ShieldedError::NonCanonicalOutputBody);
    }
    Ok(body)
}

pub fn verify_spend_public(bytes: &[u8], public: SpendProofPublic) -> Result<()> {
    validate_proof_bytes(bytes)?;
    let proof: SpendProof = pb::ZkSpendProof {
        inner: bytes.to_vec(),
    }
    .try_into()
    .map_err(|_| ShieldedError::InvalidProofEncoding)?;
    proof
        .verify(&SPEND_PROOF_VERIFICATION_KEY, public)
        .map_err(|_| ShieldedError::SpendProofRejected)
}

pub fn verify_output_public(bytes: &[u8], public: OutputProofPublic) -> Result<()> {
    validate_proof_bytes(bytes)?;
    let proof: OutputProof = pb::ZkOutputProof {
        inner: bytes.to_vec(),
    }
    .try_into()
    .map_err(|_| ShieldedError::InvalidProofEncoding)?;
    proof
        .verify(&OUTPUT_PROOF_VERIFICATION_KEY, public)
        .map_err(|_| ShieldedError::OutputProofRejected)
}

pub fn verify_spend(bytes: &[u8], body_bytes: &[u8], anchor: Root) -> Result<SpendBody> {
    let body = decode_spend_body(body_bytes)?;
    verify_spend_public(
        bytes,
        SpendProofPublic {
            anchor,
            balance_commitment: body.balance_commitment,
            nullifier: body.nullifier,
            rk: body.rk,
        },
    )?;
    Ok(body)
}

pub fn verify_output(bytes: &[u8], body_bytes: &[u8]) -> Result<OutputBody> {
    let body = decode_output_body(body_bytes)?;
    verify_output_public(
        bytes,
        OutputProofPublic {
            note_commitment: body.note_payload.note_commitment,
            balance_commitment: body.balance_commitment,
        },
    )?;
    Ok(body)
}

/// Verify all upstream cryptographic material for a BIT Transfer.
///
/// Proofs are ordered as all Spends followed by all Outputs. The native asset
/// ID is supplied by the chain configuration so this adapter never embeds a
/// test asset as a consensus constant.
#[allow(clippy::too_many_arguments)]
pub fn verify_transfer_crypto(
    anchor_bytes: [u8; 32],
    spend_bodies: &[Vec<u8>],
    output_bodies: &[Vec<u8>],
    proofs: &[Vec<u8>],
    spend_authorizations: &[Vec<u8>],
    binding_signature: &[u8],
    effect_hash: &[u8; 64],
    fee_atomic: u128,
    native_asset_id_bytes: [u8; 32],
) -> Result<VerifiedShieldedTransfer> {
    verify_transaction_crypto(
        anchor_bytes,
        spend_bodies,
        output_bodies,
        proofs,
        spend_authorizations,
        binding_signature,
        effect_hash,
        ShieldedPublicBalance {
            locked: 0,
            released: 0,
            fee: fee_atomic,
        },
        native_asset_id_bytes,
    )
}

/// Verify Spend/Output proofs, randomized Spend authorizations, and the
/// binding signature for any BIT action with an explicit public value flow.
#[allow(clippy::too_many_arguments)]
pub fn verify_transaction_crypto(
    anchor_bytes: [u8; 32],
    spend_bodies: &[Vec<u8>],
    output_bodies: &[Vec<u8>],
    proofs: &[Vec<u8>],
    spend_authorizations: &[Vec<u8>],
    binding_signature: &[u8],
    effect_hash: &[u8; 64],
    public_balance: ShieldedPublicBalance,
    native_asset_id_bytes: [u8; 32],
) -> Result<VerifiedShieldedTransfer> {
    if proofs.len() != spend_bodies.len() + output_bodies.len()
        || spend_authorizations.len() != spend_bodies.len()
    {
        return Err(ShieldedError::CardinalityMismatch);
    }

    let anchor: Root = tct_pb::MerkleRoot {
        inner: anchor_bytes.to_vec(),
    }
    .try_into()
    .map_err(|_| ShieldedError::InvalidAnchor)?;

    let mut spends = Vec::with_capacity(spend_bodies.len());
    for ((body_bytes, proof), authorization) in spend_bodies
        .iter()
        .zip(&proofs[..spend_bodies.len()])
        .zip(spend_authorizations)
    {
        let body = verify_spend(proof, body_bytes, anchor)?;
        let signature = Signature::try_from(authorization.as_slice())
            .map_err(|_| ShieldedError::InvalidSpendAuthorization)?;
        body.rk
            .verify(effect_hash, &signature)
            .map_err(|_| ShieldedError::InvalidSpendAuthorization)?;
        spends.push(body);
    }

    let mut outputs = Vec::with_capacity(output_bodies.len());
    for (body_bytes, proof) in output_bodies.iter().zip(&proofs[spend_bodies.len()..]) {
        outputs.push(verify_output(proof, body_bytes)?);
    }

    verify_binding_signature(
        &spends,
        &outputs,
        public_balance,
        native_asset_id_bytes,
        effect_hash,
        binding_signature,
    )?;

    Ok(VerifiedShieldedTransfer {
        nullifiers: spends
            .iter()
            .map(|spend| spend.nullifier.to_bytes())
            .collect(),
        output_commitments: outputs
            .iter()
            .map(|output| output.note_payload.note_commitment.into())
            .collect(),
    })
}

fn verify_binding_signature(
    spends: &[SpendBody],
    outputs: &[OutputBody],
    public_balance: ShieldedPublicBalance,
    native_asset_id_bytes: [u8; 32],
    effect_hash: &[u8; 64],
    signature_bytes: &[u8],
) -> Result<()> {
    let native_asset_id = asset::Id::try_from(native_asset_id_bytes.as_slice())
        .map_err(|_| ShieldedError::InvalidNativeAssetId)?;
    let mut balance_commitments = decaf377::Element::default();
    for spend in spends {
        balance_commitments += spend.balance_commitment.0;
    }
    for output in outputs {
        balance_commitments += output.balance_commitment.0;
    }

    let released = Value {
        amount: Amount::from(public_balance.released),
        asset_id: native_asset_id,
    };
    let locked = Value {
        amount: Amount::from(public_balance.locked),
        asset_id: native_asset_id,
    };
    let fee = Value {
        amount: Amount::from(public_balance.fee),
        asset_id: native_asset_id,
    };
    let public_flow = Balance::from(released) - Balance::from(locked) - Balance::from(fee);
    balance_commitments += public_flow.commit(Fr::from(0u64)).0;

    verify_binding_key(balance_commitments, effect_hash, signature_bytes)
}

fn verify_binding_key(
    balance_commitments: decaf377::Element,
    effect_hash: &[u8; 64],
    signature_bytes: &[u8],
) -> Result<()> {
    let key_bytes: VerificationKeyBytes<Binding> = balance_commitments.vartime_compress().0.into();
    let key = VerificationKey::<Binding>::try_from(key_bytes)
        .map_err(|_| ShieldedError::InvalidBindingSignature)?;
    if key.is_identity() {
        return Err(ShieldedError::InvalidBindingSignature);
    }
    let signature = Signature::<Binding>::try_from(signature_bytes)
        .map_err(|_| ShieldedError::InvalidBindingSignature)?;
    key.verify(effect_hash, &signature)
        .map_err(|_| ShieldedError::InvalidBindingSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use decaf377_rdsa::SigningKey;

    #[test]
    fn malformed_proofs_fail_before_upstream_verification() {
        assert_eq!(
            validate_proof_bytes(&[0; 191]),
            Err(ShieldedError::InvalidProofEncoding)
        );
        assert_eq!(
            validate_proof_bytes(&[0xff; 192]),
            Err(ShieldedError::InvalidProofEncoding)
        );
    }

    #[test]
    fn malformed_bodies_are_rejected() {
        assert!(decode_spend_body(&[0xff]).is_err());
        assert!(decode_output_body(&[0xff]).is_err());
    }

    #[test]
    fn binding_signature_binds_the_full_effect_hash() {
        let effect_hash = [23u8; 64];
        let signing_key = SigningKey::<Binding>::from(Fr::from(1u64));
        let signature = signing_key.sign_deterministic(&effect_hash);
        let commitment = Balance::zero().commit(Fr::from(1u64)).0;
        verify_binding_key(commitment, &effect_hash, signature.as_ref()).unwrap();

        let mut changed = effect_hash;
        changed[63] ^= 1;
        assert_eq!(
            verify_binding_key(commitment, &changed, signature.as_ref()),
            Err(ShieldedError::InvalidBindingSignature)
        );
        assert_eq!(
            verify_binding_key(
                decaf377::Element::default(),
                &effect_hash,
                SigningKey::<Binding>::from(Fr::from(0u64))
                    .sign_deterministic(&effect_hash)
                    .as_ref(),
            ),
            Err(ShieldedError::InvalidBindingSignature)
        );
    }
}
