//! Generate real, state-bound Unbond and ClaimExit envelopes for the four-node probe.
//!
//! The fixed seed is public test material. This binary must never be used for
//! production keys or funds.

use anyhow::{ensure, Context, Result};
use bit_emission::FeePolicy;
use bit_transaction::{
    verify_staking_stateless, ActionAuthorizationView, ExitTicketAuthorization,
    PositionAuthorization, StatelessVerificationContext, VerifiedStakingAction,
};
use bit_types::{
    chain_context, ed25519_authorization_message, position_id, proof_hash, ticket_id, Action,
    Amount, Authorization, Envelope, FeeSource, Role, TxBody,
};
use decaf377::{Fq, Fr};
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
use penumbra_sdk_shielded_pool::{
    output::{Body as OutputBody, OutputProofPrivate, OutputProofPublic},
    Note, OutputProof, Rseed,
};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use std::path::Path;

const EXIT_OWNER_SEED: [u8; 32] = [0x91; 32];
const EXIT_DELEGATION_ATOMIC: u128 = 50 * bit_staking::ATOMIC_PER_BIT;
const FEE_ATOMIC: u128 = 1_000_000;
const MAX_LIFETIME: u64 = 100;
const MAX_ENVELOPE_BYTES: usize = 65_536;
type Hash32 = [u8; 32];

struct ExitAuthorizationView {
    owner: Hash32,
    position: Hash32,
    ticket: Hash32,
    release: Option<Amount>,
}

struct ShieldedOutputFixture {
    proof: Vec<u8>,
    output: Vec<u8>,
    memo_ciphertext: Vec<u8>,
    binding_blinding: Fr,
}

impl ActionAuthorizationView for ExitAuthorizationView {
    fn validator_operator(&self, _validator_id: &Hash32) -> Option<Hash32> {
        None
    }

    fn active_position(&self, position_id: &Hash32) -> Option<PositionAuthorization> {
        (*position_id == self.position).then_some(PositionAuthorization {
            owner: self.owner,
            sequence: 1,
        })
    }

    fn exit_ticket(&self, ticket_id: &Hash32) -> Option<ExitTicketAuthorization> {
        if *ticket_id != self.ticket {
            return None;
        }
        Some(ExitTicketAuthorization {
            owner: self.owner,
            sequence: 0,
            release: self.release?,
        })
    }
}

fn random_fr() -> Fr {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Fr::from_le_bytes_mod_order(&bytes)
}

fn random_fq() -> Fq {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Fq::from_le_bytes_mod_order(&bytes)
}

fn parse_height(value: &str) -> Result<u64> {
    let height: u64 = value
        .parse()
        .context("height must be an unsigned integer")?;
    ensure!(height > 0, "height must be positive");
    Ok(height)
}

fn parse_hash(value: &str, name: &str) -> Result<Hash32> {
    hex::decode(value)
        .with_context(|| format!("{name} must be hexadecimal"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain 32 bytes"))
}

fn native_value(amount: u128) -> Value {
    Value {
        amount: PenumbraAmount::from(amount),
        asset_id: asset::Id(Fq::from(1u64)),
    }
}

fn common() -> (Hash32, Ed25519SigningKey, Hash32, Hash32, Hash32) {
    let chain = chain_context([0x33; 32]);
    let owner_key = Ed25519SigningKey::from(EXIT_OWNER_SEED);
    let owner = owner_key.verification_key().to_bytes();
    let position = position_id(&chain, &owner);
    let ticket = ticket_id(&chain, &position, 1);
    (chain, owner_key, owner, position, ticket)
}

fn finish_envelope(
    current_height: u64,
    anchor: Hash32,
    action: Action,
    shielded: ShieldedOutputFixture,
    owner_key: &Ed25519SigningKey,
) -> Result<(Vec<u8>, [u8; 64])> {
    let ShieldedOutputFixture {
        proof,
        output,
        memo_ciphertext,
        binding_blinding,
    } = shielded;
    let expiry_height = current_height
        .checked_add(50)
        .context("expiry height overflow")?;
    let body = TxBody {
        version: 1,
        chain_context: chain_context([0x33; 32]),
        expiry_height,
        anchor,
        fee: Amount::new(FEE_ATOMIC)?,
        spends: Vec::new(),
        outputs: vec![output],
        action,
        proof_hashes: vec![proof_hash(&proof)],
        memo_ciphertext: Some(memo_ciphertext),
    };
    let effect_hash = body.effect_hash()?;
    let owner_message = ed25519_authorization_message(Role::PositionOwner, &effect_hash)
        .context("PositionOwner signature domain is missing")?;
    let envelope = Envelope {
        envelope_version: 1,
        canonical_body: body.encode_canonical()?,
        proofs: vec![proof],
        authorizations: vec![Authorization {
            role: Role::PositionOwner,
            index: 0,
            signature: owner_key.sign(&owner_message).to_bytes().to_vec(),
        }],
        binding_signature: SigningKey::<Binding>::from(binding_blinding)
            .sign_deterministic(&effect_hash)
            .to_bytes()
            .to_vec(),
    };
    let bytes = envelope.encode_canonical(current_height, MAX_LIFETIME)?;
    Ok((bytes, effect_hash))
}

fn unbond(
    parameter_directory: &Path,
    current_height: u64,
    anchor: Hash32,
) -> Result<serde_json::Value> {
    let output_pk = std::fs::read(parameter_directory.join("output_pk.bin"))
        .context("cannot read output proving key")?;
    proof_params::OUTPUT_PROOF_PROVING_KEY.try_load(&output_pk)?;

    let (chain, owner_key, owner, position, ticket) = common();
    let shares = Amount::new(EXIT_DELEGATION_ATOMIC)?;
    let receiver = SpendKey::from_seed_phrase_bip44(
        SeedPhrase::from_randomness(&[0x95; 32]),
        &Bip44Path::new(0),
    );
    let full_viewing_key = receiver.full_viewing_key();
    let (address, _) = full_viewing_key.incoming().payment_address(0u32.into());
    let note = Note::from_parts(address, native_value(0), Rseed([0x96; 32]))?;
    let blinding = random_fr();
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
    )?;
    let encoded_proof: pb::ZkOutputProof = proof.into();
    let memo_key = penumbra_sdk_keys::PayloadKey::random_key(&mut OsRng);
    let memo_ciphertext = memo_key.encrypt(vec![0u8; 512], PayloadKind::Memo);
    let output = OutputBody {
        note_payload: note.payload(),
        balance_commitment: public.balance_commitment,
        ovk_wrapped_key: note.encrypt_key(full_viewing_key.outgoing(), public.balance_commitment),
        wrapped_memo_key: WrappedMemoKey::encrypt(
            &memo_key,
            note.ephemeral_secret_key(),
            note.transmission_key(),
            &note.diversified_generator(),
        ),
    }
    .encode_to_vec();
    let action = Action::Unbond {
        position_id: position,
        expected_sequence: 1,
        shares,
        min_gross: shares,
        max_fee: Amount::new(FEE_ATOMIC)?,
        fee_source: FeeSource::ReleasedValue,
    };
    let (bytes, effect_hash) = finish_envelope(
        current_height,
        anchor,
        action,
        ShieldedOutputFixture {
            proof: encoded_proof.inner,
            output,
            memo_ciphertext,
            binding_blinding: blinding,
        },
        &owner_key,
    )?;
    let view = ExitAuthorizationView {
        owner,
        position,
        ticket,
        release: None,
    };
    let verified = verify_staking_stateless(
        &bytes,
        &StatelessVerificationContext {
            expected_chain_context: chain,
            current_height,
            max_lifetime: MAX_LIFETIME,
            max_envelope_bytes: MAX_ENVELOPE_BYTES,
            native_asset_id: asset::Id(Fq::from(1u64)).to_bytes(),
            fee_policy: FeePolicy::reference_testnet(),
        },
        &view,
    )?;
    ensure!(
        matches!(verified.action, VerifiedStakingAction::Unbond { position_id, .. } if position_id == position),
        "generated Unbond action was not preserved"
    );
    ensure!(
        verified.shielded.output_commitments.len() == 1,
        "Unbond must create one zero-value blinding output"
    );
    Ok(json!({
        "kind": "Unbond",
        "canonical_envelope_bytes": bytes.len(),
        "canonical_envelope_hex": hex::encode(&bytes),
        "tx_id": hex::encode(verified.shielded.tx_id),
        "effect_hash": hex::encode(effect_hash),
        "owner_pubkey": hex::encode(owner),
        "position_id": hex::encode(position),
        "ticket_id": hex::encode(ticket),
        "shares_atomic": shares.to_string(),
        "fee_atomic": FEE_ATOMIC.to_string(),
        "zero_value_output_commitment": hex::encode(verified.shielded.output_commitments[0]),
        "expiry_height": current_height + 50,
        "output_proof_verified": true,
        "stateless_authorization_verified": true,
        "binding_signature_verified": true,
    }))
}

fn claim_exit(
    parameter_directory: &Path,
    current_height: u64,
    anchor: Hash32,
    expected_release: Amount,
) -> Result<serde_json::Value> {
    ensure!(
        expected_release.value() > FEE_ATOMIC,
        "exit release must exceed the transaction fee"
    );
    let output_pk = std::fs::read(parameter_directory.join("output_pk.bin"))
        .context("cannot read output proving key")?;
    proof_params::OUTPUT_PROOF_PROVING_KEY.try_load(&output_pk)?;

    let (chain, owner_key, owner, position, ticket) = common();
    let receiver = SpendKey::from_seed_phrase_bip44(
        SeedPhrase::from_randomness(&[0x93; 32]),
        &Bip44Path::new(0),
    );
    let full_viewing_key = receiver.full_viewing_key();
    let (address, _) = full_viewing_key.incoming().payment_address(0u32.into());
    let output_amount = expected_release.value() - FEE_ATOMIC;
    let note = Note::from_parts(address, native_value(output_amount), Rseed([0x94; 32]))?;
    let blinding = random_fr();
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
    )?;
    let encoded_proof: pb::ZkOutputProof = proof.into();
    let memo_key = penumbra_sdk_keys::PayloadKey::random_key(&mut OsRng);
    let memo_ciphertext = memo_key.encrypt(vec![0u8; 512], PayloadKind::Memo);
    let output = OutputBody {
        note_payload: note.payload(),
        balance_commitment: public.balance_commitment,
        ovk_wrapped_key: note.encrypt_key(full_viewing_key.outgoing(), public.balance_commitment),
        wrapped_memo_key: WrappedMemoKey::encrypt(
            &memo_key,
            note.ephemeral_secret_key(),
            note.transmission_key(),
            &note.diversified_generator(),
        ),
    }
    .encode_to_vec();
    let action = Action::ClaimExit {
        ticket_id: ticket,
        expected_sequence: 0,
        expected_release,
        fee_source: FeeSource::ReleasedValue,
    };
    let (bytes, effect_hash) = finish_envelope(
        current_height,
        anchor,
        action,
        ShieldedOutputFixture {
            proof: encoded_proof.inner,
            output,
            memo_ciphertext,
            binding_blinding: blinding,
        },
        &owner_key,
    )?;
    let view = ExitAuthorizationView {
        owner,
        position,
        ticket,
        release: Some(expected_release),
    };
    let verified = verify_staking_stateless(
        &bytes,
        &StatelessVerificationContext {
            expected_chain_context: chain,
            current_height,
            max_lifetime: MAX_LIFETIME,
            max_envelope_bytes: MAX_ENVELOPE_BYTES,
            native_asset_id: asset::Id(Fq::from(1u64)).to_bytes(),
            fee_policy: FeePolicy::reference_testnet(),
        },
        &view,
    )?;
    ensure!(
        matches!(verified.action, VerifiedStakingAction::ClaimExit { ticket_id, expected_release: release, .. } if ticket_id == ticket && release == expected_release),
        "generated ClaimExit action was not preserved"
    );
    ensure!(
        verified.shielded.output_commitments.len() == 1,
        "ClaimExit must create one shielded output"
    );
    Ok(json!({
        "kind": "ClaimExit",
        "canonical_envelope_bytes": bytes.len(),
        "canonical_envelope_hex": hex::encode(&bytes),
        "tx_id": hex::encode(verified.shielded.tx_id),
        "effect_hash": hex::encode(effect_hash),
        "owner_pubkey": hex::encode(owner),
        "position_id": hex::encode(position),
        "ticket_id": hex::encode(ticket),
        "expected_release_atomic": expected_release.to_string(),
        "output_amount_atomic": output_amount.to_string(),
        "fee_atomic": FEE_ATOMIC.to_string(),
        "output_commitments_hex": verified
            .shielded
            .output_commitments
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>(),
        "expiry_height": current_height + 50,
        "output_proof_verified": true,
        "stateless_authorization_verified": true,
        "binding_signature_verified": true,
    }))
}

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let mode = args.get(1).map(String::as_str).unwrap_or_default();
    let result = match mode {
        "unbond" => {
            ensure!(
                args.len() == 5,
                "usage: bit-exit-fixture unbond PARAM_DIR HEIGHT ANCHOR_HEX"
            );
            unbond(
                Path::new(&args[2]),
                parse_height(&args[3])?,
                parse_hash(&args[4], "anchor")?,
            )?
        }
        "claim" => {
            ensure!(
                args.len() == 6,
                "usage: bit-exit-fixture claim PARAM_DIR HEIGHT ANCHOR_HEX EXPECTED_RELEASE"
            );
            claim_exit(
                Path::new(&args[2]),
                parse_height(&args[3])?,
                parse_hash(&args[4], "anchor")?,
                Amount::new(
                    args[5]
                        .parse()
                        .context("expected release must be an unsigned integer")?,
                )?,
            )?
        }
        _ => anyhow::bail!(
            "usage: bit-exit-fixture unbond PARAM_DIR HEIGHT ANCHOR_HEX | claim PARAM_DIR HEIGHT ANCHOR_HEX EXPECTED_RELEASE"
        ),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
