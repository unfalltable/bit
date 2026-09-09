//! Real upstream primitive experiments, NOT a BIT transaction codec or blockchain.
//! Fresh ephemeral fixture secrets only. No tracing subscriber or secret output.
use anyhow::{ensure, Result};
use bit_shielded::{
    validate_proof_bytes, verify_output, verify_output_public, verify_spend, verify_spend_public,
};
use bit_transaction::{Error as TransactionError, MemoryLedger};
use bit_types::{chain_context, proof_hash, Action, Authorization, Envelope, Role, TxBody};
use decaf377::{Fq, Fr};
use decaf377_rdsa::{Binding, SigningKey, VerificationKey};
use penumbra_sdk_asset::{asset, Balance, Value};
use penumbra_sdk_keys::keys::{Bip44Path, SeedPhrase, SpendKey};
use penumbra_sdk_keys::symmetric::{PayloadKind, WrappedMemoKey};
use penumbra_sdk_num::Amount;
use penumbra_sdk_proof_params as params;
use penumbra_sdk_proto::{
    penumbra::{core::component::shielded_pool::v1 as pb, crypto::tct::v1 as tct_pb},
    DomainType,
};
use penumbra_sdk_sct::Nullifier;
use penumbra_sdk_shielded_pool::{
    output::{Body as OutputBody, OutputProofPrivate, OutputProofPublic},
    spend::{Body as SpendBody, SpendProofPrivate, SpendProofPublic},
    EncryptedBackref, Note, OutputProof, Rseed, SpendProof,
};
use penumbra_sdk_tct as tct;
use rand_core::{OsRng, RngCore};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{path::Path, time::Instant};

fn secret() -> [u8; 32] {
    let mut b = [0; 32];
    OsRng.fill_bytes(&mut b);
    b
}
fn fr() -> Fr {
    Fr::from_le_bytes_mod_order(&secret())
}
fn fq() -> Fq {
    Fq::from_le_bytes_mod_order(&secret())
}
fn key() -> SpendKey {
    SpendKey::from_seed_phrase_bip44(SeedPhrase::from_randomness(&secret()), &Bip44Path::new(0))
}
fn value(amount: u128, id: u64) -> Value {
    Value {
        amount: Amount::from(amount),
        asset_id: asset::Id(Fq::from(id)),
    }
}

fn parameters(path: &Path, name: &str, expected: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path.join(name))?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == expected,
        "parameter SHA256"
    );
    Ok(bytes)
}
fn binding_check(
    provided: Value,
    outputs: &[Value],
    locked: u128,
    released: u128,
    fee: u128,
) -> Result<()> {
    let blind = fr();
    let signing = SigningKey::<Binding>::from(blind);
    let mut commitment = provided.commit(blind).0;
    for v in outputs {
        commitment += (-Balance::from(*v)).commit(Fr::from(0u64)).0;
    }
    commitment += value(released, 1).commit(Fr::from(0u64)).0;
    commitment += (-Balance::from(value(locked + fee, 1)))
        .commit(Fr::from(0u64))
        .0;
    let vk = VerificationKey::<Binding>::try_from(commitment.vartime_compress().0)?;
    // A 64-byte primitive-test message; deliberately not claimed as a BIT encoded body.
    let effect = [19u8; 64];
    let sig = signing.sign(OsRng, &effect);
    vk.verify(&effect, &sig)?;
    let mut changed = effect;
    changed[0] ^= 1;
    ensure!(
        vk.verify(&changed, &sig).is_err(),
        "changed effect accepted"
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let path = Path::new(
        args.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: bit-proof-probe PARAM_DIR [samples]"))?,
    );
    let samples: usize = args.get(2).map(|x| x.parse()).transpose()?.unwrap_or(5);
    ensure!((1..=30).contains(&samples), "samples outside 1..30");
    let start = Instant::now();
    let spend_pk = parameters(
        path,
        "spend_pk.bin",
        "87eca85bef562803fb9684c56c0a6db84aa6d0791b1c00b909e6f2a5c2cff452",
    )?;
    let output_pk = parameters(
        path,
        "output_pk.bin",
        "c9e97866edd6c815a7bcb2f3b5493713794369692bb96e5a2e682613c330e4a8",
    )?;
    params::SPEND_PROOF_PROVING_KEY.try_load(&spend_pk)?;
    params::OUTPUT_PROOF_PROVING_KEY.try_load(&output_pk)?;
    let load_ms = start.elapsed().as_secs_f64() * 1000.;
    drop(spend_pk);
    drop(output_pk);
    let sender = key();
    let receiver = key();
    let fvk = sender.full_viewing_key();
    let (sender_address, _) = fvk.incoming().payment_address(0u32.into());
    let (receiver_address, _) = receiver
        .full_viewing_key()
        .incoming()
        .payment_address(0u32.into());
    let mut tree = tct::Tree::new();
    let inputs: Vec<Note> = (0..2)
        .map(|_| {
            Note::from_parts(
                sender_address.clone(),
                value(7_500_000_000, 1),
                Rseed(secret()),
            )
            .unwrap()
        })
        .collect();
    for note in &inputs {
        tree.insert(tct::Witness::Keep, note.commit())?;
    }
    let mut results = vec![];
    let mut complete_transfer = None;
    for sample in 0..samples {
        let mut proving_ms = 0.;
        let mut verifying_ms = 0.;
        let memo_key = penumbra_sdk_keys::PayloadKey::random_key(&mut OsRng);
        let mut spend_bodies = Vec::with_capacity(inputs.len());
        let mut spend_proofs = Vec::with_capacity(inputs.len());
        let mut spend_randomizers = Vec::with_capacity(inputs.len());
        let mut output_bodies = Vec::with_capacity(2);
        let mut output_proofs = Vec::with_capacity(2);
        let mut synthetic_blinding_factor = Fr::from(0u64);
        for note in &inputs {
            let witness = tree.witness(note.commit()).unwrap();
            let randomizer = fr();
            let blinding = fr();
            synthetic_blinding_factor += blinding;
            let public = SpendProofPublic {
                anchor: tree.root(),
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
            let t = Instant::now();
            let proof = SpendProof::prove(
                fq(),
                fq(),
                &params::SPEND_PROOF_PROVING_KEY,
                public.clone(),
                private,
            )?;
            proving_ms += t.elapsed().as_secs_f64() * 1000.;
            let encoded: pb::ZkSpendProof = proof.clone().into();
            let body = SpendBody {
                balance_commitment: public.balance_commitment,
                nullifier: public.nullifier,
                rk: public.rk,
                encrypted_backref: EncryptedBackref::dummy(),
            };
            let body_bytes = body.encode_to_vec();
            let t = Instant::now();
            verify_spend(&encoded.inner, &body_bytes, tree.root())?;
            verifying_ms += t.elapsed().as_secs_f64() * 1000.;
            let mut changed = public;
            changed.nullifier = Nullifier(fq());
            ensure!(
                verify_spend_public(&encoded.inner, changed).is_err(),
                "wrong nullifier accepted"
            );
            spend_bodies.push(body_bytes);
            spend_proofs.push(encoded.inner);
            spend_randomizers.push(randomizer);
        }
        for (dest, amount) in [
            (receiver_address.clone(), 10_000_000_000u128),
            (sender_address.clone(), 4_999_000_000),
        ] {
            let note = Note::from_parts(dest, value(amount, 1), Rseed(secret()))?;
            let blinding = fr();
            synthetic_blinding_factor += blinding;
            let public = OutputProofPublic {
                note_commitment: note.commit(),
                balance_commitment: (-Balance::from(note.value())).commit(blinding),
            };
            let private = OutputProofPrivate {
                note: note.clone(),
                balance_blinding: blinding,
            };
            let t = Instant::now();
            let proof = OutputProof::prove(
                fq(),
                fq(),
                &params::OUTPUT_PROOF_PROVING_KEY,
                public.clone(),
                private,
            )?;
            proving_ms += t.elapsed().as_secs_f64() * 1000.;
            let encoded: pb::ZkOutputProof = proof.clone().into();
            let body = OutputBody {
                note_payload: note.payload(),
                balance_commitment: public.balance_commitment,
                ovk_wrapped_key: note.encrypt_key(fvk.outgoing(), public.balance_commitment),
                wrapped_memo_key: WrappedMemoKey::encrypt(
                    &memo_key,
                    note.ephemeral_secret_key(),
                    note.transmission_key(),
                    &note.diversified_generator(),
                ),
            };
            let body_bytes = body.encode_to_vec();
            let t = Instant::now();
            verify_output(&encoded.inner, &body_bytes)?;
            verifying_ms += t.elapsed().as_secs_f64() * 1000.;
            let mut changed = public;
            changed.balance_commitment = value(amount + 1, 1).commit(fr());
            ensure!(
                verify_output_public(&encoded.inner, changed).is_err(),
                "wrong output balance accepted"
            );
            output_bodies.push(body_bytes);
            output_proofs.push(encoded.inner);
        }

        if sample == 0 {
            let root_proto: tct_pb::MerkleRoot = tree.root().into();
            let anchor: [u8; 32] = root_proto.inner.try_into().expect("root is 32 bytes");
            let chain = chain_context([0x33; 32]);
            let mut memo_plaintext = vec![0u8; 512];
            let return_address = sender_address.to_vec();
            memo_plaintext[..return_address.len()].copy_from_slice(&return_address);
            let memo_ciphertext = memo_key.encrypt(memo_plaintext, PayloadKind::Memo);
            ensure!(memo_ciphertext.len() == 528, "memo ciphertext length");

            let mut proofs = spend_proofs.clone();
            proofs.extend(output_proofs.clone());
            let body = TxBody {
                version: 1,
                chain_context: chain,
                expiry_height: 100,
                anchor,
                fee: bit_types::Amount::new(1_000_000)?,
                spends: spend_bodies,
                outputs: output_bodies,
                action: Action::Transfer,
                proof_hashes: proofs.iter().map(|proof| proof_hash(proof)).collect(),
                memo_ciphertext: Some(memo_ciphertext),
            };
            let effect_hash = body.effect_hash()?;
            let authorizations = spend_randomizers
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
            let binding_signature = SigningKey::<Binding>::from(synthetic_blinding_factor)
                .sign_deterministic(&effect_hash)
                .to_bytes()
                .to_vec();
            let envelope = Envelope {
                envelope_version: 1,
                canonical_body: body.encode_canonical()?,
                proofs,
                authorizations,
                binding_signature,
            };
            let envelope_bytes = envelope.encode_canonical(50, 100)?;
            let native_asset_id = value(0, 1).asset_id.to_bytes();
            let mut ledger = MemoryLedger::new(chain, native_asset_id, 50, 100, 65_536);
            ledger.allow_anchor(anchor);
            let verified = ledger.verify_and_record(&envelope_bytes)?;
            ensure!(verified.nullifiers.len() == 2, "verified nullifier count");
            ensure!(
                verified.output_commitments.len() == 2,
                "verified output count"
            );
            ensure!(ledger.nullifier_count() == 2, "recorded nullifier count");
            ensure!(
                ledger.transaction_count() == 1,
                "recorded transaction count"
            );
            ensure!(
                ledger.verify_and_record(&envelope_bytes).is_err(),
                "duplicate transaction accepted"
            );

            let mut double_spend_body = body.clone();
            double_spend_body.expiry_height = 101;
            let double_spend_effect = double_spend_body.effect_hash()?;
            let double_spend_authorizations = spend_randomizers
                .iter()
                .enumerate()
                .map(|(index, randomizer)| Authorization {
                    role: Role::Spend,
                    index: index as u32,
                    signature: sender
                        .spend_auth_key()
                        .randomize(randomizer)
                        .sign_deterministic(&double_spend_effect)
                        .to_bytes()
                        .to_vec(),
                })
                .collect();
            let double_spend_binding = SigningKey::<Binding>::from(synthetic_blinding_factor)
                .sign_deterministic(&double_spend_effect)
                .to_bytes()
                .to_vec();
            let double_spend = Envelope {
                envelope_version: 1,
                canonical_body: double_spend_body.encode_canonical()?,
                proofs: envelope.proofs.clone(),
                authorizations: double_spend_authorizations,
                binding_signature: double_spend_binding,
            }
            .encode_canonical(50, 100)?;
            ensure!(
                matches!(
                    ledger.verify_and_record(&double_spend),
                    Err(TransactionError::NullifierAlreadySpent)
                ),
                "same nullifiers in a different valid envelope accepted"
            );

            let mut bad_authorization = envelope.clone();
            bad_authorization.authorizations[0].signature[0] ^= 1;
            let bad_authorization_bytes = bad_authorization.encode_canonical(50, 100)?;
            let mut auth_ledger = MemoryLedger::new(chain, native_asset_id, 50, 100, 65_536);
            auth_ledger.allow_anchor(anchor);
            ensure!(
                matches!(
                    auth_ledger.verify_and_record(&bad_authorization_bytes),
                    Err(TransactionError::Shielded(
                        bit_shielded::ShieldedError::InvalidSpendAuthorization
                    ))
                ),
                "bad Spend authorization accepted"
            );
            ensure!(
                auth_ledger.nullifier_count() == 0,
                "failed auth changed state"
            );

            let mut bad_envelope = envelope;
            bad_envelope.binding_signature[0] ^= 1;
            let bad_bytes = bad_envelope.encode_canonical(50, 100)?;
            let mut clean_ledger = MemoryLedger::new(chain, native_asset_id, 50, 100, 65_536);
            clean_ledger.allow_anchor(anchor);
            ensure!(
                clean_ledger.verify_and_record(&bad_bytes).is_err(),
                "bad binding signature accepted"
            );
            ensure!(
                clean_ledger.nullifier_count() == 0,
                "failed tx changed state"
            );
            ensure!(
                clean_ledger.transaction_count() == 0,
                "failed tx was recorded"
            );

            complete_transfer = Some(json!({
                "canonical_envelope_bytes": envelope_bytes.len(),
                "tx_id": hex::encode(verified.tx_id),
                "effect_hash": hex::encode(verified.effect_hash),
                "spends": verified.nullifiers.len(),
                "outputs": verified.output_commitments.len(),
                "memo_ciphertext_bytes": 528,
                "proofs": 4,
                "spend_authorizations": 2,
                "spend_authorizations_verified": true,
                "binding_signature_verified": true,
                "bad_spend_authorization_rejected": true,
                "bad_binding_signature_rejected": true,
                "duplicate_transaction_rejected": true,
                "duplicate_nullifiers_in_distinct_envelope_rejected": true,
                "failed_transaction_left_state_unchanged": true,
                "native_asset_scope": "reference test fixture; mainnet undecided",
                "native_asset_id_hex": hex::encode(native_asset_id)
            }));
        }
        eprintln!("sample {sample}: proving {proving_ms:.1} ms, verification {verifying_ms:.1} ms");
        results.push(json!({"sample":sample,"two_spend_two_output_proving_ms":proving_ms,"strict_verification_ms":verifying_ms}));
    }
    ensure!(
        validate_proof_bytes(&[255; 192]).is_err(),
        "malformed proof accepted"
    );
    ensure!(
        validate_proof_bytes(&[0; 191]).is_err(),
        "short proof accepted"
    );
    binding_check(
        value(15_000_000_000, 1),
        &[value(10_000_000_000, 1), value(4_999_000_000, 1)],
        0,
        0,
        1_000_000,
    )?;
    binding_check(
        value(15_000_000_000, 1),
        &[value(4_999_000_000, 1)],
        10_000_000_000,
        0,
        1_000_000,
    )?;
    binding_check(
        value(0, 1),
        &[value(9_999_000_000, 1)],
        0,
        10_000_000_000,
        1_000_000,
    )?;
    ensure!(
        binding_check(
            value(15_000_000_000, 1),
            &[value(14_999_000_000, 2)],
            0,
            0,
            1_000_000
        )
        .is_err(),
        "foreign positive output accepted"
    );
    ensure!(
        binding_check(
            value(15_000_000_000, 1),
            &[value(15_000_000_000, 1)],
            0,
            0,
            1_000_000
        )
        .is_err(),
        "unfunded fee accepted"
    );
    let scan_n = 1000u64;
    let mut payloads = Vec::new();
    for i in 0..scan_n {
        let address = if i % 100 == 0 {
            sender_address.clone()
        } else {
            receiver_address.clone()
        };
        payloads.push(Note::from_parts(address, value(100, 1), Rseed(secret()))?.payload());
    }
    let wire_bytes: usize = payloads.iter().map(|p| p.encode_to_vec().len()).sum();
    let t = Instant::now();
    let found = payloads
        .iter()
        .filter(|p| p.trial_decrypt(fvk).is_some())
        .count();
    let scan_ms = t.elapsed().as_secs_f64() * 1000.;
    ensure!(found == 10, "scan recovery count mismatch");
    let report = json!({"scope":"desktop BIT Transfer cryptographic acceptance and upstream primitive measurements; not network/mainnet/mobile acceptance",
        "upstream_commit":"3a87ce786373113f9b82d3b6df9504998b7f44a7","parameter_load_ms":load_ms,
        "samples":results,"negative_checks":"wrong nullifier, wrong output, malformed/short proof, changed effect, foreign positive value, unfunded fee rejected",
        "public_boundary_binding":"transfer, public lock, public release passed as primitive equations; chain authorization not tested",
        "complete_transfer":complete_transfer,
        "scan":{"payloads":scan_n,"owned":found,"elapsed_ms":scan_ms,"protobuf_bytes_total":wire_bytes},
        "mobile":"SKIPPED_BY_USER","limitations":["in-memory acceptance harness only; no persistent state or commitment-tree update", "not a formal single-asset closure proof", "no Tor, receipts, headers, database or phone in scan test", "fixture native asset ID only"]});
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
