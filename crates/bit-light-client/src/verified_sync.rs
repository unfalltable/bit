//! CometBFT header, witness, state-proof, and compact-block verification.
//!
//! The types in this module deliberately accept transport-neutral byte
//! payloads. HTTP/Tor code can fetch them, but only this module decides when a
//! header, state value, or compact block is trusted.

use crate::{Checkpoint, CheckpointPolicy, Error as CheckpointError, Hash32};
use bit_types::CompactBlock;
use ibc_types::core::commitment::{MerklePath, MerkleProof, MerkleRoot};
use prost::Message;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use tendermint::time::Time;
use tendermint_light_client_verifier::{
    errors::ErrorExt,
    options::Options,
    types::{LightBlock, TrustThreshold},
    ProdVerifier, Verdict, Verifier,
};
use thiserror::Error;

pub const DEFAULT_CLOCK_DRIFT_SECONDS: u64 = 10;
pub const DEFAULT_REQUIRED_WITNESSES: usize = 2;
pub const MAX_PROOF_OPS: usize = 2;
pub const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_LIGHT_BLOCK_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENDPOINT_ID_BYTES: usize = 256;
const MAX_STATE_KEY_BYTES: usize = 512;

const SUBSTORES: &[&str] = &[
    "staking",
    "shielded",
    "supply",
    "fees",
    "genesis",
    "emission",
    "transactions",
    "execution",
    "compact",
];

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SyncError {
    #[error("invalid light-client configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("checkpoint does not match the supplied CometBFT light block: {0}")]
    CheckpointMismatch(&'static str),
    #[error("CometBFT light block is invalid: {0}")]
    InvalidHeader(String),
    #[error("trusted CometBFT state has expired")]
    TrustExpired,
    #[error("candidate does not have enough trusted validator overlap")]
    NotEnoughTrust,
    #[error("conflicting cryptographically valid headers were observed")]
    ConflictingHeaders,
    #[error("unknown or invalid witness")]
    InvalidWitness,
    #[error("witness response is for a different height")]
    WitnessHeightMismatch,
    #[error("witness header was verified from a different trusted state")]
    WitnessTrustBaseMismatch,
    #[error("state proof is malformed or exceeds resource limits: {0}")]
    InvalidStateProof(&'static str),
    #[error("state proof is not bound to the verified header")]
    StateProofBinding,
    #[error("ICS23 verification failed")]
    Ics23Verification,
    #[error("compact block is invalid: {0}")]
    InvalidCompactBlock(&'static str),
    #[error("compact block sequence is not continuous")]
    CompactDiscontinuity,
    #[error("checkpoint validation failed: {0}")]
    Checkpoint(String),
}

pub type Result<T> = core::result::Result<T, SyncError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationParameters {
    pub trusting_period_seconds: u64,
    pub unbonding_period_seconds: u64,
    pub clock_drift_seconds: u64,
}

impl VerificationParameters {
    pub fn new(
        trusting_period_seconds: u64,
        unbonding_period_seconds: u64,
        clock_drift_seconds: u64,
    ) -> Result<Self> {
        if trusting_period_seconds == 0
            || unbonding_period_seconds == 0
            || trusting_period_seconds >= unbonding_period_seconds
        {
            return Err(SyncError::InvalidConfiguration(
                "trusting period must be positive and shorter than unbonding",
            ));
        }
        if clock_drift_seconds > trusting_period_seconds {
            return Err(SyncError::InvalidConfiguration(
                "clock drift exceeds trusting period",
            ));
        }
        Ok(Self {
            trusting_period_seconds,
            unbonding_period_seconds,
            clock_drift_seconds,
        })
    }

    pub fn from_checkpoint_policy(
        trusting_period_seconds: u64,
        unbonding_period_seconds: u64,
    ) -> Result<Self> {
        Self::new(
            trusting_period_seconds,
            unbonding_period_seconds,
            DEFAULT_CLOCK_DRIFT_SECONDS,
        )
    }

    fn options(self) -> Options {
        Options {
            trust_threshold: TrustThreshold::default(),
            trusting_period: Duration::from_secs(self.trusting_period_seconds),
            clock_drift: Duration::from_secs(self.clock_drift_seconds),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct HeaderIdentity {
    pub height: u64,
    pub header_hash: Hash32,
    pub state_height: u64,
    pub app_hash: Hash32,
}

impl HeaderIdentity {
    fn from_light_block(block: &LightBlock) -> Result<Self> {
        let height = block.height().value();
        let state_height = height.checked_sub(1).ok_or(SyncError::InvalidHeader(
            "header height must be positive".to_owned(),
        ))?;
        Ok(Self {
            height,
            header_hash: fixed_hash(
                block.signed_header.header.hash().as_bytes(),
                "header hash is not SHA-256",
            )?,
            state_height,
            app_hash: fixed_hash(
                block.signed_header.header.app_hash.as_bytes(),
                "application hash is not 32 bytes",
            )?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedHeader {
    block: LightBlock,
    identity: HeaderIdentity,
    verification_base: Option<HeaderIdentity>,
}

impl VerifiedHeader {
    pub fn light_block(&self) -> &LightBlock {
        &self.block
    }

    pub fn identity(&self) -> &HeaderIdentity {
        &self.identity
    }

    pub fn state_height(&self) -> u64 {
        self.identity.state_height
    }

    pub fn app_hash(&self) -> Hash32 {
        self.identity.app_hash
    }

    /// Preserve the exact full header, commit, and validator sets needed after
    /// a wallet restart. The bytes remain untrusted until passed back through
    /// `restore_from_checkpoint`.
    pub fn encode_json(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&self.block)
            .map_err(|error| SyncError::InvalidHeader(error.to_string()))?;
        if bytes.is_empty() || bytes.len() > MAX_LIGHT_BLOCK_BYTES {
            return Err(SyncError::InvalidHeader(
                "serialized light block exceeds size limit".to_owned(),
            ));
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Default)]
pub struct CometVerifier {
    verifier: ProdVerifier,
}

impl CometVerifier {
    /// Materialize the full trusted state pinned by a signed checkpoint.
    /// Validator hashes and the commit are checked before the supplied block
    /// can be used to verify any successor.
    pub fn bootstrap_from_verified_checkpoint(
        &self,
        checkpoint: &Checkpoint,
        block: LightBlock,
    ) -> Result<VerifiedHeader> {
        let identity = HeaderIdentity::from_light_block(&block)?;
        if identity.height != checkpoint.header_height
            || identity.header_hash != checkpoint.header_hash
            || identity.state_height != checkpoint.state_height
            || identity.app_hash != checkpoint.app_hash
        {
            return Err(SyncError::CheckpointMismatch(
                "height, header hash, or application root differs",
            ));
        }
        map_verdict(
            self.verifier
                .verify_validator_sets(&block.as_untrusted_state()),
        )?;
        map_verdict(self.verifier.verify_commit(&block.as_untrusted_state()))?;
        Ok(VerifiedHeader {
            block,
            identity,
            verification_base: None,
        })
    }

    /// Decode persisted or downloaded JSON and re-run checkpoint, commit, and
    /// validator-set verification before recreating a trusted header.
    pub fn restore_from_checkpoint(
        &self,
        checkpoint: &Checkpoint,
        bytes: &[u8],
    ) -> Result<VerifiedHeader> {
        if bytes.is_empty() || bytes.len() > MAX_LIGHT_BLOCK_BYTES {
            return Err(SyncError::InvalidHeader(
                "serialized light block is empty or too large".to_owned(),
            ));
        }
        let block = serde_json::from_slice(bytes)
            .map_err(|error| SyncError::InvalidHeader(error.to_string()))?;
        self.bootstrap_from_verified_checkpoint(checkpoint, block)
    }

    /// Verify a successor against a previously trusted light block using the
    /// Tendermint light-client verifier. Non-adjacent updates are allowed only
    /// when the configured trust threshold overlaps the old validator set.
    pub fn verify_update(
        &self,
        trusted: &VerifiedHeader,
        candidate: LightBlock,
        policy: &CheckpointPolicy,
        unbonding_period_seconds: u64,
        now_seconds: u64,
    ) -> Result<VerifiedHeader> {
        policy.validate_safety(unbonding_period_seconds)?;
        let parameters = VerificationParameters::from_checkpoint_policy(
            policy.trust_period_seconds,
            unbonding_period_seconds,
        )?;
        let now = tm_time(now_seconds)?;
        let identity = HeaderIdentity::from_light_block(&candidate)?;
        map_verdict(self.verifier.verify_update_header(
            candidate.as_untrusted_state(),
            trusted.block.as_trusted_state(),
            &parameters.options(),
            now,
        ))?;
        Ok(VerifiedHeader {
            block: candidate,
            identity,
            verification_base: Some(trusted.identity.clone()),
        })
    }

    /// Verify a same-height alternative under the relaxed misbehaviour rule.
    /// Callers can persist the two signed headers as fork evidence.
    pub fn verify_misbehaviour(
        &self,
        trusted: &VerifiedHeader,
        candidate: &LightBlock,
        policy: &CheckpointPolicy,
        unbonding_period_seconds: u64,
        now_seconds: u64,
    ) -> Result<HeaderIdentity> {
        policy.validate_safety(unbonding_period_seconds)?;
        let parameters = VerificationParameters::from_checkpoint_policy(
            policy.trust_period_seconds,
            unbonding_period_seconds,
        )?;
        let identity = HeaderIdentity::from_light_block(candidate)?;
        map_verdict(self.verifier.verify_misbehaviour_header(
            candidate.as_untrusted_state(),
            trusted.block.as_trusted_state(),
            &parameters.options(),
            tm_time(now_seconds)?,
        ))?;
        Ok(identity)
    }
}

fn map_verdict(verdict: Verdict) -> Result<()> {
    match verdict {
        Verdict::Success => Ok(()),
        Verdict::NotEnoughTrust(_) => Err(SyncError::NotEnoughTrust),
        Verdict::Invalid(detail) if detail.has_expired() => Err(SyncError::TrustExpired),
        Verdict::Invalid(detail) => Err(SyncError::InvalidHeader(detail.to_string())),
    }
}

fn tm_time(seconds: u64) -> Result<Time> {
    let seconds = i64::try_from(seconds)
        .map_err(|_| SyncError::InvalidConfiguration("wall clock exceeds i64"))?;
    Time::from_unix_timestamp(seconds, 0)
        .map_err(|error| SyncError::InvalidHeader(error.to_string()))
}

fn fixed_hash(bytes: &[u8], message: &'static str) -> Result<Hash32> {
    bytes
        .try_into()
        .map_err(|_| SyncError::InvalidHeader(message.to_owned()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessStatus {
    Awaiting { confirmed: usize, required: usize },
    Confirmed,
    Conflict,
}

/// A per-height quorum for responses that have already passed cryptographic
/// header verification against the same trusted state.
#[derive(Clone, Debug)]
pub struct WitnessQuorum {
    primary_id: String,
    witnesses: BTreeSet<String>,
    required: usize,
    candidate: HeaderIdentity,
    verification_base: Option<HeaderIdentity>,
    confirmations: BTreeSet<String>,
    observations: BTreeMap<String, HeaderIdentity>,
    conflicted: bool,
}

impl WitnessQuorum {
    pub fn new(
        primary_id: String,
        witness_ids: Vec<String>,
        required: usize,
        candidate: &VerifiedHeader,
    ) -> Result<Self> {
        validate_endpoint_id(&primary_id)?;
        if required < DEFAULT_REQUIRED_WITNESSES || required > witness_ids.len() {
            return Err(SyncError::InvalidConfiguration(
                "at least two witness confirmations are required",
            ));
        }
        let mut witnesses = BTreeSet::new();
        for id in witness_ids {
            validate_endpoint_id(&id)?;
            if id == primary_id || !witnesses.insert(id) {
                return Err(SyncError::InvalidConfiguration(
                    "primary and witness IDs must be unique",
                ));
            }
        }
        Ok(Self {
            primary_id,
            witnesses,
            required,
            candidate: candidate.identity.clone(),
            verification_base: candidate.verification_base.clone(),
            confirmations: BTreeSet::new(),
            observations: BTreeMap::new(),
            conflicted: false,
        })
    }

    pub fn primary_id(&self) -> &str {
        &self.primary_id
    }

    pub fn candidate(&self) -> &HeaderIdentity {
        &self.candidate
    }

    /// Record an independently fetched header only after it has passed
    /// `CometVerifier` against the round's common trusted state.
    pub fn observe_verified(
        &mut self,
        witness_id: &str,
        observation: &VerifiedHeader,
    ) -> Result<WitnessStatus> {
        if self.conflicted {
            return Err(SyncError::ConflictingHeaders);
        }
        if !self.witnesses.contains(witness_id) {
            return Err(SyncError::InvalidWitness);
        }
        if observation.identity.height != self.candidate.height {
            return Err(SyncError::WitnessHeightMismatch);
        }
        if observation.verification_base != self.verification_base {
            return Err(SyncError::WitnessTrustBaseMismatch);
        }
        let observation = observation.identity.clone();
        if let Some(previous) = self.observations.get(witness_id) {
            if previous == &observation {
                return Ok(self.status());
            }
            self.conflicted = true;
            return Err(SyncError::ConflictingHeaders);
        }
        self.observations
            .insert(witness_id.to_owned(), observation.clone());
        if observation != self.candidate {
            self.conflicted = true;
            return Err(SyncError::ConflictingHeaders);
        }
        self.confirmations.insert(witness_id.to_owned());
        Ok(self.status())
    }

    pub fn status(&self) -> WitnessStatus {
        if self.conflicted {
            WitnessStatus::Conflict
        } else if self.confirmations.len() >= self.required {
            WitnessStatus::Confirmed
        } else {
            WitnessStatus::Awaiting {
                confirmed: self.confirmations.len(),
                required: self.required,
            }
        }
    }
}

fn validate_endpoint_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_ENDPOINT_ID_BYTES || !id.is_ascii() {
        return Err(SyncError::InvalidConfiguration(
            "endpoint ID is empty, too long, or non-ASCII",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProof {
    pub state_height: u64,
    pub key: String,
    pub value: Option<Vec<u8>>,
    /// Each item is one protobuf-encoded ICS23 CommitmentProof, matching the
    /// gateway's `proof_ops_base64` order.
    pub proof_ops: Vec<Vec<u8>>,
    pub app_hash: Hash32,
}

impl VerifiedHeader {
    pub fn verify_state_proof(&self, proof: &StateProof) -> Result<()> {
        if proof.state_height != self.identity.state_height
            || proof.app_hash != self.identity.app_hash
        {
            return Err(SyncError::StateProofBinding);
        }
        if proof.key.is_empty()
            || proof.key.len() > MAX_STATE_KEY_BYTES
            || !proof.key.is_ascii()
            || proof.proof_ops.is_empty()
            || proof.proof_ops.len() > MAX_PROOF_OPS
        {
            return Err(SyncError::InvalidStateProof("invalid key or proof count"));
        }
        let total_bytes = proof
            .proof_ops
            .iter()
            .try_fold(0usize, |total, item| total.checked_add(item.len()))
            .ok_or(SyncError::InvalidStateProof("proof size overflow"))?;
        if total_bytes == 0 || total_bytes > MAX_PROOF_BYTES {
            return Err(SyncError::InvalidStateProof("proof is empty or too large"));
        }
        let proofs = proof
            .proof_ops
            .iter()
            .map(|bytes| {
                ics23::CommitmentProof::decode(bytes.as_slice())
                    .map_err(|_| SyncError::InvalidStateProof("invalid proof protobuf"))
            })
            .collect::<Result<Vec<_>>>()?;
        let (path, specs) = proof_path(&proof.key);
        if proofs.len() != path.key_path.len() {
            return Err(SyncError::InvalidStateProof(
                "proof count does not match key path",
            ));
        }
        let merkle = MerkleProof { proofs };
        let root = MerkleRoot {
            hash: proof.app_hash.to_vec(),
        };
        match &proof.value {
            Some(value) => merkle
                .verify_membership(&specs, root, path, value.clone(), 0)
                .map_err(|_| SyncError::Ics23Verification),
            None => merkle
                .verify_non_membership(&specs, root, path)
                .map_err(|_| SyncError::Ics23Verification),
        }
    }
}

fn proof_path(key: &str) -> (MerklePath, Vec<ics23::ProofSpec>) {
    for prefix in SUBSTORES {
        if let Some(remainder) = key.strip_prefix(&format!("{prefix}/")) {
            return (
                MerklePath {
                    key_path: vec![(*prefix).to_owned(), remainder.to_owned()],
                },
                vec![jmt::ics23_spec(), jmt::ics23_spec()],
            );
        }
    }
    (
        MerklePath {
            key_path: vec![key.to_owned()],
        },
        vec![jmt::ics23_spec()],
    )
}

#[derive(Clone, Debug)]
pub struct CompactBlockVerifier {
    chain_context: Hash32,
    next_height: u64,
}

impl CompactBlockVerifier {
    pub fn new(chain_context: Hash32, next_height: u64) -> Result<Self> {
        if chain_context == [0; 32] || next_height == 0 {
            return Err(SyncError::InvalidConfiguration(
                "compact verifier needs a network and positive height",
            ));
        }
        Ok(Self {
            chain_context,
            next_height,
        })
    }

    pub fn next_height(&self) -> u64 {
        self.next_height
    }

    /// Accept exactly one canonical compact block after its hash membership
    /// proof has been verified against a trusted header.
    pub fn verify_next(
        &mut self,
        verified_header: &VerifiedHeader,
        canonical_block: &[u8],
        hash_proof: &StateProof,
    ) -> Result<CompactBlock> {
        let block = CompactBlock::decode_canonical(canonical_block)
            .map_err(|_| SyncError::InvalidCompactBlock("canonical decoding failed"))?;
        if block.chain_context != self.chain_context || block.height != self.next_height {
            return Err(SyncError::CompactDiscontinuity);
        }
        let expected_key = format!("compact/hash/{:020}", block.height);
        let compact_hash = block
            .hash()
            .map_err(|_| SyncError::InvalidCompactBlock("hashing failed"))?;
        if hash_proof.key != expected_key || hash_proof.value.as_deref() != Some(&compact_hash) {
            return Err(SyncError::InvalidCompactBlock(
                "state proof does not commit to this compact block",
            ));
        }
        verified_header.verify_state_proof(hash_proof)?;
        self.next_height = self
            .next_height
            .checked_add(1)
            .ok_or(SyncError::CompactDiscontinuity)?;
        Ok(block)
    }
}

impl From<CheckpointError> for SyncError {
    fn from(error: CheckpointError) -> Self {
        Self::Checkpoint(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Sub;
    use tendermint_testgen::{
        light_block::{LightBlock as TestgenLightBlock, TmLightBlock},
        Generator,
    };

    fn generated(block: TmLightBlock) -> LightBlock {
        LightBlock::new(
            block.signed_header,
            block.validators,
            block.next_validators,
            block.provider,
        )
    }

    fn pair() -> (LightBlock, LightBlock, Time) {
        let now = Time::from_unix_timestamp(2_000_000_000, 0).unwrap();
        let mut trusted_generator = TestgenLightBlock::new_default_with_time_and_chain_id(
            "bit-test-chain".to_owned(),
            now.sub(Duration::from_secs(20)).unwrap(),
            10,
        );
        let header = trusted_generator
            .header
            .take()
            .unwrap()
            .app_hash(tendermint::hash::AppHash::try_from(vec![0x42; 32]).unwrap());
        trusted_generator = TestgenLightBlock::new_default_with_header(header);
        let candidate_generator = trusted_generator.next();
        let trusted = generated(trusted_generator.generate().unwrap());
        let candidate = generated(candidate_generator.generate().unwrap());
        (trusted, candidate, now)
    }

    fn checkpoint_for(block: &LightBlock) -> Checkpoint {
        let identity = HeaderIdentity::from_light_block(block).unwrap();
        Checkpoint {
            policy_hash: [1; 32],
            genesis_manifest_hash: [2; 32],
            chain_context: [3; 32],
            header_height: identity.height,
            header_hash: identity.header_hash,
            state_height: identity.state_height,
            app_hash: identity.app_hash,
            issued_at_seconds: 1,
            expires_at_seconds: 2,
        }
    }

    fn sync_policy() -> CheckpointPolicy {
        let publisher = ed25519_consensus::SigningKey::from([7; 32])
            .verification_key()
            .to_bytes();
        CheckpointPolicy {
            genesis_manifest_hash: [1; 32],
            chain_context: [2; 32],
            consensus_parameters_sha256: [3; 32],
            sequence: 1,
            previous_policy_hash: None,
            activates_at_seconds: 1,
            trust_period_seconds: 60,
            expiry_warning_seconds: 10,
            threshold: 1,
            publishers: vec![publisher],
            revoke_previous_immediately: false,
        }
    }

    fn test_verified(identity: HeaderIdentity) -> VerifiedHeader {
        VerifiedHeader {
            block: pair().0,
            identity,
            verification_base: None,
        }
    }

    fn leaf_membership(key: &[u8], value: &[u8]) -> (ics23::CommitmentProof, Vec<u8>) {
        let existence = ics23::ExistenceProof {
            key: key.to_vec(),
            value: value.to_vec(),
            leaf: jmt::ics23_spec().leaf_spec,
            path: Vec::new(),
        };
        let root =
            ics23::calculate_existence_root::<ics23::HostFunctionsManager>(&existence).unwrap();
        (
            ics23::CommitmentProof {
                proof: Some(ics23::commitment_proof::Proof::Exist(existence)),
            },
            root,
        )
    }

    fn block_with_app_hash(height: u64, app_hash: Vec<u8>) -> LightBlock {
        let now = Time::from_unix_timestamp(2_000_000_000, 0).unwrap();
        let mut generator = TestgenLightBlock::new_default_with_time_and_chain_id(
            "bit-test-chain".to_owned(),
            now.sub(Duration::from_secs(20)).unwrap(),
            height,
        );
        let header = generator
            .header
            .take()
            .unwrap()
            .app_hash(tendermint::hash::AppHash::try_from(app_hash).unwrap());
        generated(
            TestgenLightBlock::new_default_with_header(header)
                .generate()
                .unwrap(),
        )
    }

    #[test]
    fn checkpoint_bootstrap_checks_full_light_block() {
        let (trusted, _, _) = pair();
        let checkpoint = checkpoint_for(&trusted);
        let verified = CometVerifier::default()
            .bootstrap_from_verified_checkpoint(&checkpoint, trusted.clone())
            .unwrap();
        assert_eq!(verified.identity().height, 10);
        let persisted = verified.encode_json().unwrap();
        let restored = CometVerifier::default()
            .restore_from_checkpoint(&checkpoint, &persisted)
            .unwrap();
        assert_eq!(restored.identity(), verified.identity());

        let mut corrupt = persisted;
        corrupt[0] = b'[';
        assert!(CometVerifier::default()
            .restore_from_checkpoint(&checkpoint, &corrupt)
            .is_err());

        let mut wrong = checkpoint;
        wrong.app_hash[0] ^= 1;
        assert!(matches!(
            CometVerifier::default().bootstrap_from_verified_checkpoint(&wrong, trusted),
            Err(SyncError::CheckpointMismatch(_))
        ));
    }

    #[test]
    fn comet_verifier_accepts_valid_successor_and_rejects_wrong_chain() {
        let (trusted, candidate, _now) = pair();
        let verifier = CometVerifier::default();
        let verified = verifier
            .bootstrap_from_verified_checkpoint(&checkpoint_for(&trusted), trusted)
            .unwrap();
        assert!(verifier
            .verify_update(
                &verified,
                candidate.clone(),
                &sync_policy(),
                120,
                2_000_000_000
            )
            .is_ok());

        let mut wrong_chain = candidate;
        wrong_chain.signed_header.header.chain_id = "other-chain".parse().unwrap();
        assert!(matches!(
            verifier.verify_update(&verified, wrong_chain, &sync_policy(), 120, 2_000_000_000),
            Err(SyncError::InvalidHeader(_))
        ));
    }

    #[test]
    fn witness_quorum_requires_two_unique_confirmations_and_locks_conflict() {
        let candidate = HeaderIdentity {
            height: 42,
            header_hash: [1; 32],
            state_height: 41,
            app_hash: [2; 32],
        };
        let candidate_header = test_verified(candidate.clone());
        let mut quorum = WitnessQuorum::new(
            "primary".to_owned(),
            vec!["witness-a".to_owned(), "witness-b".to_owned()],
            2,
            &candidate_header,
        )
        .unwrap();
        assert_eq!(
            quorum.observe_verified("witness-a", &test_verified(candidate.clone())),
            Ok(WitnessStatus::Awaiting {
                confirmed: 1,
                required: 2
            })
        );
        assert_eq!(
            quorum.observe_verified("witness-b", &test_verified(candidate.clone())),
            Ok(WitnessStatus::Confirmed)
        );

        let mut conflicting = candidate;
        conflicting.header_hash[0] ^= 1;
        let mut quorum = WitnessQuorum::new(
            "primary".to_owned(),
            vec!["witness-a".to_owned(), "witness-b".to_owned()],
            2,
            &candidate_header,
        )
        .unwrap();
        assert_eq!(
            quorum.observe_verified("witness-a", &test_verified(conflicting)),
            Err(SyncError::ConflictingHeaders)
        );
        assert_eq!(quorum.status(), WitnessStatus::Conflict);
    }

    #[test]
    fn state_proof_rejects_wrong_height_before_parsing() {
        let (trusted, _, _) = pair();
        let verified = CometVerifier::default()
            .bootstrap_from_verified_checkpoint(&checkpoint_for(&trusted), trusted)
            .unwrap();
        let proof = StateProof {
            state_height: verified.state_height() + 1,
            key: "meta/height".to_owned(),
            value: Some(vec![1]),
            proof_ops: vec![vec![0]],
            app_hash: verified.app_hash(),
        };
        assert_eq!(
            verified.verify_state_proof(&proof),
            Err(SyncError::StateProofBinding)
        );
    }

    #[test]
    fn compact_block_requires_an_exact_ics23_hash_proof_and_continuity() {
        let chain_context = [3; 32];
        let compact = CompactBlock {
            chain_context,
            height: 9,
            block_time_seconds: 1_999_999_980,
            shielded_tree_root: [4; 32],
            transactions: Vec::new(),
            events: Vec::new(),
        };
        let canonical = compact.encode_canonical().unwrap();
        let compact_hash = compact.hash().unwrap();
        let key = "compact/hash/00000000000000000009";
        let (inner, subroot) = leaf_membership(b"hash/00000000000000000009", &compact_hash);
        let (outer, root) = leaf_membership(b"compact", &subroot);
        let block = block_with_app_hash(10, root.clone());
        let verified = CometVerifier::default()
            .bootstrap_from_verified_checkpoint(&checkpoint_for(&block), block)
            .unwrap();
        let proof = StateProof {
            state_height: 9,
            key: key.to_owned(),
            value: Some(compact_hash.to_vec()),
            proof_ops: vec![inner.encode_to_vec(), outer.encode_to_vec()],
            app_hash: root.try_into().unwrap(),
        };
        let mut verifier = CompactBlockVerifier::new(chain_context, 9).unwrap();
        assert_eq!(
            verifier.verify_next(&verified, &canonical, &proof).unwrap(),
            compact
        );
        assert_eq!(verifier.next_height(), 10);
        assert_eq!(
            verifier.verify_next(&verified, &canonical, &proof),
            Err(SyncError::CompactDiscontinuity)
        );

        let mut tampered = proof;
        tampered.value.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            verified.verify_state_proof(&tampered),
            Err(SyncError::Ics23Verification)
        );
    }
}
