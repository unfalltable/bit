//! Signed weak-subjectivity checkpoints and explicit trust lifecycle for BIT.
//!
//! A checkpoint publisher signature is an endorsement of a CometBFT header and
//! its corresponding application root. It is not consensus authority. The
//! publisher policy is independently approved by the genesis approval keys and
//! is bound to the signed genesis identity, chain context, and runtime-parameter
//! digest.

use bit_types::cbor::{Cursor, Writer};
use ed25519_consensus::{
    Signature as Ed25519Signature, SigningKey, VerificationKey as Ed25519VerificationKey,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub type Hash32 = [u8; 32];

pub const POLICY_FORMAT: &str = "BIT-CHECKPOINT-POLICY";
pub const POLICY_VERSION: u64 = 1;
pub const POLICY_HASH_DOMAIN: &[u8] = b"BIT-CHECKPOINT-POLICY-HASH-V1";
pub const POLICY_APPROVAL_FORMAT: &str = "BIT-CHECKPOINT-POLICY-APPROVALS";
pub const POLICY_APPROVAL_VERSION: u64 = 1;
pub const POLICY_APPROVAL_DOMAIN: &[u8] = b"BIT-CHECKPOINT-POLICY-APPROVAL-V1";
pub const CHECKPOINT_FORMAT: &str = "BIT-CHECKPOINT";
pub const CHECKPOINT_VERSION: u64 = 1;
pub const CHECKPOINT_HASH_DOMAIN: &[u8] = b"BIT-CHECKPOINT-HASH-V1";
pub const SIGNED_CHECKPOINT_FORMAT: &str = "BIT-SIGNED-CHECKPOINT";
pub const SIGNED_CHECKPOINT_VERSION: u64 = 1;
pub const CHECKPOINT_SIGNATURE_DOMAIN: &[u8] = b"BIT-CHECKPOINT-PUBLISHER-SIGNATURE-V1";
pub const MAX_PUBLISHERS: usize = 1_024;
pub const MAX_CHECKPOINT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid checkpoint policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("invalid checkpoint policy approvals: {0}")]
    InvalidPolicyApprovals(&'static str),
    #[error("invalid signed checkpoint: {0}")]
    InvalidCheckpoint(&'static str),
    #[error("invalid canonical CBOR: {0}")]
    InvalidCbor(&'static str),
    #[error("checkpoint trust has expired; explicit re-establishment is required")]
    TrustExpired,
    #[error("conflicting threshold-signed checkpoints were observed")]
    Conflict,
    #[error("checkpoint was issued in the future")]
    NotYetValid,
    #[error("incoming checkpoint has expired")]
    IncomingExpired,
    #[error("checkpoint height is not monotonic")]
    NonMonotonic,
    #[error("manual checkpoint confirmation hash does not match")]
    ConfirmationMismatch,
    #[error("trusted checkpoint is unavailable")]
    Unavailable,
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityPolicy {
    pub threshold: u16,
    pub signers: Vec<Hash32>,
}

impl AuthorityPolicy {
    pub fn validate(&self) -> Result<()> {
        validate_signer_set(self.threshold, &self.signers, Error::InvalidPolicyApprovals)
    }
}

/// Genesis-authority-approved set of checkpoint publishers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointPolicy {
    pub genesis_manifest_hash: Hash32,
    pub chain_context: Hash32,
    pub consensus_parameters_sha256: Hash32,
    pub sequence: u64,
    pub previous_policy_hash: Option<Hash32>,
    pub activates_at_seconds: u64,
    pub trust_period_seconds: u64,
    pub expiry_warning_seconds: u64,
    pub threshold: u16,
    pub publishers: Vec<Hash32>,
    pub revoke_previous_immediately: bool,
}

impl CheckpointPolicy {
    pub fn validate(&self) -> Result<()> {
        for hash in [
            self.genesis_manifest_hash,
            self.chain_context,
            self.consensus_parameters_sha256,
        ] {
            if hash == [0; 32] {
                return Err(Error::InvalidPolicy("binding hash is zero"));
            }
        }
        if self.sequence == 0 || self.activates_at_seconds == 0 {
            return Err(Error::InvalidPolicy(
                "sequence and activation time must be positive",
            ));
        }
        match (self.sequence, self.previous_policy_hash) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(Error::InvalidPolicy(
                    "initial policy must not name a previous policy",
                ))
            }
            (_, None) => {
                return Err(Error::InvalidPolicy(
                    "rotated policy must name the previous policy",
                ))
            }
            (_, Some(hash)) if hash == [0; 32] => {
                return Err(Error::InvalidPolicy("previous policy hash is zero"))
            }
            _ => {}
        }
        if self.sequence == 1 && self.revoke_previous_immediately {
            return Err(Error::InvalidPolicy(
                "initial policy cannot revoke a previous policy",
            ));
        }
        if self.trust_period_seconds == 0
            || self.expiry_warning_seconds == 0
            || self.expiry_warning_seconds >= self.trust_period_seconds
        {
            return Err(Error::InvalidPolicy("invalid trust or warning period"));
        }
        validate_signer_set(self.threshold, &self.publishers, Error::InvalidPolicy)
    }

    /// Enforces the consensus safety relation required by the BIT specification.
    pub fn validate_safety(&self, unbonding_seconds: u64) -> Result<()> {
        self.validate()?;
        if unbonding_seconds == 0 || self.trust_period_seconds >= unbonding_seconds {
            return Err(Error::InvalidPolicy(
                "trust period must be shorter than unbonding",
            ));
        }
        Ok(())
    }

    pub fn verify_binding(
        &self,
        genesis_manifest_hash: &Hash32,
        chain_context: &Hash32,
        consensus_parameters_sha256: &Hash32,
    ) -> Result<()> {
        if self.genesis_manifest_hash != *genesis_manifest_hash
            || self.chain_context != *chain_context
            || self.consensus_parameters_sha256 != *consensus_parameters_sha256
        {
            return Err(Error::InvalidPolicy("genesis or network binding mismatch"));
        }
        Ok(())
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.array(13);
        writer.text(POLICY_FORMAT);
        writer.uint(POLICY_VERSION);
        writer.bytes(&self.genesis_manifest_hash);
        writer.bytes(&self.chain_context);
        writer.bytes(&self.consensus_parameters_sha256);
        writer.uint(self.sequence);
        if let Some(hash) = self.previous_policy_hash {
            writer.bytes(&hash);
        } else {
            writer.null();
        }
        writer.uint(self.activates_at_seconds);
        writer.uint(self.trust_period_seconds);
        writer.uint(self.expiry_warning_seconds);
        writer.uint(u64::from(self.threshold));
        writer.array(self.publishers.len());
        for publisher in &self.publishers {
            writer.bytes(publisher);
        }
        writer.boolean(self.revoke_previous_immediately);
        Ok(writer.finish())
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        require_size(bytes)?;
        let mut cursor = Cursor::new(bytes);
        if map_cbor(cursor.array())? != 13
            || map_cbor(cursor.text())? != POLICY_FORMAT
            || map_cbor(cursor.uint())? != POLICY_VERSION
        {
            return Err(Error::InvalidPolicy("unknown policy format"));
        }
        let genesis_manifest_hash = fixed32(map_cbor(cursor.bytes())?, "genesis hash length")?;
        let chain_context = fixed32(map_cbor(cursor.bytes())?, "chain context length")?;
        let consensus_parameters_sha256 =
            fixed32(map_cbor(cursor.bytes())?, "parameter hash length")?;
        let sequence = map_cbor(cursor.uint())?;
        let previous_policy_hash = map_cbor(cursor.nullable(|cursor| cursor.bytes()))?
            .map(|value| fixed32(value, "previous policy hash length"))
            .transpose()?;
        let activates_at_seconds = map_cbor(cursor.uint())?;
        let trust_period_seconds = map_cbor(cursor.uint())?;
        let expiry_warning_seconds = map_cbor(cursor.uint())?;
        let threshold = u16::try_from(map_cbor(cursor.uint())?)
            .map_err(|_| Error::InvalidPolicy("publisher threshold exceeds u16"))?;
        let count = bounded_count(map_cbor(cursor.array())?)?;
        let mut publishers = Vec::with_capacity(count);
        for _ in 0..count {
            publishers.push(fixed32(
                map_cbor(cursor.bytes())?,
                "publisher public key length",
            )?);
        }
        let revoke_previous_immediately = map_cbor(cursor.boolean())?;
        map_cbor(cursor.finish())?;
        let policy = Self {
            genesis_manifest_hash,
            chain_context,
            consensus_parameters_sha256,
            sequence,
            previous_policy_hash,
            activates_at_seconds,
            trust_period_seconds,
            expiry_warning_seconds,
            threshold,
            publishers,
            revoke_previous_immediately,
        };
        if policy.encode_canonical()?.as_slice() != bytes {
            return Err(Error::InvalidCbor("policy does not round-trip canonically"));
        }
        Ok(policy)
    }

    pub fn hash(&self) -> Result<Hash32> {
        Ok(domain_hash(POLICY_HASH_DOMAIN, &self.encode_canonical()?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureEntry {
    pub signer_pubkey: Hash32,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySignaturePackage {
    pub genesis_manifest_hash: Hash32,
    pub policy_hash: Hash32,
    pub approvals: Vec<SignatureEntry>,
}

impl PolicySignaturePackage {
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        validate_signature_entries(&self.approvals, Error::InvalidPolicyApprovals)?;
        let mut writer = Writer::new();
        writer.array(5);
        writer.text(POLICY_APPROVAL_FORMAT);
        writer.uint(POLICY_APPROVAL_VERSION);
        writer.bytes(&self.genesis_manifest_hash);
        writer.bytes(&self.policy_hash);
        encode_signatures(&mut writer, &self.approvals);
        let bytes = writer.finish();
        require_size(&bytes)?;
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        require_size(bytes)?;
        let mut cursor = Cursor::new(bytes);
        if map_cbor(cursor.array())? != 5
            || map_cbor(cursor.text())? != POLICY_APPROVAL_FORMAT
            || map_cbor(cursor.uint())? != POLICY_APPROVAL_VERSION
        {
            return Err(Error::InvalidPolicyApprovals(
                "unknown approval package format",
            ));
        }
        let package = Self {
            genesis_manifest_hash: fixed32(
                map_cbor(cursor.bytes())?,
                "approval genesis hash length",
            )?,
            policy_hash: fixed32(map_cbor(cursor.bytes())?, "approval policy hash length")?,
            approvals: decode_signatures(&mut cursor, Error::InvalidPolicyApprovals)?,
        };
        map_cbor(cursor.finish())?;
        if package.encode_canonical()?.as_slice() != bytes {
            return Err(Error::InvalidCbor(
                "policy approvals do not round-trip canonically",
            ));
        }
        Ok(package)
    }

    pub fn verify(&self, policy: &CheckpointPolicy, authority: &AuthorityPolicy) -> Result<usize> {
        let count = self.verify_partial(policy, authority)?;
        if count < usize::from(authority.threshold) {
            return Err(Error::InvalidPolicyApprovals(
                "genesis approval threshold is not satisfied",
            ));
        }
        Ok(count)
    }

    pub fn verify_partial(
        &self,
        policy: &CheckpointPolicy,
        authority: &AuthorityPolicy,
    ) -> Result<usize> {
        policy.validate()?;
        authority.validate()?;
        let policy_hash = policy.hash()?;
        if self.genesis_manifest_hash != policy.genesis_manifest_hash
            || self.policy_hash != policy_hash
        {
            return Err(Error::InvalidPolicyApprovals(
                "policy approval binding mismatch",
            ));
        }
        verify_signatures(
            &self.approvals,
            &authority.signers,
            &policy_approval_message(&self.genesis_manifest_hash, &policy_hash),
            Error::InvalidPolicyApprovals,
        )
    }

    pub fn add_signature(
        &mut self,
        policy: &CheckpointPolicy,
        authority: &AuthorityPolicy,
        secret_key: [u8; 32],
    ) -> Result<Hash32> {
        self.verify_partial(policy, authority)?;
        add_signature(
            &mut self.approvals,
            &authority.signers,
            &policy_approval_message(&self.genesis_manifest_hash, &self.policy_hash),
            secret_key,
            Error::InvalidPolicyApprovals,
        )
    }
}

pub fn policy_approval_message(genesis_manifest_hash: &Hash32, policy_hash: &Hash32) -> Vec<u8> {
    let mut message = Vec::with_capacity(POLICY_APPROVAL_DOMAIN.len() + 64);
    message.extend_from_slice(POLICY_APPROVAL_DOMAIN);
    message.extend_from_slice(genesis_manifest_hash);
    message.extend_from_slice(policy_hash);
    message
}

/// Header H authenticates application state committed by H-1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub policy_hash: Hash32,
    pub genesis_manifest_hash: Hash32,
    pub chain_context: Hash32,
    pub header_height: u64,
    pub header_hash: Hash32,
    pub state_height: u64,
    pub app_hash: Hash32,
    pub issued_at_seconds: u64,
    pub expires_at_seconds: u64,
}

impl Checkpoint {
    pub fn validate(&self, policy: &CheckpointPolicy) -> Result<()> {
        if self.policy_hash != policy.hash()?
            || self.genesis_manifest_hash != policy.genesis_manifest_hash
            || self.chain_context != policy.chain_context
        {
            return Err(Error::InvalidCheckpoint(
                "checkpoint policy or network binding mismatch",
            ));
        }
        if self.header_height == 0
            || self.state_height != self.header_height - 1
            || self.header_hash == [0; 32]
            || self.app_hash == [0; 32]
        {
            return Err(Error::InvalidCheckpoint(
                "invalid height, header hash, or application hash",
            ));
        }
        if self.issued_at_seconds < policy.activates_at_seconds
            || self.expires_at_seconds <= self.issued_at_seconds
            || self.expires_at_seconds - self.issued_at_seconds > policy.trust_period_seconds
        {
            return Err(Error::InvalidCheckpoint(
                "invalid checkpoint validity interval",
            ));
        }
        Ok(())
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        if self.header_height == 0
            || self.state_height != self.header_height - 1
            || self.header_hash == [0; 32]
            || self.app_hash == [0; 32]
            || self.policy_hash == [0; 32]
            || self.genesis_manifest_hash == [0; 32]
            || self.chain_context == [0; 32]
            || self.expires_at_seconds <= self.issued_at_seconds
        {
            return Err(Error::InvalidCheckpoint("invalid checkpoint fields"));
        }
        let mut writer = Writer::new();
        writer.array(11);
        writer.text(CHECKPOINT_FORMAT);
        writer.uint(CHECKPOINT_VERSION);
        writer.bytes(&self.policy_hash);
        writer.bytes(&self.genesis_manifest_hash);
        writer.bytes(&self.chain_context);
        writer.uint(self.header_height);
        writer.bytes(&self.header_hash);
        writer.uint(self.state_height);
        writer.bytes(&self.app_hash);
        writer.uint(self.issued_at_seconds);
        writer.uint(self.expires_at_seconds);
        Ok(writer.finish())
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        require_size(bytes)?;
        let mut cursor = Cursor::new(bytes);
        if map_cbor(cursor.array())? != 11
            || map_cbor(cursor.text())? != CHECKPOINT_FORMAT
            || map_cbor(cursor.uint())? != CHECKPOINT_VERSION
        {
            return Err(Error::InvalidCheckpoint("unknown checkpoint format"));
        }
        let checkpoint = Self {
            policy_hash: fixed32(map_cbor(cursor.bytes())?, "policy hash length")?,
            genesis_manifest_hash: fixed32(map_cbor(cursor.bytes())?, "genesis hash length")?,
            chain_context: fixed32(map_cbor(cursor.bytes())?, "chain context length")?,
            header_height: map_cbor(cursor.uint())?,
            header_hash: fixed32(map_cbor(cursor.bytes())?, "header hash length")?,
            state_height: map_cbor(cursor.uint())?,
            app_hash: fixed32(map_cbor(cursor.bytes())?, "application hash length")?,
            issued_at_seconds: map_cbor(cursor.uint())?,
            expires_at_seconds: map_cbor(cursor.uint())?,
        };
        map_cbor(cursor.finish())?;
        if checkpoint.encode_canonical()?.as_slice() != bytes {
            return Err(Error::InvalidCbor(
                "checkpoint does not round-trip canonically",
            ));
        }
        Ok(checkpoint)
    }

    pub fn hash(&self) -> Result<Hash32> {
        Ok(domain_hash(
            CHECKPOINT_HASH_DOMAIN,
            &self.encode_canonical()?,
        ))
    }

    pub fn status(&self, policy: &CheckpointPolicy, now_seconds: u64) -> Result<TrustStatus> {
        self.validate(policy)?;
        status_at(
            self.issued_at_seconds,
            self.expires_at_seconds,
            policy.expiry_warning_seconds,
            now_seconds,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    pub signatures: Vec<SignatureEntry>,
}

impl SignedCheckpoint {
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        validate_signature_entries(&self.signatures, Error::InvalidCheckpoint)?;
        let checkpoint = self.checkpoint.encode_canonical()?;
        let mut writer = Writer::new();
        writer.array(4);
        writer.text(SIGNED_CHECKPOINT_FORMAT);
        writer.uint(SIGNED_CHECKPOINT_VERSION);
        writer.bytes(&checkpoint);
        encode_signatures(&mut writer, &self.signatures);
        let bytes = writer.finish();
        require_size(&bytes)?;
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        require_size(bytes)?;
        let mut cursor = Cursor::new(bytes);
        if map_cbor(cursor.array())? != 4
            || map_cbor(cursor.text())? != SIGNED_CHECKPOINT_FORMAT
            || map_cbor(cursor.uint())? != SIGNED_CHECKPOINT_VERSION
        {
            return Err(Error::InvalidCheckpoint("unknown signed checkpoint format"));
        }
        let checkpoint_bytes = map_cbor(cursor.bytes())?;
        let signed = Self {
            checkpoint: Checkpoint::decode_canonical(&checkpoint_bytes)?,
            signatures: decode_signatures(&mut cursor, Error::InvalidCheckpoint)?,
        };
        map_cbor(cursor.finish())?;
        if signed.encode_canonical()?.as_slice() != bytes {
            return Err(Error::InvalidCbor(
                "signed checkpoint does not round-trip canonically",
            ));
        }
        Ok(signed)
    }

    pub fn verify(&self, policy: &CheckpointPolicy) -> Result<usize> {
        let count = self.verify_partial(policy)?;
        if count < usize::from(policy.threshold) {
            return Err(Error::InvalidCheckpoint(
                "publisher signature threshold is not satisfied",
            ));
        }
        Ok(count)
    }

    pub fn verify_partial(&self, policy: &CheckpointPolicy) -> Result<usize> {
        self.checkpoint.validate(policy)?;
        let hash = self.checkpoint.hash()?;
        verify_signatures(
            &self.signatures,
            &policy.publishers,
            &checkpoint_signature_message(&self.checkpoint.policy_hash, &hash),
            Error::InvalidCheckpoint,
        )
    }

    pub fn add_signature(
        &mut self,
        policy: &CheckpointPolicy,
        secret_key: [u8; 32],
    ) -> Result<Hash32> {
        self.verify_partial(policy)?;
        let checkpoint_hash = self.checkpoint.hash()?;
        add_signature(
            &mut self.signatures,
            &policy.publishers,
            &checkpoint_signature_message(&self.checkpoint.policy_hash, &checkpoint_hash),
            secret_key,
            Error::InvalidCheckpoint,
        )
    }
}

pub fn checkpoint_signature_message(policy_hash: &Hash32, checkpoint_hash: &Hash32) -> Vec<u8> {
    let mut message = Vec::with_capacity(CHECKPOINT_SIGNATURE_DOMAIN.len() + 64);
    message.extend_from_slice(CHECKPOINT_SIGNATURE_DOMAIN);
    message.extend_from_slice(policy_hash);
    message.extend_from_slice(checkpoint_hash);
    message
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustStatus {
    NeedsCheckpoint,
    NotYetValid,
    Current,
    ExpiringSoon,
    Expired,
    Conflict,
}

impl TrustStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeedsCheckpoint => "needs_checkpoint",
            Self::NotYetValid => "not_yet_valid",
            Self::Current => "current",
            Self::ExpiringSoon => "expiring_soon",
            Self::Expired => "expired",
            Self::Conflict => "conflict",
        }
    }
}

#[derive(Clone, Debug)]
struct TrustedCheckpoint {
    checkpoint: Checkpoint,
    warning_seconds: u64,
}

/// In-memory transition guard for a caller that persists the verified policy,
/// signed checkpoint, and conflict marker atomically.
#[derive(Clone, Debug)]
pub struct TrustStore {
    active_policy: CheckpointPolicy,
    latest: Option<TrustedCheckpoint>,
    conflicted: bool,
}

impl TrustStore {
    pub fn install_initial_policy(
        policy: CheckpointPolicy,
        approvals: &PolicySignaturePackage,
        authority: &AuthorityPolicy,
        unbonding_seconds: u64,
    ) -> Result<Self> {
        policy.validate_safety(unbonding_seconds)?;
        if policy.sequence != 1 || policy.previous_policy_hash.is_some() {
            return Err(Error::InvalidPolicy("expected initial policy sequence"));
        }
        approvals.verify(&policy, authority)?;
        Ok(Self {
            active_policy: policy,
            latest: None,
            conflicted: false,
        })
    }

    pub fn active_policy(&self) -> &CheckpointPolicy {
        &self.active_policy
    }

    pub fn latest_checkpoint(&self) -> Option<&Checkpoint> {
        self.latest.as_ref().map(|trusted| &trusted.checkpoint)
    }

    pub fn status(&self, now_seconds: u64) -> TrustStatus {
        if self.conflicted {
            return TrustStatus::Conflict;
        }
        let Some(trusted) = &self.latest else {
            return TrustStatus::NeedsCheckpoint;
        };
        match status_at(
            trusted.checkpoint.issued_at_seconds,
            trusted.checkpoint.expires_at_seconds,
            trusted.warning_seconds,
            now_seconds,
        ) {
            Ok(status) => status,
            Err(Error::NotYetValid) => TrustStatus::NotYetValid,
            Err(_) => TrustStatus::Expired,
        }
    }

    pub fn rotate_policy(
        &mut self,
        next: CheckpointPolicy,
        approvals: &PolicySignaturePackage,
        authority: &AuthorityPolicy,
        unbonding_seconds: u64,
        now_seconds: u64,
    ) -> Result<()> {
        next.validate_safety(unbonding_seconds)?;
        approvals.verify(&next, authority)?;
        if next.genesis_manifest_hash != self.active_policy.genesis_manifest_hash
            || next.chain_context != self.active_policy.chain_context
            || next.consensus_parameters_sha256 != self.active_policy.consensus_parameters_sha256
            || next.sequence
                != self
                    .active_policy
                    .sequence
                    .checked_add(1)
                    .ok_or(Error::InvalidPolicy("policy sequence overflow"))?
            || next.previous_policy_hash != Some(self.active_policy.hash()?)
        {
            return Err(Error::InvalidPolicy("invalid policy rotation chain"));
        }
        if next.activates_at_seconds > now_seconds {
            return Err(Error::InvalidPolicy("policy is not active yet"));
        }
        if next.revoke_previous_immediately {
            self.latest = None;
        }
        self.active_policy = next;
        Ok(())
    }

    /// Imports a routine checkpoint update. Once trust has expired, this path
    /// refuses every candidate so a network response cannot silently restore
    /// trust.
    pub fn import_checkpoint(
        &mut self,
        signed: &SignedCheckpoint,
        now_seconds: u64,
    ) -> Result<TrustStatus> {
        if self.conflicted {
            return Err(Error::Conflict);
        }
        if self.status(now_seconds) == TrustStatus::Expired {
            return Err(Error::TrustExpired);
        }
        signed.verify(&self.active_policy)?;
        require_usable(&signed.checkpoint, &self.active_policy, now_seconds)?;
        self.accept_monotonic(signed.checkpoint.clone())?;
        Ok(self.status(now_seconds))
    }

    /// Re-establishes trust after the user or operator independently confirms
    /// an exact checkpoint hash. Endpoint agreement alone cannot call this
    /// method without supplying that separate confirmation value.
    pub fn reestablish(
        &mut self,
        signed: &SignedCheckpoint,
        confirmed_checkpoint_hash: Hash32,
        now_seconds: u64,
    ) -> Result<TrustStatus> {
        signed.verify(&self.active_policy)?;
        let checkpoint_hash = signed.checkpoint.hash()?;
        if checkpoint_hash != confirmed_checkpoint_hash {
            return Err(Error::ConfirmationMismatch);
        }
        require_usable(&signed.checkpoint, &self.active_policy, now_seconds)?;
        if self.latest.as_ref().is_some_and(|trusted| {
            signed.checkpoint.header_height < trusted.checkpoint.header_height
        }) {
            return Err(Error::NonMonotonic);
        }
        self.conflicted = false;
        self.latest = Some(TrustedCheckpoint {
            checkpoint: signed.checkpoint.clone(),
            warning_seconds: self.active_policy.expiry_warning_seconds,
        });
        Ok(self.status(now_seconds))
    }

    pub fn verified_anchor(&self, now_seconds: u64) -> Result<&Checkpoint> {
        match self.status(now_seconds) {
            TrustStatus::Current | TrustStatus::ExpiringSoon => self
                .latest
                .as_ref()
                .map(|trusted| &trusted.checkpoint)
                .ok_or(Error::Unavailable),
            TrustStatus::Expired => Err(Error::TrustExpired),
            TrustStatus::Conflict => Err(Error::Conflict),
            TrustStatus::NeedsCheckpoint | TrustStatus::NotYetValid => Err(Error::Unavailable),
        }
    }

    fn accept_monotonic(&mut self, checkpoint: Checkpoint) -> Result<()> {
        if let Some(latest) = &self.latest {
            if checkpoint.header_height < latest.checkpoint.header_height {
                return Err(Error::NonMonotonic);
            }
            if checkpoint.header_height == latest.checkpoint.header_height {
                if checkpoint == latest.checkpoint {
                    return Ok(());
                }
                if checkpoint.header_hash != latest.checkpoint.header_hash
                    || checkpoint.app_hash != latest.checkpoint.app_hash
                {
                    self.conflicted = true;
                    return Err(Error::Conflict);
                }
                return Err(Error::NonMonotonic);
            }
        }
        self.latest = Some(TrustedCheckpoint {
            checkpoint,
            warning_seconds: self.active_policy.expiry_warning_seconds,
        });
        Ok(())
    }
}

fn require_usable(
    checkpoint: &Checkpoint,
    policy: &CheckpointPolicy,
    now_seconds: u64,
) -> Result<()> {
    match checkpoint.status(policy, now_seconds)? {
        TrustStatus::Current | TrustStatus::ExpiringSoon => Ok(()),
        TrustStatus::Expired => Err(Error::IncomingExpired),
        TrustStatus::NotYetValid | TrustStatus::NeedsCheckpoint | TrustStatus::Conflict => {
            Err(Error::NotYetValid)
        }
    }
}

fn status_at(
    issued_at_seconds: u64,
    expires_at_seconds: u64,
    warning_seconds: u64,
    now_seconds: u64,
) -> Result<TrustStatus> {
    if now_seconds < issued_at_seconds {
        return Err(Error::NotYetValid);
    }
    if now_seconds >= expires_at_seconds {
        return Ok(TrustStatus::Expired);
    }
    if expires_at_seconds - now_seconds <= warning_seconds {
        Ok(TrustStatus::ExpiringSoon)
    } else {
        Ok(TrustStatus::Current)
    }
}

fn validate_signer_set(
    threshold: u16,
    signers: &[Hash32],
    invalid: fn(&'static str) -> Error,
) -> Result<()> {
    if signers.is_empty() || signers.len() > MAX_PUBLISHERS {
        return Err(invalid("signer set is empty or too large"));
    }
    if threshold == 0 || usize::from(threshold) > signers.len() {
        return Err(invalid("signature threshold is outside signer set"));
    }
    require_sorted_unique(signers.iter().copied(), invalid)?;
    for signer in signers {
        Ed25519VerificationKey::try_from(*signer)
            .map_err(|_| invalid("invalid Ed25519 public key"))?;
    }
    Ok(())
}

fn validate_signature_entries(
    signatures: &[SignatureEntry],
    invalid: fn(&'static str) -> Error,
) -> Result<()> {
    if signatures.len() > MAX_PUBLISHERS {
        return Err(invalid("too many signatures"));
    }
    require_sorted_unique(signatures.iter().map(|entry| entry.signer_pubkey), invalid)
}

fn verify_signatures(
    signatures: &[SignatureEntry],
    authorized: &[Hash32],
    message: &[u8],
    invalid: fn(&'static str) -> Error,
) -> Result<usize> {
    validate_signature_entries(signatures, invalid)?;
    let authorized: BTreeSet<_> = authorized.iter().copied().collect();
    for entry in signatures {
        if !authorized.contains(&entry.signer_pubkey) {
            return Err(invalid("unauthorized signer"));
        }
        let key = Ed25519VerificationKey::try_from(entry.signer_pubkey)
            .map_err(|_| invalid("invalid signer public key"))?;
        let signature = Ed25519Signature::try_from(entry.signature.as_slice())
            .map_err(|_| invalid("invalid signature encoding"))?;
        key.verify(&signature, message)
            .map_err(|_| invalid("signature verification failed"))?;
    }
    Ok(signatures.len())
}

fn add_signature(
    signatures: &mut Vec<SignatureEntry>,
    authorized: &[Hash32],
    message: &[u8],
    secret_key: [u8; 32],
    invalid: fn(&'static str) -> Error,
) -> Result<Hash32> {
    let mut secret_key = secret_key;
    let signing_key = SigningKey::from(secret_key);
    secret_key.fill(0);
    let signer_pubkey = signing_key.verification_key().to_bytes();
    if !authorized.contains(&signer_pubkey) {
        return Err(invalid("secret key is not authorized"));
    }
    if signatures
        .iter()
        .any(|entry| entry.signer_pubkey == signer_pubkey)
    {
        return Err(invalid("signer already signed"));
    }
    signatures.push(SignatureEntry {
        signer_pubkey,
        signature: signing_key.sign(message).to_bytes(),
    });
    signatures.sort_by_key(|entry| entry.signer_pubkey);
    Ok(signer_pubkey)
}

fn encode_signatures(writer: &mut Writer, signatures: &[SignatureEntry]) {
    writer.array(signatures.len());
    for entry in signatures {
        writer.array(2);
        writer.bytes(&entry.signer_pubkey);
        writer.bytes(&entry.signature);
    }
}

fn decode_signatures(
    cursor: &mut Cursor<'_>,
    invalid: fn(&'static str) -> Error,
) -> Result<Vec<SignatureEntry>> {
    let count = bounded_count(map_cbor(cursor.array())?)?;
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        if map_cbor(cursor.array())? != 2 {
            return Err(invalid("signature entry field count"));
        }
        signatures.push(SignatureEntry {
            signer_pubkey: fixed32(map_cbor(cursor.bytes())?, "signature public key length")?,
            signature: fixed64(map_cbor(cursor.bytes())?, "signature length")?,
        });
    }
    validate_signature_entries(&signatures, invalid)?;
    Ok(signatures)
}

fn require_sorted_unique(
    values: impl IntoIterator<Item = Hash32>,
    invalid: fn(&'static str) -> Error,
) -> Result<()> {
    let mut previous = None;
    for value in values {
        if previous.is_some_and(|prior| prior >= value) {
            return Err(invalid("entries must be strictly sorted and unique"));
        }
        previous = Some(value);
    }
    Ok(())
}

fn bounded_count(count: usize) -> Result<usize> {
    if count > MAX_PUBLISHERS {
        Err(Error::InvalidCbor("collection exceeds maximum size"))
    } else {
        Ok(count)
    }
}

fn require_size(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_CHECKPOINT_BYTES {
        Err(Error::InvalidCbor("artifact is empty or exceeds 1 MiB"))
    } else {
        Ok(())
    }
}

fn map_cbor<T>(result: bit_types::Result<T>) -> Result<T> {
    result.map_err(|error| match error {
        bit_types::Error::InvalidCbor(reason) => Error::InvalidCbor(reason),
        _ => Error::InvalidCbor("unexpected CBOR error"),
    })
}

fn fixed32(bytes: Vec<u8>, reason: &'static str) -> Result<Hash32> {
    bytes.try_into().map_err(|_| Error::InvalidCbor(reason))
}

fn fixed64(bytes: Vec<u8>, reason: &'static str) -> Result<[u8; 64]> {
    bytes.try_into().map_err(|_| Error::InvalidCbor(reason))
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const ACTIVATION: u64 = 1_900_000_000;
    const TRUST_PERIOD: u64 = 259_200;
    const WARNING: u64 = 43_200;
    const UNBONDING: u64 = 1_814_400;

    fn key(seed: u8) -> (SigningKey, Hash32) {
        let signing = SigningKey::from([seed; 32]);
        let public = signing.verification_key().to_bytes();
        (signing, public)
    }

    fn authority() -> AuthorityPolicy {
        let mut signers = vec![key(5).1, key(6).1];
        signers.sort();
        AuthorityPolicy {
            threshold: 2,
            signers,
        }
    }

    fn policy() -> CheckpointPolicy {
        let mut publishers = vec![key(7).1, key(8).1, key(9).1];
        publishers.sort();
        CheckpointPolicy {
            genesis_manifest_hash: [0x11; 32],
            chain_context: [0x22; 32],
            consensus_parameters_sha256: [0x33; 32],
            sequence: 1,
            previous_policy_hash: None,
            activates_at_seconds: ACTIVATION,
            trust_period_seconds: TRUST_PERIOD,
            expiry_warning_seconds: WARNING,
            threshold: 2,
            publishers,
            revoke_previous_immediately: false,
        }
    }

    fn approved_policy(policy: &CheckpointPolicy) -> PolicySignaturePackage {
        let authority = authority();
        let mut package = PolicySignaturePackage {
            genesis_manifest_hash: policy.genesis_manifest_hash,
            policy_hash: policy.hash().unwrap(),
            approvals: Vec::new(),
        };
        package.add_signature(policy, &authority, [5; 32]).unwrap();
        package.add_signature(policy, &authority, [6; 32]).unwrap();
        package
    }

    fn checkpoint(policy: &CheckpointPolicy, height: u64, issued: u64) -> Checkpoint {
        Checkpoint {
            policy_hash: policy.hash().unwrap(),
            genesis_manifest_hash: policy.genesis_manifest_hash,
            chain_context: policy.chain_context,
            header_height: height,
            header_hash: domain_hash(b"header", &height.to_be_bytes()),
            state_height: height - 1,
            app_hash: domain_hash(b"app", &height.to_be_bytes()),
            issued_at_seconds: issued,
            expires_at_seconds: issued + TRUST_PERIOD,
        }
    }

    fn signed_checkpoint(policy: &CheckpointPolicy, height: u64, issued: u64) -> SignedCheckpoint {
        let mut signed = SignedCheckpoint {
            checkpoint: checkpoint(policy, height, issued),
            signatures: Vec::new(),
        };
        signed.add_signature(policy, [7; 32]).unwrap();
        signed.add_signature(policy, [8; 32]).unwrap();
        signed
    }

    #[test]
    fn policy_and_checkpoint_round_trip_with_threshold_signatures() {
        let policy = policy();
        policy.validate_safety(UNBONDING).unwrap();
        let policy_bytes = policy.encode_canonical().unwrap();
        assert_eq!(
            CheckpointPolicy::decode_canonical(&policy_bytes).unwrap(),
            policy
        );

        let approvals = approved_policy(&policy);
        assert_eq!(approvals.verify(&policy, &authority()).unwrap(), 2);
        let approval_bytes = approvals.encode_canonical().unwrap();
        assert_eq!(
            PolicySignaturePackage::decode_canonical(&approval_bytes).unwrap(),
            approvals
        );

        let signed = signed_checkpoint(&policy, 100, ACTIVATION + 100);
        assert_eq!(signed.verify(&policy).unwrap(), 2);
        let bytes = signed.encode_canonical().unwrap();
        assert_eq!(SignedCheckpoint::decode_canonical(&bytes).unwrap(), signed);
    }

    #[test]
    fn policy_is_bound_and_trust_period_is_strictly_shorter_than_unbonding() {
        let mut policy = policy();
        assert!(policy.validate_safety(TRUST_PERIOD).is_err());
        assert!(policy.validate_safety(TRUST_PERIOD + 1).is_ok());
        assert!(policy
            .verify_binding(&[0x11; 32], &[0x22; 32], &[0x33; 32])
            .is_ok());
        assert!(policy
            .verify_binding(&[0x10; 32], &[0x22; 32], &[0x33; 32])
            .is_err());
        policy.publishers.swap(0, 1);
        assert!(policy.validate().is_err());
    }

    #[test]
    fn threshold_and_tampering_are_rejected() {
        let policy = policy();
        let mut signed = signed_checkpoint(&policy, 100, ACTIVATION + 100);
        signed.signatures.pop();
        assert!(signed.verify(&policy).is_err());

        let mut signed = signed_checkpoint(&policy, 100, ACTIVATION + 100);
        signed.checkpoint.app_hash[0] ^= 1;
        assert!(signed.verify(&policy).is_err());

        let mut approvals = approved_policy(&policy);
        approvals.policy_hash[0] ^= 1;
        assert!(approvals.verify(&policy, &authority()).is_err());
    }

    #[test]
    fn lifecycle_warns_expires_and_requires_explicit_reestablishment() {
        let policy = policy();
        let approvals = approved_policy(&policy);
        let mut trust =
            TrustStore::install_initial_policy(policy.clone(), &approvals, &authority(), UNBONDING)
                .unwrap();
        assert_eq!(trust.status(ACTIVATION), TrustStatus::NeedsCheckpoint);

        let first = signed_checkpoint(&policy, 100, ACTIVATION + 100);
        assert_eq!(
            trust.import_checkpoint(&first, ACTIVATION + 101).unwrap(),
            TrustStatus::Current
        );
        let warning_at = first.checkpoint.expires_at_seconds - WARNING;
        assert_eq!(trust.status(warning_at), TrustStatus::ExpiringSoon);
        assert_eq!(
            trust.status(first.checkpoint.expires_at_seconds),
            TrustStatus::Expired
        );

        let second = signed_checkpoint(&policy, 200, first.checkpoint.expires_at_seconds + 10);
        assert_eq!(
            trust.import_checkpoint(&second, second.checkpoint.issued_at_seconds),
            Err(Error::TrustExpired)
        );
        assert_eq!(
            trust.reestablish(&second, [0; 32], second.checkpoint.issued_at_seconds),
            Err(Error::ConfirmationMismatch)
        );
        let confirmed = second.checkpoint.hash().unwrap();
        assert_eq!(
            trust
                .reestablish(&second, confirmed, second.checkpoint.issued_at_seconds)
                .unwrap(),
            TrustStatus::Current
        );
    }

    #[test]
    fn conflicts_halt_trust_until_exact_manual_reestablishment() {
        let policy = policy();
        let mut trust = TrustStore::install_initial_policy(
            policy.clone(),
            &approved_policy(&policy),
            &authority(),
            UNBONDING,
        )
        .unwrap();
        let first = signed_checkpoint(&policy, 100, ACTIVATION + 100);
        trust
            .import_checkpoint(&first, first.checkpoint.issued_at_seconds)
            .unwrap();
        let mut conflict = signed_checkpoint(&policy, 100, ACTIVATION + 101);
        conflict.checkpoint.header_hash = [0x88; 32];
        conflict.signatures.clear();
        conflict.add_signature(&policy, [7; 32]).unwrap();
        conflict.add_signature(&policy, [8; 32]).unwrap();
        assert_eq!(
            trust.import_checkpoint(&conflict, conflict.checkpoint.issued_at_seconds),
            Err(Error::Conflict)
        );
        assert_eq!(
            trust.status(conflict.checkpoint.issued_at_seconds),
            TrustStatus::Conflict
        );
        let newer = signed_checkpoint(&policy, 101, ACTIVATION + 102);
        assert_eq!(
            trust.import_checkpoint(&newer, newer.checkpoint.issued_at_seconds),
            Err(Error::Conflict)
        );
        let confirmed = newer.checkpoint.hash().unwrap();
        trust
            .reestablish(&newer, confirmed, newer.checkpoint.issued_at_seconds)
            .unwrap();
        assert_eq!(
            trust.status(newer.checkpoint.issued_at_seconds),
            TrustStatus::Current
        );
    }

    #[test]
    fn rotation_requires_an_approved_contiguous_hash_chain_and_can_revoke() {
        let initial = policy();
        let mut trust = TrustStore::install_initial_policy(
            initial.clone(),
            &approved_policy(&initial),
            &authority(),
            UNBONDING,
        )
        .unwrap();
        let first = signed_checkpoint(&initial, 100, ACTIVATION + 100);
        trust
            .import_checkpoint(&first, first.checkpoint.issued_at_seconds)
            .unwrap();

        let mut next = initial.clone();
        next.sequence = 2;
        next.previous_policy_hash = Some(initial.hash().unwrap());
        next.activates_at_seconds = ACTIVATION + 1_000;
        next.publishers = vec![key(10).1, key(11).1];
        next.publishers.sort();
        next.revoke_previous_immediately = true;
        let approvals = approved_policy(&next);
        assert!(trust
            .rotate_policy(
                next.clone(),
                &approvals,
                &authority(),
                UNBONDING,
                next.activates_at_seconds - 1,
            )
            .is_err());
        trust
            .rotate_policy(
                next.clone(),
                &approvals,
                &authority(),
                UNBONDING,
                next.activates_at_seconds,
            )
            .unwrap();
        assert_eq!(trust.active_policy(), &next);
        assert_eq!(
            trust.status(next.activates_at_seconds),
            TrustStatus::NeedsCheckpoint
        );
    }

    #[test]
    fn golden_vector_freezes_encoding_hashes_messages_and_signatures() {
        let vector: Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/checkpoint-vectors.json"
        ))
        .unwrap();
        let policy = policy();
        let policy_hash = policy.hash().unwrap();
        assert_eq!(
            hex::encode(policy.encode_canonical().unwrap()),
            vector["initial_policy"]["canonical_cbor_hex"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            hex::encode(policy_hash),
            vector["initial_policy"]["policy_hash_hex"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            hex::encode(policy_approval_message(
                &policy.genesis_manifest_hash,
                &policy_hash
            )),
            vector["initial_policy"]["approval_message_hex"]
                .as_str()
                .unwrap()
        );
        let approval_bytes = hex::decode(
            vector["initial_policy"]["threshold_approvals_cbor_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        PolicySignaturePackage::decode_canonical(&approval_bytes)
            .unwrap()
            .verify(&policy, &authority())
            .unwrap();

        let checkpoint = Checkpoint {
            policy_hash,
            genesis_manifest_hash: policy.genesis_manifest_hash,
            chain_context: policy.chain_context,
            header_height: 100,
            header_hash: [0x44; 32],
            state_height: 99,
            app_hash: [0x55; 32],
            issued_at_seconds: 1_900_000_100,
            expires_at_seconds: 1_900_259_300,
        };
        let checkpoint_hash = checkpoint.hash().unwrap();
        assert_eq!(
            hex::encode(checkpoint.encode_canonical().unwrap()),
            vector["checkpoint"]["canonical_cbor_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(checkpoint_hash),
            vector["checkpoint"]["checkpoint_hash_hex"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            hex::encode(checkpoint_signature_message(&policy_hash, &checkpoint_hash)),
            vector["checkpoint"]["signature_message_hex"]
                .as_str()
                .unwrap()
        );
        let signed_bytes = hex::decode(
            vector["checkpoint"]["threshold_signed_cbor_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let signed = SignedCheckpoint::decode_canonical(&signed_bytes).unwrap();
        assert_eq!(signed.checkpoint, checkpoint);
        signed.verify(&policy).unwrap();
    }
}
