//! Canonical BIT genesis identity manifests and multi-party approvals.
//!
//! Identity inputs are encoded before `chain_context` and height-zero state are
//! derived.  Human descriptions and derived identifiers are deliberately not
//! part of this format.

use bit_types::{chain_context, Amount, MonetaryPolicy, MAX_SUPPLY_ATOMIC};
use ed25519_consensus::{
    Signature as Ed25519Signature, SigningKey, VerificationKey as Ed25519VerificationKey,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub type Hash32 = [u8; 32];

pub const IDENTITY_FORMAT: &str = "BIT-GENESIS-IDENTITY";
pub const IDENTITY_VERSION: u64 = 1;
pub const IDENTITY_HASH_DOMAIN: &[u8] = b"BIT-GENESIS-IDENTITY-V1";
pub const APPROVAL_FORMAT: &str = "BIT-GENESIS-SIGNATURES";
pub const APPROVAL_VERSION: u64 = 1;
pub const APPROVAL_DOMAIN: &[u8] = b"BIT-GENESIS-APPROVAL-V1";
pub const MAX_IDENTITY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_GENESIS_ENTRIES: usize = 100_000;
pub const MAX_APPROVAL_SIGNERS: usize = 1_024;
pub const MAX_SIGNATURE_PACKAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid genesis identity: {0}")]
    InvalidIdentity(&'static str),
    #[error("invalid canonical CBOR: {0}")]
    InvalidCbor(&'static str),
    #[error("invalid signature package: {0}")]
    InvalidSignaturePackage(&'static str),
    #[error("invalid hex field {field}: {reason}")]
    InvalidHex {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid monetary policy: {0}")]
    Policy(#[from] bit_types::Error),
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum AllocationKind {
    GenesisClaim = 1,
    ShieldedCommitment = 2,
    ValidatorSelfBond = 3,
    FeeReserve = 4,
}

impl AllocationKind {
    fn from_tag(tag: u64) -> Result<Self> {
        match tag {
            1 => Ok(Self::GenesisClaim),
            2 => Ok(Self::ShieldedCommitment),
            3 => Ok(Self::ValidatorSelfBond),
            4 => Ok(Self::FeeReserve),
            _ => Err(Error::InvalidIdentity("unknown allocation kind")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Allocation {
    pub allocation_id: Hash32,
    pub kind: AllocationKind,
    pub amount: Amount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimInput {
    pub allocation_id: Hash32,
    pub claim_pubkey: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentInput {
    pub allocation_id: Hash32,
    pub commitment: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorInput {
    pub allocation_id: Hash32,
    pub operator_pubkey: Hash32,
    pub consensus_pubkey: Hash32,
    pub owner_pubkey: Hash32,
    pub commission_bps: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalPolicy {
    pub threshold: u16,
    pub signers: Vec<Hash32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    pub protocol_version: u64,
    pub max_block_bytes: u64,
    pub max_tx_lifetime_blocks: u64,
    pub max_envelope_bytes: u64,
    pub anchor_retention_blocks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisIdentityManifest {
    pub chain_id: String,
    pub genesis_time_unix_seconds: u64,
    pub source_commit: Vec<u8>,
    pub crypto_manifest_sha256: Hash32,
    pub consensus_parameters_sha256: Hash32,
    pub native_asset_id: Hash32,
    pub key_derivation_version: String,
    pub address_encoding_version: String,
    pub resource_limits: ResourceLimits,
    pub monetary_policy: MonetaryPolicy,
    pub allocations: Vec<Allocation>,
    pub claims: Vec<ClaimInput>,
    pub commitments: Vec<CommitmentInput>,
    pub validators: Vec<ValidatorInput>,
    pub approval_policy: ApprovalPolicy,
}

impl GenesisIdentityManifest {
    pub fn validate(&self) -> Result<()> {
        validate_text(&self.chain_id, 64, "invalid chain_id")?;
        if !self
            .chain_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(Error::InvalidIdentity("invalid chain_id"));
        }
        if self.genesis_time_unix_seconds == 0 || self.genesis_time_unix_seconds > i64::MAX as u64 {
            return Err(Error::InvalidIdentity(
                "genesis time must be in 1..=i64::MAX",
            ));
        }
        if !matches!(self.source_commit.len(), 20 | 32) {
            return Err(Error::InvalidIdentity(
                "source commit must contain 20 or 32 bytes",
            ));
        }
        if self.source_commit.iter().all(|byte| *byte == 0) {
            return Err(Error::InvalidIdentity("source commit is zero"));
        }
        for value in [
            self.crypto_manifest_sha256,
            self.consensus_parameters_sha256,
            self.native_asset_id,
        ] {
            if value == [0; 32] {
                return Err(Error::InvalidIdentity("identity hash field is zero"));
            }
        }
        validate_text(
            &self.key_derivation_version,
            64,
            "invalid key derivation version",
        )?;
        validate_text(
            &self.address_encoding_version,
            64,
            "invalid address encoding version",
        )?;
        if self.resource_limits.protocol_version == 0
            || self.resource_limits.max_block_bytes == 0
            || self.resource_limits.max_tx_lifetime_blocks == 0
            || self.resource_limits.max_envelope_bytes == 0
            || self.resource_limits.anchor_retention_blocks == 0
        {
            return Err(Error::InvalidIdentity("resource limits must be positive"));
        }
        if self.resource_limits.max_envelope_bytes > self.resource_limits.max_block_bytes {
            return Err(Error::InvalidIdentity(
                "maximum envelope size exceeds maximum block size",
            ));
        }
        self.monetary_policy.validate()?;

        if self.allocations.is_empty() {
            return Err(Error::InvalidIdentity("allocation list is empty"));
        }
        if self.allocations.len() > MAX_GENESIS_ENTRIES {
            return Err(Error::InvalidIdentity("too many allocations"));
        }
        require_sorted_unique(
            self.allocations.iter().map(|entry| entry.allocation_id),
            "allocations must be strictly sorted by allocation_id",
        )?;
        let mut allocation_map = BTreeMap::new();
        let mut total = 0u128;
        let mut fee_reserves = 0usize;
        for entry in &self.allocations {
            if entry.allocation_id == [0; 32] || entry.amount == Amount::ZERO {
                return Err(Error::InvalidIdentity("allocation id or amount is zero"));
            }
            total = total
                .checked_add(entry.amount.value())
                .ok_or(Error::InvalidIdentity("allocation sum overflow"))?;
            if entry.kind == AllocationKind::FeeReserve {
                fee_reserves += 1;
            }
            allocation_map.insert(entry.allocation_id, (entry.kind, entry.amount));
        }
        if total != self.monetary_policy.genesis_supply.value() {
            return Err(Error::InvalidIdentity(
                "allocation sum does not equal genesis supply",
            ));
        }
        if total >= MAX_SUPPLY_ATOMIC || fee_reserves > 1 {
            return Err(Error::InvalidIdentity("invalid genesis allocation set"));
        }

        if self.claims.len() > MAX_GENESIS_ENTRIES
            || self.commitments.len() > MAX_GENESIS_ENTRIES
            || self.validators.len() > MAX_GENESIS_ENTRIES
        {
            return Err(Error::InvalidIdentity("too many genesis entries"));
        }
        require_sorted_unique(
            self.claims.iter().map(|entry| entry.allocation_id),
            "claims must be strictly sorted by allocation_id",
        )?;
        require_sorted_unique(
            self.commitments.iter().map(|entry| entry.allocation_id),
            "commitments must be strictly sorted by allocation_id",
        )?;
        require_sorted_unique(
            self.validators.iter().map(|entry| entry.allocation_id),
            "validators must be strictly sorted by allocation_id",
        )?;

        let mut mapped = BTreeSet::new();
        let mut claim_keys = BTreeSet::new();
        for claim in &self.claims {
            require_allocation_kind(
                &allocation_map,
                claim.allocation_id,
                AllocationKind::GenesisClaim,
            )?;
            validate_ed25519(&claim.claim_pubkey, "invalid claim public key")?;
            if !mapped.insert(claim.allocation_id) || !claim_keys.insert(claim.claim_pubkey) {
                return Err(Error::InvalidIdentity(
                    "duplicate claim mapping or public key",
                ));
            }
        }

        let mut commitment_values = BTreeSet::new();
        for commitment in &self.commitments {
            require_allocation_kind(
                &allocation_map,
                commitment.allocation_id,
                AllocationKind::ShieldedCommitment,
            )?;
            if commitment.commitment == [0; 32]
                || !mapped.insert(commitment.allocation_id)
                || !commitment_values.insert(commitment.commitment)
            {
                return Err(Error::InvalidIdentity(
                    "duplicate or zero shielded commitment",
                ));
            }
        }

        if self.validators.is_empty() {
            return Err(Error::InvalidIdentity("initial validator list is empty"));
        }
        let mut operators = BTreeSet::new();
        let mut consensus_keys = BTreeSet::new();
        let mut owners = BTreeSet::new();
        for validator in &self.validators {
            require_allocation_kind(
                &allocation_map,
                validator.allocation_id,
                AllocationKind::ValidatorSelfBond,
            )?;
            validate_ed25519(&validator.operator_pubkey, "invalid validator operator key")?;
            validate_ed25519(
                &validator.consensus_pubkey,
                "invalid validator consensus key",
            )?;
            validate_ed25519(&validator.owner_pubkey, "invalid self-bond owner key")?;
            if validator.commission_bps > 10_000
                || !mapped.insert(validator.allocation_id)
                || !operators.insert(validator.operator_pubkey)
                || !consensus_keys.insert(validator.consensus_pubkey)
                || !owners.insert(validator.owner_pubkey)
            {
                return Err(Error::InvalidIdentity(
                    "invalid or duplicate initial validator",
                ));
            }
        }

        for allocation in &self.allocations {
            if allocation.kind != AllocationKind::FeeReserve
                && !mapped.contains(&allocation.allocation_id)
            {
                return Err(Error::InvalidIdentity(
                    "allocation is not mapped to exactly one genesis target",
                ));
            }
        }

        if self.approval_policy.signers.is_empty()
            || self.approval_policy.signers.len() > MAX_APPROVAL_SIGNERS
            || self.approval_policy.threshold == 0
            || usize::from(self.approval_policy.threshold) > self.approval_policy.signers.len()
        {
            return Err(Error::InvalidIdentity("invalid approval threshold"));
        }
        require_sorted_unique(
            self.approval_policy.signers.iter().copied(),
            "approval signers must be strictly sorted",
        )?;
        for signer in &self.approval_policy.signers {
            validate_ed25519(signer, "invalid approval public key")?;
        }
        Ok(())
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.array(16);
        writer.text(IDENTITY_FORMAT);
        writer.uint(IDENTITY_VERSION);
        writer.text(&self.chain_id);
        writer.uint(self.genesis_time_unix_seconds);
        writer.bytes(&self.source_commit);
        writer.bytes(&self.crypto_manifest_sha256);
        writer.bytes(&self.consensus_parameters_sha256);
        writer.bytes(&self.native_asset_id);
        writer.text(&self.key_derivation_version);
        writer.text(&self.address_encoding_version);
        encode_resource_limits(&mut writer, &self.resource_limits);
        writer.bytes(&self.monetary_policy.encode_canonical()?);
        encode_allocations(&mut writer, &self.allocations);
        encode_claims(&mut writer, &self.claims);
        encode_commitments(&mut writer, &self.commitments);
        encode_validators_and_policy(&mut writer, &self.validators, &self.approval_policy);
        let bytes = writer.finish();
        if bytes.len() > MAX_IDENTITY_BYTES {
            return Err(Error::InvalidIdentity("identity exceeds maximum size"));
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_IDENTITY_BYTES {
            return Err(Error::InvalidCbor("identity exceeds maximum size"));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.array()? != 16
            || cursor.text()? != IDENTITY_FORMAT
            || cursor.uint()? != IDENTITY_VERSION
        {
            return Err(Error::InvalidIdentity(
                "unknown identity format or field count",
            ));
        }
        let chain_id = cursor.text()?;
        let genesis_time_unix_seconds = cursor.uint()?;
        let source_commit = cursor.bytes()?;
        let crypto_manifest_sha256 = fixed32(cursor.bytes()?, "crypto manifest hash length")?;
        let consensus_parameters_sha256 =
            fixed32(cursor.bytes()?, "consensus parameters hash length")?;
        let native_asset_id = fixed32(cursor.bytes()?, "native asset id length")?;
        let key_derivation_version = cursor.text()?;
        let address_encoding_version = cursor.text()?;
        let resource_limits = decode_resource_limits(&mut cursor)?;
        let monetary_policy = MonetaryPolicy::decode_canonical(&cursor.bytes()?)?;
        let allocations = decode_allocations(&mut cursor)?;
        let claims = decode_claims(&mut cursor)?;
        let commitments = decode_commitments(&mut cursor)?;
        let (validators, approval_policy) = decode_validators_and_policy(&mut cursor)?;
        cursor.finish()?;
        let manifest = Self {
            chain_id,
            genesis_time_unix_seconds,
            source_commit,
            crypto_manifest_sha256,
            consensus_parameters_sha256,
            native_asset_id,
            key_derivation_version,
            address_encoding_version,
            resource_limits,
            monetary_policy,
            allocations,
            claims,
            commitments,
            validators,
            approval_policy,
        };
        manifest.validate()?;
        if manifest.encode_canonical()?.as_slice() != bytes {
            return Err(Error::InvalidCbor(
                "identity does not round-trip canonically",
            ));
        }
        Ok(manifest)
    }

    pub fn hash(&self) -> Result<Hash32> {
        let bytes = self.encode_canonical()?;
        let mut hash = Sha256::new();
        hash.update(IDENTITY_HASH_DOMAIN);
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
        Ok(hash.finalize().into())
    }

    pub fn chain_context(&self) -> Result<Hash32> {
        Ok(chain_context(self.hash()?))
    }

    pub fn allocation_totals(&self) -> Result<AllocationTotals> {
        self.validate()?;
        let mut totals = AllocationTotals::default();
        for allocation in &self.allocations {
            let target = match allocation.kind {
                AllocationKind::GenesisClaim => &mut totals.genesis_claims,
                AllocationKind::ShieldedCommitment => &mut totals.shielded_commitments,
                AllocationKind::ValidatorSelfBond => &mut totals.validator_self_bonds,
                AllocationKind::FeeReserve => &mut totals.fee_reserve,
            };
            *target = target
                .checked_add(allocation.amount.value())
                .ok_or(Error::InvalidIdentity("allocation sum overflow"))?;
        }
        Ok(totals)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationTotals {
    pub genesis_claims: u128,
    pub shielded_commitments: u128,
    pub validator_self_bonds: u128,
    pub fee_reserve: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Approval {
    pub signer_pubkey: Hash32,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignaturePackage {
    pub manifest_hash: Hash32,
    pub approvals: Vec<Approval>,
}

impl SignaturePackage {
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        if self.approvals.len() > MAX_APPROVAL_SIGNERS {
            return Err(Error::InvalidSignaturePackage("too many approvals"));
        }
        require_sorted_unique(
            self.approvals.iter().map(|approval| approval.signer_pubkey),
            "signature approvals must be strictly sorted",
        )
        .map_err(|_| Error::InvalidSignaturePackage("duplicate or unsorted approvals"))?;
        let mut writer = Writer::new();
        writer.array(4);
        writer.text(APPROVAL_FORMAT);
        writer.uint(APPROVAL_VERSION);
        writer.bytes(&self.manifest_hash);
        writer.array(self.approvals.len());
        for approval in &self.approvals {
            writer.array(2);
            writer.bytes(&approval.signer_pubkey);
            writer.bytes(&approval.signature);
        }
        let bytes = writer.finish();
        if bytes.len() > MAX_SIGNATURE_PACKAGE_BYTES {
            return Err(Error::InvalidSignaturePackage(
                "signature package exceeds maximum size",
            ));
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SIGNATURE_PACKAGE_BYTES {
            return Err(Error::InvalidCbor("signature package exceeds maximum size"));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.array()? != 4
            || cursor.text()? != APPROVAL_FORMAT
            || cursor.uint()? != APPROVAL_VERSION
        {
            return Err(Error::InvalidSignaturePackage(
                "unknown signature package format",
            ));
        }
        let manifest_hash = fixed32(cursor.bytes()?, "manifest hash length")?;
        let count = bounded_count(cursor.array()?, MAX_APPROVAL_SIGNERS, "too many approvals")?;
        let mut approvals = Vec::with_capacity(count);
        for _ in 0..count {
            if cursor.array()? != 2 {
                return Err(Error::InvalidSignaturePackage("approval field count"));
            }
            approvals.push(Approval {
                signer_pubkey: fixed32(cursor.bytes()?, "approval public key length")?,
                signature: fixed64(cursor.bytes()?, "approval signature length")?,
            });
        }
        cursor.finish()?;
        let package = Self {
            manifest_hash,
            approvals,
        };
        if package.encode_canonical()?.as_slice() != bytes {
            return Err(Error::InvalidCbor(
                "signature package does not round-trip canonically",
            ));
        }
        Ok(package)
    }

    pub fn verify(&self, manifest: &GenesisIdentityManifest) -> Result<usize> {
        let count = self.verify_partial(manifest)?;
        if count < usize::from(manifest.approval_policy.threshold) {
            return Err(Error::InvalidSignaturePackage(
                "approval threshold is not satisfied",
            ));
        }
        Ok(count)
    }

    pub fn verify_partial(&self, manifest: &GenesisIdentityManifest) -> Result<usize> {
        let expected_hash = manifest.hash()?;
        if self.manifest_hash != expected_hash {
            return Err(Error::InvalidSignaturePackage("manifest hash mismatch"));
        }
        require_sorted_unique(
            self.approvals.iter().map(|approval| approval.signer_pubkey),
            "signature approvals must be strictly sorted",
        )
        .map_err(|_| Error::InvalidSignaturePackage("duplicate or unsorted approvals"))?;
        let authorized: BTreeSet<_> = manifest.approval_policy.signers.iter().copied().collect();
        let message = approval_message(&expected_hash);
        for approval in &self.approvals {
            if !authorized.contains(&approval.signer_pubkey) {
                return Err(Error::InvalidSignaturePackage("unauthorized signer"));
            }
            let key = Ed25519VerificationKey::try_from(approval.signer_pubkey)
                .map_err(|_| Error::InvalidSignaturePackage("invalid signer public key"))?;
            let signature = Ed25519Signature::try_from(approval.signature.as_slice())
                .map_err(|_| Error::InvalidSignaturePackage("invalid signature encoding"))?;
            key.verify(&signature, &message)
                .map_err(|_| Error::InvalidSignaturePackage("signature verification failed"))?;
        }
        Ok(self.approvals.len())
    }

    pub fn add_signature(
        &mut self,
        manifest: &GenesisIdentityManifest,
        secret_key: [u8; 32],
    ) -> Result<Hash32> {
        let expected_hash = manifest.hash()?;
        if self.manifest_hash != expected_hash {
            return Err(Error::InvalidSignaturePackage("manifest hash mismatch"));
        }
        self.verify_partial(manifest)?;
        let signing_key = SigningKey::from(secret_key);
        let signer_pubkey = signing_key.verification_key().to_bytes();
        if !manifest.approval_policy.signers.contains(&signer_pubkey) {
            return Err(Error::InvalidSignaturePackage(
                "secret key is not an authorized signer",
            ));
        }
        if self
            .approvals
            .iter()
            .any(|approval| approval.signer_pubkey == signer_pubkey)
        {
            return Err(Error::InvalidSignaturePackage("signer already approved"));
        }
        let signature = signing_key
            .sign(&approval_message(&expected_hash))
            .to_bytes();
        self.approvals.push(Approval {
            signer_pubkey,
            signature,
        });
        self.approvals
            .sort_by_key(|approval| approval.signer_pubkey);
        Ok(signer_pubkey)
    }
}

pub fn approval_message(manifest_hash: &Hash32) -> Vec<u8> {
    let mut message = Vec::with_capacity(APPROVAL_DOMAIN.len() + 32);
    message.extend_from_slice(APPROVAL_DOMAIN);
    message.extend_from_slice(manifest_hash);
    message
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityInputDocument {
    pub chain_id: String,
    pub genesis_time_unix_seconds: u64,
    pub source_commit: String,
    pub crypto_manifest_sha256: String,
    pub consensus_parameters_sha256: String,
    pub native_asset_id: String,
    pub key_derivation_version: String,
    pub address_encoding_version: String,
    pub resource_limits: ResourceLimitsDocument,
    pub monetary_policy: MonetaryPolicyDocument,
    pub allocations: Vec<AllocationDocument>,
    pub genesis_claims: Vec<ClaimDocument>,
    pub genesis_commitments: Vec<CommitmentDocument>,
    pub initial_validators: Vec<ValidatorDocument>,
    pub approval_policy: ApprovalPolicyDocument,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimitsDocument {
    pub protocol_version: u64,
    pub max_block_bytes: u64,
    pub max_tx_lifetime_blocks: u64,
    pub max_envelope_bytes: u64,
    pub anchor_retention_blocks: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonetaryPolicyDocument {
    pub policy_id: String,
    pub max_supply_atomic: String,
    pub decimals: u8,
    pub genesis_supply_atomic: Amount,
    pub epoch_blocks: u64,
    pub halving_interval_epochs: u64,
    pub empty_set_policy: String,
    pub burn_reopens_issuance: bool,
    pub tail_emission_enabled: bool,
    pub monetary_policy_hash: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationDocument {
    pub allocation_id: String,
    pub kind: String,
    pub amount_atomic: Amount,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimDocument {
    pub allocation_id: String,
    pub claim_pubkey: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentDocument {
    pub allocation_id: String,
    pub commitment: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorDocument {
    pub allocation_id: String,
    pub operator_pubkey: String,
    pub consensus_pubkey: String,
    pub owner_pubkey: String,
    pub commission_bps: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPolicyDocument {
    pub threshold: u16,
    pub signers: Vec<String>,
}

impl IdentityInputDocument {
    pub fn into_manifest(self) -> Result<GenesisIdentityManifest> {
        let source_commit = decode_hex(&self.source_commit, "source_commit")?;
        let policy = MonetaryPolicy {
            genesis_supply: self.monetary_policy.genesis_supply_atomic,
            epoch_blocks: self.monetary_policy.epoch_blocks,
            halving_interval_epochs: self.monetary_policy.halving_interval_epochs,
        };
        policy.validate()?;
        if self.monetary_policy.policy_id != bit_types::POLICY_ID
            || self.monetary_policy.max_supply_atomic != MAX_SUPPLY_ATOMIC.to_string()
            || self.monetary_policy.decimals != 8
            || self.monetary_policy.empty_set_policy != bit_types::EMPTY_SET_POLICY
            || self.monetary_policy.burn_reopens_issuance
            || self.monetary_policy.tail_emission_enabled
            || parse_hash(
                &self.monetary_policy.monetary_policy_hash,
                "monetary_policy_hash",
            )? != policy.hash()?
        {
            return Err(Error::InvalidIdentity("monetary policy fields disagree"));
        }
        let allocations = self
            .allocations
            .into_iter()
            .map(|entry| {
                Ok(Allocation {
                    allocation_id: parse_hash(&entry.allocation_id, "allocation_id")?,
                    kind: match entry.kind.as_str() {
                        "GENESIS_CLAIM" => AllocationKind::GenesisClaim,
                        "SHIELDED_COMMITMENT" => AllocationKind::ShieldedCommitment,
                        "VALIDATOR_SELF_BOND" => AllocationKind::ValidatorSelfBond,
                        "FEE_RESERVE" => AllocationKind::FeeReserve,
                        _ => return Err(Error::InvalidIdentity("unknown allocation kind")),
                    },
                    amount: entry.amount_atomic,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let claims = self
            .genesis_claims
            .into_iter()
            .map(|entry| {
                Ok(ClaimInput {
                    allocation_id: parse_hash(&entry.allocation_id, "allocation_id")?,
                    claim_pubkey: parse_hash(&entry.claim_pubkey, "claim_pubkey")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let commitments = self
            .genesis_commitments
            .into_iter()
            .map(|entry| {
                Ok(CommitmentInput {
                    allocation_id: parse_hash(&entry.allocation_id, "allocation_id")?,
                    commitment: parse_hash(&entry.commitment, "commitment")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let validators = self
            .initial_validators
            .into_iter()
            .map(|entry| {
                Ok(ValidatorInput {
                    allocation_id: parse_hash(&entry.allocation_id, "allocation_id")?,
                    operator_pubkey: parse_hash(&entry.operator_pubkey, "operator_pubkey")?,
                    consensus_pubkey: parse_hash(&entry.consensus_pubkey, "consensus_pubkey")?,
                    owner_pubkey: parse_hash(&entry.owner_pubkey, "owner_pubkey")?,
                    commission_bps: entry.commission_bps,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let approval_policy = ApprovalPolicy {
            threshold: self.approval_policy.threshold,
            signers: self
                .approval_policy
                .signers
                .iter()
                .map(|value| parse_hash(value, "approval signer"))
                .collect::<Result<Vec<_>>>()?,
        };
        let manifest = GenesisIdentityManifest {
            chain_id: self.chain_id,
            genesis_time_unix_seconds: self.genesis_time_unix_seconds,
            source_commit,
            crypto_manifest_sha256: parse_hash(
                &self.crypto_manifest_sha256,
                "crypto_manifest_sha256",
            )?,
            consensus_parameters_sha256: parse_hash(
                &self.consensus_parameters_sha256,
                "consensus_parameters_sha256",
            )?,
            native_asset_id: parse_hash(&self.native_asset_id, "native_asset_id")?,
            key_derivation_version: self.key_derivation_version,
            address_encoding_version: self.address_encoding_version,
            resource_limits: ResourceLimits {
                protocol_version: self.resource_limits.protocol_version,
                max_block_bytes: self.resource_limits.max_block_bytes,
                max_tx_lifetime_blocks: self.resource_limits.max_tx_lifetime_blocks,
                max_envelope_bytes: self.resource_limits.max_envelope_bytes,
                anchor_retention_blocks: self.resource_limits.anchor_retention_blocks,
            },
            monetary_policy: policy,
            allocations,
            claims,
            commitments,
            validators,
            approval_policy,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

fn validate_text(value: &str, maximum: usize, error: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(Error::InvalidIdentity(error));
    }
    Ok(())
}

fn validate_ed25519(value: &Hash32, error: &'static str) -> Result<()> {
    Ed25519VerificationKey::try_from(*value).map_err(|_| Error::InvalidIdentity(error))?;
    Ok(())
}

fn require_sorted_unique(
    values: impl IntoIterator<Item = Hash32>,
    error: &'static str,
) -> Result<()> {
    let mut previous = None;
    for value in values {
        if previous.is_some_and(|prior| prior >= value) {
            return Err(Error::InvalidIdentity(error));
        }
        previous = Some(value);
    }
    Ok(())
}

fn require_allocation_kind(
    allocations: &BTreeMap<Hash32, (AllocationKind, Amount)>,
    allocation_id: Hash32,
    expected: AllocationKind,
) -> Result<()> {
    match allocations.get(&allocation_id) {
        Some((actual, _)) if *actual == expected => Ok(()),
        Some(_) => Err(Error::InvalidIdentity(
            "allocation kind does not match target",
        )),
        None => Err(Error::InvalidIdentity(
            "target references missing allocation",
        )),
    }
}

fn decode_hex(value: &str, field: &'static str) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() % 2 != 0
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(Error::InvalidHex {
            field,
            reason: "must be non-empty, even-length lowercase hex",
        });
    }
    hex::decode(value).map_err(|_| Error::InvalidHex {
        field,
        reason: "decode failed",
    })
}

pub fn parse_hash(value: &str, field: &'static str) -> Result<Hash32> {
    decode_hex(value, field)?
        .try_into()
        .map_err(|_| Error::InvalidHex {
            field,
            reason: "must contain exactly 32 bytes",
        })
}

fn fixed32(value: Vec<u8>, error: &'static str) -> Result<Hash32> {
    value.try_into().map_err(|_| Error::InvalidCbor(error))
}

fn fixed64(value: Vec<u8>, error: &'static str) -> Result<[u8; 64]> {
    value.try_into().map_err(|_| Error::InvalidCbor(error))
}

fn encode_resource_limits(writer: &mut Writer, limits: &ResourceLimits) {
    writer.array(5);
    writer.uint(limits.protocol_version);
    writer.uint(limits.max_block_bytes);
    writer.uint(limits.max_tx_lifetime_blocks);
    writer.uint(limits.max_envelope_bytes);
    writer.uint(limits.anchor_retention_blocks);
}

fn decode_resource_limits(cursor: &mut Cursor<'_>) -> Result<ResourceLimits> {
    if cursor.array()? != 5 {
        return Err(Error::InvalidCbor("resource limits field count"));
    }
    Ok(ResourceLimits {
        protocol_version: cursor.uint()?,
        max_block_bytes: cursor.uint()?,
        max_tx_lifetime_blocks: cursor.uint()?,
        max_envelope_bytes: cursor.uint()?,
        anchor_retention_blocks: cursor.uint()?,
    })
}

fn encode_allocations(writer: &mut Writer, entries: &[Allocation]) {
    writer.array(entries.len());
    for entry in entries {
        writer.array(3);
        writer.bytes(&entry.allocation_id);
        writer.uint(entry.kind as u64);
        writer.bytes(&entry.amount.to_be_bytes());
    }
}

fn decode_allocations(cursor: &mut Cursor<'_>) -> Result<Vec<Allocation>> {
    let count = bounded_count(cursor.array()?, MAX_GENESIS_ENTRIES, "too many allocations")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor.array()? != 3 {
            return Err(Error::InvalidCbor("allocation field count"));
        }
        entries.push(Allocation {
            allocation_id: fixed32(cursor.bytes()?, "allocation id length")?,
            kind: AllocationKind::from_tag(cursor.uint()?)?,
            amount: Amount::from_be_bytes(
                cursor
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::InvalidCbor("allocation amount length"))?,
            )?,
        });
    }
    Ok(entries)
}

fn encode_claims(writer: &mut Writer, entries: &[ClaimInput]) {
    writer.array(entries.len());
    for entry in entries {
        writer.array(2);
        writer.bytes(&entry.allocation_id);
        writer.bytes(&entry.claim_pubkey);
    }
}

fn decode_claims(cursor: &mut Cursor<'_>) -> Result<Vec<ClaimInput>> {
    let count = bounded_count(cursor.array()?, MAX_GENESIS_ENTRIES, "too many claims")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor.array()? != 2 {
            return Err(Error::InvalidCbor("claim field count"));
        }
        entries.push(ClaimInput {
            allocation_id: fixed32(cursor.bytes()?, "claim allocation id length")?,
            claim_pubkey: fixed32(cursor.bytes()?, "claim public key length")?,
        });
    }
    Ok(entries)
}

fn encode_commitments(writer: &mut Writer, entries: &[CommitmentInput]) {
    writer.array(entries.len());
    for entry in entries {
        writer.array(2);
        writer.bytes(&entry.allocation_id);
        writer.bytes(&entry.commitment);
    }
}

fn decode_commitments(cursor: &mut Cursor<'_>) -> Result<Vec<CommitmentInput>> {
    let count = bounded_count(cursor.array()?, MAX_GENESIS_ENTRIES, "too many commitments")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor.array()? != 2 {
            return Err(Error::InvalidCbor("commitment field count"));
        }
        entries.push(CommitmentInput {
            allocation_id: fixed32(cursor.bytes()?, "commitment allocation id length")?,
            commitment: fixed32(cursor.bytes()?, "commitment length")?,
        });
    }
    Ok(entries)
}

fn encode_validators_and_policy(
    writer: &mut Writer,
    validators: &[ValidatorInput],
    policy: &ApprovalPolicy,
) {
    writer.array(2);
    writer.array(validators.len());
    for entry in validators {
        writer.array(5);
        writer.bytes(&entry.allocation_id);
        writer.bytes(&entry.operator_pubkey);
        writer.bytes(&entry.consensus_pubkey);
        writer.bytes(&entry.owner_pubkey);
        writer.uint(u64::from(entry.commission_bps));
    }
    writer.array(2);
    writer.uint(u64::from(policy.threshold));
    writer.array(policy.signers.len());
    for signer in &policy.signers {
        writer.bytes(signer);
    }
}

fn decode_validators_and_policy(
    cursor: &mut Cursor<'_>,
) -> Result<(Vec<ValidatorInput>, ApprovalPolicy)> {
    if cursor.array()? != 2 {
        return Err(Error::InvalidCbor("validator/policy wrapper field count"));
    }
    let count = bounded_count(cursor.array()?, MAX_GENESIS_ENTRIES, "too many validators")?;
    let mut validators = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor.array()? != 5 {
            return Err(Error::InvalidCbor("validator field count"));
        }
        validators.push(ValidatorInput {
            allocation_id: fixed32(cursor.bytes()?, "validator allocation id length")?,
            operator_pubkey: fixed32(cursor.bytes()?, "operator public key length")?,
            consensus_pubkey: fixed32(cursor.bytes()?, "consensus public key length")?,
            owner_pubkey: fixed32(cursor.bytes()?, "owner public key length")?,
            commission_bps: u16::try_from(cursor.uint()?)
                .map_err(|_| Error::InvalidCbor("commission does not fit u16"))?,
        });
    }
    if cursor.array()? != 2 {
        return Err(Error::InvalidCbor("approval policy field count"));
    }
    let threshold = u16::try_from(cursor.uint()?)
        .map_err(|_| Error::InvalidCbor("approval threshold does not fit u16"))?;
    let signer_count = bounded_count(
        cursor.array()?,
        MAX_APPROVAL_SIGNERS,
        "too many approval signers",
    )?;
    let mut signers = Vec::with_capacity(signer_count);
    for _ in 0..signer_count {
        signers.push(fixed32(cursor.bytes()?, "approval signer length")?);
    }
    Ok((validators, ApprovalPolicy { threshold, signers }))
}

fn bounded_count(value: usize, maximum: usize, error: &'static str) -> Result<usize> {
    if value > maximum {
        Err(Error::InvalidCbor(error))
    } else {
        Ok(value)
    }
}

struct Writer(Vec<u8>);

impl Writer {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn finish(self) -> Vec<u8> {
        self.0
    }
    fn array(&mut self, len: usize) {
        self.head(4, len as u64);
    }
    fn uint(&mut self, value: u64) {
        self.head(0, value);
    }
    fn bytes(&mut self, value: &[u8]) {
        self.head(2, value.len() as u64);
        self.0.extend_from_slice(value);
    }
    fn text(&mut self, value: &str) {
        self.head(3, value.len() as u64);
        self.0.extend_from_slice(value.as_bytes());
    }
    fn head(&mut self, major: u8, value: u64) {
        let prefix = major << 5;
        match value {
            0..=23 => self.0.push(prefix | value as u8),
            24..=0xff => self.0.extend_from_slice(&[prefix | 24, value as u8]),
            0x100..=0xffff => {
                self.0.push(prefix | 25);
                self.0.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(prefix | 26);
                self.0.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.0.push(prefix | 27);
                self.0.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn finish(self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::InvalidCbor("trailing bytes"))
        }
    }
    fn array(&mut self) -> Result<usize> {
        let (major, value) = self.head()?;
        if major != 4 {
            return Err(Error::InvalidCbor("expected array"));
        }
        usize::try_from(value).map_err(|_| Error::InvalidCbor("array too large"))
    }
    fn uint(&mut self) -> Result<u64> {
        let (major, value) = self.head()?;
        if major != 0 {
            return Err(Error::InvalidCbor("expected unsigned integer"));
        }
        Ok(value)
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let (major, len) = self.head()?;
        if major != 2 {
            return Err(Error::InvalidCbor("expected byte string"));
        }
        Ok(self
            .take(usize::try_from(len).map_err(|_| Error::InvalidCbor("bytes too large"))?)?
            .to_vec())
    }
    fn text(&mut self) -> Result<String> {
        let (major, len) = self.head()?;
        if major != 3 {
            return Err(Error::InvalidCbor("expected text"));
        }
        let bytes =
            self.take(usize::try_from(len).map_err(|_| Error::InvalidCbor("text too large"))?)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidCbor("invalid UTF-8"))
    }
    fn head(&mut self) -> Result<(u8, u64)> {
        let first = self.byte()?;
        let major = first >> 5;
        let info = first & 31;
        let value = match info {
            0..=23 => info as u64,
            24 => {
                let value = self.byte()? as u64;
                if value < 24 {
                    return Err(Error::InvalidCbor("non-shortest integer or length"));
                }
                value
            }
            25 => {
                let value = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if value <= 0xff {
                    return Err(Error::InvalidCbor("non-shortest integer or length"));
                }
                value
            }
            26 => {
                let value = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64;
                if value <= 0xffff {
                    return Err(Error::InvalidCbor("non-shortest integer or length"));
                }
                value
            }
            27 => {
                let value = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if value <= 0xffff_ffff {
                    return Err(Error::InvalidCbor("non-shortest integer or length"));
                }
                value
            }
            _ => return Err(Error::InvalidCbor("indefinite or reserved value")),
        };
        Ok((major, value))
    }
    fn byte(&mut self) -> Result<u8> {
        let value = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or(Error::InvalidCbor("truncated value"))?;
        self.offset += 1;
        Ok(value)
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(Error::InvalidCbor("length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::InvalidCbor("truncated value"))?;
        self.offset = end;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct GenesisVectors {
        canonical_identity_cbor_hex: String,
        genesis_manifest_hash: String,
        chain_context: String,
        approval_message_hex: String,
        threshold_signature_package_cbor_hex: String,
    }

    fn vectors() -> GenesisVectors {
        serde_json::from_str(include_str!(
            "../../../tests/vectors/genesis-identity-vectors.json"
        ))
        .unwrap()
    }

    fn key(seed: u8) -> (SigningKey, Hash32) {
        let signing = SigningKey::from([seed; 32]);
        let public = signing.verification_key().to_bytes();
        (signing, public)
    }

    fn manifest() -> GenesisIdentityManifest {
        let (_, claim) = key(1);
        let (_, operator) = key(2);
        let (_, consensus) = key(3);
        let (_, owner) = key(4);
        let (_, approver_one) = key(5);
        let (_, approver_two) = key(6);
        let mut signers = vec![approver_one, approver_two];
        signers.sort();
        GenesisIdentityManifest {
            chain_id: "bit-test-genesis-v1".to_owned(),
            genesis_time_unix_seconds: 1_800_000_000,
            source_commit: vec![0x11; 20],
            crypto_manifest_sha256: [0x22; 32],
            consensus_parameters_sha256: [0x33; 32],
            native_asset_id: [0x44; 32],
            key_derivation_version: "bit-kd-v1".to_owned(),
            address_encoding_version: "bit-address-v1".to_owned(),
            resource_limits: ResourceLimits {
                protocol_version: 1,
                max_block_bytes: 1_048_576,
                max_tx_lifetime_blocks: 120,
                max_envelope_bytes: 65_536,
                anchor_retention_blocks: 720,
            },
            monetary_policy: MonetaryPolicy {
                genesis_supply: Amount::new(1_000_000_000).unwrap(),
                epoch_blocks: 720,
                halving_interval_epochs: 35_040,
            },
            allocations: vec![
                Allocation {
                    allocation_id: [0x10; 32],
                    kind: AllocationKind::GenesisClaim,
                    amount: Amount::new(400_000_000).unwrap(),
                },
                Allocation {
                    allocation_id: [0x20; 32],
                    kind: AllocationKind::ShieldedCommitment,
                    amount: Amount::new(100_000_000).unwrap(),
                },
                Allocation {
                    allocation_id: [0x30; 32],
                    kind: AllocationKind::ValidatorSelfBond,
                    amount: Amount::new(400_000_000).unwrap(),
                },
                Allocation {
                    allocation_id: [0x40; 32],
                    kind: AllocationKind::FeeReserve,
                    amount: Amount::new(100_000_000).unwrap(),
                },
            ],
            claims: vec![ClaimInput {
                allocation_id: [0x10; 32],
                claim_pubkey: claim,
            }],
            commitments: vec![CommitmentInput {
                allocation_id: [0x20; 32],
                commitment: [0x55; 32],
            }],
            validators: vec![ValidatorInput {
                allocation_id: [0x30; 32],
                operator_pubkey: operator,
                consensus_pubkey: consensus,
                owner_pubkey: owner,
                commission_bps: 500,
            }],
            approval_policy: ApprovalPolicy {
                threshold: 2,
                signers,
            },
        }
    }

    #[test]
    fn canonical_identity_round_trip_and_hash_are_stable() {
        let manifest = manifest();
        let bytes = manifest.encode_canonical().unwrap();
        let vectors = vectors();
        assert_eq!(hex::encode(&bytes), vectors.canonical_identity_cbor_hex);
        assert_eq!(
            GenesisIdentityManifest::decode_canonical(&bytes).unwrap(),
            manifest
        );
        assert_eq!(
            hex::encode(manifest.hash().unwrap()),
            vectors.genesis_manifest_hash
        );
        assert_eq!(
            hex::encode(manifest.chain_context().unwrap()),
            vectors.chain_context
        );
        assert_eq!(
            hex::encode(approval_message(&manifest.hash().unwrap())),
            vectors.approval_message_hex
        );
    }

    #[test]
    fn allocation_mapping_prevents_double_counting_and_gaps() {
        let mut duplicate = manifest();
        duplicate.commitments[0].allocation_id = duplicate.claims[0].allocation_id;
        assert!(duplicate.validate().is_err());

        let mut gap = manifest();
        gap.claims.clear();
        assert!(gap.validate().is_err());

        let mut wrong_total = manifest();
        wrong_total.allocations[0].amount = Amount::new(399_999_999).unwrap();
        assert!(wrong_total.validate().is_err());
    }

    #[test]
    fn signature_package_requires_authorized_threshold() {
        let manifest = manifest();
        let mut package = SignaturePackage {
            manifest_hash: manifest.hash().unwrap(),
            approvals: Vec::new(),
        };
        package.add_signature(&manifest, [5; 32]).unwrap();
        assert!(package.verify(&manifest).is_err());
        package.add_signature(&manifest, [6; 32]).unwrap();
        assert_eq!(package.verify(&manifest).unwrap(), 2);
        let bytes = package.encode_canonical().unwrap();
        assert_eq!(
            hex::encode(&bytes),
            vectors().threshold_signature_package_cbor_hex
        );
        assert_eq!(SignaturePackage::decode_canonical(&bytes).unwrap(), package);
    }

    #[test]
    fn canonical_decoder_rejects_trailing_bytes() {
        let mut bytes = manifest().encode_canonical().unwrap();
        bytes.push(0);
        assert!(GenesisIdentityManifest::decode_canonical(&bytes).is_err());
    }

    #[test]
    fn canonical_decoders_reject_oversized_inputs_before_parsing() {
        assert!(
            GenesisIdentityManifest::decode_canonical(&vec![0; MAX_IDENTITY_BYTES + 1]).is_err()
        );
        assert!(
            SignaturePackage::decode_canonical(&vec![0; MAX_SIGNATURE_PACKAGE_BYTES + 1]).is_err()
        );
    }
}
