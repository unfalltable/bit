use crate::{
    genesis_claims_hash, genesis_commitments_hash, AllocationKind, DerivedClaim,
    DerivedSignaturePackage, DerivedValidator, GenesisDerivedManifest, GenesisIdentityManifest,
    Hash32, SignaturePackage, MAX_GENESIS_ENTRIES,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bit_emission::{FeePolicy, GenesisAllocation};
use bit_staking::{
    consensus_address, ConsensusPowerUpdate, StakingBook, StakingParameters, RECOVERY_RECEIPT_BYTES,
};
use bit_state::{GenesisClaim, GenesisConfig, PersistentState};
use bit_types::{position_id, validator_id, Amount};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
use thiserror::Error;

pub const RUNTIME_INPUT_FORMAT: &str = "BIT-GENESIS-RUNTIME-INPUTS";
pub const RUNTIME_INPUT_VERSION: u64 = 1;
pub const MATERIALIZED_BUNDLE_FORMAT: &str = "BIT-GENESIS-BUNDLE";
pub const MATERIALIZED_BUNDLE_VERSION: u64 = 1;
const MAX_RUNTIME_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_BUNDLE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_GENESIS_TIME: u64 = 253_402_300_799;

#[derive(Debug, Error)]
pub enum MaterializeError {
    #[error("invalid genesis materialization input: {0}")]
    Invalid(&'static str),
    #[error("invalid genesis materialization input: {0}")]
    InvalidOwned(String),
    #[error("genesis manifest error: {0}")]
    Genesis(#[from] crate::Error),
    #[error("staking error: {0}")]
    Staking(#[from] bit_staking::Error),
    #[error("state error: {0}")]
    State(#[from] bit_state::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type MaterializeResult<T> = core::result::Result<T, MaterializeError>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInputDocument {
    pub format: String,
    pub version: u64,
    pub fees: FeeRuntimeParameters,
    pub staking: StakingRuntimeParameters,
    pub validators: Vec<ValidatorRuntimeInput>,
    pub cometbft: CometBftRuntimeParameters,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeeRuntimeParameters {
    pub base_atomic: Amount,
    pub per_kib_atomic: Amount,
    pub per_spend_proof_atomic: Amount,
    pub per_output_proof_atomic: Amount,
    pub new_position_surcharge_atomic: Amount,
    pub validator_registration_surcharge_atomic: Amount,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StakingRuntimeParameters {
    pub min_delegation_atomic: Amount,
    pub min_self_bond_atomic: Amount,
    pub max_validators: u16,
    pub power_unit_atomic: Amount,
    #[serde(with = "decimal_u64")]
    pub max_total_voting_power: u64,
    pub max_pending_positions_per_activation_epoch: u32,
    pub max_commission_bps: u16,
    pub default_commission_bps: u16,
    pub max_commission_increase_bps: u16,
    pub jail_seconds: u64,
    pub jail_blocks: u64,
    pub commission_notice_seconds: u64,
    pub commission_notice_blocks: u64,
    pub evidence_max_age_seconds: u64,
    pub evidence_max_age_blocks: u64,
    pub downtime_window: u32,
    pub min_signed_bps: u16,
    pub unbonding_seconds: u64,
    pub unbonding_blocks: u64,
    pub byzantine_slash_bps: u16,
    pub slash_cohorts_per_block: u16,
}

mod decimal_u64 {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(D::Error::custom(
                "expected an unsigned canonical decimal string",
            ));
        }
        value.parse().map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorRuntimeInput {
    pub allocation_id: String,
    pub display_name: String,
    pub website: String,
    pub description: String,
    pub recovery_receipt: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CometBftRuntimeParameters {
    pub max_gas: i64,
    pub evidence_max_bytes: i64,
    pub vote_extensions_enable_height: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedGenesis {
    pub format: String,
    pub version: u64,
    pub identity_manifest_hash: String,
    pub runtime_inputs_sha256: String,
    pub derived_manifest_hash: String,
    pub derived_manifest_sha256: String,
    pub cometbft_genesis_sha256: String,
    pub app_hash: String,
    pub shielded_tree_root: String,
    pub genesis_execution_hash: String,
    pub genesis_compact_hash: String,
    pub identity_approval_count: usize,
    pub claim_count: usize,
    pub commitment_count: usize,
    pub validator_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenesisInitValidator {
    pub consensus_pubkey: Hash32,
    pub power: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisInitChain {
    pub genesis_time_seconds: i64,
    pub chain_id: String,
    pub initial_height: i64,
    pub max_block_bytes: i64,
    pub max_gas: i64,
    pub evidence_max_age_blocks: i64,
    pub evidence_max_age_seconds: i64,
    pub evidence_max_bytes: i64,
    pub validator_key_types: Vec<String>,
    pub protocol_version: u64,
    pub vote_extensions_enable_height: i64,
    pub validators: Vec<GenesisInitValidator>,
    pub app_state_json: Vec<u8>,
}

pub struct VerifiedGenesisBundle {
    pub genesis_config: GenesisConfig,
    pub init_chain: GenesisInitChain,
    pub report: MaterializedGenesis,
    pub derived_approval_count: usize,
}

struct PreparedGenesis {
    config: GenesisConfig,
    validators: Vec<ConsensusPowerUpdate>,
    derived_claims: Vec<DerivedClaim>,
    derived_validators: Vec<DerivedValidator>,
    commitments_hash: Hash32,
    claims_hash: Hash32,
    identity_hash: Hash32,
    runtime_hash: Hash32,
    genesis_execution_hash: Hash32,
    genesis_compact_hash: Hash32,
}

impl RuntimeInputDocument {
    pub fn decode(bytes: &[u8]) -> MaterializeResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_RUNTIME_INPUT_BYTES {
            return Err(MaterializeError::Invalid(
                "runtime input file is empty or exceeds 16 MiB",
            ));
        }
        let document: Self = serde_json::from_slice(bytes)?;
        document.validate_intrinsic()?;
        Ok(document)
    }

    fn validate_intrinsic(&self) -> MaterializeResult<()> {
        if self.format != RUNTIME_INPUT_FORMAT || self.version != RUNTIME_INPUT_VERSION {
            return Err(MaterializeError::Invalid(
                "unknown runtime input format or version",
            ));
        }
        if self.validators.is_empty() || self.validators.len() > MAX_GENESIS_ENTRIES {
            return Err(MaterializeError::Invalid(
                "runtime validator list is empty or too large",
            ));
        }
        let mut previous = None;
        for validator in &self.validators {
            let allocation_id = parse_hash(&validator.allocation_id, "validator allocation_id")?;
            if previous.is_some_and(|value| value >= allocation_id) {
                return Err(MaterializeError::Invalid(
                    "runtime validators must be strictly sorted by allocation_id",
                ));
            }
            previous = Some(allocation_id);
            let receipt = decode_receipt(&validator.recovery_receipt)?;
            if receipt.iter().all(|byte| *byte == 0) {
                return Err(MaterializeError::Invalid(
                    "validator recovery receipt must not be all zero",
                ));
            }
        }
        let parameters = self.staking_parameters();
        parameters.validate()?;
        if usize::from(parameters.max_validators) < self.validators.len() {
            return Err(MaterializeError::Invalid(
                "max_validators is smaller than the initial validator count",
            ));
        }
        if self.cometbft.max_gas < -1
            || self.cometbft.evidence_max_bytes <= 0
            || self.cometbft.vote_extensions_enable_height != 0
        {
            return Err(MaterializeError::Invalid("invalid CometBFT parameters"));
        }
        self.staking
            .evidence_max_age_seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(MaterializeError::Invalid(
                "evidence max age does not fit CometBFT duration",
            ))?;
        i64::try_from(self.staking.evidence_max_age_blocks)
            .map_err(|_| MaterializeError::Invalid("evidence block age does not fit CometBFT"))?;
        Ok(())
    }

    fn staking_parameters(&self) -> StakingParameters {
        StakingParameters {
            min_delegation: self.staking.min_delegation_atomic,
            min_self_bond: self.staking.min_self_bond_atomic,
            max_validators: self.staking.max_validators,
            power_unit_atomic: self.staking.power_unit_atomic,
            max_total_voting_power: self.staking.max_total_voting_power,
            max_pending_per_epoch: self.staking.max_pending_positions_per_activation_epoch,
            max_commission_bps: self.staking.max_commission_bps,
            default_commission_bps: self.staking.default_commission_bps,
            max_commission_increase_bps: self.staking.max_commission_increase_bps,
            jail_seconds: self.staking.jail_seconds,
            jail_blocks: self.staking.jail_blocks,
            commission_notice_seconds: self.staking.commission_notice_seconds,
            commission_notice_blocks: self.staking.commission_notice_blocks,
            evidence_max_age_seconds: self.staking.evidence_max_age_seconds,
            evidence_max_age_blocks: self.staking.evidence_max_age_blocks,
            downtime_window: self.staking.downtime_window,
            min_signed_bps: self.staking.min_signed_bps,
            unbonding_seconds: self.staking.unbonding_seconds,
            unbonding_blocks: self.staking.unbonding_blocks,
            byzantine_slash_bps: self.staking.byzantine_slash_bps,
            slash_cohorts_per_block: self.staking.slash_cohorts_per_block,
        }
    }

    fn fee_policy(&self) -> FeePolicy {
        FeePolicy {
            base: self.fees.base_atomic,
            per_kib: self.fees.per_kib_atomic,
            per_spend_proof: self.fees.per_spend_proof_atomic,
            per_output_proof: self.fees.per_output_proof_atomic,
            new_position_surcharge: self.fees.new_position_surcharge_atomic,
            validator_registration_surcharge: self.fees.validator_registration_surcharge_atomic,
        }
    }
}

/// Materialize a deterministic height-zero construction bundle in a sibling
/// temporary directory and publish it with one final rename. Existing output is
/// always rejected. The identity approval threshold must already be satisfied;
/// the derived manifest is approved after materialization.
pub async fn materialize_bundle(
    identity_bytes: &[u8],
    signature_bytes: &[u8],
    runtime_bytes: &[u8],
    output: &Path,
) -> MaterializeResult<MaterializedGenesis> {
    if output.exists() {
        return Err(MaterializeError::InvalidOwned(format!(
            "refusing to overwrite existing output: {}",
            output.display()
        )));
    }
    let identity = GenesisIdentityManifest::decode_canonical(identity_bytes)?;
    let signatures = SignaturePackage::decode_canonical(signature_bytes)?;
    let approval_count = signatures.verify(&identity)?;
    let runtime_hash: Hash32 = Sha256::digest(runtime_bytes).into();
    if runtime_hash != identity.consensus_parameters_sha256 {
        return Err(MaterializeError::Invalid(
            "runtime input SHA-256 differs from identity consensus_parameters_sha256",
        ));
    }
    let runtime = RuntimeInputDocument::decode(runtime_bytes)?;
    validate_runtime_against_identity(&runtime, &identity)?;

    let prepared = prepare_genesis(&identity, &runtime, runtime_hash)?;

    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".bit-genesis-staging-")
        .tempdir_in(parent)?;
    let state_path = staging.path().join("state");
    fs::create_dir(&state_path)?;
    let state = PersistentState::open(state_path, prepared.config.clone()).await?;
    let summary = state.summary().await?;
    state.close().await;

    let comet_bytes = encode_cometbft_genesis(
        &identity,
        &runtime,
        &prepared.validators,
        summary.app_hash,
        summary.shielded_tree_root,
        prepared.commitments_hash,
        prepared.claims_hash,
        prepared.genesis_execution_hash,
        prepared.genesis_compact_hash,
        prepared.runtime_hash,
    )?;
    let comet_hash: Hash32 = Sha256::digest(&comet_bytes).into();
    let derived = GenesisDerivedManifest {
        identity_manifest_hash: prepared.identity_hash,
        chain_context: prepared.config.chain_context,
        runtime_inputs_sha256: prepared.runtime_hash,
        claims: prepared.derived_claims.clone(),
        validators: prepared.derived_validators.clone(),
        genesis_commitments_hash: prepared.commitments_hash,
        genesis_claims_hash: prepared.claims_hash,
        shielded_tree_root: summary.shielded_tree_root,
        app_hash: summary.app_hash,
        genesis_execution_hash: prepared.genesis_execution_hash,
        genesis_compact_hash: prepared.genesis_compact_hash,
        cometbft_genesis_sha256: comet_hash,
    };
    let derived_bytes = derived.encode_canonical(&identity)?;
    let derived_hash = derived.hash(&identity)?;
    let derived_sha256: Hash32 = Sha256::digest(&derived_bytes).into();

    fs::write(staging.path().join("identity.cbor"), identity_bytes)?;
    fs::write(
        staging.path().join("identity-signatures.cbor"),
        signature_bytes,
    )?;
    fs::write(staging.path().join("runtime-inputs.json"), runtime_bytes)?;
    fs::write(staging.path().join("genesis.json"), &comet_bytes)?;
    fs::write(staging.path().join("derived.cbor"), &derived_bytes)?;
    let report = MaterializedGenesis {
        format: MATERIALIZED_BUNDLE_FORMAT.to_owned(),
        version: MATERIALIZED_BUNDLE_VERSION,
        identity_manifest_hash: hex::encode(prepared.identity_hash),
        runtime_inputs_sha256: hex::encode(prepared.runtime_hash),
        derived_manifest_hash: hex::encode(derived_hash),
        derived_manifest_sha256: hex::encode(derived_sha256),
        cometbft_genesis_sha256: hex::encode(comet_hash),
        app_hash: hex::encode(summary.app_hash),
        shielded_tree_root: hex::encode(summary.shielded_tree_root),
        genesis_execution_hash: hex::encode(prepared.genesis_execution_hash),
        genesis_compact_hash: hex::encode(prepared.genesis_compact_hash),
        identity_approval_count: approval_count,
        claim_count: identity.claims.len(),
        commitment_count: identity.commitments.len(),
        validator_count: identity.validators.len(),
    };
    let mut report_bytes = serde_json::to_vec_pretty(&report)?;
    report_bytes.push(b'\n');
    fs::write(staging.path().join("build-report.json"), report_bytes)?;

    let staging_path = staging.keep();
    if let Err(error) = fs::rename(&staging_path, output) {
        let _ = fs::remove_dir_all(&staging_path);
        return Err(error.into());
    }
    Ok(report)
}

/// Verify both approval stages and independently replay every deterministic
/// height-zero protocol artifact. The bundled RocksDB directory is required as
/// a construction artifact but is never trusted as node input.
pub async fn verify_bundle(
    bundle: &Path,
    derived_signatures: &Path,
) -> MaterializeResult<VerifiedGenesisBundle> {
    require_plain_directory(bundle, "genesis bundle")?;
    require_plain_directory(&bundle.join("state"), "bundled state")?;
    let identity_bytes = read_plain_file(&bundle.join("identity.cbor"))?;
    let signature_bytes = read_plain_file(&bundle.join("identity-signatures.cbor"))?;
    let runtime_bytes = read_plain_file(&bundle.join("runtime-inputs.json"))?;
    let comet_bytes = read_plain_file(&bundle.join("genesis.json"))?;
    let derived_bytes = read_plain_file(&bundle.join("derived.cbor"))?;
    let report_bytes = read_plain_file(&bundle.join("build-report.json"))?;
    let derived_signature_bytes = read_plain_file(derived_signatures)?;

    let identity = GenesisIdentityManifest::decode_canonical(&identity_bytes)?;
    let signatures = SignaturePackage::decode_canonical(&signature_bytes)?;
    let identity_approval_count = signatures.verify(&identity)?;
    let runtime_hash: Hash32 = Sha256::digest(&runtime_bytes).into();
    if runtime_hash != identity.consensus_parameters_sha256 {
        return Err(MaterializeError::Invalid(
            "runtime input SHA-256 differs from identity consensus_parameters_sha256",
        ));
    }
    let runtime = RuntimeInputDocument::decode(&runtime_bytes)?;
    validate_runtime_against_identity(&runtime, &identity)?;
    let prepared = prepare_genesis(&identity, &runtime, runtime_hash)?;
    let derived = GenesisDerivedManifest::decode_canonical(&derived_bytes, &identity)?;
    let derived_signature_package =
        DerivedSignaturePackage::decode_canonical(&derived_signature_bytes)?;
    let derived_approval_count = derived_signature_package.verify(&identity, &derived)?;

    if <[u8; 32]>::from(Sha256::digest(&comet_bytes)) != derived.cometbft_genesis_sha256 {
        return Err(MaterializeError::Invalid(
            "CometBFT genesis SHA-256 differs from derived manifest",
        ));
    }
    let comet: CometGenesis = serde_json::from_slice(&comet_bytes)?;
    let mut canonical_comet = serde_json::to_vec_pretty(&comet)?;
    canonical_comet.push(b'\n');
    if canonical_comet != comet_bytes {
        return Err(MaterializeError::Invalid(
            "CometBFT genesis is not the canonical generated JSON",
        ));
    }

    let report: MaterializedGenesis = serde_json::from_slice(&report_bytes)?;
    let mut canonical_report = serde_json::to_vec_pretty(&report)?;
    canonical_report.push(b'\n');
    if canonical_report != report_bytes {
        return Err(MaterializeError::Invalid(
            "build report is not the canonical generated JSON",
        ));
    }

    let replay_root = tempfile::tempdir()?;
    let replay_bundle = replay_root.path().join("replay");
    let replay_report = materialize_bundle(
        &identity_bytes,
        &signature_bytes,
        &runtime_bytes,
        &replay_bundle,
    )
    .await?;
    if report != replay_report || report.identity_approval_count != identity_approval_count {
        return Err(MaterializeError::Invalid(
            "build report differs from independent replay",
        ));
    }
    for name in [
        "identity.cbor",
        "identity-signatures.cbor",
        "runtime-inputs.json",
        "genesis.json",
        "derived.cbor",
        "build-report.json",
    ] {
        if read_plain_file(&bundle.join(name))? != read_plain_file(&replay_bundle.join(name))? {
            return Err(MaterializeError::InvalidOwned(format!(
                "bundle file differs from independent replay: {name}"
            )));
        }
    }
    let init_chain = build_init_chain(&identity, &runtime, &prepared, &comet, &comet_bytes)?;
    Ok(VerifiedGenesisBundle {
        genesis_config: prepared.config,
        init_chain,
        report,
        derived_approval_count,
    })
}

fn require_plain_directory(path: &Path, name: &'static str) -> MaterializeResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(MaterializeError::InvalidOwned(format!(
            "{name} must be a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn read_plain_file(path: &Path) -> MaterializeResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_BUNDLE_FILE_BYTES
    {
        return Err(MaterializeError::InvalidOwned(format!(
            "bundle input must be a real file no larger than 16 MiB: {}",
            path.display()
        )));
    }
    Ok(fs::read(path)?)
}

fn build_init_chain(
    identity: &GenesisIdentityManifest,
    runtime: &RuntimeInputDocument,
    prepared: &PreparedGenesis,
    comet: &CometGenesis,
    comet_bytes: &[u8],
) -> MaterializeResult<GenesisInitChain> {
    if comet.genesis_time != rfc3339(identity.genesis_time_unix_seconds)?
        || comet.chain_id != identity.chain_id
        || comet.initial_height != "1"
    {
        return Err(MaterializeError::Invalid(
            "CometBFT identity fields differ from signed identity",
        ));
    }
    let raw: RawCometGenesis<'_> = serde_json::from_slice(comet_bytes)?;
    let app_state_json = raw.app_state.get().as_bytes().to_vec();
    Ok(GenesisInitChain {
        genesis_time_seconds: i64::try_from(identity.genesis_time_unix_seconds)
            .map_err(|_| MaterializeError::Invalid("genesis time exceeds i64"))?,
        chain_id: identity.chain_id.clone(),
        initial_height: 1,
        max_block_bytes: i64::try_from(identity.resource_limits.max_block_bytes)
            .map_err(|_| MaterializeError::Invalid("max block bytes exceeds i64"))?,
        max_gas: runtime.cometbft.max_gas,
        evidence_max_age_blocks: i64::try_from(runtime.staking.evidence_max_age_blocks)
            .map_err(|_| MaterializeError::Invalid("evidence block age exceeds i64"))?,
        evidence_max_age_seconds: i64::try_from(runtime.staking.evidence_max_age_seconds)
            .map_err(|_| MaterializeError::Invalid("evidence time age exceeds i64"))?,
        evidence_max_bytes: runtime.cometbft.evidence_max_bytes,
        validator_key_types: vec!["ed25519".to_owned()],
        protocol_version: identity.resource_limits.protocol_version,
        vote_extensions_enable_height: runtime.cometbft.vote_extensions_enable_height,
        validators: prepared
            .validators
            .iter()
            .map(|validator| GenesisInitValidator {
                consensus_pubkey: validator.consensus_pubkey,
                power: validator.power,
            })
            .collect(),
        app_state_json,
    })
}

fn prepare_genesis(
    identity: &GenesisIdentityManifest,
    runtime: &RuntimeInputDocument,
    runtime_hash: Hash32,
) -> MaterializeResult<PreparedGenesis> {
    let identity_hash = identity.hash()?;
    let chain_context = identity.chain_context()?;
    let allocation_by_id: BTreeMap<_, _> = identity
        .allocations
        .iter()
        .map(|entry| (entry.allocation_id, (entry.kind, entry.amount)))
        .collect();
    let runtime_by_allocation: BTreeMap<_, _> = runtime
        .validators
        .iter()
        .map(|entry| {
            Ok((
                parse_hash(&entry.allocation_id, "validator allocation_id")?,
                entry,
            ))
        })
        .collect::<MaterializeResult<_>>()?;

    let mut staking = StakingBook::new(chain_context, runtime.staking_parameters())?;
    let mut derived_validators = Vec::with_capacity(identity.validators.len());
    for source in &identity.validators {
        let metadata =
            runtime_by_allocation
                .get(&source.allocation_id)
                .ok_or(MaterializeError::Invalid(
                    "validator runtime input is missing",
                ))?;
        let (_, self_bond) = allocation_by_id
            .get(&source.allocation_id)
            .copied()
            .ok_or(MaterializeError::Invalid("validator allocation is missing"))?;
        let validator = validator_id(&chain_context, &source.operator_pubkey);
        let position = position_id(&chain_context, &source.owner_pubkey);
        staking.register_validator_with_metadata(
            validator,
            source.operator_pubkey,
            source.consensus_pubkey,
            source.commission_bps,
            metadata.display_name.clone(),
            metadata.website.clone(),
            metadata.description.clone(),
        )?;
        staking.open_pending_delegation(
            0,
            0,
            position,
            source.owner_pubkey,
            validator,
            self_bond,
            Amount::ZERO,
            true,
            decode_receipt(&metadata.recovery_receipt)?,
        )?;
        staking.activate_pending(&position, 1)?;
        derived_validators.push((source, validator, position));
    }
    staking.apply_validator_set()?;
    let effective_set = staking.effective_validator_set()?;
    if effective_set.validators().len() != identity.validators.len() {
        return Err(MaterializeError::Invalid(
            "every identity validator must have positive genesis voting power",
        ));
    }
    let powers: BTreeMap<_, _> = effective_set
        .validators()
        .iter()
        .map(|entry| (entry.consensus_pubkey, entry.power))
        .collect();
    let derived_validators =
        derived_validators
            .into_iter()
            .map(|(source, validator, position)| {
                let power = powers.get(&source.consensus_pubkey).copied().ok_or(
                    MaterializeError::Invalid("identity validator was excluded from effective set"),
                )?;
                Ok(DerivedValidator {
                    allocation_id: source.allocation_id,
                    validator_id: validator,
                    self_bond_position_id: position,
                    consensus_address: consensus_address(&source.consensus_pubkey),
                    voting_power: power,
                })
            })
            .collect::<MaterializeResult<Vec<_>>>()?;
    let validators = effective_set.validators().to_vec();

    let genesis_claims = identity
        .claims
        .iter()
        .map(|claim| {
            let (_, amount) = allocation_by_id
                .get(&claim.allocation_id)
                .copied()
                .ok_or(MaterializeError::Invalid("claim allocation is missing"))?;
            Ok(GenesisClaim::new(
                &chain_context,
                claim.claim_pubkey,
                amount,
            )?)
        })
        .collect::<MaterializeResult<Vec<_>>>()?;
    let derived_claims = identity
        .claims
        .iter()
        .zip(&genesis_claims)
        .map(|(source, claim)| DerivedClaim {
            allocation_id: source.allocation_id,
            claim_id: claim.claim_id,
        })
        .collect::<Vec<_>>();
    let commitments = identity
        .commitments
        .iter()
        .map(|entry| entry.commitment)
        .collect::<Vec<_>>();
    let totals = identity.allocation_totals()?;
    let genesis_allocation = GenesisAllocation {
        shielded: amount(totals.shielded_commitments)?,
        stake: amount(totals.validator_self_bonds)?,
        pending_delegation: Amount::ZERO,
        exits: Amount::ZERO,
        commission: Amount::ZERO,
        fee_reserve: amount(totals.fee_reserve)?,
        unclaimed_genesis: amount(totals.genesis_claims)?,
    };
    let genesis_execution_hash =
        bound_genesis_hash(b"BIT-GENESIS-EXECUTION-V1", &identity_hash, &runtime_hash);
    let genesis_compact_hash =
        bound_genesis_hash(b"BIT-GENESIS-COMPACT-V1", &identity_hash, &runtime_hash);
    let max_envelope_bytes = usize::try_from(identity.resource_limits.max_envelope_bytes)
        .map_err(|_| MaterializeError::Invalid("max_envelope_bytes does not fit usize"))?;
    let commitments_hash = genesis_commitments_hash(identity);
    let claims_hash = genesis_claims_hash(identity, &derived_claims)?;
    let config = GenesisConfig {
        genesis_manifest_hash: identity_hash,
        chain_context,
        native_asset_id: identity.native_asset_id,
        protocol_version: identity.resource_limits.protocol_version,
        max_block_bytes: identity.resource_limits.max_block_bytes,
        max_tx_lifetime_blocks: identity.resource_limits.max_tx_lifetime_blocks,
        max_envelope_bytes,
        anchor_retention_blocks: identity.resource_limits.anchor_retention_blocks,
        monetary_policy: identity.monetary_policy.clone(),
        fee_policy: runtime.fee_policy(),
        genesis_allocation,
        genesis_staking: staking,
        genesis_commitments: commitments,
        genesis_claims,
        genesis_execution_hash,
        genesis_compact_hash,
    };
    Ok(PreparedGenesis {
        config,
        validators,
        derived_claims,
        derived_validators,
        commitments_hash,
        claims_hash,
        identity_hash,
        runtime_hash,
        genesis_execution_hash,
        genesis_compact_hash,
    })
}

fn validate_runtime_against_identity(
    runtime: &RuntimeInputDocument,
    identity: &GenesisIdentityManifest,
) -> MaterializeResult<()> {
    if identity.genesis_time_unix_seconds > MAX_GENESIS_TIME {
        return Err(MaterializeError::Invalid(
            "genesis time exceeds RFC 3339 year 9999",
        ));
    }
    if identity.resource_limits.max_block_bytes > i64::MAX as u64
        || runtime.cometbft.evidence_max_bytes as u64 > identity.resource_limits.max_block_bytes
    {
        return Err(MaterializeError::Invalid(
            "CometBFT byte limits exceed the signed block limit",
        ));
    }
    if runtime.validators.len() != identity.validators.len() {
        return Err(MaterializeError::Invalid(
            "runtime validator count differs from identity",
        ));
    }
    for (runtime_validator, identity_validator) in
        runtime.validators.iter().zip(&identity.validators)
    {
        if parse_hash(&runtime_validator.allocation_id, "validator allocation_id")?
            != identity_validator.allocation_id
        {
            return Err(MaterializeError::Invalid(
                "runtime validator order or allocation differs from identity",
            ));
        }
        if identity_validator.commission_bps > runtime.staking.max_commission_bps {
            return Err(MaterializeError::Invalid(
                "identity validator commission exceeds runtime maximum",
            ));
        }
    }
    for validator in &identity.validators {
        let allocation = identity
            .allocations
            .iter()
            .find(|allocation| allocation.allocation_id == validator.allocation_id)
            .ok_or(MaterializeError::Invalid("validator allocation is missing"))?;
        if allocation.kind != AllocationKind::ValidatorSelfBond
            || allocation.amount < runtime.staking.min_self_bond_atomic
            || allocation.amount.value() / runtime.staking.power_unit_atomic.value() == 0
        {
            return Err(MaterializeError::Invalid(
                "validator allocation cannot produce positive eligible voting power",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_cometbft_genesis(
    identity: &GenesisIdentityManifest,
    runtime: &RuntimeInputDocument,
    validators: &[ConsensusPowerUpdate],
    app_hash: Hash32,
    shielded_tree_root: Hash32,
    commitments_hash: Hash32,
    claims_hash: Hash32,
    genesis_execution_hash: Hash32,
    genesis_compact_hash: Hash32,
    runtime_hash: Hash32,
) -> MaterializeResult<Vec<u8>> {
    let names: BTreeMap<_, _> = identity
        .validators
        .iter()
        .zip(&runtime.validators)
        .map(|(source, runtime_entry)| {
            (source.consensus_pubkey, runtime_entry.display_name.clone())
        })
        .collect();
    let validators = validators
        .iter()
        .map(|validator| CometValidator {
            address: hex::encode_upper(consensus_address(&validator.consensus_pubkey)),
            pub_key: CometPublicKey {
                key_type: "tendermint/PubKeyEd25519".to_owned(),
                value: BASE64.encode(validator.consensus_pubkey),
            },
            power: validator.power.to_string(),
            name: names
                .get(&validator.consensus_pubkey)
                .expect("effective key belongs to an identity validator")
                .clone(),
        })
        .collect();
    let document = CometGenesis {
        genesis_time: rfc3339(identity.genesis_time_unix_seconds)?,
        chain_id: identity.chain_id.clone(),
        initial_height: "1".to_owned(),
        consensus_params: CometConsensusParams {
            block: CometBlockParams {
                max_bytes: identity.resource_limits.max_block_bytes.to_string(),
                max_gas: runtime.cometbft.max_gas.to_string(),
            },
            evidence: CometEvidenceParams {
                max_age_num_blocks: runtime.staking.evidence_max_age_blocks.to_string(),
                max_age_duration: runtime
                    .staking
                    .evidence_max_age_seconds
                    .checked_mul(1_000_000_000)
                    .expect("duration was validated")
                    .to_string(),
                max_bytes: runtime.cometbft.evidence_max_bytes.to_string(),
            },
            validator: CometValidatorParams {
                pub_key_types: vec!["ed25519".to_owned()],
            },
            version: CometVersionParams {
                app: identity.resource_limits.protocol_version.to_string(),
            },
            abci: CometAbciParams {
                vote_extensions_enable_height: runtime
                    .cometbft
                    .vote_extensions_enable_height
                    .to_string(),
            },
        },
        validators,
        app_hash: hex::encode_upper(app_hash),
        app_state: CometAppState {
            format: "BIT-APP-GENESIS".to_owned(),
            version: 1,
            genesis_manifest_hash: hex::encode(identity.hash()?),
            runtime_inputs_sha256: hex::encode(runtime_hash),
            genesis_commitments_hash: hex::encode(commitments_hash),
            genesis_claims_hash: hex::encode(claims_hash),
            shielded_tree_root: hex::encode(shielded_tree_root),
            app_hash: hex::encode(app_hash),
            genesis_execution_hash: hex::encode(genesis_execution_hash),
            genesis_compact_hash: hex::encode(genesis_compact_hash),
        },
    };
    let mut bytes = serde_json::to_vec_pretty(&document)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CometGenesis {
    genesis_time: String,
    chain_id: String,
    initial_height: String,
    consensus_params: CometConsensusParams,
    validators: Vec<CometValidator>,
    app_hash: String,
    app_state: CometAppState,
}

#[derive(Deserialize)]
struct RawCometGenesis<'a> {
    #[serde(borrow)]
    app_state: &'a RawValue,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CometConsensusParams {
    block: CometBlockParams,
    evidence: CometEvidenceParams,
    validator: CometValidatorParams,
    version: CometVersionParams,
    abci: CometAbciParams,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CometBlockParams {
    max_bytes: String,
    max_gas: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CometEvidenceParams {
    max_age_num_blocks: String,
    max_age_duration: String,
    max_bytes: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CometValidatorParams {
    pub_key_types: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CometVersionParams {
    app: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CometAbciParams {
    vote_extensions_enable_height: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CometValidator {
    address: String,
    pub_key: CometPublicKey,
    power: String,
    name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CometPublicKey {
    #[serde(rename = "type")]
    key_type: String,
    value: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CometAppState {
    format: String,
    version: u64,
    genesis_manifest_hash: String,
    runtime_inputs_sha256: String,
    genesis_commitments_hash: String,
    genesis_claims_hash: String,
    shielded_tree_root: String,
    app_hash: String,
    genesis_execution_hash: String,
    genesis_compact_hash: String,
}

fn parse_hash(value: &str, field: &'static str) -> MaterializeResult<Hash32> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(MaterializeError::InvalidOwned(format!(
            "{field} must be 64 lowercase hex characters"
        )));
    }
    let bytes = hex::decode(value)
        .map_err(|_| MaterializeError::InvalidOwned(format!("invalid {field}")))?;
    bytes
        .try_into()
        .map_err(|_| MaterializeError::InvalidOwned(format!("invalid {field} length")))
}

fn decode_receipt(value: &str) -> MaterializeResult<Vec<u8>> {
    if value.len() != RECOVERY_RECEIPT_BYTES * 2
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(MaterializeError::Invalid(
            "recovery_receipt must be exactly 512 bytes of lowercase hex",
        ));
    }
    Ok(hex::decode(value).expect("validated hexadecimal recovery receipt"))
}

fn amount(value: u128) -> MaterializeResult<Amount> {
    Amount::new(value).map_err(|_| MaterializeError::Invalid("allocation amount is invalid"))
}

fn bound_genesis_hash(domain: &[u8], identity_hash: &Hash32, runtime_hash: &Hash32) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(identity_hash);
    hasher.update(runtime_hash);
    hasher.finalize().into()
}

fn rfc3339(unix_seconds: u64) -> MaterializeResult<String> {
    if unix_seconds > MAX_GENESIS_TIME {
        return Err(MaterializeError::Invalid(
            "genesis time exceeds RFC 3339 year 9999",
        ));
    }
    let days = unix_seconds / 86_400;
    let seconds = unix_seconds % 86_400;
    let z = i64::try_from(days).expect("bounded genesis day") + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = seconds / 3_600;
    let minute = seconds % 3_600 / 60;
    let second = seconds % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DerivedSignaturePackage, IdentityInputDocument, SignaturePackage};

    fn runtime_bytes() -> Vec<u8> {
        include_bytes!("../../../tests/fixtures/genesis-runtime-inputs.test.json").to_vec()
    }

    fn signed_identity(runtime: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let root: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/genesis-identity-input.test.json"
        ))
        .unwrap();
        let document: IdentityInputDocument =
            serde_json::from_value(root.get("identity").unwrap().clone()).unwrap();
        let identity = document.into_manifest().unwrap();
        let runtime_hash: Hash32 = Sha256::digest(runtime).into();
        assert_eq!(identity.consensus_parameters_sha256, runtime_hash);
        let identity_bytes = identity.encode_canonical().unwrap();
        let mut signatures = SignaturePackage {
            manifest_hash: identity.hash().unwrap(),
            approvals: Vec::new(),
        };
        signatures.add_signature(&identity, [5; 32]).unwrap();
        signatures.add_signature(&identity, [6; 32]).unwrap();
        (identity_bytes, signatures.encode_canonical().unwrap())
    }

    #[test]
    fn runtime_contract_rejects_unknown_fields_and_fake_receipt() {
        let runtime = runtime_bytes();
        RuntimeInputDocument::decode(&runtime).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&runtime).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(RuntimeInputDocument::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value.as_object_mut().unwrap().remove("unexpected");
        value["staking"]["max_total_voting_power"] =
            serde_json::json!(1_152_921_504_606_846_975_u64);
        assert!(RuntimeInputDocument::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["staking"]["max_total_voting_power"] = serde_json::json!("01");
        assert!(RuntimeInputDocument::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["staking"]["max_total_voting_power"] = serde_json::json!("1152921504606846975");
        value["staking"]["evidence_max_age_blocks"] =
            serde_json::json!(9_223_372_036_854_775_808_u64);
        assert!(RuntimeInputDocument::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["staking"]["evidence_max_age_blocks"] = serde_json::json!(120960);
        value["validators"][0]["recovery_receipt"] =
            serde_json::Value::String("00".repeat(RECOVERY_RECEIPT_BYTES));
        assert!(RuntimeInputDocument::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn unix_seconds_are_rendered_without_local_time_dependence() {
        assert_eq!(rfc3339(1).unwrap(), "1970-01-01T00:00:01Z");
        assert_eq!(rfc3339(1_800_000_000).unwrap(), "2027-01-15T08:00:00Z");
        assert_eq!(rfc3339(MAX_GENESIS_TIME).unwrap(), "9999-12-31T23:59:59Z");
    }

    #[tokio::test]
    async fn materialization_is_deterministic_and_refuses_overwrite() {
        let runtime = runtime_bytes();
        let (identity, signatures) = signed_identity(&runtime);
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        let report = materialize_bundle(&identity, &signatures, &runtime, &first)
            .await
            .unwrap();
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/genesis-materialized-vectors.json"
        ))
        .unwrap();
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            expected["materialized_genesis"]
        );
        let second_report = materialize_bundle(&identity, &signatures, &runtime, &second)
            .await
            .unwrap();
        assert_eq!(report, second_report);
        for name in [
            "identity.cbor",
            "identity-signatures.cbor",
            "runtime-inputs.json",
            "genesis.json",
            "derived.cbor",
            "build-report.json",
        ] {
            assert_eq!(
                fs::read(first.join(name)).unwrap(),
                fs::read(second.join(name)).unwrap()
            );
        }
        assert!(first.join("state").is_dir());
        let identity_manifest = GenesisIdentityManifest::decode_canonical(&identity).unwrap();
        let derived = GenesisDerivedManifest::decode_canonical(
            &fs::read(first.join("derived.cbor")).unwrap(),
            &identity_manifest,
        )
        .unwrap();
        assert_eq!(hex::encode(derived.app_hash), report.app_hash);
        let mut derived_signatures = DerivedSignaturePackage {
            identity_manifest_hash: identity_manifest.hash().unwrap(),
            derived_manifest_hash: derived.hash(&identity_manifest).unwrap(),
            approvals: Vec::new(),
        };
        derived_signatures
            .add_signature(&identity_manifest, &derived, [5; 32])
            .unwrap();
        let partial_path = directory.path().join("partial-derived-signatures.cbor");
        fs::write(
            &partial_path,
            derived_signatures.encode_canonical().unwrap(),
        )
        .unwrap();
        assert!(verify_bundle(&first, &partial_path).await.is_err());
        derived_signatures
            .add_signature(&identity_manifest, &derived, [6; 32])
            .unwrap();
        let derived_signature_path = first.join("derived-signatures.cbor");
        fs::write(
            &derived_signature_path,
            derived_signatures.encode_canonical().unwrap(),
        )
        .unwrap();
        let verified = verify_bundle(&first, &derived_signature_path)
            .await
            .unwrap();
        assert_eq!(verified.report, report);
        assert_eq!(verified.derived_approval_count, 2);
        assert_eq!(
            verified.genesis_config.genesis_manifest_hash,
            identity_manifest.hash().unwrap()
        );
        assert_eq!(verified.init_chain.chain_id, identity_manifest.chain_id);
        assert_eq!(verified.init_chain.validators.len(), 1);
        assert_eq!(verified.init_chain.validators[0].power, 4);
        let genesis_bytes = fs::read(first.join("genesis.json")).unwrap();
        let raw: RawCometGenesis<'_> = serde_json::from_slice(&genesis_bytes).unwrap();
        assert_eq!(
            verified.init_chain.app_state_json,
            raw.app_state.get().as_bytes()
        );
        let comet: serde_json::Value =
            serde_json::from_slice(&fs::read(first.join("genesis.json")).unwrap()).unwrap();
        assert_eq!(comet["chain_id"], identity_manifest.chain_id);
        assert_eq!(
            comet["app_hash"],
            serde_json::Value::String(report.app_hash.to_uppercase())
        );
        assert_eq!(comet["app_state"]["app_hash"], report.app_hash);
        assert!(materialize_bundle(&identity, &signatures, &runtime, &first)
            .await
            .is_err());
        fs::write(first.join("genesis.json"), b"{}\n").unwrap();
        assert!(verify_bundle(&first, &derived_signature_path)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn materialization_requires_runtime_hash_and_signature_threshold() {
        let runtime = runtime_bytes();
        let (identity, signatures) = signed_identity(&runtime);
        let directory = tempfile::tempdir().unwrap();
        let mut changed = runtime.clone();
        changed.push(b' ');
        assert!(materialize_bundle(
            &identity,
            &signatures,
            &changed,
            &directory.path().join("wrong-hash")
        )
        .await
        .is_err());
        let manifest = GenesisIdentityManifest::decode_canonical(&identity).unwrap();
        let mut partial = SignaturePackage {
            manifest_hash: manifest.hash().unwrap(),
            approvals: Vec::new(),
        };
        partial.add_signature(&manifest, [5; 32]).unwrap();
        assert!(materialize_bundle(
            &identity,
            &partial.encode_canonical().unwrap(),
            &runtime,
            &directory.path().join("partial")
        )
        .await
        .is_err());
    }
}
