//! Four-node integration probe for the real BIT application and state crates.
//!
//! This is not a production node executable. It intentionally uses an
//! accelerated epoch while exercising the production execution and compact
//! block encoders.

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bit_app::abci::{AbciApplication, AbciConfig};
use bit_emission::{FeePolicy, GenesisAllocation};
use bit_staking::{
    consensus_address, StakingBook, StakingParameters, ATOMIC_PER_BIT, RECOVERY_RECEIPT_BYTES,
};
use bit_state::GenesisConfig;
use bit_types::{chain_context, position_id, validator_id, Amount, MonetaryPolicy};
use decaf377::Fq;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use tendermint::Time;
use tendermint_proto::{
    google::protobuf::{Duration, Timestamp},
    v0_38::{
        abci::{RequestInitChain, ValidatorUpdate},
        crypto::{public_key, PublicKey},
        types::{
            AbciParams, BlockParams, ConsensusParams, EvidenceParams, ValidatorParams,
            VersionParams,
        },
    },
};

const PROBE_EPOCH_BLOCKS: u64 = 5;
const PROBE_POWER_UNIT_ATOMIC: u128 = 100 * ATOMIC_PER_BIT;
const PROBE_SHIELDED_ATOMIC: u128 = 15_000_000_000;
const PROBE_GENESIS_MANIFEST_HASH: [u8; 32] = [0x33; 32];

#[derive(Deserialize)]
struct GenesisDocument {
    genesis_time: String,
    chain_id: String,
    initial_height: String,
    consensus_params: JsonConsensusParams,
    validators: Vec<JsonValidator>,
    app_state: Value,
}

#[derive(Deserialize)]
struct ProbeAppState {
    bit_app_network_probe: u64,
    genesis_manifest_hash_hex: String,
    genesis_commitments_hex: Vec<String>,
}

#[derive(Deserialize)]
struct JsonConsensusParams {
    block: JsonBlockParams,
    evidence: JsonEvidenceParams,
    validator: JsonValidatorParams,
    version: JsonVersionParams,
    abci: JsonAbciParams,
}

#[derive(Deserialize)]
struct JsonBlockParams {
    max_bytes: String,
    max_gas: String,
}

#[derive(Deserialize)]
struct JsonEvidenceParams {
    max_age_num_blocks: String,
    max_age_duration: String,
    max_bytes: String,
}

#[derive(Deserialize)]
struct JsonValidatorParams {
    pub_key_types: Vec<String>,
}

#[derive(Deserialize)]
struct JsonVersionParams {
    app: String,
}

#[derive(Deserialize)]
struct JsonAbciParams {
    vote_extensions_enable_height: String,
}

#[derive(Deserialize)]
struct JsonValidator {
    address: String,
    pub_key: JsonPublicKey,
    power: String,
}

#[derive(Deserialize)]
struct JsonPublicKey {
    #[serde(rename = "type")]
    key_type: String,
    value: String,
}

fn parse_number<T>(value: &str, name: &'static str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    value.parse().with_context(|| format!("invalid {name}"))
}

fn domain_hash(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
    hasher.finalize().into()
}

fn hash32_hex(value: &str, name: &'static str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("invalid {name} hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must be 32 bytes"))
}

fn protobuf_timestamp(value: &str) -> Result<Timestamp> {
    let time = Time::parse_from_rfc3339(value).context("invalid genesis_time")?;
    Ok(time.into())
}

fn protobuf_duration(nanoseconds: &str) -> Result<Duration> {
    let value: i128 = parse_number(nanoseconds, "max_age_duration")?;
    ensure!(value > 0, "max_age_duration must be positive");
    let seconds =
        i64::try_from(value / 1_000_000_000).context("max_age_duration seconds exceed i64")?;
    let nanos =
        i32::try_from(value % 1_000_000_000).context("max_age_duration nanos exceed i32")?;
    Ok(Duration { seconds, nanos })
}

fn validator_key(validator: &JsonValidator) -> Result<[u8; 32]> {
    ensure!(
        validator.pub_key.key_type == "tendermint/PubKeyEd25519",
        "only Ed25519 genesis validators are supported"
    );
    let bytes = BASE64
        .decode(&validator.pub_key.value)
        .context("invalid validator public key base64")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("validator public key must be 32 bytes"))?;
    ensure!(
        hex::encode_upper(consensus_address(&key)) == validator.address,
        "validator address does not match public key"
    );
    Ok(key)
}

fn build_configuration(document: GenesisDocument) -> Result<(GenesisConfig, AbciConfig)> {
    ensure!(
        !document.validators.is_empty(),
        "at least one validator is required"
    );
    let max_block_bytes: u64 =
        parse_number(&document.consensus_params.block.max_bytes, "max_bytes")?;
    let protocol_version: u64 =
        parse_number(&document.consensus_params.version.app, "app version")?;
    ensure!(protocol_version > 0, "app version must be positive");

    let app_state: ProbeAppState = serde_json::from_value(document.app_state.clone())
        .context("invalid BIT probe app_state")?;
    ensure!(
        app_state.bit_app_network_probe == 2,
        "unsupported BIT probe app_state version"
    );
    let genesis_manifest_hash = hash32_hex(
        &app_state.genesis_manifest_hash_hex,
        "genesis_manifest_hash",
    )?;
    ensure!(
        genesis_manifest_hash == PROBE_GENESIS_MANIFEST_HASH,
        "unexpected probe genesis manifest hash"
    );
    let genesis_commitments = app_state
        .genesis_commitments_hex
        .iter()
        .map(|value| hash32_hex(value, "genesis commitment"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        genesis_commitments.len() == 2,
        "probe genesis must contain two commitments"
    );
    ensure!(
        genesis_commitments[0] != genesis_commitments[1],
        "probe genesis commitments must be distinct"
    );
    let chain_context = chain_context(genesis_manifest_hash);
    let mut parameters = StakingParameters::reference_testnet();
    parameters.power_unit_atomic = Amount::new(PROBE_POWER_UNIT_ATOMIC)?;
    let mut staking = StakingBook::new(chain_context, parameters)?;
    let principal = Amount::new(bit_staking::TESTNET_MIN_SELF_BOND_ATOMIC)?;
    let mut expected_validators = Vec::with_capacity(document.validators.len());

    for validator in &document.validators {
        let key = validator_key(validator)?;
        let power: u64 = parse_number(&validator.power, "validator power")?;
        ensure!(power == 10, "probe validators must start with power 10");
        let operator = domain_hash(b"BIT-COMET-NETWORK-PROBE-OPERATOR-V1", &key);
        let owner = domain_hash(b"BIT-COMET-NETWORK-PROBE-OWNER-V1", &key);
        let validator_id = validator_id(&chain_context, &operator);
        let position_id = position_id(&chain_context, &owner);
        staking.register_validator(validator_id, operator, key, 500)?;
        staking.open_pending_delegation(
            0,
            0,
            position_id,
            owner,
            validator_id,
            principal,
            Amount::ZERO,
            true,
            vec![key[0]; RECOVERY_RECEIPT_BYTES],
        )?;
        staking.activate_pending(&position_id, 1)?;
        expected_validators.push(ValidatorUpdate {
            pub_key: Some(PublicKey {
                sum: Some(public_key::Sum::Ed25519(key.to_vec())),
            }),
            power: i64::try_from(power).context("validator power exceeds i64")?,
        });
    }
    expected_validators.sort_by(|left, right| {
        right.power.cmp(&left.power).then_with(|| {
            let left_key: [u8; 32] = left
                .pub_key
                .as_ref()
                .and_then(|key| key.sum.as_ref())
                .and_then(|sum| match sum {
                    public_key::Sum::Ed25519(key) => key.as_slice().try_into().ok(),
                    _ => None,
                })
                .expect("probe validators were validated as 32-byte Ed25519 keys");
            let right_key: [u8; 32] = right
                .pub_key
                .as_ref()
                .and_then(|key| key.sum.as_ref())
                .and_then(|sum| match sum {
                    public_key::Sum::Ed25519(key) => key.as_slice().try_into().ok(),
                    _ => None,
                })
                .expect("probe validators were validated as 32-byte Ed25519 keys");
            consensus_address(&left_key).cmp(&consensus_address(&right_key))
        })
    });
    let selected = staking.apply_validator_set()?;
    ensure!(
        selected.iter().all(|validator| validator.power == 10),
        "staking power does not match CometBFT genesis"
    );

    let validator_count =
        u128::try_from(document.validators.len()).context("validator count exceeds u128")?;
    let total_stake = Amount::new(
        principal
            .value()
            .checked_mul(validator_count)
            .context("genesis stake overflow")?,
    )?;
    let mut monetary_policy = MonetaryPolicy::reference_testnet();
    monetary_policy.epoch_blocks = PROBE_EPOCH_BLOCKS;
    let shielded = Amount::new(PROBE_SHIELDED_ATOMIC)?;
    let unclaimed = Amount::new(
        monetary_policy
            .genesis_supply
            .value()
            .checked_sub(total_stake.value())
            .and_then(|value| value.checked_sub(shielded.value()))
            .context("genesis stake exceeds supply")?,
    )?;
    let mut native_asset_id = [0u8; 32];
    native_asset_id.copy_from_slice(&Fq::from(1u64).to_bytes());
    let app_state_bytes = serde_json::to_vec(&document.app_state)?;
    let initial_height: i64 = parse_number(&document.initial_height, "initial_height")?;
    let initial_height = initial_height.max(1);
    let expected_init_chain = RequestInitChain {
        time: Some(protobuf_timestamp(&document.genesis_time)?),
        chain_id: document.chain_id,
        consensus_params: Some(ConsensusParams {
            block: Some(BlockParams {
                max_bytes: i64::try_from(max_block_bytes).context("max_bytes exceeds i64")?,
                max_gas: parse_number(&document.consensus_params.block.max_gas, "max_gas")?,
            }),
            evidence: Some(EvidenceParams {
                max_age_num_blocks: parse_number(
                    &document.consensus_params.evidence.max_age_num_blocks,
                    "max_age_num_blocks",
                )?,
                max_age_duration: Some(protobuf_duration(
                    &document.consensus_params.evidence.max_age_duration,
                )?),
                max_bytes: parse_number(
                    &document.consensus_params.evidence.max_bytes,
                    "evidence max_bytes",
                )?,
            }),
            validator: Some(ValidatorParams {
                pub_key_types: document.consensus_params.validator.pub_key_types,
            }),
            version: Some(VersionParams {
                app: protocol_version,
            }),
            abci: Some(AbciParams {
                vote_extensions_enable_height: parse_number(
                    &document.consensus_params.abci.vote_extensions_enable_height,
                    "vote_extensions_enable_height",
                )?,
            }),
        }),
        validators: expected_validators,
        app_state_bytes: app_state_bytes.clone().into(),
        initial_height,
    };
    let genesis = GenesisConfig {
        chain_context,
        native_asset_id,
        protocol_version,
        max_block_bytes,
        max_tx_lifetime_blocks: 100,
        max_envelope_bytes: 65_536,
        anchor_retention_blocks: 100,
        monetary_policy,
        fee_policy: FeePolicy::reference_testnet(),
        genesis_allocation: GenesisAllocation {
            shielded,
            stake: total_stake,
            pending_delegation: Amount::ZERO,
            exits: Amount::ZERO,
            commission: Amount::ZERO,
            fee_reserve: Amount::ZERO,
            unclaimed_genesis: unclaimed,
        },
        genesis_staking: staking,
        genesis_commitments,
        genesis_claims: Vec::new(),
        genesis_execution_hash: domain_hash(
            b"BIT-COMET-NETWORK-PROBE-GENESIS-EXECUTION-V1",
            &app_state_bytes,
        ),
        genesis_compact_hash: domain_hash(
            b"BIT-COMET-NETWORK-PROBE-GENESIS-COMPACT-V1",
            &app_state_bytes,
        ),
    };
    let config = AbciConfig {
        application_name: "bit-app-comet-network-probe".to_owned(),
        application_version: env!("CARGO_PKG_VERSION").to_owned(),
        expected_init_chain,
        retain_height: 0,
        state_sync: None,
    };
    Ok((genesis, config))
}

fn main() -> Result<()> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let listen = args.next().context("missing LISTEN argument")?;
    let state_path = PathBuf::from(args.next().context("missing STATE_DIR argument")?);
    let genesis_path = PathBuf::from(args.next().context("missing GENESIS_JSON argument")?);
    ensure!(args.next().is_none(), "unexpected extra argument");

    let document: GenesisDocument = serde_json::from_slice(
        &fs::read(&genesis_path)
            .with_context(|| format!("cannot read {}", genesis_path.display()))?,
    )
    .context("cannot decode CometBFT genesis JSON")?;
    let (genesis, config) = build_configuration(document)?;
    fs::create_dir_all(&state_path)?;
    let app = AbciApplication::open(state_path, genesis, config)?;
    eprintln!(
        "BIT real-app/JMT CometBFT probe; canonical block artifacts; listening {}",
        listen.to_string_lossy()
    );
    app.bind(listen.to_string_lossy().as_ref(), 16 * 1024 * 1024)?
        .listen()?;
    Ok(())
}
