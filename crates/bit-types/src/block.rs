use crate::{cbor::Cursor, cbor::Writer, Action, Amount, Error, Result};
use sha2::{Digest, Sha256};

pub const EXECUTION_SUMMARY_DOMAIN: &[u8] = b"bit/execution-summary/v1";
pub const COMPACT_BLOCK_DOMAIN: &[u8] = b"bit/compact-block/v1";

const ARTIFACT_VERSION: u64 = 1;
const MAX_TRANSACTIONS: usize = 100_000;
const MAX_EVENTS: usize = 100_000;
const MAX_EVENT_ITEMS: usize = 100_000;
const MAX_OUTPUT_BODY_BYTES: usize = 8_192;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

pub type Hash32 = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedExecution {
    pub tx_id: Hash32,
    pub effect_hash: [u8; 64],
    pub action_tag: u8,
    pub fee: Amount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionResult {
    pub index: u32,
    pub envelope_hash: Hash32,
    pub code: u32,
    pub accepted: Option<AcceptedExecution>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorRewardRecord {
    pub validator_id: Hash32,
    pub score: u128,
    pub gross_reward: Amount,
    pub stake_reward: Amount,
    pub commission_reward: Amount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationResult {
    Activated { minted_shares: Amount },
    Refundable { amount: Amount, reason: u8 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorPowerRecord {
    pub validator_id: Hash32,
    pub consensus_pubkey: Hash32,
    pub stake: Amount,
    pub power: u64,
}

/// Public state-machine events included in both committed block artifacts.
///
/// Event encodings are sorted by their complete canonical bytes. This makes
/// ordering independent of map iteration and gives compact consumers one
/// unambiguous stream for payment, staking, reward, and slashing recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockEvent {
    PreviousCommit {
        height: u64,
    },
    RewardSettlement {
        epoch: u64,
        issuance_quota: Amount,
        distributed: Amount,
        fee_reserve_remainder: Amount,
        validator_rewards: Vec<ValidatorRewardRecord>,
    },
    Activation {
        position_id: Hash32,
        result: ActivationResult,
    },
    ValidatorSet {
        validators: Vec<ValidatorPowerRecord>,
    },
    ValidatorUpdate {
        consensus_pubkey: Hash32,
        power: u64,
    },
    Evidence {
        evidence_hash: Hash32,
        validator_id: Hash32,
        newly_tombstoned: bool,
        slashed_active_assets: Amount,
    },
    SlashAdvance {
        touched_jobs: Vec<Hash32>,
        touched_cohorts: Vec<Hash32>,
        completed_jobs: Vec<Hash32>,
        slashed_exit_assets: Amount,
    },
    ExitAdvance {
        exposure_recorded: Vec<Hash32>,
        matured: Vec<Hash32>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionSummary {
    pub chain_context: Hash32,
    pub height: u64,
    pub block_time_seconds: u64,
    pub shielded_tree_root: Hash32,
    pub transactions: Vec<ExecutionResult>,
    pub events: Vec<BlockEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactTransaction {
    pub index: u32,
    pub tx_id: Hash32,
    pub action: Action,
    pub nullifiers: Vec<Hash32>,
    pub output_commitments: Vec<Hash32>,
    /// Exact canonical upstream OutputBody protobuf bytes.
    pub output_bodies: Vec<Vec<u8>>,
    pub memo_ciphertext: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactBlock {
    pub chain_context: Hash32,
    pub height: u64,
    pub block_time_seconds: u64,
    pub shielded_tree_root: Hash32,
    pub transactions: Vec<CompactTransaction>,
    pub events: Vec<BlockEvent>,
}

pub fn block_artifact_hash(domain: &[u8], bytes: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

impl ExecutionSummary {
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.array(7);
        writer.uint(ARTIFACT_VERSION);
        bytes32(&mut writer, &self.chain_context);
        writer.uint(self.height);
        writer.uint(self.block_time_seconds);
        bytes32(&mut writer, &self.shielded_tree_root);
        writer.array(self.transactions.len());
        for result in &self.transactions {
            encode_execution_result(&mut writer, result);
        }
        encode_events(&mut writer, &self.events)?;
        let bytes = writer.finish();
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(Error::InvalidBlockArtifact(
                "execution summary is too large",
            ));
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(Error::InvalidBlockArtifact(
                "execution summary is too large",
            ));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.array()? != 7 || cursor.uint()? != ARTIFACT_VERSION {
            return Err(Error::InvalidBlockArtifact(
                "unsupported execution summary version or arity",
            ));
        }
        let chain_context = read32(&mut cursor)?;
        let height = cursor.uint()?;
        let block_time_seconds = cursor.uint()?;
        let shielded_tree_root = read32(&mut cursor)?;
        let count = bounded_count(
            cursor.array()?,
            MAX_TRANSACTIONS,
            "too many transaction results",
        )?;
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            transactions.push(decode_execution_result(&mut cursor)?);
        }
        let events = decode_events(&mut cursor)?;
        cursor.finish()?;
        let summary = Self {
            chain_context,
            height,
            block_time_seconds,
            shielded_tree_root,
            transactions,
            events,
        };
        summary.validate()?;
        if summary.encode_canonical()?.as_slice() != bytes {
            return Err(Error::InvalidBlockArtifact(
                "execution summary does not round-trip canonically",
            ));
        }
        Ok(summary)
    }

    pub fn hash(&self) -> Result<Hash32> {
        Ok(block_artifact_hash(
            EXECUTION_SUMMARY_DOMAIN,
            &self.encode_canonical()?,
        ))
    }

    fn validate(&self) -> Result<()> {
        if self.height == 0 {
            return Err(Error::InvalidBlockArtifact("block height must be positive"));
        }
        if self.transactions.len() > MAX_TRANSACTIONS {
            return Err(Error::InvalidBlockArtifact("too many transaction results"));
        }
        for (position, result) in self.transactions.iter().enumerate() {
            let expected = u32::try_from(position)
                .map_err(|_| Error::InvalidBlockArtifact("transaction index overflow"))?;
            if result.index != expected {
                return Err(Error::InvalidBlockArtifact(
                    "transaction results are not consecutively indexed",
                ));
            }
            if (result.code == 0) != result.accepted.is_some() {
                return Err(Error::InvalidBlockArtifact(
                    "success code and accepted execution disagree",
                ));
            }
            if result
                .accepted
                .as_ref()
                .is_some_and(|accepted| accepted.action_tag > 10)
            {
                return Err(Error::InvalidBlockArtifact("unknown action tag"));
            }
        }
        validate_events(&self.events)
    }
}

impl CompactBlock {
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.array(7);
        writer.uint(ARTIFACT_VERSION);
        bytes32(&mut writer, &self.chain_context);
        writer.uint(self.height);
        writer.uint(self.block_time_seconds);
        bytes32(&mut writer, &self.shielded_tree_root);
        writer.array(self.transactions.len());
        for transaction in &self.transactions {
            encode_compact_transaction(&mut writer, transaction)?;
        }
        encode_events(&mut writer, &self.events)?;
        let bytes = writer.finish();
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(Error::InvalidBlockArtifact("compact block is too large"));
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(Error::InvalidBlockArtifact("compact block is too large"));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.array()? != 7 || cursor.uint()? != ARTIFACT_VERSION {
            return Err(Error::InvalidBlockArtifact(
                "unsupported compact block version or arity",
            ));
        }
        let chain_context = read32(&mut cursor)?;
        let height = cursor.uint()?;
        let block_time_seconds = cursor.uint()?;
        let shielded_tree_root = read32(&mut cursor)?;
        let count = bounded_count(
            cursor.array()?,
            MAX_TRANSACTIONS,
            "too many compact transactions",
        )?;
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            transactions.push(decode_compact_transaction(&mut cursor)?);
        }
        let events = decode_events(&mut cursor)?;
        cursor.finish()?;
        let block = Self {
            chain_context,
            height,
            block_time_seconds,
            shielded_tree_root,
            transactions,
            events,
        };
        block.validate()?;
        if block.encode_canonical()?.as_slice() != bytes {
            return Err(Error::InvalidBlockArtifact(
                "compact block does not round-trip canonically",
            ));
        }
        Ok(block)
    }

    pub fn hash(&self) -> Result<Hash32> {
        Ok(block_artifact_hash(
            COMPACT_BLOCK_DOMAIN,
            &self.encode_canonical()?,
        ))
    }

    fn validate(&self) -> Result<()> {
        if self.height == 0 {
            return Err(Error::InvalidBlockArtifact("block height must be positive"));
        }
        if self.transactions.len() > MAX_TRANSACTIONS {
            return Err(Error::InvalidBlockArtifact("too many compact transactions"));
        }
        let mut previous_index = None;
        for transaction in &self.transactions {
            if previous_index.is_some_and(|previous| transaction.index <= previous) {
                return Err(Error::InvalidBlockArtifact(
                    "compact transaction indices are not strictly increasing",
                ));
            }
            previous_index = Some(transaction.index);
            if transaction.nullifiers.len() > 8
                || transaction.output_bodies.len() > 8
                || transaction.output_commitments.len() != transaction.output_bodies.len()
            {
                return Err(Error::InvalidBlockArtifact(
                    "invalid compact Spend/Output cardinality",
                ));
            }
            if transaction
                .output_bodies
                .iter()
                .any(|body| body.is_empty() || body.len() > MAX_OUTPUT_BODY_BYTES)
            {
                return Err(Error::InvalidBlockArtifact(
                    "compact OutputBody length is invalid",
                ));
            }
            match (
                &transaction.memo_ciphertext,
                transaction.output_bodies.is_empty(),
            ) {
                (None, true) | (Some(_), false) => {}
                _ => {
                    return Err(Error::InvalidBlockArtifact(
                        "compact memo presence disagrees with Outputs",
                    ))
                }
            }
            if transaction
                .memo_ciphertext
                .as_ref()
                .is_some_and(|memo| memo.len() != 528)
            {
                return Err(Error::InvalidBlockArtifact(
                    "compact memo ciphertext must be 528 bytes",
                ));
            }
            transaction.action.validate()?;
        }
        validate_events(&self.events)
    }
}

fn encode_execution_result(writer: &mut Writer, result: &ExecutionResult) {
    writer.array(4);
    writer.uint(result.index.into());
    bytes32(writer, &result.envelope_hash);
    writer.uint(result.code.into());
    match &result.accepted {
        Some(accepted) => {
            writer.array(4);
            bytes32(writer, &accepted.tx_id);
            writer.bytes(&accepted.effect_hash);
            writer.uint(accepted.action_tag.into());
            amount(writer, accepted.fee);
        }
        None => writer.null(),
    }
}

fn decode_execution_result(cursor: &mut Cursor<'_>) -> Result<ExecutionResult> {
    if cursor.array()? != 4 {
        return Err(Error::InvalidBlockArtifact(
            "execution result must have four fields",
        ));
    }
    let index = u32::try_from(cursor.uint()?)
        .map_err(|_| Error::InvalidBlockArtifact("transaction index overflow"))?;
    let envelope_hash = read32(cursor)?;
    let code = u32::try_from(cursor.uint()?)
        .map_err(|_| Error::InvalidBlockArtifact("transaction code overflow"))?;
    let accepted = cursor.nullable(|cursor| {
        if cursor.array()? != 4 {
            return Err(Error::InvalidBlockArtifact(
                "accepted execution must have four fields",
            ));
        }
        Ok(AcceptedExecution {
            tx_id: read32(cursor)?,
            effect_hash: read64(cursor)?,
            action_tag: u8::try_from(cursor.uint()?)
                .map_err(|_| Error::InvalidBlockArtifact("action tag overflow"))?,
            fee: read_amount(cursor)?,
        })
    })?;
    Ok(ExecutionResult {
        index,
        envelope_hash,
        code,
        accepted,
    })
}

fn encode_compact_transaction(writer: &mut Writer, transaction: &CompactTransaction) -> Result<()> {
    writer.array(7);
    writer.uint(transaction.index.into());
    bytes32(writer, &transaction.tx_id);
    transaction.action.encode(writer)?;
    encode_hashes(writer, &transaction.nullifiers);
    encode_hashes(writer, &transaction.output_commitments);
    writer.array(transaction.output_bodies.len());
    for body in &transaction.output_bodies {
        writer.bytes(body);
    }
    match &transaction.memo_ciphertext {
        Some(memo) => writer.bytes(memo),
        None => writer.null(),
    }
    Ok(())
}

fn decode_compact_transaction(cursor: &mut Cursor<'_>) -> Result<CompactTransaction> {
    if cursor.array()? != 7 {
        return Err(Error::InvalidBlockArtifact(
            "compact transaction must have seven fields",
        ));
    }
    let index = u32::try_from(cursor.uint()?)
        .map_err(|_| Error::InvalidBlockArtifact("compact transaction index overflow"))?;
    let tx_id = read32(cursor)?;
    let action = Action::decode(cursor)?;
    let nullifiers = decode_hashes(cursor, 8, "too many compact nullifiers")?;
    let output_commitments = decode_hashes(cursor, 8, "too many compact commitments")?;
    let output_count = bounded_count(cursor.array()?, 8, "too many compact Output bodies")?;
    let mut output_bodies = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        output_bodies.push(cursor.bytes()?);
    }
    let memo_ciphertext = cursor.nullable(|cursor| cursor.bytes())?;
    Ok(CompactTransaction {
        index,
        tx_id,
        action,
        nullifiers,
        output_commitments,
        output_bodies,
        memo_ciphertext,
    })
}

fn encode_events(writer: &mut Writer, events: &[BlockEvent]) -> Result<()> {
    writer.array(events.len());
    for event in events {
        event.encode(writer)?;
    }
    Ok(())
}

fn decode_events(cursor: &mut Cursor<'_>) -> Result<Vec<BlockEvent>> {
    let count = bounded_count(cursor.array()?, MAX_EVENTS, "too many block events")?;
    let mut events = Vec::with_capacity(count);
    for _ in 0..count {
        events.push(BlockEvent::decode(cursor)?);
    }
    Ok(events)
}

fn validate_events(events: &[BlockEvent]) -> Result<()> {
    if events.len() > MAX_EVENTS {
        return Err(Error::InvalidBlockArtifact("too many block events"));
    }
    let mut previous: Option<Vec<u8>> = None;
    for event in events {
        event.validate()?;
        let encoded = event.encode_to_vec()?;
        if previous.as_ref().is_some_and(|value| encoded <= *value) {
            return Err(Error::InvalidBlockArtifact(
                "block events are not in strict canonical order",
            ));
        }
        previous = Some(encoded);
    }
    Ok(())
}

impl BlockEvent {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        self.encode(&mut writer)?;
        Ok(writer.finish())
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::PreviousCommit { height } if *height == 0 => Err(Error::InvalidBlockArtifact(
                "previous commit height is zero",
            )),
            Self::RewardSettlement {
                validator_rewards, ..
            } if validator_rewards.len() > MAX_EVENT_ITEMS => {
                Err(Error::InvalidBlockArtifact("too many validator rewards"))
            }
            Self::RewardSettlement {
                validator_rewards, ..
            } if !validator_rewards
                .windows(2)
                .all(|pair| pair[0].validator_id < pair[1].validator_id) =>
            {
                Err(Error::InvalidBlockArtifact(
                    "validator rewards are not in canonical order",
                ))
            }
            Self::Activation {
                result: ActivationResult::Refundable { reason, .. },
                ..
            } if *reason > 3 => Err(Error::InvalidBlockArtifact("unknown refund reason")),
            Self::ValidatorSet { validators } if validators.len() > MAX_EVENT_ITEMS => {
                Err(Error::InvalidBlockArtifact("too many validators"))
            }
            Self::ValidatorSet { validators }
                if !validators.windows(2).all(|pair| {
                    pair[0].stake > pair[1].stake
                        || (pair[0].stake == pair[1].stake
                            && pair[0].validator_id < pair[1].validator_id)
                }) =>
            {
                Err(Error::InvalidBlockArtifact(
                    "validator set is not in canonical order",
                ))
            }
            Self::SlashAdvance {
                touched_jobs,
                touched_cohorts,
                completed_jobs,
                ..
            } if touched_jobs.len() > MAX_EVENT_ITEMS
                || touched_cohorts.len() > MAX_EVENT_ITEMS
                || completed_jobs.len() > MAX_EVENT_ITEMS =>
            {
                Err(Error::InvalidBlockArtifact("too many slash items"))
            }
            Self::SlashAdvance {
                touched_jobs,
                touched_cohorts,
                completed_jobs,
                ..
            } if !strict_hash_order(touched_jobs)
                || !strict_hash_order(touched_cohorts)
                || !strict_hash_order(completed_jobs) =>
            {
                Err(Error::InvalidBlockArtifact(
                    "slash items are not in canonical order",
                ))
            }
            Self::ExitAdvance {
                exposure_recorded,
                matured,
            } if exposure_recorded.len() > MAX_EVENT_ITEMS || matured.len() > MAX_EVENT_ITEMS => {
                Err(Error::InvalidBlockArtifact("too many exit items"))
            }
            Self::ExitAdvance {
                exposure_recorded,
                matured,
            } if !strict_hash_order(exposure_recorded) || !strict_hash_order(matured) => Err(
                Error::InvalidBlockArtifact("exit items are not in canonical order"),
            ),
            _ => Ok(()),
        }
    }

    fn encode(&self, writer: &mut Writer) -> Result<()> {
        self.validate()?;
        match self {
            Self::PreviousCommit { height } => {
                writer.array(2);
                writer.uint(0);
                writer.uint(*height);
            }
            Self::RewardSettlement {
                epoch,
                issuance_quota,
                distributed,
                fee_reserve_remainder,
                validator_rewards,
            } => {
                writer.array(6);
                writer.uint(1);
                writer.uint(*epoch);
                amount(writer, *issuance_quota);
                amount(writer, *distributed);
                amount(writer, *fee_reserve_remainder);
                writer.array(validator_rewards.len());
                for reward in validator_rewards {
                    writer.array(5);
                    bytes32(writer, &reward.validator_id);
                    writer.bytes(&reward.score.to_be_bytes());
                    amount(writer, reward.gross_reward);
                    amount(writer, reward.stake_reward);
                    amount(writer, reward.commission_reward);
                }
            }
            Self::Activation {
                position_id,
                result,
            } => {
                writer.array(5);
                writer.uint(2);
                bytes32(writer, position_id);
                match result {
                    ActivationResult::Activated { minted_shares } => {
                        writer.uint(0);
                        amount(writer, *minted_shares);
                        writer.null();
                    }
                    ActivationResult::Refundable {
                        amount: value,
                        reason,
                    } => {
                        writer.uint(1);
                        amount(writer, *value);
                        writer.uint((*reason).into());
                    }
                }
            }
            Self::ValidatorSet { validators } => {
                writer.array(2);
                writer.uint(3);
                writer.array(validators.len());
                for validator in validators {
                    writer.array(4);
                    bytes32(writer, &validator.validator_id);
                    bytes32(writer, &validator.consensus_pubkey);
                    amount(writer, validator.stake);
                    writer.uint(validator.power);
                }
            }
            Self::ValidatorUpdate {
                consensus_pubkey,
                power,
            } => {
                writer.array(3);
                writer.uint(4);
                bytes32(writer, consensus_pubkey);
                writer.uint(*power);
            }
            Self::Evidence {
                evidence_hash,
                validator_id,
                newly_tombstoned,
                slashed_active_assets,
            } => {
                writer.array(5);
                writer.uint(5);
                bytes32(writer, evidence_hash);
                bytes32(writer, validator_id);
                writer.boolean(*newly_tombstoned);
                amount(writer, *slashed_active_assets);
            }
            Self::SlashAdvance {
                touched_jobs,
                touched_cohorts,
                completed_jobs,
                slashed_exit_assets,
            } => {
                writer.array(5);
                writer.uint(6);
                encode_hashes(writer, touched_jobs);
                encode_hashes(writer, touched_cohorts);
                encode_hashes(writer, completed_jobs);
                amount(writer, *slashed_exit_assets);
            }
            Self::ExitAdvance {
                exposure_recorded,
                matured,
            } => {
                writer.array(3);
                writer.uint(7);
                encode_hashes(writer, exposure_recorded);
                encode_hashes(writer, matured);
            }
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor<'_>) -> Result<Self> {
        let arity = cursor.array()?;
        let tag = cursor.uint()?;
        let event = match (tag, arity) {
            (0, 2) => Self::PreviousCommit {
                height: cursor.uint()?,
            },
            (1, 6) => {
                let epoch = cursor.uint()?;
                let issuance_quota = read_amount(cursor)?;
                let distributed = read_amount(cursor)?;
                let fee_reserve_remainder = read_amount(cursor)?;
                let count = bounded_count(
                    cursor.array()?,
                    MAX_EVENT_ITEMS,
                    "too many validator rewards",
                )?;
                let mut validator_rewards = Vec::with_capacity(count);
                for _ in 0..count {
                    if cursor.array()? != 5 {
                        return Err(Error::InvalidBlockArtifact(
                            "validator reward must have five fields",
                        ));
                    }
                    validator_rewards.push(ValidatorRewardRecord {
                        validator_id: read32(cursor)?,
                        score: read_u128(cursor)?,
                        gross_reward: read_amount(cursor)?,
                        stake_reward: read_amount(cursor)?,
                        commission_reward: read_amount(cursor)?,
                    });
                }
                Self::RewardSettlement {
                    epoch,
                    issuance_quota,
                    distributed,
                    fee_reserve_remainder,
                    validator_rewards,
                }
            }
            (2, 5) => {
                let position_id = read32(cursor)?;
                let result = match cursor.uint()? {
                    0 => {
                        let minted_shares = read_amount(cursor)?;
                        if cursor.nullable(|_| Ok(()))?.is_some() {
                            return Err(Error::InvalidBlockArtifact(
                                "activated result reason must be null",
                            ));
                        }
                        ActivationResult::Activated { minted_shares }
                    }
                    1 => ActivationResult::Refundable {
                        amount: read_amount(cursor)?,
                        reason: u8::try_from(cursor.uint()?)
                            .map_err(|_| Error::InvalidBlockArtifact("refund reason overflow"))?,
                    },
                    _ => return Err(Error::InvalidBlockArtifact("unknown activation result tag")),
                };
                Self::Activation {
                    position_id,
                    result,
                }
            }
            (3, 2) => {
                let count = bounded_count(cursor.array()?, MAX_EVENT_ITEMS, "too many validators")?;
                let mut validators = Vec::with_capacity(count);
                for _ in 0..count {
                    if cursor.array()? != 4 {
                        return Err(Error::InvalidBlockArtifact(
                            "validator power record must have four fields",
                        ));
                    }
                    validators.push(ValidatorPowerRecord {
                        validator_id: read32(cursor)?,
                        consensus_pubkey: read32(cursor)?,
                        stake: read_amount(cursor)?,
                        power: cursor.uint()?,
                    });
                }
                Self::ValidatorSet { validators }
            }
            (4, 3) => Self::ValidatorUpdate {
                consensus_pubkey: read32(cursor)?,
                power: cursor.uint()?,
            },
            (5, 5) => Self::Evidence {
                evidence_hash: read32(cursor)?,
                validator_id: read32(cursor)?,
                newly_tombstoned: cursor.boolean()?,
                slashed_active_assets: read_amount(cursor)?,
            },
            (6, 5) => Self::SlashAdvance {
                touched_jobs: decode_hashes(cursor, MAX_EVENT_ITEMS, "too many slash jobs")?,
                touched_cohorts: decode_hashes(cursor, MAX_EVENT_ITEMS, "too many slash cohorts")?,
                completed_jobs: decode_hashes(
                    cursor,
                    MAX_EVENT_ITEMS,
                    "too many completed slash jobs",
                )?,
                slashed_exit_assets: read_amount(cursor)?,
            },
            (7, 3) => Self::ExitAdvance {
                exposure_recorded: decode_hashes(
                    cursor,
                    MAX_EVENT_ITEMS,
                    "too many exposure records",
                )?,
                matured: decode_hashes(cursor, MAX_EVENT_ITEMS, "too many matured cohorts")?,
            },
            _ => {
                return Err(Error::InvalidBlockArtifact(
                    "unknown block event tag or arity",
                ))
            }
        };
        event.validate()?;
        Ok(event)
    }
}

fn bytes32(writer: &mut Writer, value: &Hash32) {
    writer.bytes(value);
}

fn amount(writer: &mut Writer, value: Amount) {
    writer.bytes(&value.to_be_bytes());
}

fn read32(cursor: &mut Cursor<'_>) -> Result<Hash32> {
    cursor
        .bytes()?
        .try_into()
        .map_err(|_| Error::InvalidBlockArtifact("expected 32-byte value"))
}

fn read64(cursor: &mut Cursor<'_>) -> Result<[u8; 64]> {
    cursor
        .bytes()?
        .try_into()
        .map_err(|_| Error::InvalidBlockArtifact("expected 64-byte value"))
}

fn read_u128(cursor: &mut Cursor<'_>) -> Result<u128> {
    let bytes: [u8; 16] = cursor
        .bytes()?
        .try_into()
        .map_err(|_| Error::InvalidBlockArtifact("expected 16-byte integer"))?;
    Ok(u128::from_be_bytes(bytes))
}

fn read_amount(cursor: &mut Cursor<'_>) -> Result<Amount> {
    let bytes: [u8; 16] = cursor
        .bytes()?
        .try_into()
        .map_err(|_| Error::InvalidBlockArtifact("expected 16-byte amount"))?;
    Amount::from_be_bytes(bytes)
}

fn encode_hashes(writer: &mut Writer, values: &[Hash32]) {
    writer.array(values.len());
    for value in values {
        bytes32(writer, value);
    }
}

fn decode_hashes(
    cursor: &mut Cursor<'_>,
    maximum: usize,
    reason: &'static str,
) -> Result<Vec<Hash32>> {
    let count = bounded_count(cursor.array()?, maximum, reason)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(read32(cursor)?);
    }
    Ok(values)
}

fn bounded_count(value: usize, maximum: usize, reason: &'static str) -> Result<usize> {
    if value > maximum {
        Err(Error::InvalidBlockArtifact(reason))
    } else {
        Ok(value)
    }
}

fn strict_hash_order(values: &[Hash32]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn amount_value(value: u128) -> Amount {
        Amount::new(value).unwrap()
    }

    #[derive(Deserialize)]
    struct ArtifactVectors {
        empty_block: EmptyBlockVector,
    }

    #[derive(Deserialize)]
    struct EmptyBlockVector {
        canonical_cbor_hex: String,
        execution_hash_hex: String,
        compact_hash_hex: String,
    }

    #[test]
    fn empty_artifacts_match_cross_language_vector() {
        let vectors: ArtifactVectors = serde_json::from_str(include_str!(
            "../../../tests/vectors/block-artifact-vectors.json"
        ))
        .unwrap();
        let summary = ExecutionSummary {
            chain_context: [0; 32],
            height: 1,
            block_time_seconds: 2,
            shielded_tree_root: [0x11; 32],
            transactions: vec![],
            events: vec![],
        };
        let compact = CompactBlock {
            chain_context: summary.chain_context,
            height: summary.height,
            block_time_seconds: summary.block_time_seconds,
            shielded_tree_root: summary.shielded_tree_root,
            transactions: vec![],
            events: vec![],
        };
        assert_eq!(
            hex::encode(summary.encode_canonical().unwrap()),
            vectors.empty_block.canonical_cbor_hex
        );
        assert_eq!(
            hex::encode(summary.hash().unwrap()),
            vectors.empty_block.execution_hash_hex
        );
        assert_eq!(
            hex::encode(compact.hash().unwrap()),
            vectors.empty_block.compact_hash_hex
        );
    }

    #[test]
    fn execution_and_compact_artifacts_round_trip() {
        let mut events = vec![
            BlockEvent::ValidatorUpdate {
                consensus_pubkey: [7; 32],
                power: 42,
            },
            BlockEvent::PreviousCommit { height: 8 },
            BlockEvent::Evidence {
                evidence_hash: [9; 32],
                validator_id: [10; 32],
                newly_tombstoned: true,
                slashed_active_assets: amount_value(11),
            },
        ];
        events.sort_by_key(|event| event.canonical_bytes().unwrap());
        let summary = ExecutionSummary {
            chain_context: [1; 32],
            height: 9,
            block_time_seconds: 10,
            shielded_tree_root: [2; 32],
            transactions: vec![ExecutionResult {
                index: 0,
                envelope_hash: [3; 32],
                code: 0,
                accepted: Some(AcceptedExecution {
                    tx_id: [4; 32],
                    effect_hash: [5; 64],
                    action_tag: 0,
                    fee: amount_value(6),
                }),
            }],
            events: events.clone(),
        };
        let encoded = summary.encode_canonical().unwrap();
        assert_eq!(
            ExecutionSummary::decode_canonical(&encoded).unwrap(),
            summary
        );
        assert_ne!(summary.hash().unwrap(), [0; 32]);

        let compact = CompactBlock {
            chain_context: [1; 32],
            height: 9,
            block_time_seconds: 10,
            shielded_tree_root: [2; 32],
            transactions: vec![CompactTransaction {
                index: 0,
                tx_id: [4; 32],
                action: Action::Transfer,
                nullifiers: vec![[6; 32]],
                output_commitments: vec![[7; 32]],
                output_bodies: vec![vec![8; 32]],
                memo_ciphertext: Some(vec![9; 528]),
            }],
            events,
        };
        let encoded = compact.encode_canonical().unwrap();
        assert_eq!(CompactBlock::decode_canonical(&encoded).unwrap(), compact);
        assert_ne!(compact.hash().unwrap(), [0; 32]);
    }

    #[test]
    fn artifacts_reject_ambiguous_results_and_event_order() {
        let mut summary = ExecutionSummary {
            chain_context: [1; 32],
            height: 1,
            block_time_seconds: 1,
            shielded_tree_root: [2; 32],
            transactions: vec![ExecutionResult {
                index: 0,
                envelope_hash: [3; 32],
                code: 1,
                accepted: Some(AcceptedExecution {
                    tx_id: [4; 32],
                    effect_hash: [5; 64],
                    action_tag: 0,
                    fee: Amount::ZERO,
                }),
            }],
            events: vec![],
        };
        assert!(summary.encode_canonical().is_err());
        summary.transactions[0].code = 0;
        summary.events = vec![
            BlockEvent::ValidatorUpdate {
                consensus_pubkey: [8; 32],
                power: 1,
            },
            BlockEvent::PreviousCommit { height: 1 },
        ];
        assert!(summary.encode_canonical().is_err());
    }

    #[test]
    fn every_system_event_round_trips() {
        let mut events = vec![
            BlockEvent::PreviousCommit { height: 9 },
            BlockEvent::RewardSettlement {
                epoch: 2,
                issuance_quota: amount_value(100),
                distributed: amount_value(90),
                fee_reserve_remainder: amount_value(10),
                validator_rewards: vec![
                    ValidatorRewardRecord {
                        validator_id: [1; 32],
                        score: 20,
                        gross_reward: amount_value(40),
                        stake_reward: amount_value(38),
                        commission_reward: amount_value(2),
                    },
                    ValidatorRewardRecord {
                        validator_id: [2; 32],
                        score: 30,
                        gross_reward: amount_value(50),
                        stake_reward: amount_value(47),
                        commission_reward: amount_value(3),
                    },
                ],
            },
            BlockEvent::Activation {
                position_id: [3; 32],
                result: ActivationResult::Activated {
                    minted_shares: amount_value(44),
                },
            },
            BlockEvent::Activation {
                position_id: [4; 32],
                result: ActivationResult::Refundable {
                    amount: amount_value(45),
                    reason: 2,
                },
            },
            BlockEvent::ValidatorSet {
                validators: vec![
                    ValidatorPowerRecord {
                        validator_id: [5; 32],
                        consensus_pubkey: [6; 32],
                        stake: amount_value(60),
                        power: 6,
                    },
                    ValidatorPowerRecord {
                        validator_id: [7; 32],
                        consensus_pubkey: [8; 32],
                        stake: amount_value(50),
                        power: 5,
                    },
                ],
            },
            BlockEvent::ValidatorUpdate {
                consensus_pubkey: [9; 32],
                power: 7,
            },
            BlockEvent::Evidence {
                evidence_hash: [10; 32],
                validator_id: [11; 32],
                newly_tombstoned: true,
                slashed_active_assets: amount_value(12),
            },
            BlockEvent::SlashAdvance {
                touched_jobs: vec![[12; 32], [13; 32]],
                touched_cohorts: vec![[14; 32]],
                completed_jobs: vec![[15; 32]],
                slashed_exit_assets: amount_value(16),
            },
            BlockEvent::ExitAdvance {
                exposure_recorded: vec![[17; 32]],
                matured: vec![[18; 32], [19; 32]],
            },
        ];
        events.sort_by_key(|event| event.canonical_bytes().unwrap());
        let summary = ExecutionSummary {
            chain_context: [20; 32],
            height: 10,
            block_time_seconds: 11,
            shielded_tree_root: [21; 32],
            transactions: vec![],
            events,
        };
        let encoded = summary.encode_canonical().unwrap();
        assert_eq!(
            ExecutionSummary::decode_canonical(&encoded).unwrap(),
            summary
        );
    }
}
