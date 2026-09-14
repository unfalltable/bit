use crate::{Error, Hash32, TxResult};
use bit_shielded::{decode_output_body, decode_spend_body};
use bit_staking::{ActivationOutcome, RefundReason};
use bit_state::SystemBlockOutcome;
use bit_types::{
    AcceptedExecution, ActivationResult, BlockEvent, CompactBlock, CompactTransaction, Envelope,
    ExecutionResult, ExecutionSummary, ValidatorPowerRecord, ValidatorRewardRecord,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockArtifacts {
    pub execution_summary: Vec<u8>,
    pub execution_hash: Hash32,
    pub compact_block: Vec<u8>,
    pub compact_hash: Hash32,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_block_artifacts(
    chain_context: Hash32,
    height: u64,
    block_time_seconds: u64,
    shielded_tree_root: Hash32,
    transactions: &[Vec<u8>],
    results: &[TxResult],
    system: &SystemBlockOutcome,
    max_envelope_bytes: usize,
    max_tx_lifetime_blocks: u64,
) -> crate::Result<BlockArtifacts> {
    if transactions.len() != results.len() {
        return Err(Error::InvalidConfig(
            "transaction and execution-result cardinality differs",
        ));
    }
    let mut execution_results = Vec::with_capacity(results.len());
    let mut compact_transactions = Vec::new();
    for (index, (transaction, result)) in transactions.iter().zip(results).enumerate() {
        let index = u32::try_from(index)
            .map_err(|_| Error::InvalidConfig("transaction index exceeds u32"))?;
        let envelope_hash = Sha256::digest(transaction).into();
        let accepted = match result.tx_id {
            Some(tx_id) => {
                if !result.is_ok() {
                    return Err(Error::InvalidConfig(
                        "rejected transaction unexpectedly has a transaction ID",
                    ));
                }
                let envelope = Envelope::decode_canonical(
                    transaction,
                    max_envelope_bytes,
                    height,
                    max_tx_lifetime_blocks,
                )?;
                let body = envelope.validate(height, max_tx_lifetime_blocks)?;
                if body.chain_context != chain_context
                    || envelope.tx_id(height, max_tx_lifetime_blocks)? != tx_id
                {
                    return Err(Error::InvalidConfig(
                        "accepted transaction does not match artifact context",
                    ));
                }
                let effect_hash = body.effect_hash()?;
                let nullifiers = body
                    .spends
                    .iter()
                    .map(|bytes| decode_spend_body(bytes).map(|body| body.nullifier.to_bytes()))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let output_commitments = body
                    .outputs
                    .iter()
                    .map(|bytes| {
                        decode_output_body(bytes)
                            .map(|body| body.note_payload.note_commitment.into())
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                compact_transactions.push(CompactTransaction {
                    index,
                    tx_id,
                    action: body.action.clone(),
                    nullifiers,
                    output_commitments,
                    output_bodies: body.outputs.clone(),
                    memo_ciphertext: body.memo_ciphertext.clone(),
                });
                Some(AcceptedExecution {
                    tx_id,
                    effect_hash,
                    action_tag: body.action.tag(),
                    fee: body.fee,
                })
            }
            None => {
                if result.is_ok() {
                    return Err(Error::InvalidConfig(
                        "successful transaction is missing its transaction ID",
                    ));
                }
                None
            }
        };
        execution_results.push(ExecutionResult {
            index,
            envelope_hash,
            code: result.code as u32,
            accepted,
        });
    }

    let events = canonical_events(system)?;
    let execution = ExecutionSummary {
        chain_context,
        height,
        block_time_seconds,
        shielded_tree_root,
        transactions: execution_results,
        events: events.clone(),
    };
    let compact = CompactBlock {
        chain_context,
        height,
        block_time_seconds,
        shielded_tree_root,
        transactions: compact_transactions,
        events,
    };
    let execution_summary = execution.encode_canonical()?;
    let execution_hash = execution.hash()?;
    let compact_block = compact.encode_canonical()?;
    let compact_hash = compact.hash()?;
    Ok(BlockArtifacts {
        execution_summary,
        execution_hash,
        compact_block,
        compact_hash,
    })
}

fn canonical_events(system: &SystemBlockOutcome) -> crate::Result<Vec<BlockEvent>> {
    let mut events = Vec::new();
    if let Some(height) = system.last_commit_height {
        events.push(BlockEvent::PreviousCommit { height });
    }
    if let Some(settlement) = &system.reward_settlement {
        let mut validator_rewards: Vec<_> = settlement
            .validator_rewards
            .iter()
            .map(|reward| ValidatorRewardRecord {
                validator_id: reward.validator_id,
                score: reward.score,
                gross_reward: reward.gross_reward,
                stake_reward: reward.stake_reward,
                commission_reward: reward.commission_reward,
            })
            .collect();
        validator_rewards.sort_by_key(|reward| reward.validator_id);
        events.push(BlockEvent::RewardSettlement {
            epoch: settlement.epoch,
            issuance_quota: settlement.issuance_quota,
            distributed: settlement.distributed,
            fee_reserve_remainder: settlement.fee_reserve_remainder,
            validator_rewards,
        });
    }
    for (position_id, outcome) in &system.activations {
        let result = match outcome {
            ActivationOutcome::Activated { minted_shares } => ActivationResult::Activated {
                minted_shares: *minted_shares,
            },
            ActivationOutcome::Refundable { amount, reason } => ActivationResult::Refundable {
                amount: *amount,
                reason: refund_reason(*reason),
            },
        };
        events.push(BlockEvent::Activation {
            position_id: *position_id,
            result,
        });
    }
    if let Some(validators) = &system.validator_set {
        events.push(BlockEvent::ValidatorSet {
            validators: validators
                .iter()
                .map(|validator| ValidatorPowerRecord {
                    validator_id: validator.validator_id,
                    consensus_pubkey: validator.consensus_pubkey,
                    stake: validator.stake,
                    power: validator.power,
                })
                .collect(),
        });
    }
    for update in &system.validator_updates {
        events.push(BlockEvent::ValidatorUpdate {
            consensus_pubkey: update.consensus_pubkey,
            power: update.power,
        });
    }
    for evidence in &system.evidence {
        events.push(BlockEvent::Evidence {
            evidence_hash: evidence.evidence_hash,
            validator_id: evidence.validator_id,
            newly_tombstoned: evidence.newly_tombstoned,
            slashed_active_assets: evidence.slashed_active_assets,
        });
    }
    if !system.slash_advance.touched_jobs.is_empty()
        || !system.slash_advance.touched_cohorts.is_empty()
        || !system.slash_advance.completed_jobs.is_empty()
        || system.slash_advance.slashed_exit_assets != bit_types::Amount::ZERO
    {
        events.push(BlockEvent::SlashAdvance {
            touched_jobs: system.slash_advance.touched_jobs.iter().copied().collect(),
            touched_cohorts: system
                .slash_advance
                .touched_cohorts
                .iter()
                .copied()
                .collect(),
            completed_jobs: system
                .slash_advance
                .completed_jobs
                .iter()
                .copied()
                .collect(),
            slashed_exit_assets: system.slash_advance.slashed_exit_assets,
        });
    }
    if !system.exit_advance.exposure_recorded.is_empty() || !system.exit_advance.matured.is_empty()
    {
        events.push(BlockEvent::ExitAdvance {
            exposure_recorded: system
                .exit_advance
                .exposure_recorded
                .iter()
                .copied()
                .collect(),
            matured: system.exit_advance.matured.iter().copied().collect(),
        });
    }
    let mut keyed = events
        .into_iter()
        .map(|event| Ok((event.canonical_bytes()?, event)))
        .collect::<bit_types::Result<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    if keyed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::InvalidConfig("duplicate canonical block event"));
    }
    Ok(keyed.into_iter().map(|(_, event)| event).collect())
}

fn refund_reason(reason: RefundReason) -> u8 {
    match reason {
        RefundReason::ValidatorIneligible => 0,
        RefundReason::PoolInsolvent => 1,
        RefundReason::ZeroShares => 2,
        RefundReason::MinimumSharesNotMet => 3,
    }
}
