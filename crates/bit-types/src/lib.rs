//! Consensus-facing primitive types for BIT spec 1.2.
//!
//! This crate owns canonical amounts, signing-body encoding, envelope framing,
//! identifiers, and the fixed-cap monetary schedule. It does not verify ZK or
//! authorization signatures and does not contain mainnet genesis values.

mod amount;
mod block;
mod cbor;
mod envelope;
mod policy;
mod tx;

pub use amount::{Amount, MAX_AMOUNT_EXCLUSIVE, MAX_SUPPLY_ATOMIC};
pub use block::{
    block_artifact_hash, AcceptedExecution, ActivationResult, BlockEvent, CompactBlock,
    CompactTransaction, ExecutionResult, ExecutionSummary, ValidatorPowerRecord,
    ValidatorRewardRecord, COMPACT_BLOCK_DOMAIN, EXECUTION_SUMMARY_DOMAIN,
};
pub use envelope::{ed25519_authorization_message, Authorization, Envelope, Role};
pub use policy::{quota, scheduled_issuance, MonetaryPolicy};
pub use tx::{
    chain_context, cohort_id, effect_hash, position_id, proof_hash, ticket_id, validator_id,
    Action, FeeSource, TxBody,
};

use core::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidAmount,
    InvalidCbor(&'static str),
    InvalidBlockArtifact(&'static str),
    InvalidEnvelope(&'static str),
    InvalidPolicy(&'static str),
    InvalidTransaction(&'static str),
    Overflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAmount => f.write_str("amount must be below 2^120"),
            Self::InvalidCbor(reason) => write!(f, "invalid canonical CBOR: {reason}"),
            Self::InvalidBlockArtifact(reason) => write!(f, "invalid block artifact: {reason}"),
            Self::InvalidEnvelope(reason) => write!(f, "invalid canonical envelope: {reason}"),
            Self::InvalidPolicy(reason) => write!(f, "invalid monetary policy: {reason}"),
            Self::InvalidTransaction(reason) => write!(f, "invalid transaction: {reason}"),
            Self::Overflow => f.write_str("integer overflow"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
