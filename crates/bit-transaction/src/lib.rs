//! BIT transaction verification and a small in-memory Transfer state harness.
//!
//! The verifier joins the BIT canonical transaction format to the frozen
//! Penumbra Spend/Output primitives. The in-memory ledger is a deterministic
//! test harness for atomic nullifier recording; it is not persistent state or
//! a replacement for the production commitment tree.

use bit_emission::{FeeClass, FeePolicy};
use bit_shielded::{
    verify_transaction_crypto, verify_transfer_crypto, ShieldedError, ShieldedPublicBalance,
};
use bit_types::{
    ed25519_authorization_message, position_id, validator_id, Action, Amount, Authorization,
    Envelope, FeeSource, Role,
};
use ed25519_consensus::{Signature as Ed25519Signature, VerificationKey as Ed25519VerificationKey};
use std::{collections::BTreeSet, fmt};

pub type Hash32 = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTransfer {
    pub tx_id: Hash32,
    pub effect_hash: [u8; 64],
    pub anchor: Hash32,
    pub nullifiers: Vec<Hash32>,
    pub output_commitments: Vec<Hash32>,
    pub fee: Amount,
    pub minimum_fee: Amount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedStakingAction {
    Delegate {
        position_id: Hash32,
        owner: Hash32,
        validator_id: Hash32,
        deposit: Amount,
        min_shares: Amount,
        self_bond: bool,
        recovery: Vec<u8>,
    },
    RegisterValidator {
        validator_id: Hash32,
        operator: Hash32,
        consensus: Hash32,
        commission_bps: u16,
        display_name: String,
        website: String,
        description: String,
    },
    CancelPending {
        position_id: Hash32,
        expected_sequence: u64,
        expected_release: Amount,
        fee_source: FeeSource,
    },
    UpdateValidator {
        validator_id: Hash32,
        expected_sequence: u64,
        display_name: Option<String>,
        website: Option<String>,
        description: Option<String>,
        commission_bps: Option<u16>,
        request_disable: Option<bool>,
    },
    UnjailValidator {
        validator_id: Hash32,
        expected_sequence: u64,
    },
    RotateConsensusKey {
        validator_id: Hash32,
        expected_sequence: u64,
        new_consensus: Hash32,
    },
    ClaimCommission {
        validator_id: Hash32,
        expected_sequence: u64,
        requested_amount: Amount,
        fee_source: FeeSource,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStakingTransaction {
    pub shielded: VerifiedTransfer,
    pub action: VerifiedStakingAction,
}

/// Read-only keys needed to authenticate actions whose authority already lives
/// in consensus state. Direct keys carried by a new Delegate or registration
/// are verified without consulting this view.
pub trait ActionAuthorizationView {
    fn validator_operator(&self, validator_id: &Hash32) -> Option<Hash32>;

    fn validator_sequence(&self, _validator_id: &Hash32) -> Option<u64> {
        None
    }

    fn pending_position(&self, _position_id: &Hash32) -> Option<PendingPositionAuthorization> {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingPositionAuthorization {
    pub owner: Hash32,
    pub sequence: u64,
    pub release: Amount,
}

pub trait StateView {
    fn contains_anchor(&self, anchor: &Hash32) -> bool;
    fn contains_nullifier(&self, nullifier: &Hash32) -> bool;
    fn contains_transaction(&self, tx_id: &Hash32) -> bool;
}

pub struct VerificationContext<'a, S: StateView + ?Sized> {
    pub expected_chain_context: Hash32,
    pub current_height: u64,
    pub max_lifetime: u64,
    pub max_envelope_bytes: usize,
    pub native_asset_id: Hash32,
    pub fee_policy: FeePolicy,
    pub state: &'a S,
}

#[derive(Clone, Copy, Debug)]
pub struct StatelessVerificationContext {
    pub expected_chain_context: Hash32,
    pub current_height: u64,
    pub max_lifetime: u64,
    pub max_envelope_bytes: usize,
    pub native_asset_id: Hash32,
    pub fee_policy: FeePolicy,
}

#[derive(Debug)]
pub enum Error {
    Types(bit_types::Error),
    Shielded(ShieldedError),
    WrongChainContext,
    UnsupportedAction,
    UnknownAnchor,
    DuplicateNullifier,
    NullifierAlreadySpent,
    TransactionAlreadyApplied,
    FeeTooLow { required: Amount, provided: Amount },
    FeeCalculation(bit_emission::Error),
    IdentifierMismatch(&'static str),
    AuthorizationKeyNotFound { role: Role, id: Hash32 },
    InvalidAuthorization { role: Role, index: u32 },
    StaleStateQuote(&'static str),
    InvalidFeeSource(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Types(error) => write!(f, "transaction format rejected: {error}"),
            Self::Shielded(error) => write!(f, "shielded cryptography rejected: {error}"),
            Self::WrongChainContext => f.write_str("transaction belongs to another chain"),
            Self::UnsupportedAction => {
                f.write_str("action is not enabled by this transaction verifier")
            }
            Self::UnknownAnchor => f.write_str("transaction anchor is not accepted"),
            Self::DuplicateNullifier => f.write_str("transaction repeats a nullifier"),
            Self::NullifierAlreadySpent => f.write_str("nullifier is already spent"),
            Self::TransactionAlreadyApplied => f.write_str("transaction is already applied"),
            Self::FeeTooLow { required, provided } => {
                write!(
                    f,
                    "transaction fee {provided} is below required minimum {required}"
                )
            }
            Self::FeeCalculation(error) => write!(f, "minimum fee calculation failed: {error}"),
            Self::IdentifierMismatch(kind) => {
                write!(f, "{kind} identifier does not match its authorization key")
            }
            Self::AuthorizationKeyNotFound { role, id } => write!(
                f,
                "authorization key for role {role:?} and object {} was not found",
                hex_id(id)
            ),
            Self::InvalidAuthorization { role, index } => {
                write!(f, "authorization {role:?}[{index}] was rejected")
            }
            Self::StaleStateQuote(field) => write!(f, "stale state quote for {field}"),
            Self::InvalidFeeSource(reason) => write!(f, "invalid fee source: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<bit_types::Error> for Error {
    fn from(error: bit_types::Error) -> Self {
        Self::Types(error)
    }
}

impl From<ShieldedError> for Error {
    fn from(error: ShieldedError) -> Self {
        Self::Shielded(error)
    }
}

impl From<bit_emission::Error> for Error {
    fn from(error: bit_emission::Error) -> Self {
        Self::FeeCalculation(error)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Decode and verify one canonical BIT Transfer envelope against a state view.
///
/// State is read only here. Callers can commit the returned nullifiers and
/// commitments atomically after every other block-level check succeeds.
pub fn verify_transfer<S: StateView + ?Sized>(
    envelope_bytes: &[u8],
    context: &VerificationContext<'_, S>,
) -> Result<VerifiedTransfer> {
    // Reject cheap state conflicts before invoking Groth16 verification.
    let envelope = Envelope::decode_canonical(
        envelope_bytes,
        context.max_envelope_bytes,
        context.current_height,
        context.max_lifetime,
    )?;
    let body = envelope.validate(context.current_height, context.max_lifetime)?;
    if body.chain_context != context.expected_chain_context {
        return Err(Error::WrongChainContext);
    }
    if !matches!(body.action, Action::Transfer) {
        return Err(Error::UnsupportedAction);
    }
    if !context.state.contains_anchor(&body.anchor) {
        return Err(Error::UnknownAnchor);
    }
    let tx_id = envelope.tx_id(context.current_height, context.max_lifetime)?;
    if context.state.contains_transaction(&tx_id) {
        return Err(Error::TransactionAlreadyApplied);
    }

    let stateless_context = StatelessVerificationContext {
        expected_chain_context: context.expected_chain_context,
        current_height: context.current_height,
        max_lifetime: context.max_lifetime,
        max_envelope_bytes: context.max_envelope_bytes,
        native_asset_id: context.native_asset_id,
        fee_policy: context.fee_policy,
    };
    let verified = verify_transfer_stateless(envelope_bytes, &stateless_context)?;
    for nullifier in &verified.nullifiers {
        if context.state.contains_nullifier(nullifier) {
            return Err(Error::NullifierAlreadySpent);
        }
    }
    Ok(verified)
}

/// Decode and cryptographically verify one Transfer without consulting state.
///
/// Callers that maintain asynchronous storage can use this function and then
/// apply [`validate_transfer_state`] against their own transactional view.
pub fn verify_transfer_stateless(
    envelope_bytes: &[u8],
    context: &StatelessVerificationContext,
) -> Result<VerifiedTransfer> {
    let envelope = Envelope::decode_canonical(
        envelope_bytes,
        context.max_envelope_bytes,
        context.current_height,
        context.max_lifetime,
    )?;
    let body = envelope.validate(context.current_height, context.max_lifetime)?;
    if body.chain_context != context.expected_chain_context {
        return Err(Error::WrongChainContext);
    }
    if !matches!(body.action, Action::Transfer) {
        return Err(Error::UnsupportedAction);
    }

    let minimum_fee = context.fee_policy.minimum_fee(
        envelope_bytes.len(),
        body.spends.len(),
        body.outputs.len(),
        FeeClass::Standard,
    )?;
    if body.fee < minimum_fee {
        return Err(Error::FeeTooLow {
            required: minimum_fee,
            provided: body.fee,
        });
    }

    let tx_id = envelope.tx_id(context.current_height, context.max_lifetime)?;
    let effect_hash = body.effect_hash()?;
    let spend_authorizations: Vec<_> = envelope
        .authorizations
        .iter()
        .map(|authorization| authorization.signature.clone())
        .collect();
    let shielded = verify_transfer_crypto(
        body.anchor,
        &body.spends,
        &body.outputs,
        &envelope.proofs,
        &spend_authorizations,
        &envelope.binding_signature,
        &effect_hash,
        body.fee.value(),
        context.native_asset_id,
    )?;

    let mut within_transaction = BTreeSet::new();
    for nullifier in &shielded.nullifiers {
        if !within_transaction.insert(*nullifier) {
            return Err(Error::DuplicateNullifier);
        }
    }

    Ok(VerifiedTransfer {
        tx_id,
        effect_hash,
        anchor: body.anchor,
        nullifiers: shielded.nullifiers,
        output_commitments: shielded.output_commitments,
        fee: body.fee,
        minimum_fee,
    })
}

/// Verify the D-007 staking actions whose state transitions are currently
/// implemented: RegisterValidator and Delegate. This verifies the complete
/// canonical envelope, role signatures/PoP, fee, shielded proofs, Spend
/// authorizations, and the public-lock binding equation.
pub fn verify_staking_stateless<S: ActionAuthorizationView + ?Sized>(
    envelope_bytes: &[u8],
    context: &StatelessVerificationContext,
    authorization_view: &S,
) -> Result<VerifiedStakingTransaction> {
    let envelope = Envelope::decode_canonical(
        envelope_bytes,
        context.max_envelope_bytes,
        context.current_height,
        context.max_lifetime,
    )?;
    let body = envelope.validate(context.current_height, context.max_lifetime)?;
    if body.chain_context != context.expected_chain_context {
        return Err(Error::WrongChainContext);
    }

    let (action, fee_class, public_lock, public_release) = match &body.action {
        Action::Delegate {
            position_id,
            owner,
            validator_id,
            deposit,
            min_shares,
            self_bond,
            recovery,
        } => (
            VerifiedStakingAction::Delegate {
                position_id: *position_id,
                owner: *owner,
                validator_id: *validator_id,
                deposit: *deposit,
                min_shares: *min_shares,
                self_bond: *self_bond,
                recovery: recovery.clone(),
            },
            FeeClass::NewPosition,
            deposit.value(),
            0,
        ),
        Action::RegisterValidator {
            validator_id,
            operator,
            consensus,
            commission_bps,
            display_name,
            website,
            description,
        } => (
            VerifiedStakingAction::RegisterValidator {
                validator_id: *validator_id,
                operator: *operator,
                consensus: *consensus,
                commission_bps: *commission_bps,
                display_name: display_name.clone(),
                website: website.clone(),
                description: description.clone(),
            },
            FeeClass::ValidatorRegistration,
            0,
            0,
        ),
        Action::CancelPending {
            position_id,
            expected_sequence,
            expected_release,
            fee_source,
        } => {
            match fee_source {
                FeeSource::Shielded if body.spends.is_empty() => {
                    return Err(Error::InvalidFeeSource(
                        "SHIELDED requires at least one private Spend",
                    ));
                }
                FeeSource::ReleasedValue if *expected_release <= body.fee => {
                    return Err(Error::InvalidFeeSource(
                        "RELEASED_VALUE requires release greater than fee",
                    ));
                }
                _ => {}
            }
            (
                VerifiedStakingAction::CancelPending {
                    position_id: *position_id,
                    expected_sequence: *expected_sequence,
                    expected_release: *expected_release,
                    fee_source: *fee_source,
                },
                FeeClass::Standard,
                0,
                expected_release.value(),
            )
        }
        Action::UpdateValidator {
            validator_id,
            expected_sequence,
            display_name,
            website,
            description,
            commission_bps,
            request_disable,
        } => (
            VerifiedStakingAction::UpdateValidator {
                validator_id: *validator_id,
                expected_sequence: *expected_sequence,
                display_name: display_name.clone(),
                website: website.clone(),
                description: description.clone(),
                commission_bps: *commission_bps,
                request_disable: *request_disable,
            },
            FeeClass::Standard,
            0,
            0,
        ),
        Action::UnjailValidator {
            validator_id,
            expected_sequence,
        } => (
            VerifiedStakingAction::UnjailValidator {
                validator_id: *validator_id,
                expected_sequence: *expected_sequence,
            },
            FeeClass::Standard,
            0,
            0,
        ),
        Action::RotateConsensusKey {
            validator_id,
            expected_sequence,
            new_consensus,
        } => (
            VerifiedStakingAction::RotateConsensusKey {
                validator_id: *validator_id,
                expected_sequence: *expected_sequence,
                new_consensus: *new_consensus,
            },
            FeeClass::Standard,
            0,
            0,
        ),
        Action::ClaimCommission {
            validator_id,
            expected_sequence,
            requested_amount,
            fee_source,
        } => {
            match fee_source {
                FeeSource::Shielded if body.spends.is_empty() => {
                    return Err(Error::InvalidFeeSource(
                        "SHIELDED requires at least one private Spend",
                    ));
                }
                FeeSource::ReleasedValue if *requested_amount <= body.fee => {
                    return Err(Error::InvalidFeeSource(
                        "RELEASED_VALUE requires release greater than fee",
                    ));
                }
                _ => {}
            }
            (
                VerifiedStakingAction::ClaimCommission {
                    validator_id: *validator_id,
                    expected_sequence: *expected_sequence,
                    requested_amount: *requested_amount,
                    fee_source: *fee_source,
                },
                FeeClass::Standard,
                0,
                requested_amount.value(),
            )
        }
        _ => return Err(Error::UnsupportedAction),
    };

    let minimum_fee = context.fee_policy.minimum_fee(
        envelope_bytes.len(),
        body.spends.len(),
        body.outputs.len(),
        fee_class,
    )?;
    if body.fee < minimum_fee {
        return Err(Error::FeeTooLow {
            required: minimum_fee,
            provided: body.fee,
        });
    }

    let effect_hash = body.effect_hash()?;
    verify_staking_authorizations(
        &envelope,
        &body.action,
        &body.chain_context,
        &effect_hash,
        authorization_view,
    )?;

    let spend_authorizations: Vec<_> = envelope.authorizations[..body.spends.len()]
        .iter()
        .map(|authorization| authorization.signature.clone())
        .collect();
    let shielded = verify_transaction_crypto(
        body.anchor,
        &body.spends,
        &body.outputs,
        &envelope.proofs,
        &spend_authorizations,
        &envelope.binding_signature,
        &effect_hash,
        ShieldedPublicBalance {
            locked: public_lock,
            released: public_release,
            fee: body.fee.value(),
        },
        context.native_asset_id,
    )?;
    let mut within_transaction = BTreeSet::new();
    for nullifier in &shielded.nullifiers {
        if !within_transaction.insert(*nullifier) {
            return Err(Error::DuplicateNullifier);
        }
    }

    Ok(VerifiedStakingTransaction {
        shielded: VerifiedTransfer {
            tx_id: envelope.tx_id(context.current_height, context.max_lifetime)?,
            effect_hash,
            anchor: body.anchor,
            nullifiers: shielded.nullifiers,
            output_commitments: shielded.output_commitments,
            fee: body.fee,
            minimum_fee,
        },
        action,
    })
}

/// Verify all non-Spend Ed25519 authorizations for a supported D-007 action.
/// This is public so state and vector tests can exercise role/key resolution
/// independently from the expensive Groth16 proofs.
pub fn verify_staking_authorizations<S: ActionAuthorizationView + ?Sized>(
    envelope: &Envelope,
    action: &Action,
    chain_context: &Hash32,
    effect_hash: &[u8; 64],
    authorization_view: &S,
) -> Result<()> {
    let first = envelope
        .authorizations
        .len()
        .checked_sub(match action {
            Action::Delegate { self_bond, .. } => 1 + usize::from(*self_bond),
            Action::RegisterValidator { .. } => 2,
            Action::CancelPending { .. } => 1,
            Action::UpdateValidator { .. }
            | Action::UnjailValidator { .. }
            | Action::ClaimCommission { .. } => 1,
            Action::RotateConsensusKey { .. } => 2,
            _ => return Err(Error::UnsupportedAction),
        })
        .ok_or(Error::UnsupportedAction)?;

    match action {
        Action::Delegate {
            position_id: supplied_position_id,
            owner,
            validator_id: target_validator,
            self_bond,
            ..
        } => {
            if position_id(chain_context, owner) != *supplied_position_id {
                return Err(Error::IdentifierMismatch("position"));
            }
            verify_ed25519(
                &envelope.authorizations[first],
                Role::PositionOwner,
                owner,
                effect_hash,
            )?;
            if *self_bond {
                let operator = authorization_view
                    .validator_operator(target_validator)
                    .ok_or(Error::AuthorizationKeyNotFound {
                        role: Role::Operator,
                        id: *target_validator,
                    })?;
                verify_ed25519(
                    &envelope.authorizations[first + 1],
                    Role::Operator,
                    &operator,
                    effect_hash,
                )?;
            }
        }
        Action::RegisterValidator {
            validator_id: supplied_validator_id,
            operator,
            consensus,
            ..
        } => {
            if validator_id(chain_context, operator) != *supplied_validator_id {
                return Err(Error::IdentifierMismatch("validator"));
            }
            verify_ed25519(
                &envelope.authorizations[first],
                Role::Operator,
                operator,
                effect_hash,
            )?;
            verify_ed25519(
                &envelope.authorizations[first + 1],
                Role::ConsensusPop,
                consensus,
                effect_hash,
            )?;
        }
        Action::CancelPending {
            position_id,
            expected_sequence,
            expected_release,
            ..
        } => {
            let pending = authorization_view.pending_position(position_id).ok_or(
                Error::AuthorizationKeyNotFound {
                    role: Role::PositionOwner,
                    id: *position_id,
                },
            )?;
            if pending.sequence != *expected_sequence {
                return Err(Error::StaleStateQuote("position sequence"));
            }
            if pending.release != *expected_release {
                return Err(Error::StaleStateQuote("pending release"));
            }
            verify_ed25519(
                &envelope.authorizations[first],
                Role::PositionOwner,
                &pending.owner,
                effect_hash,
            )?;
        }
        Action::UpdateValidator {
            validator_id,
            expected_sequence,
            ..
        }
        | Action::UnjailValidator {
            validator_id,
            expected_sequence,
        }
        | Action::ClaimCommission {
            validator_id,
            expected_sequence,
            ..
        } => {
            verify_validator_operator(
                envelope,
                first,
                validator_id,
                *expected_sequence,
                effect_hash,
                authorization_view,
            )?;
        }
        Action::RotateConsensusKey {
            validator_id,
            expected_sequence,
            new_consensus,
        } => {
            verify_validator_operator(
                envelope,
                first,
                validator_id,
                *expected_sequence,
                effect_hash,
                authorization_view,
            )?;
            verify_ed25519(
                &envelope.authorizations[first + 1],
                Role::ConsensusPop,
                new_consensus,
                effect_hash,
            )?;
        }
        _ => return Err(Error::UnsupportedAction),
    }
    Ok(())
}

fn verify_validator_operator<S: ActionAuthorizationView + ?Sized>(
    envelope: &Envelope,
    authorization_index: usize,
    validator_id: &Hash32,
    expected_sequence: u64,
    effect_hash: &[u8; 64],
    authorization_view: &S,
) -> Result<()> {
    let operator = authorization_view.validator_operator(validator_id).ok_or(
        Error::AuthorizationKeyNotFound {
            role: Role::Operator,
            id: *validator_id,
        },
    )?;
    if authorization_view.validator_sequence(validator_id) != Some(expected_sequence) {
        return Err(Error::StaleStateQuote("validator sequence"));
    }
    verify_ed25519(
        &envelope.authorizations[authorization_index],
        Role::Operator,
        &operator,
        effect_hash,
    )
}

fn verify_ed25519(
    authorization: &Authorization,
    expected_role: Role,
    public_key: &Hash32,
    effect_hash: &[u8; 64],
) -> Result<()> {
    if authorization.role != expected_role {
        return Err(Error::InvalidAuthorization {
            role: expected_role,
            index: authorization.index,
        });
    }
    let message = ed25519_authorization_message(expected_role, effect_hash)
        .expect("all non-Spend authorization roles have an Ed25519 domain");
    let key =
        Ed25519VerificationKey::try_from(*public_key).map_err(|_| Error::InvalidAuthorization {
            role: expected_role,
            index: authorization.index,
        })?;
    let signature =
        Ed25519Signature::try_from(authorization.signature.as_slice()).map_err(|_| {
            Error::InvalidAuthorization {
                role: expected_role,
                index: authorization.index,
            }
        })?;
    key.verify(&signature, &message)
        .map_err(|_| Error::InvalidAuthorization {
            role: expected_role,
            index: authorization.index,
        })
}

fn hex_id(id: &Hash32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in id {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

/// Check a cryptographically verified Transfer against a state snapshot.
pub fn validate_transfer_state<S: StateView + ?Sized>(
    verified: &VerifiedTransfer,
    state: &S,
) -> Result<()> {
    if !state.contains_anchor(&verified.anchor) {
        return Err(Error::UnknownAnchor);
    }
    if state.contains_transaction(&verified.tx_id) {
        return Err(Error::TransactionAlreadyApplied);
    }
    for nullifier in &verified.nullifiers {
        if state.contains_nullifier(nullifier) {
            return Err(Error::NullifierAlreadySpent);
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct MemoryLedger {
    chain_context: Hash32,
    native_asset_id: Hash32,
    current_height: u64,
    max_lifetime: u64,
    max_envelope_bytes: usize,
    fee_policy: FeePolicy,
    anchors: BTreeSet<Hash32>,
    nullifiers: BTreeSet<Hash32>,
    transactions: BTreeSet<Hash32>,
    output_commitments: Vec<Hash32>,
}

impl MemoryLedger {
    pub fn new(
        chain_context: Hash32,
        native_asset_id: Hash32,
        current_height: u64,
        max_lifetime: u64,
        max_envelope_bytes: usize,
        fee_policy: FeePolicy,
    ) -> Self {
        Self {
            chain_context,
            native_asset_id,
            current_height,
            max_lifetime,
            max_envelope_bytes,
            fee_policy,
            anchors: BTreeSet::new(),
            nullifiers: BTreeSet::new(),
            transactions: BTreeSet::new(),
            output_commitments: Vec::new(),
        }
    }

    pub fn allow_anchor(&mut self, anchor: Hash32) {
        self.anchors.insert(anchor);
    }

    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    pub fn verify_and_record(&mut self, envelope_bytes: &[u8]) -> Result<VerifiedTransfer> {
        let verified = {
            let context = VerificationContext {
                expected_chain_context: self.chain_context,
                current_height: self.current_height,
                max_lifetime: self.max_lifetime,
                max_envelope_bytes: self.max_envelope_bytes,
                native_asset_id: self.native_asset_id,
                fee_policy: self.fee_policy,
                state: self,
            };
            verify_transfer(envelope_bytes, &context)?
        };
        self.commit_verified(&verified)?;
        Ok(verified)
    }

    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
    }

    pub fn output_commitments(&self) -> &[Hash32] {
        &self.output_commitments
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn commit_verified(&mut self, verified: &VerifiedTransfer) -> Result<()> {
        if self.transactions.contains(&verified.tx_id) {
            return Err(Error::TransactionAlreadyApplied);
        }
        let mut additions = BTreeSet::new();
        for nullifier in &verified.nullifiers {
            if !additions.insert(*nullifier) {
                return Err(Error::DuplicateNullifier);
            }
            if self.nullifiers.contains(nullifier) {
                return Err(Error::NullifierAlreadySpent);
            }
        }

        self.nullifiers.extend(additions);
        self.output_commitments
            .extend_from_slice(&verified.output_commitments);
        self.transactions.insert(verified.tx_id);
        Ok(())
    }
}

impl StateView for MemoryLedger {
    fn contains_anchor(&self, anchor: &Hash32) -> bool {
        self.anchors.contains(anchor)
    }

    fn contains_nullifier(&self, nullifier: &Hash32) -> bool {
        self.nullifiers.contains(nullifier)
    }

    fn contains_transaction(&self, tx_id: &Hash32) -> bool {
        self.transactions.contains(tx_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bit_types::{
        chain_context, ed25519_authorization_message, position_id, validator_id, Amount,
        Authorization, Envelope, Role, TxBody,
    };
    use decaf377::Fr;
    use decaf377_rdsa::{Binding, SigningKey};
    use ed25519_consensus::SigningKey as Ed25519SigningKey;

    struct OperatorView {
        validator_id: Hash32,
        operator: Hash32,
    }

    impl ActionAuthorizationView for OperatorView {
        fn validator_operator(&self, validator_id: &Hash32) -> Option<Hash32> {
            (*validator_id == self.validator_id).then_some(self.operator)
        }
    }

    struct ValidatorView {
        validator_id: Hash32,
        operator: Hash32,
        sequence: u64,
    }

    impl ActionAuthorizationView for ValidatorView {
        fn validator_operator(&self, validator_id: &Hash32) -> Option<Hash32> {
            (*validator_id == self.validator_id).then_some(self.operator)
        }

        fn validator_sequence(&self, validator_id: &Hash32) -> Option<u64> {
            (*validator_id == self.validator_id).then_some(self.sequence)
        }
    }

    struct PendingView {
        position_id: Hash32,
        pending: PendingPositionAuthorization,
    }

    impl ActionAuthorizationView for PendingView {
        fn validator_operator(&self, _validator_id: &Hash32) -> Option<Hash32> {
            None
        }

        fn pending_position(&self, position_id: &Hash32) -> Option<PendingPositionAuthorization> {
            (*position_id == self.position_id).then_some(self.pending)
        }
    }

    fn ed25519_authorization(
        role: Role,
        key: &Ed25519SigningKey,
        effect_hash: &[u8; 64],
    ) -> Authorization {
        let message = ed25519_authorization_message(role, effect_hash).unwrap();
        Authorization {
            role,
            index: 0,
            signature: key.sign(&message).to_bytes().to_vec(),
        }
    }

    fn staking_envelope(action: Action, authorizations: Vec<Authorization>) -> (Envelope, TxBody) {
        let body = TxBody {
            version: 1,
            chain_context: chain_context([0x55; 32]),
            expiry_height: 20,
            anchor: [0; 32],
            fee: Amount::ZERO,
            spends: vec![],
            outputs: vec![],
            action,
            proof_hashes: vec![],
            memo_ciphertext: None,
        };
        (
            Envelope {
                envelope_version: 1,
                canonical_body: body.encode_canonical().unwrap(),
                proofs: vec![],
                authorizations,
                binding_signature: vec![0; 64],
            },
            body,
        )
    }

    fn empty_transfer(chain_context: Hash32, anchor: Hash32, fee: Amount) -> Vec<u8> {
        let body = TxBody {
            version: 1,
            chain_context,
            expiry_height: 20,
            anchor,
            fee,
            spends: vec![],
            outputs: vec![],
            action: Action::Transfer,
            proof_hashes: vec![],
            memo_ciphertext: None,
        };
        let effect_hash = body.effect_hash().unwrap();
        let signature = SigningKey::<Binding>::from(Fr::from(0u64))
            .sign_deterministic(&effect_hash)
            .to_bytes()
            .to_vec();
        Envelope {
            envelope_version: 1,
            canonical_body: body.encode_canonical().unwrap(),
            proofs: vec![],
            authorizations: vec![],
            binding_signature: signature,
        }
        .encode_canonical(10, 20)
        .unwrap()
    }

    #[test]
    fn transfer_policy_is_checked_before_crypto() {
        let chain = [1; 32];
        let anchor = [0; 32];
        let bytes = empty_transfer(chain, anchor, Amount::new(1_000_000).unwrap());
        let mut ledger = MemoryLedger::new(
            chain,
            [0; 32],
            10,
            20,
            65_536,
            FeePolicy::reference_testnet(),
        );
        assert_eq!(
            ledger.verify_and_record(&bytes).unwrap_err().to_string(),
            "transaction anchor is not accepted"
        );
        ledger.allow_anchor(anchor);
        assert!(matches!(
            ledger.verify_and_record(&bytes),
            Err(Error::Shielded(ShieldedError::InvalidBindingSignature))
        ));

        let underpriced = empty_transfer(chain, anchor, Amount::ZERO);
        assert!(matches!(
            ledger.verify_and_record(&underpriced),
            Err(Error::FeeTooLow {
                provided: Amount::ZERO,
                ..
            })
        ));

        let mut wrong_chain = MemoryLedger::new(
            [2; 32],
            [0; 32],
            10,
            20,
            65_536,
            FeePolicy::reference_testnet(),
        );
        wrong_chain.allow_anchor(anchor);
        assert!(matches!(
            wrong_chain.verify_and_record(&bytes),
            Err(Error::WrongChainContext)
        ));
    }

    #[test]
    fn failed_commit_does_not_partially_mutate_state() {
        let mut ledger = MemoryLedger::new(
            [1; 32],
            [0; 32],
            10,
            20,
            65_536,
            FeePolicy::reference_testnet(),
        );
        let duplicate = [7; 32];
        let verified = VerifiedTransfer {
            tx_id: [3; 32],
            effect_hash: [4; 64],
            anchor: [5; 32],
            nullifiers: vec![duplicate, duplicate],
            output_commitments: vec![[6; 32]],
            fee: Amount::ZERO,
            minimum_fee: Amount::ZERO,
        };
        assert!(matches!(
            ledger.commit_verified(&verified),
            Err(Error::DuplicateNullifier)
        ));
        assert_eq!(ledger.nullifier_count(), 0);
        assert_eq!(ledger.transaction_count(), 0);
        assert!(ledger.output_commitments().is_empty());

        let valid = VerifiedTransfer {
            tx_id: [8; 32],
            effect_hash: [9; 64],
            anchor: [5; 32],
            nullifiers: vec![[10; 32]],
            output_commitments: vec![[11; 32]],
            fee: Amount::ZERO,
            minimum_fee: Amount::ZERO,
        };
        ledger.commit_verified(&valid).unwrap();
        assert!(matches!(
            ledger.commit_verified(&valid),
            Err(Error::TransactionAlreadyApplied)
        ));
    }

    #[test]
    fn registration_requires_operator_signature_and_new_consensus_pop() {
        let chain = chain_context([0x55; 32]);
        let operator_key = Ed25519SigningKey::from([1; 32]);
        let consensus_key = Ed25519SigningKey::from([2; 32]);
        let operator = operator_key.verification_key().to_bytes();
        let consensus = consensus_key.verification_key().to_bytes();
        let action = Action::RegisterValidator {
            validator_id: validator_id(&chain, &operator),
            operator,
            consensus,
            commission_bps: 500,
            display_name: "validator".to_owned(),
            website: String::new(),
            description: String::new(),
        };
        let (_, unsigned_body) = staking_envelope(action.clone(), vec![]);
        let effect = unsigned_body.effect_hash().unwrap();
        let (envelope, body) = staking_envelope(
            action.clone(),
            vec![
                ed25519_authorization(Role::Operator, &operator_key, &effect),
                ed25519_authorization(Role::ConsensusPop, &consensus_key, &effect),
            ],
        );
        let view = OperatorView {
            validator_id: [0; 32],
            operator: [0; 32],
        };
        verify_staking_authorizations(&envelope, &action, &body.chain_context, &effect, &view)
            .unwrap();

        let (wrong_pop, _) = staking_envelope(
            action.clone(),
            vec![
                ed25519_authorization(Role::Operator, &operator_key, &effect),
                ed25519_authorization(Role::ConsensusPop, &operator_key, &effect),
            ],
        );
        assert!(matches!(
            verify_staking_authorizations(&wrong_pop, &action, &body.chain_context, &effect, &view),
            Err(Error::InvalidAuthorization {
                role: Role::ConsensusPop,
                ..
            })
        ));
    }

    #[test]
    fn self_bond_binds_owner_and_registered_operator() {
        let chain = chain_context([0x55; 32]);
        let owner_key = Ed25519SigningKey::from([3; 32]);
        let operator_key = Ed25519SigningKey::from([4; 32]);
        let owner = owner_key.verification_key().to_bytes();
        let operator = operator_key.verification_key().to_bytes();
        let target_validator = validator_id(&chain, &operator);
        let action = Action::Delegate {
            position_id: position_id(&chain, &owner),
            owner,
            validator_id: target_validator,
            deposit: Amount::new(100_000_000_000).unwrap(),
            min_shares: Amount::ZERO,
            self_bond: true,
            recovery: vec![9; 512],
        };
        let (_, unsigned_body) = staking_envelope(action.clone(), vec![]);
        let effect = unsigned_body.effect_hash().unwrap();
        let (envelope, body) = staking_envelope(
            action.clone(),
            vec![
                ed25519_authorization(Role::PositionOwner, &owner_key, &effect),
                ed25519_authorization(Role::Operator, &operator_key, &effect),
            ],
        );
        let view = OperatorView {
            validator_id: target_validator,
            operator,
        };
        verify_staking_authorizations(&envelope, &action, &body.chain_context, &effect, &view)
            .unwrap();

        let missing = OperatorView {
            validator_id: [0; 32],
            operator,
        };
        assert!(matches!(
            verify_staking_authorizations(
                &envelope,
                &action,
                &body.chain_context,
                &effect,
                &missing
            ),
            Err(Error::AuthorizationKeyNotFound {
                role: Role::Operator,
                ..
            })
        ));

        let mut mismatched = action;
        if let Action::Delegate { position_id, .. } = &mut mismatched {
            *position_id = [0xff; 32];
        }
        assert!(matches!(
            verify_staking_authorizations(
                &envelope,
                &mismatched,
                &body.chain_context,
                &effect,
                &view
            ),
            Err(Error::IdentifierMismatch("position"))
        ));
    }

    #[test]
    fn cancel_pending_uses_current_owner_and_exact_state_quote() {
        let chain = chain_context([0x55; 32]);
        let owner_key = Ed25519SigningKey::from([5; 32]);
        let owner = owner_key.verification_key().to_bytes();
        let position = position_id(&chain, &owner);
        let release = Amount::new(900_000_000).unwrap();
        let action = Action::CancelPending {
            position_id: position,
            expected_sequence: 4,
            expected_release: release,
            fee_source: FeeSource::ReleasedValue,
        };
        let (_, unsigned_body) = staking_envelope(action.clone(), vec![]);
        let effect = unsigned_body.effect_hash().unwrap();
        let (envelope, body) = staking_envelope(
            action.clone(),
            vec![ed25519_authorization(
                Role::PositionOwner,
                &owner_key,
                &effect,
            )],
        );
        let view = PendingView {
            position_id: position,
            pending: PendingPositionAuthorization {
                owner,
                sequence: 4,
                release,
            },
        };
        verify_staking_authorizations(&envelope, &action, &body.chain_context, &effect, &view)
            .unwrap();

        let stale = Action::CancelPending {
            position_id: position,
            expected_sequence: 5,
            expected_release: release,
            fee_source: FeeSource::ReleasedValue,
        };
        assert!(matches!(
            verify_staking_authorizations(&envelope, &stale, &body.chain_context, &effect, &view),
            Err(Error::StaleStateQuote("position sequence"))
        ));
    }

    #[test]
    fn validator_mutations_bind_current_operator_sequence_and_new_key_pop() {
        let chain = chain_context([0x55; 32]);
        let operator_key = Ed25519SigningKey::from([6; 32]);
        let new_consensus_key = Ed25519SigningKey::from([7; 32]);
        let operator = operator_key.verification_key().to_bytes();
        let validator_id = validator_id(&chain, &operator);
        let view = ValidatorView {
            validator_id,
            operator,
            sequence: 9,
        };

        for action in [
            Action::UpdateValidator {
                validator_id,
                expected_sequence: 9,
                display_name: Some("updated".to_owned()),
                website: None,
                description: None,
                commission_bps: None,
                request_disable: None,
            },
            Action::UnjailValidator {
                validator_id,
                expected_sequence: 9,
            },
            Action::ClaimCommission {
                validator_id,
                expected_sequence: 9,
                requested_amount: Amount::new(1_000_000).unwrap(),
                fee_source: FeeSource::ReleasedValue,
            },
        ] {
            let (_, unsigned_body) = staking_envelope(action.clone(), vec![]);
            let effect = unsigned_body.effect_hash().unwrap();
            let (envelope, body) = staking_envelope(
                action.clone(),
                vec![ed25519_authorization(
                    Role::Operator,
                    &operator_key,
                    &effect,
                )],
            );
            verify_staking_authorizations(&envelope, &action, &body.chain_context, &effect, &view)
                .unwrap();
        }

        let stale = Action::UnjailValidator {
            validator_id,
            expected_sequence: 10,
        };
        let (_, stale_body) = staking_envelope(stale.clone(), vec![]);
        let stale_effect = stale_body.effect_hash().unwrap();
        let (stale_envelope, _) = staking_envelope(
            stale.clone(),
            vec![ed25519_authorization(
                Role::Operator,
                &operator_key,
                &stale_effect,
            )],
        );
        assert!(matches!(
            verify_staking_authorizations(
                &stale_envelope,
                &stale,
                &stale_body.chain_context,
                &stale_effect,
                &view
            ),
            Err(Error::StaleStateQuote("validator sequence"))
        ));

        let new_consensus = new_consensus_key.verification_key().to_bytes();
        let rotate = Action::RotateConsensusKey {
            validator_id,
            expected_sequence: 9,
            new_consensus,
        };
        let (_, unsigned_body) = staking_envelope(rotate.clone(), vec![]);
        let effect = unsigned_body.effect_hash().unwrap();
        let (envelope, body) = staking_envelope(
            rotate.clone(),
            vec![
                ed25519_authorization(Role::Operator, &operator_key, &effect),
                ed25519_authorization(Role::ConsensusPop, &new_consensus_key, &effect),
            ],
        );
        verify_staking_authorizations(&envelope, &rotate, &body.chain_context, &effect, &view)
            .unwrap();

        let (wrong_pop, _) = staking_envelope(
            rotate.clone(),
            vec![
                ed25519_authorization(Role::Operator, &operator_key, &effect),
                ed25519_authorization(Role::ConsensusPop, &operator_key, &effect),
            ],
        );
        assert!(matches!(
            verify_staking_authorizations(&wrong_pop, &rotate, &body.chain_context, &effect, &view),
            Err(Error::InvalidAuthorization {
                role: Role::ConsensusPop,
                ..
            })
        ));
    }
}
