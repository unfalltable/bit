"""Independent stdlib oracle for BIT 1.2 golden vectors.

This code is deliberately separate from the Rust consensus implementation. It
constructs only the fixed policy and the structural no-value transaction vector.
It is not a wallet, signer, proof verifier, or mainnet policy generator.
"""
from __future__ import annotations

import hashlib

MAX_SUPPLY_ATOMIC = 10_240_000_000_000_000_000
MAX_AMOUNT_EXCLUSIVE = 1 << 120


def scheduled_issuance(budget: int, interval: int, completed: int) -> int:
    if not 0 <= budget <= MAX_SUPPLY_ATOMIC or interval <= 0 or completed < 0:
        raise ValueError("invalid schedule input")
    era, offset = divmod(completed, interval)
    remaining = 0 if era >= 128 else budget >> era
    tranche = remaining - remaining // 2
    return budget - remaining + tranche * offset // interval


def quota(budget: int, interval: int, epoch: int) -> int:
    return scheduled_issuance(budget, interval, epoch + 1) - scheduled_issuance(budget, interval, epoch)


def _head(major: int, value: int) -> bytes:
    if not 0 <= value < 1 << 64:
        raise ValueError("CBOR argument outside uint64")
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value < 1 << 8:
        return bytes([prefix | 24, value])
    if value < 1 << 16:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    if value < 1 << 32:
        return bytes([prefix | 26]) + value.to_bytes(4, "big")
    return bytes([prefix | 27]) + value.to_bytes(8, "big")


def cbor_uint(value: int) -> bytes:
    return _head(0, value)


def cbor_bytes(value: bytes) -> bytes:
    return _head(2, len(value)) + value


def cbor_text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return _head(3, len(raw)) + raw


def cbor_array(*values: bytes) -> bytes:
    return _head(4, len(values)) + b"".join(values)


def amount(value: int) -> bytes:
    if not 0 <= value < MAX_AMOUNT_EXCLUSIVE:
        raise ValueError("amount outside [0, 2^120)")
    return cbor_bytes(value.to_bytes(16, "big"))


def reference_policy() -> bytes:
    return cbor_array(
        cbor_text("BUDGET_HALVING_EPOCH_V1"), amount(MAX_SUPPLY_ATOMIC), cbor_uint(8),
        amount(10_000_000_000_000_000), cbor_uint(720), cbor_uint(35_040),
        cbor_text("FORFEIT_UNISSUED_NO_CATCHUP"), b"\xf4", b"\xf4",
    )


def structural_body() -> bytes:
    return cbor_array(
        cbor_uint(1), cbor_bytes(bytes(32)), cbor_uint(10), cbor_bytes(bytes([0x11]) * 32),
        amount(0), cbor_array(), cbor_array(), cbor_array(cbor_uint(0)), cbor_array(), b"\xf6",
    )


def _varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def structural_envelope(body: bytes) -> bytes:
    binding = bytes([5]) * 64
    return b"\x08\x01\x12" + _varint(len(body)) + body + b"\x2a" + _varint(len(binding)) + binding


def effect_hash(body: bytes) -> bytes:
    return hashlib.blake2b(b"bit/effect/v1" + len(body).to_bytes(8, "big") + body, digest_size=64).digest()


def empty_block_artifact(chain_context: bytes, height: int, block_time_seconds: int,
                         shielded_tree_root: bytes) -> bytes:
    if len(chain_context) != 32 or len(shielded_tree_root) != 32 or height <= 0:
        raise ValueError("invalid empty block artifact input")
    return cbor_array(
        cbor_uint(1), cbor_bytes(chain_context), cbor_uint(height),
        cbor_uint(block_time_seconds), cbor_bytes(shielded_tree_root),
        cbor_array(), cbor_array(),
    )


def block_artifact_hash(domain: bytes, artifact: bytes) -> bytes:
    return hashlib.sha256(domain + len(artifact).to_bytes(8, "big") + artifact).digest()


def checkpoint_policy(values: dict) -> bytes:
    publishers = [bytes.fromhex(value) for value in values["publisher_pubkeys_hex"]]
    if publishers != sorted(set(publishers)) or not publishers:
        raise ValueError("checkpoint publishers must be sorted and unique")
    threshold = int(values["publisher_threshold"])
    trust_period = int(values["trust_period_seconds"])
    warning_period = int(values["expiry_warning_seconds"])
    if not 0 < threshold <= len(publishers):
        raise ValueError("invalid checkpoint threshold")
    if not 0 < warning_period < trust_period:
        raise ValueError("invalid checkpoint trust periods")
    sequence = int(values["sequence"])
    previous = values["previous_policy_hash_hex"]
    if (sequence == 1) != (previous is None):
        raise ValueError("invalid checkpoint policy chain")
    return cbor_array(
        cbor_text("BIT-CHECKPOINT-POLICY"),
        cbor_uint(1),
        cbor_bytes(bytes.fromhex(values["genesis_manifest_hash_hex"])),
        cbor_bytes(bytes.fromhex(values["chain_context_hex"])),
        cbor_bytes(bytes.fromhex(values["consensus_parameters_sha256_hex"])),
        cbor_uint(sequence),
        b"\xf6" if previous is None else cbor_bytes(bytes.fromhex(previous)),
        cbor_uint(int(values["activates_at_seconds"])),
        cbor_uint(trust_period),
        cbor_uint(warning_period),
        cbor_uint(threshold),
        cbor_array(*(cbor_bytes(value) for value in publishers)),
        b"\xf5" if values["revoke_previous_immediately"] else b"\xf4",
    )


def checkpoint_policy_hash(encoded: bytes) -> bytes:
    return hashlib.sha256(
        b"BIT-CHECKPOINT-POLICY-HASH-V1"
        + len(encoded).to_bytes(8, "big")
        + encoded
    ).digest()


def signed_checkpoint_body(policy: dict, checkpoint: dict, policy_hash: bytes) -> bytes:
    header_height = int(checkpoint["header_height"])
    state_height = int(checkpoint["state_height"])
    issued = int(checkpoint["issued_at_seconds"])
    expires = int(checkpoint["expires_at_seconds"])
    if header_height <= 0 or state_height != header_height - 1:
        raise ValueError("checkpoint header/state height mismatch")
    if issued < int(policy["activates_at_seconds"]) or not issued < expires:
        raise ValueError("invalid checkpoint validity interval")
    if expires - issued > int(policy["trust_period_seconds"]):
        raise ValueError("checkpoint exceeds trust period")
    return cbor_array(
        cbor_text("BIT-CHECKPOINT"),
        cbor_uint(1),
        cbor_bytes(policy_hash),
        cbor_bytes(bytes.fromhex(policy["genesis_manifest_hash_hex"])),
        cbor_bytes(bytes.fromhex(policy["chain_context_hex"])),
        cbor_uint(header_height),
        cbor_bytes(bytes.fromhex(checkpoint["header_hash_hex"])),
        cbor_uint(state_height),
        cbor_bytes(bytes.fromhex(checkpoint["app_hash_hex"])),
        cbor_uint(issued),
        cbor_uint(expires),
    )


def checkpoint_hash(encoded: bytes) -> bytes:
    return hashlib.sha256(
        b"BIT-CHECKPOINT-HASH-V1"
        + len(encoded).to_bytes(8, "big")
        + encoded
    ).digest()


SUPPLY_AMOUNT_FIELDS = (
    "max_supply", "genesis_supply", "cumulative_minted", "burned",
    "issued_total", "current_supply", "scheduled_to_date",
    "forfeited_unissued", "future_issuance_budget", "shielded_total",
    "stake_total", "pending_delegation_total", "exit_total",
    "commission_total", "fee_reserve", "unclaimed_genesis_total",
)


def supply_audit_snapshot(values: dict[str, int | bytes]) -> bytes:
    amounts = {name: int(values[name]) for name in SUPPLY_AMOUNT_FIELDS}
    if amounts["max_supply"] != MAX_SUPPLY_ATOMIC:
        raise ValueError("wrong fixed supply")
    if amounts["issued_total"] != amounts["genesis_supply"] + amounts["cumulative_minted"]:
        raise ValueError("wrong issued total")
    if amounts["current_supply"] != amounts["issued_total"] - amounts["burned"]:
        raise ValueError("wrong current supply")
    if amounts["scheduled_to_date"] != amounts["cumulative_minted"] + amounts["forfeited_unissued"]:
        raise ValueError("wrong scheduled issuance")
    if amounts["max_supply"] != sum(amounts[name] for name in (
        "issued_total", "forfeited_unissued", "future_issuance_budget"
    )):
        raise ValueError("wrong future issuance identity")
    if amounts["current_supply"] != sum(amounts[name] for name in (
        "shielded_total", "stake_total", "pending_delegation_total", "exit_total",
        "commission_total", "fee_reserve", "unclaimed_genesis_total"
    )):
        raise ValueError("wrong container identity")
    policy_hash = values["monetary_policy_hash"]
    if not isinstance(policy_hash, bytes) or len(policy_hash) != 32:
        raise ValueError("policy hash must be 32 bytes")
    return cbor_array(
        cbor_uint(1),
        *(amount(amounts[name]) for name in SUPPLY_AMOUNT_FIELDS),
        cbor_uint(int(values["completed_epochs"])),
        cbor_bytes(policy_hash),
    )
