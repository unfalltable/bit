//! Durable, operator-auditable records for consensus safety halts.
//!
//! A safety halt record lives beside the application state directory rather
//! than inside the committed JMT.  The block that triggered the halt cannot be
//! committed (its validator updates would make consensus unsafe), but the
//! reason for refusing it must survive a process restart.

use crate::Hash32;
use bit_state::{ByzantineEvidence, ByzantineEvidenceKind};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::fs::File;

const MAGIC: &[u8; 15] = b"BIT-SAFETY-HALT";
const FORMAT_VERSION: u8 = 1;
const RECORD_HASH_DOMAIN: &[u8] = b"BIT-SAFETY-HALT-RECORD-V1";
const EVIDENCE_BYTES: usize = 1 + 20 + 8 + 8 + 8 + 4 + 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SafetyHaltReason {
    NoSafeValidatorSet = 1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyHaltRecord {
    pub reason: SafetyHaltReason,
    pub chain_context: Hash32,
    pub committed_height: u64,
    pub committed_app_hash: Hash32,
    pub attempted_height: u64,
    pub attempted_block_hash: Hash32,
    pub attempted_block_time_seconds: u64,
    pub next_validators_hash: Hash32,
    pub evidence: Vec<ByzantineEvidence>,
}

impl SafetyHaltRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn no_safe_validator_set(
        chain_context: Hash32,
        committed_height: u64,
        committed_app_hash: Hash32,
        attempted_height: u64,
        attempted_block_hash: Hash32,
        attempted_block_time_seconds: u64,
        next_validators_hash: Hash32,
        evidence: Vec<ByzantineEvidence>,
    ) -> Result<Self, SafetyHaltError> {
        let mut ordered = BTreeMap::new();
        for item in evidence {
            let hash = item.canonical_hash(&chain_context);
            if let Some(previous) = ordered.insert(hash, item.clone()) {
                if previous != item {
                    return Err(SafetyHaltError::Corrupt(
                        "canonical evidence hash collision",
                    ));
                }
            }
        }
        let record = Self {
            reason: SafetyHaltReason::NoSafeValidatorSet,
            chain_context,
            committed_height,
            committed_app_hash,
            attempted_height,
            attempted_block_hash,
            attempted_block_time_seconds,
            next_validators_hash,
            evidence: ordered.into_values().collect(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn record_hash(&self) -> Hash32 {
        hash_payload(&self.encode_payload())
    }

    pub fn evidence_hashes(&self) -> Vec<Hash32> {
        self.evidence
            .iter()
            .map(|item| item.canonical_hash(&self.chain_context))
            .collect()
    }

    fn validate(&self) -> Result<(), SafetyHaltError> {
        if self.attempted_height == 0
            || self
                .committed_height
                .checked_add(1)
                .filter(|height| *height == self.attempted_height)
                .is_none()
        {
            return Err(SafetyHaltError::Corrupt(
                "halt height does not immediately follow committed height",
            ));
        }
        if self.evidence.len() > u32::MAX as usize {
            return Err(SafetyHaltError::Corrupt(
                "halt evidence count exceeds the format limit",
            ));
        }
        let mut previous = None;
        for item in &self.evidence {
            if item.validator_power == 0
                || item.total_voting_power == 0
                || item.validator_power > item.total_voting_power
                || item.infraction_height == 0
                || item.infraction_height >= self.attempted_height
                || item.infraction_time_seconds > self.attempted_block_time_seconds
                || item.infraction_time_nanos >= 1_000_000_000
            {
                return Err(SafetyHaltError::Corrupt(
                    "halt evidence has an invalid consensus field",
                ));
            }
            let hash = item.canonical_hash(&self.chain_context);
            if previous.is_some_and(|previous| previous >= hash) {
                return Err(SafetyHaltError::Corrupt(
                    "halt evidence is duplicated or out of canonical order",
                ));
            }
            previous = Some(hash);
        }
        Ok(())
    }

    fn encode_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MAGIC.len()
                + 2
                + 32
                + 8
                + 32
                + 8
                + 32
                + 8
                + 32
                + 4
                + self.evidence.len() * EVIDENCE_BYTES,
        );
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(self.reason as u8);
        out.extend_from_slice(&self.chain_context);
        out.extend_from_slice(&self.committed_height.to_be_bytes());
        out.extend_from_slice(&self.committed_app_hash);
        out.extend_from_slice(&self.attempted_height.to_be_bytes());
        out.extend_from_slice(&self.attempted_block_hash);
        out.extend_from_slice(&self.attempted_block_time_seconds.to_be_bytes());
        out.extend_from_slice(&self.next_validators_hash);
        let evidence_count =
            u32::try_from(self.evidence.len()).expect("validated evidence count fits u32");
        out.extend_from_slice(&evidence_count.to_be_bytes());
        for item in &self.evidence {
            out.push(item.kind as u8);
            out.extend_from_slice(&item.validator_address);
            out.extend_from_slice(&item.validator_power.to_be_bytes());
            out.extend_from_slice(&item.infraction_height.to_be_bytes());
            out.extend_from_slice(&item.infraction_time_seconds.to_be_bytes());
            out.extend_from_slice(&item.infraction_time_nanos.to_be_bytes());
            out.extend_from_slice(&item.total_voting_power.to_be_bytes());
        }
        out
    }

    fn encode_file(&self) -> Vec<u8> {
        let mut bytes = self.encode_payload();
        bytes.extend_from_slice(&hash_payload(&bytes));
        bytes
    }

    fn decode_file(bytes: &[u8]) -> Result<Self, SafetyHaltError> {
        if bytes.len() < MAGIC.len() + 2 + 32 {
            return Err(SafetyHaltError::Corrupt("halt journal is truncated"));
        }
        let payload_len = bytes.len() - 32;
        let (payload, checksum) = bytes.split_at(payload_len);
        if hash_payload(payload) != checksum {
            return Err(SafetyHaltError::Corrupt(
                "halt journal checksum does not match",
            ));
        }
        let mut reader = Reader::new(payload);
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(SafetyHaltError::Corrupt("halt journal magic is invalid"));
        }
        if reader.u8()? != FORMAT_VERSION {
            return Err(SafetyHaltError::Corrupt(
                "halt journal format version is unsupported",
            ));
        }
        let reason = match reader.u8()? {
            1 => SafetyHaltReason::NoSafeValidatorSet,
            _ => return Err(SafetyHaltError::Corrupt("halt reason is unknown")),
        };
        let chain_context = reader.hash32()?;
        let committed_height = reader.u64()?;
        let committed_app_hash = reader.hash32()?;
        let attempted_height = reader.u64()?;
        let attempted_block_hash = reader.hash32()?;
        let attempted_block_time_seconds = reader.u64()?;
        let next_validators_hash = reader.hash32()?;
        let evidence_count = usize::try_from(reader.u32()?)
            .map_err(|_| SafetyHaltError::Corrupt("halt evidence count overflows usize"))?;
        let expected = evidence_count
            .checked_mul(EVIDENCE_BYTES)
            .ok_or(SafetyHaltError::Corrupt("halt evidence size overflows"))?;
        if reader.remaining() != expected {
            return Err(SafetyHaltError::Corrupt(
                "halt evidence count differs from payload length",
            ));
        }
        let mut evidence = Vec::with_capacity(evidence_count);
        for _ in 0..evidence_count {
            let kind = match reader.u8()? {
                1 => ByzantineEvidenceKind::DuplicateVote,
                2 => ByzantineEvidenceKind::LightClientAttack,
                _ => return Err(SafetyHaltError::Corrupt("halt evidence kind is unknown")),
            };
            evidence.push(ByzantineEvidence {
                kind,
                validator_address: reader.array20()?,
                validator_power: reader.u64()?,
                infraction_height: reader.u64()?,
                infraction_time_seconds: reader.u64()?,
                infraction_time_nanos: reader.u32()?,
                total_voting_power: reader.u64()?,
            });
        }
        if reader.remaining() != 0 {
            return Err(SafetyHaltError::Corrupt(
                "halt journal has trailing payload bytes",
            ));
        }
        let record = Self {
            reason,
            chain_context,
            committed_height,
            committed_app_hash,
            attempted_height,
            attempted_block_hash,
            attempted_block_time_seconds,
            next_validators_hash,
            evidence,
        };
        record.validate()?;
        Ok(record)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SafetyHaltError {
    #[error("failed to {action} safety halt journal {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("safety halt journal is corrupt: {0}")]
    Corrupt(&'static str),
    #[error(
        "a different safety halt is already recorded (existing {existing}, attempted {attempted})"
    )]
    Conflict { existing: String, attempted: String },
    #[error("no active safety halt journal exists")]
    Missing,
    #[error("safety halt acknowledgement hash differs (expected {expected}, actual {actual})")]
    AcknowledgementMismatch { expected: String, actual: String },
}

pub fn safety_halt_journal_path(state_path: &Path) -> PathBuf {
    let mut path = state_path.as_os_str().to_os_string();
    path.push(".safety-halt-v1");
    PathBuf::from(path)
}

fn temporary_journal_path(state_path: &Path) -> PathBuf {
    let mut path = safety_halt_journal_path(state_path).into_os_string();
    path.push(".tmp");
    PathBuf::from(path)
}

/// Read the active journal. A fully written temporary file left by a crash is
/// promoted before it is returned, so restart remains fail closed.
pub fn read_safety_halt(
    state_path: impl AsRef<Path>,
) -> Result<Option<SafetyHaltRecord>, SafetyHaltError> {
    let state_path = state_path.as_ref();
    let final_path = safety_halt_journal_path(state_path);
    if path_exists(&final_path)? {
        return read_record(&final_path).map(Some);
    }
    let temporary_path = temporary_journal_path(state_path);
    if !path_exists(&temporary_path)? {
        return Ok(None);
    }
    let record = read_record(&temporary_path)?;
    fs::rename(&temporary_path, &final_path)
        .map_err(|source| io_error("promote", &final_path, source))?;
    sync_parent(&final_path)?;
    Ok(Some(record))
}

pub(crate) fn persist_safety_halt(
    state_path: &Path,
    record: &SafetyHaltRecord,
) -> Result<(), SafetyHaltError> {
    if let Some(existing) = read_safety_halt(state_path)? {
        let existing_hash = existing.record_hash();
        let attempted_hash = record.record_hash();
        if existing_hash == attempted_hash {
            return Ok(());
        }
        return Err(SafetyHaltError::Conflict {
            existing: encode_hex(&existing_hash),
            attempted: encode_hex(&attempted_hash),
        });
    }
    let final_path = safety_halt_journal_path(state_path);
    let temporary_path = temporary_journal_path(state_path);
    let bytes = record.encode_file();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .map_err(|source| io_error("create", &temporary_path, source))?;
    file.write_all(&bytes)
        .map_err(|source| io_error("write", &temporary_path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync", &temporary_path, source))?;
    drop(file);
    fs::rename(&temporary_path, &final_path)
        .map_err(|source| io_error("publish", &final_path, source))?;
    sync_parent(&final_path)
}

/// Archive an active halt after an operator has checked its exact record hash.
/// The triggering evidence remains on disk for audit, and replaying the same
/// unsafe block creates a new active journal and halts again.
pub fn acknowledge_safety_halt(
    state_path: impl AsRef<Path>,
    expected_record_hash: Hash32,
) -> Result<PathBuf, SafetyHaltError> {
    let state_path = state_path.as_ref();
    let record = read_safety_halt(state_path)?.ok_or(SafetyHaltError::Missing)?;
    let actual = record.record_hash();
    if actual != expected_record_hash {
        return Err(SafetyHaltError::AcknowledgementMismatch {
            expected: encode_hex(&expected_record_hash),
            actual: encode_hex(&actual),
        });
    }
    let active_path = safety_halt_journal_path(state_path);
    let mut archive = active_path.as_os_str().to_os_string();
    archive.push(".acknowledged-");
    archive.push(encode_hex(&actual));
    let archive = PathBuf::from(archive);
    if path_exists(&archive)? {
        return Err(SafetyHaltError::Conflict {
            existing: encode_hex(&actual),
            attempted: encode_hex(&actual),
        });
    }
    fs::rename(&active_path, &archive)
        .map_err(|source| io_error("archive", &active_path, source))?;
    sync_parent(&active_path)?;
    Ok(archive)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn decode_hash_hex(value: &str) -> Result<Hash32, SafetyHaltError> {
    if value.len() != 64 {
        return Err(SafetyHaltError::Corrupt(
            "record hash must contain exactly 64 hexadecimal characters",
        ));
    }
    let mut out = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(out)
}

fn hex_nibble(value: u8) -> Result<u8, SafetyHaltError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(SafetyHaltError::Corrupt(
            "record hash contains a non-hexadecimal character",
        )),
    }
}

fn hash_payload(payload: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_HASH_DOMAIN);
    hasher.update(payload);
    hasher.finalize().into()
}

fn path_exists(path: &Path) -> Result<bool, SafetyHaltError> {
    path.try_exists()
        .map_err(|source| io_error("inspect", path, source))
}

fn read_record(path: &Path) -> Result<SafetyHaltRecord, SafetyHaltError> {
    let bytes = fs::read(path).map_err(|source| io_error("read", path, source))?;
    SafetyHaltRecord::decode_file(&bytes)
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> SafetyHaltError {
    SafetyHaltError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), SafetyHaltError> {
    let parent = path
        .parent()
        .ok_or(SafetyHaltError::Corrupt("halt journal has no parent"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync parent of", path, source))
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), SafetyHaltError> {
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SafetyHaltError> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(SafetyHaltError::Corrupt("halt journal is truncated"))?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, SafetyHaltError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, SafetyHaltError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("length is checked"),
        ))
    }

    fn u64(&mut self) -> Result<u64, SafetyHaltError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("length is checked"),
        ))
    }

    fn hash32(&mut self) -> Result<Hash32, SafetyHaltError> {
        Ok(self.take(32)?.try_into().expect("length is checked"))
    }

    fn array20(&mut self) -> Result<[u8; 20], SafetyHaltError> {
        Ok(self.take(20)?.try_into().expect("length is checked"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn record() -> SafetyHaltRecord {
        let chain_context = [1; 32];
        SafetyHaltRecord::no_safe_validator_set(
            chain_context,
            7,
            [2; 32],
            8,
            [3; 32],
            42,
            [4; 32],
            vec![ByzantineEvidence {
                kind: ByzantineEvidenceKind::DuplicateVote,
                validator_address: [5; 20],
                validator_power: 11,
                infraction_height: 6,
                infraction_time_seconds: 40,
                infraction_time_nanos: 123,
                total_voting_power: 31,
            }],
        )
        .unwrap()
    }

    #[test]
    fn journal_roundtrip_restart_lock_and_acknowledgement_are_strict() {
        let dir = TempDir::new().unwrap();
        let state_path = dir.path().join("state");
        let record = record();
        persist_safety_halt(&state_path, &record).unwrap();
        assert_eq!(read_safety_halt(&state_path).unwrap(), Some(record.clone()));
        persist_safety_halt(&state_path, &record).unwrap();
        let mut conflicting = record.clone();
        conflicting.attempted_block_hash[0] ^= 1;
        assert!(matches!(
            persist_safety_halt(&state_path, &conflicting),
            Err(SafetyHaltError::Conflict { .. })
        ));

        let wrong = [9; 32];
        assert!(matches!(
            acknowledge_safety_halt(&state_path, wrong),
            Err(SafetyHaltError::AcknowledgementMismatch { .. })
        ));
        assert!(read_safety_halt(&state_path).unwrap().is_some());

        let archive = acknowledge_safety_halt(&state_path, record.record_hash()).unwrap();
        assert!(archive.is_file());
        assert!(read_safety_halt(&state_path).unwrap().is_none());
    }

    #[test]
    fn valid_crash_temporary_is_promoted_and_corruption_fails_closed() {
        let dir = TempDir::new().unwrap();
        let state_path = dir.path().join("state");
        let record = record();
        fs::write(temporary_journal_path(&state_path), record.encode_file()).unwrap();
        assert_eq!(read_safety_halt(&state_path).unwrap(), Some(record));
        assert!(safety_halt_journal_path(&state_path).is_file());

        let mut bytes = fs::read(safety_halt_journal_path(&state_path)).unwrap();
        bytes[10] ^= 1;
        fs::write(safety_halt_journal_path(&state_path), bytes).unwrap();
        assert!(matches!(
            read_safety_halt(&state_path),
            Err(SafetyHaltError::Corrupt(_))
        ));
    }

    #[test]
    fn record_hash_hex_codec_is_exact() {
        let hash = record().record_hash();
        assert_eq!(decode_hash_hex(&encode_hex(&hash)).unwrap(), hash);
        assert!(decode_hash_hex("01").is_err());
        assert!(decode_hash_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn unavailable_journal_path_fails_closed() {
        let dir = TempDir::new().unwrap();
        let state_path = dir.path().join("state");
        fs::create_dir(safety_halt_journal_path(&state_path)).unwrap();
        assert!(matches!(
            persist_safety_halt(&state_path, &record()),
            Err(SafetyHaltError::Io { .. })
        ));
        assert!(matches!(
            read_safety_halt(&state_path),
            Err(SafetyHaltError::Io { .. })
        ));
    }
}
