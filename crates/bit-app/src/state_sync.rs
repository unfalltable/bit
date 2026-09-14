use bit_state::{
    GenesisConfig, Hash32, StateSnapshotManifest, StateSummary, STATE_SNAPSHOT_CHUNK_BYTES,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};
use tendermint_proto::v0_38::abci::{
    response_apply_snapshot_chunk, response_offer_snapshot, Snapshot,
};

pub const STATE_SYNC_SNAPSHOT_FORMAT: u32 = 1;
const TRANSPORT_METADATA_MAGIC: [u8; 16] = *b"BIT-ABCI-SYNC-V1";
const ACTIVE_MARKER_MAGIC: [u8; 16] = *b"BIT-ACTIVE-ST-V1";
const ACTIVE_MARKER_DOMAIN: &[u8] = b"BIT-ACTIVE-STATE-MARKER-HASH-V1";
const MAX_STATE_SYNC_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;
const MAX_STATE_SYNC_CHUNKS: u32 = 100_000;
const MAX_SNAPSHOT_COUNT: usize = 100;
const SNAPSHOT_DIRECTORY_PREFIX: &str = "snapshot-v1-";
const INCOMING_DIRECTORY_PREFIX: &str = ".incoming-v1-";
const CHUNK_DIRECTORY: &str = "chunks";

static SESSION_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSyncConfig {
    pub snapshot_directory: PathBuf,
    pub keep_recent: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransportMetadata {
    storage_schema_version: u32,
    state_height: u64,
    chunks: u32,
    total_bytes: u64,
    snapshot_id: Hash32,
    app_hash: Hash32,
    chain_context: Hash32,
}

impl TransportMetadata {
    fn from_manifest(manifest: &StateSnapshotManifest) -> crate::Result<Self> {
        Ok(Self {
            storage_schema_version: manifest.storage_schema_version,
            state_height: manifest.state_height,
            chunks: manifest.state_sync_chunk_count()?,
            total_bytes: manifest.total_bytes,
            snapshot_id: manifest.snapshot_id,
            app_hash: manifest.app_hash,
            chain_context: manifest.chain_context,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(136);
        bytes.extend_from_slice(&TRANSPORT_METADATA_MAGIC);
        bytes.extend_from_slice(&self.storage_schema_version.to_be_bytes());
        bytes.extend_from_slice(&self.state_height.to_be_bytes());
        bytes.extend_from_slice(&self.chunks.to_be_bytes());
        bytes.extend_from_slice(&self.total_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.snapshot_id);
        bytes.extend_from_slice(&self.app_hash);
        bytes.extend_from_slice(&self.chain_context);
        bytes
    }

    fn decode(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != 136 {
            return Err(state_sync_error(
                "snapshot transport metadata length differs",
            ));
        }
        if bytes[..16] != TRANSPORT_METADATA_MAGIC {
            return Err(state_sync_error(
                "snapshot transport metadata magic differs",
            ));
        }
        let storage_schema_version = u32::from_be_bytes(
            bytes[16..20]
                .try_into()
                .expect("metadata slice length is fixed"),
        );
        let state_height = u64::from_be_bytes(
            bytes[20..28]
                .try_into()
                .expect("metadata slice length is fixed"),
        );
        let chunks = u32::from_be_bytes(
            bytes[28..32]
                .try_into()
                .expect("metadata slice length is fixed"),
        );
        let total_bytes = u64::from_be_bytes(
            bytes[32..40]
                .try_into()
                .expect("metadata slice length is fixed"),
        );
        let snapshot_id = bytes[40..72]
            .try_into()
            .expect("metadata slice length is fixed");
        let app_hash = bytes[72..104]
            .try_into()
            .expect("metadata slice length is fixed");
        let chain_context = bytes[104..136]
            .try_into()
            .expect("metadata slice length is fixed");
        if state_height == 0
            || !(2..=MAX_STATE_SYNC_CHUNKS).contains(&chunks)
            || total_bytes > MAX_STATE_SYNC_BYTES
        {
            return Err(state_sync_error("snapshot transport metadata is invalid"));
        }
        Ok(Self {
            storage_schema_version,
            state_height,
            chunks,
            total_bytes,
            snapshot_id,
            app_hash,
            chain_context,
        })
    }

    fn matches_manifest(&self, manifest: &StateSnapshotManifest) -> crate::Result<bool> {
        Ok(
            self.storage_schema_version == manifest.storage_schema_version
                && self.state_height == manifest.state_height
                && self.chunks == manifest.state_sync_chunk_count()?
                && self.total_bytes == manifest.total_bytes
                && self.snapshot_id == manifest.snapshot_id
                && self.app_hash == manifest.app_hash
                && self.chain_context == manifest.chain_context,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActiveStateMarker {
    pub snapshot_id: Hash32,
    pub state_height: u64,
    pub app_hash: Hash32,
    pub chain_context: Hash32,
}

impl ActiveStateMarker {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(152);
        bytes.extend_from_slice(&ACTIVE_MARKER_MAGIC);
        bytes.extend_from_slice(&self.snapshot_id);
        bytes.extend_from_slice(&self.state_height.to_be_bytes());
        bytes.extend_from_slice(&self.app_hash);
        bytes.extend_from_slice(&self.chain_context);
        let mut hasher = Sha256::new();
        hasher.update(ACTIVE_MARKER_DOMAIN);
        hasher.update(&bytes);
        bytes.extend_from_slice(&hasher.finalize());
        bytes
    }

    fn decode(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != 152 || bytes[..16] != ACTIVE_MARKER_MAGIC {
            return Err(state_sync_error("active state marker format differs"));
        }
        let expected_checksum: Hash32 = bytes[120..152]
            .try_into()
            .expect("active marker slice length is fixed");
        let mut hasher = Sha256::new();
        hasher.update(ACTIVE_MARKER_DOMAIN);
        hasher.update(&bytes[..120]);
        let actual_checksum: Hash32 = hasher.finalize().into();
        if actual_checksum != expected_checksum {
            return Err(state_sync_error("active state marker checksum differs"));
        }
        let marker = Self {
            snapshot_id: bytes[16..48]
                .try_into()
                .expect("active marker slice length is fixed"),
            state_height: u64::from_be_bytes(
                bytes[48..56]
                    .try_into()
                    .expect("active marker slice length is fixed"),
            ),
            app_hash: bytes[56..88]
                .try_into()
                .expect("active marker slice length is fixed"),
            chain_context: bytes[88..120]
                .try_into()
                .expect("active marker slice length is fixed"),
        };
        if marker.state_height == 0 {
            return Err(state_sync_error("active state marker height is zero"));
        }
        Ok(marker)
    }
}

#[derive(Debug)]
struct PublishedSnapshot {
    path: PathBuf,
    manifest: StateSnapshotManifest,
    snapshot: Snapshot,
}

#[derive(Debug)]
struct IncomingSession {
    directory: PathBuf,
    metadata: TransportMetadata,
    received: Vec<bool>,
    senders: Vec<Option<String>>,
    manifest: Option<StateSnapshotManifest>,
    armed: bool,
}

impl IncomingSession {
    fn create(root: &Path, metadata: TransportMetadata) -> crate::Result<Self> {
        for _ in 0..100 {
            let nonce = SESSION_NONCE.fetch_add(1, Ordering::Relaxed);
            let directory = root.join(format!(
                "{INCOMING_DIRECTORY_PREFIX}{}-{nonce}",
                std::process::id()
            ));
            match fs::create_dir(&directory) {
                Ok(()) => {
                    let chunks = directory.join(CHUNK_DIRECTORY);
                    if let Err(error) = fs::create_dir(&chunks) {
                        let _ = fs::remove_dir(&directory);
                        return Err(state_sync_io(
                            "create incoming chunk directory",
                            &chunks,
                            error,
                        ));
                    }
                    let count = usize::try_from(metadata.chunks)
                        .map_err(|_| state_sync_error("snapshot chunk count does not fit usize"))?;
                    return Ok(Self {
                        directory,
                        metadata,
                        received: vec![false; count],
                        senders: vec![None; count],
                        manifest: None,
                        armed: true,
                    });
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(state_sync_io(
                        "create incoming snapshot directory",
                        &directory,
                        error,
                    ));
                }
            }
        }
        Err(state_sync_error(
            "could not allocate an incoming snapshot directory",
        ))
    }

    fn chunk_path(&self, index: u32) -> PathBuf {
        self.directory
            .join(CHUNK_DIRECTORY)
            .join(format!("{index:08x}.chunk"))
    }

    fn ordered_chunk_paths(&self) -> crate::Result<Vec<PathBuf>> {
        (0..self.metadata.chunks)
            .map(|index| {
                let path = self.chunk_path(index);
                if !self.received[usize::try_from(index).expect("u32 fits usize")] {
                    return Err(state_sync_error("incoming snapshot is incomplete"));
                }
                Ok(path)
            })
            .collect()
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for IncomingSession {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}

pub(crate) struct CompletedIncomingSnapshot {
    session: IncomingSession,
    pub manifest: StateSnapshotManifest,
}

impl CompletedIncomingSnapshot {
    pub fn chunk_paths(&self) -> crate::Result<Vec<PathBuf>> {
        self.session.ordered_chunk_paths()
    }

    pub fn materialized_path(&self) -> PathBuf {
        self.session.directory.join("materialized")
    }

    pub fn finish(mut self) {
        self.session.disarm();
        let _ = fs::remove_dir_all(&self.session.directory);
    }
}

pub(crate) enum ApplyDecision {
    Response {
        result: response_apply_snapshot_chunk::Result,
        refetch_chunks: Vec<u32>,
        reject_senders: Vec<String>,
    },
    Complete(Box<CompletedIncomingSnapshot>),
}

pub(crate) struct StateSyncManager {
    config: Option<StateSyncConfig>,
    chain_context: Hash32,
    incoming: Mutex<Option<IncomingSession>>,
}

impl StateSyncManager {
    pub fn new(
        state_path: &Path,
        base_state_path: &Path,
        chain_context: Hash32,
        config: Option<StateSyncConfig>,
    ) -> crate::Result<Self> {
        if let Some(config) = &config {
            if config.keep_recent == 0 || config.keep_recent > MAX_SNAPSHOT_COUNT {
                return Err(crate::Error::InvalidConfig(
                    "state-sync keep_recent must be between 1 and 100",
                ));
            }
            fs::create_dir_all(&config.snapshot_directory).map_err(|error| {
                state_sync_io(
                    "create state-sync snapshot directory",
                    &config.snapshot_directory,
                    error,
                )
            })?;
            let snapshot_root = fs::canonicalize(&config.snapshot_directory).map_err(|error| {
                state_sync_io(
                    "canonicalize state-sync snapshot directory",
                    &config.snapshot_directory,
                    error,
                )
            })?;
            let state_root = fs::canonicalize(state_path).map_err(|error| {
                state_sync_io("canonicalize state directory", state_path, error)
            })?;
            let base_state_root = fs::canonicalize(base_state_path).map_err(|error| {
                state_sync_io("canonicalize base state directory", base_state_path, error)
            })?;
            if paths_overlap(&snapshot_root, &state_root)
                || paths_overlap(&snapshot_root, &base_state_root)
            {
                return Err(crate::Error::InvalidConfig(
                    "state and state-sync snapshot directories must be separate",
                ));
            }
        }
        Ok(Self {
            config,
            chain_context,
            incoming: Mutex::new(None),
        })
    }

    pub fn enabled(&self) -> bool {
        self.config.is_some()
    }

    pub fn snapshot_destination(&self, height: u64) -> crate::Result<PathBuf> {
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| state_sync_error("ABCI State Sync is disabled"))?;
        Ok(config
            .snapshot_directory
            .join(format!("{SNAPSHOT_DIRECTORY_PREFIX}{height:020}")))
    }

    pub fn register_created_snapshot(
        &self,
        path: &Path,
        expected: &StateSummary,
    ) -> crate::Result<Snapshot> {
        let manifest = StateSnapshotManifest::read_from(path)?;
        if !manifest_matches_summary(&manifest, expected, &self.chain_context) {
            return Err(state_sync_error(
                "created snapshot differs from the committed application state",
            ));
        }
        let snapshot = snapshot_from_manifest(&manifest)?;
        self.prune()?;
        Ok(snapshot)
    }

    pub fn existing_snapshot(&self, expected: &StateSummary) -> crate::Result<Option<Snapshot>> {
        let path = self.snapshot_destination(expected.state_height)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(state_sync_io("inspect state-sync snapshot", &path, error)),
            Ok(_) => {
                let published = read_published_snapshot(path, expected.state_height)?;
                if !manifest_matches_summary(&published.manifest, expected, &self.chain_context) {
                    return Err(state_sync_error(
                        "published snapshot differs from the committed application state",
                    ));
                }
                Ok(Some(published.snapshot))
            }
        }
    }

    pub fn list_snapshots(&self) -> crate::Result<Vec<Snapshot>> {
        let Some(config) = &self.config else {
            return Ok(Vec::new());
        };
        let mut snapshots = scan_snapshots(&config.snapshot_directory)?;
        if snapshots
            .iter()
            .any(|entry| entry.manifest.chain_context != self.chain_context)
        {
            return Err(state_sync_error(
                "state-sync repository contains a snapshot for another chain",
            ));
        }
        snapshots.sort_by_key(|entry| std::cmp::Reverse(entry.manifest.state_height));
        snapshots.truncate(config.keep_recent);
        Ok(snapshots.into_iter().map(|entry| entry.snapshot).collect())
    }

    pub fn load_chunk(&self, height: u64, format: u32, index: u32) -> crate::Result<Vec<u8>> {
        if format != STATE_SYNC_SNAPSHOT_FORMAT {
            return Ok(Vec::new());
        }
        let path = self.snapshot_destination(height)?;
        let published = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(state_sync_io("inspect state-sync snapshot", &path, error)),
            Ok(_) => read_published_snapshot(path, height)?,
        };
        if published.manifest.chain_context != self.chain_context {
            return Err(state_sync_error(
                "state-sync snapshot belongs to another chain",
            ));
        }
        if index >= published.snapshot.chunks {
            return Ok(Vec::new());
        }
        published
            .manifest
            .load_state_sync_chunk(&published.path, index)
            .map_err(Into::into)
    }

    pub fn offer(
        &self,
        snapshot: Option<&Snapshot>,
        trusted_app_hash: &[u8],
        pristine_summary: Option<&StateSummary>,
    ) -> crate::Result<response_offer_snapshot::Result> {
        if !self.enabled() {
            return Ok(response_offer_snapshot::Result::RejectFormat);
        }
        let Some(pristine_summary) = pristine_summary else {
            return Ok(response_offer_snapshot::Result::Abort);
        };
        let Some(snapshot) = snapshot else {
            return Ok(response_offer_snapshot::Result::Reject);
        };
        if snapshot.format != STATE_SYNC_SNAPSHOT_FORMAT {
            return Ok(response_offer_snapshot::Result::RejectFormat);
        }
        let Ok(metadata) = TransportMetadata::decode(&snapshot.metadata) else {
            return Ok(response_offer_snapshot::Result::Reject);
        };
        let Ok(snapshot_id) = <Hash32>::try_from(snapshot.hash.as_ref()) else {
            return Ok(response_offer_snapshot::Result::Reject);
        };
        let Ok(app_hash) = <Hash32>::try_from(trusted_app_hash) else {
            return Ok(response_offer_snapshot::Result::Reject);
        };
        if metadata.state_height != snapshot.height
            || metadata.chunks != snapshot.chunks
            || metadata.snapshot_id != snapshot_id
            || metadata.app_hash != app_hash
            || metadata.chain_context != self.chain_context
            || metadata.storage_schema_version != pristine_summary.storage_schema_version
        {
            return Ok(response_offer_snapshot::Result::Reject);
        }
        let config = self.config.as_ref().expect("enabled manager has config");
        let session = IncomingSession::create(&config.snapshot_directory, metadata)?;
        let mut incoming = self
            .incoming
            .lock()
            .map_err(|_| state_sync_error("incoming snapshot lock is poisoned"))?;
        *incoming = Some(session);
        Ok(response_offer_snapshot::Result::Accept)
    }

    pub fn apply_chunk(
        &self,
        index: u32,
        chunk: &[u8],
        sender: &str,
    ) -> crate::Result<ApplyDecision> {
        let mut incoming = self
            .incoming
            .lock()
            .map_err(|_| state_sync_error("incoming snapshot lock is poisoned"))?;
        let Some(session) = incoming.as_mut() else {
            return Ok(response_decision(
                response_apply_snapshot_chunk::Result::Abort,
                Vec::new(),
                Vec::new(),
            ));
        };
        if index >= session.metadata.chunks {
            *incoming = None;
            return Ok(response_decision(
                response_apply_snapshot_chunk::Result::RejectSnapshot,
                Vec::new(),
                reject_sender(sender),
            ));
        }
        if chunk.is_empty() || chunk.len() > STATE_SNAPSHOT_CHUNK_BYTES {
            return Ok(retry_chunk(session, index, sender));
        }

        let path = session.chunk_path(index);
        write_replace_synced(&path, chunk)?;
        let slot = usize::try_from(index).expect("u32 fits usize");
        session.received[slot] = true;
        session.senders[slot] = (!sender.is_empty()).then(|| sender.to_owned());

        if index == 0 {
            match StateSnapshotManifest::from_state_sync_manifest_chunk(chunk) {
                Ok(manifest) => {
                    if !session.metadata.matches_manifest(&manifest)? {
                        *incoming = None;
                        return Ok(response_decision(
                            response_apply_snapshot_chunk::Result::RejectSnapshot,
                            Vec::new(),
                            reject_sender(sender),
                        ));
                    }
                    session.manifest = Some(manifest);
                }
                Err(_) => return Ok(retry_chunk(session, index, sender)),
            }
        }

        let Some(manifest) = session.manifest.as_ref() else {
            return Ok(response_decision(
                response_apply_snapshot_chunk::Result::Accept,
                Vec::new(),
                Vec::new(),
            ));
        };

        let mut invalid = Vec::new();
        let mut bad_senders = BTreeSet::new();
        let validation_range = if index == 0 {
            0..session.metadata.chunks
        } else {
            index..index + 1
        };
        for candidate in validation_range {
            let candidate_slot = usize::try_from(candidate).expect("u32 fits usize");
            if !session.received[candidate_slot] {
                continue;
            }
            let candidate_path = session.chunk_path(candidate);
            let bytes = fs::read(&candidate_path).map_err(|error| {
                state_sync_io("read received snapshot chunk", &candidate_path, error)
            })?;
            if manifest
                .validate_state_sync_chunk(candidate, &bytes)
                .is_err()
            {
                let _ = fs::remove_file(&candidate_path);
                session.received[candidate_slot] = false;
                if let Some(sender) = session.senders[candidate_slot].take() {
                    bad_senders.insert(sender);
                }
                invalid.push(candidate);
            }
        }
        if !invalid.is_empty() {
            return Ok(response_decision(
                response_apply_snapshot_chunk::Result::Accept,
                invalid,
                bad_senders.into_iter().collect(),
            ));
        }
        if session.received.iter().any(|received| !received) {
            return Ok(response_decision(
                response_apply_snapshot_chunk::Result::Accept,
                Vec::new(),
                Vec::new(),
            ));
        }

        let session = incoming
            .take()
            .expect("incoming session exists while completing");
        let manifest = session
            .manifest
            .clone()
            .expect("complete session has a validated manifest");
        Ok(ApplyDecision::Complete(Box::new(
            CompletedIncomingSnapshot { session, manifest },
        )))
    }

    fn prune(&self) -> crate::Result<()> {
        let Some(config) = &self.config else {
            return Ok(());
        };
        let mut snapshots = scan_snapshots(&config.snapshot_directory)?;
        snapshots.sort_by_key(|entry| entry.manifest.state_height);
        let remove_count = snapshots.len().saturating_sub(config.keep_recent);
        for entry in snapshots.into_iter().take(remove_count) {
            fs::remove_dir_all(&entry.path)
                .map_err(|error| state_sync_io("prune state-sync snapshot", &entry.path, error))?;
        }
        Ok(())
    }
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn manifest_matches_summary(
    manifest: &StateSnapshotManifest,
    expected: &StateSummary,
    chain_context: &Hash32,
) -> bool {
    manifest.storage_schema_version == expected.storage_schema_version
        && manifest.state_height == expected.state_height
        && manifest.block_time_seconds == expected.block_time_seconds
        && manifest.storage_version == expected.storage_version
        && manifest.app_hash == expected.app_hash
        && manifest.shielded_tree_root == expected.shielded_tree_root
        && manifest.chain_context == *chain_context
        && manifest.monetary_policy_hash == expected.supply.monetary_policy_hash
}

fn response_decision(
    result: response_apply_snapshot_chunk::Result,
    refetch_chunks: Vec<u32>,
    reject_senders: Vec<String>,
) -> ApplyDecision {
    ApplyDecision::Response {
        result,
        refetch_chunks,
        reject_senders,
    }
}

fn retry_chunk(session: &mut IncomingSession, index: u32, sender: &str) -> ApplyDecision {
    let slot = usize::try_from(index).expect("u32 fits usize");
    let _ = fs::remove_file(session.chunk_path(index));
    session.received[slot] = false;
    session.senders[slot] = None;
    response_decision(
        response_apply_snapshot_chunk::Result::Retry,
        Vec::new(),
        reject_sender(sender),
    )
}

fn reject_sender(sender: &str) -> Vec<String> {
    (!sender.is_empty())
        .then(|| sender.to_owned())
        .into_iter()
        .collect()
}

fn snapshot_from_manifest(manifest: &StateSnapshotManifest) -> crate::Result<Snapshot> {
    let metadata = TransportMetadata::from_manifest(manifest)?;
    Ok(Snapshot {
        height: manifest.state_height,
        format: STATE_SYNC_SNAPSHOT_FORMAT,
        chunks: metadata.chunks,
        hash: manifest.snapshot_id.to_vec().into(),
        metadata: metadata.encode().into(),
    })
}

fn scan_snapshots(root: &Path) -> crate::Result<Vec<PublishedSnapshot>> {
    let mut snapshots = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|error| state_sync_io("read state-sync snapshot directory", root, error))?
    {
        let entry = entry.map_err(|error| {
            state_sync_error(format!(
                "read state-sync snapshot entry in {}: {error}",
                root.display()
            ))
        })?;
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };
        let Some(height) = parse_snapshot_directory_name(&name) else {
            continue;
        };
        snapshots.push(read_published_snapshot(entry.path(), height)?);
    }
    Ok(snapshots)
}

fn parse_snapshot_directory_name(name: &str) -> Option<u64> {
    let height = name.strip_prefix(SNAPSHOT_DIRECTORY_PREFIX)?;
    if height.len() != 20 || !height.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let parsed = height.parse().ok()?;
    (parsed > 0).then_some(parsed)
}

fn read_published_snapshot(
    path: PathBuf,
    expected_height: u64,
) -> crate::Result<PublishedSnapshot> {
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| state_sync_io("inspect published snapshot", &path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(state_sync_error(
            "published snapshot path is not a real directory",
        ));
    }
    let manifest = StateSnapshotManifest::read_from(&path)?;
    if manifest.state_height != expected_height {
        return Err(state_sync_error(
            "published snapshot height differs from its directory name",
        ));
    }
    let snapshot = snapshot_from_manifest(&manifest)?;
    Ok(PublishedSnapshot {
        path,
        manifest,
        snapshot,
    })
}

fn write_replace_synced(path: &Path, bytes: &[u8]) -> crate::Result<()> {
    let temporary = path.with_extension("chunk.tmp");
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(state_sync_io(
                "remove stale incoming chunk temporary",
                &temporary,
                error,
            ));
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| state_sync_io("create incoming snapshot chunk", &temporary, error))?;
    file.write_all(bytes)
        .map_err(|error| state_sync_io("write incoming snapshot chunk", &temporary, error))?;
    file.sync_all()
        .map_err(|error| state_sync_io("sync incoming snapshot chunk", &temporary, error))?;
    drop(file);
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(state_sync_io(
                "replace incoming snapshot chunk",
                path,
                error,
            ));
        }
    }
    fs::rename(&temporary, path)
        .map_err(|error| state_sync_io("publish incoming snapshot chunk", path, error))
}

pub(crate) fn active_marker_path(state_path: &Path) -> crate::Result<PathBuf> {
    sibling_path(state_path, ".active-state-v1")
}

fn active_marker_temporary_path(state_path: &Path) -> crate::Result<PathBuf> {
    sibling_path(state_path, ".active-state-v1.tmp")
}

pub(crate) fn active_state_path(state_path: &Path, snapshot_id: &Hash32) -> crate::Result<PathBuf> {
    sibling_path(
        state_path,
        &format!(".state-sync-v1-{}", hex::encode(snapshot_id)),
    )
}

pub(crate) fn validate_active_state_path(path: &Path) -> crate::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| state_sync_io("inspect active state database", path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(state_sync_error(
            "active state database is not a real directory",
        ));
    }
    Ok(())
}

fn sibling_path(state_path: &Path, suffix: &str) -> crate::Result<PathBuf> {
    let name = state_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(crate::Error::InvalidConfig(
            "state path must end in a UTF-8 directory name",
        ))?;
    Ok(state_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{name}{suffix}")))
}

pub(crate) fn read_active_state_marker(
    state_path: &Path,
) -> crate::Result<Option<ActiveStateMarker>> {
    let marker_path = active_marker_path(state_path)?;
    let temporary_path = active_marker_temporary_path(state_path)?;
    let temporary = match fs::symlink_metadata(&temporary_path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => {
            return Err(state_sync_io(
                "inspect active state marker temporary",
                &temporary_path,
                error,
            ));
        }
    };
    if let Some(metadata) = temporary {
        if fs::symlink_metadata(&marker_path).is_ok() {
            return Err(state_sync_error(
                "active state marker and its temporary both exist",
            ));
        }
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 152 {
            return Err(state_sync_error(
                "active state marker temporary is not a canonical file",
            ));
        }
        let bytes = fs::read(&temporary_path).map_err(|error| {
            state_sync_io("read active state marker temporary", &temporary_path, error)
        })?;
        ActiveStateMarker::decode(&bytes)?;
        fs::rename(&temporary_path, &marker_path)
            .map_err(|error| state_sync_io("recover active state marker", &marker_path, error))?;
    }
    let metadata = match fs::symlink_metadata(&marker_path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(state_sync_io(
                "inspect active state marker",
                &marker_path,
                error,
            ))
        }
        Ok(metadata) => metadata,
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 152 {
        return Err(state_sync_error(
            "active state marker is not a canonical file",
        ));
    }
    let bytes = fs::read(&marker_path)
        .map_err(|error| state_sync_io("read active state marker", &marker_path, error))?;
    Ok(Some(ActiveStateMarker::decode(&bytes)?))
}

pub(crate) fn persist_active_state_marker(
    state_path: &Path,
    marker: &ActiveStateMarker,
) -> crate::Result<()> {
    let marker_path = active_marker_path(state_path)?;
    let temporary_path = active_marker_temporary_path(state_path)?;
    if fs::symlink_metadata(&marker_path).is_ok() || fs::symlink_metadata(&temporary_path).is_ok() {
        return Err(state_sync_error("active state marker already exists"));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .map_err(|error| state_sync_io("create active state marker", &temporary_path, error))?;
    file.write_all(&marker.encode())
        .map_err(|error| state_sync_io("write active state marker", &temporary_path, error))?;
    file.sync_all()
        .map_err(|error| state_sync_io("sync active state marker", &temporary_path, error))?;
    drop(file);
    fs::rename(&temporary_path, &marker_path)
        .map_err(|error| state_sync_io("publish active state marker", &marker_path, error))
}

pub(crate) fn validate_active_summary(
    marker: &ActiveStateMarker,
    summary: &StateSummary,
    genesis: &GenesisConfig,
) -> crate::Result<()> {
    if marker.chain_context != genesis.chain_context
        || marker.state_height != summary.state_height
        || marker.app_hash != summary.app_hash
    {
        return Err(state_sync_error(
            "active state differs from its durable activation marker",
        ));
    }
    Ok(())
}

fn state_sync_error(message: impl Into<String>) -> crate::Error {
    crate::Error::StateSync(message.into())
}

fn state_sync_io(operation: &str, path: &Path, error: std::io::Error) -> crate::Error {
    state_sync_error(format!("{operation} {}: {error}", path.display()))
}
