use super::{
    Error, GenesisConfig, Hash32, PersistentState, Result, StateSummary, STORAGE_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const SNAPSHOT_MAGIC: [u8; 16] = *b"BIT-SNAPSHOT-V1\0";
const SNAPSHOT_FORMAT_VERSION: u32 = 1;
const MANIFEST_NAME: &str = "manifest.bit";
const MANIFEST_HASH_NAME: &str = "manifest.sha256";
const DATABASE_DIRECTORY: &str = "db";
const STATE_SYNC_MANIFEST_MAGIC: [u8; 16] = *b"BIT-SYNC-CHUNK1\0";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SNAPSHOT_FILES: usize = 100_000;
const MAX_SNAPSHOT_ENTRIES: usize = 200_000;
const MAX_SNAPSHOT_DEPTH: usize = 16;
const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;
const MAX_STATE_SYNC_CHUNKS: u64 = 100_000;
pub const STATE_SNAPSHOT_CHUNK_BYTES: usize = 4 * 1024 * 1024;

static STAGING_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
struct SnapshotFile {
    path: String,
    length: u64,
    chunks: Vec<Hash32>,
}

/// Canonical metadata for one portable BIT state snapshot directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSnapshotManifest {
    pub format_version: u32,
    pub storage_schema_version: u32,
    pub state_height: u64,
    pub block_time_seconds: u64,
    pub storage_version: u64,
    pub app_hash: Hash32,
    pub shielded_tree_root: Hash32,
    pub chain_context: Hash32,
    pub monetary_policy_hash: Hash32,
    pub file_count: u32,
    pub total_bytes: u64,
    pub total_chunks: u64,
    pub snapshot_id: Hash32,
    files: Vec<SnapshotFile>,
}

impl StateSnapshotManifest {
    /// Read and fully validate a snapshot manifest and its manifest checksum.
    pub fn read_from(snapshot_directory: &Path) -> Result<Self> {
        validate_snapshot_root(snapshot_directory)?;
        let manifest_path = snapshot_directory.join(MANIFEST_NAME);
        let length = file_length(&manifest_path)?;
        if length > MAX_MANIFEST_BYTES {
            return Err(snapshot_error("manifest exceeds the 64 MiB limit"));
        }
        let bytes = fs::read(&manifest_path)
            .map_err(|error| snapshot_io("read manifest", &manifest_path, error))?;
        let manifest = decode_manifest(&bytes)?;
        let checksum_path = snapshot_directory.join(MANIFEST_HASH_NAME);
        if file_length(&checksum_path)? != 65 {
            return Err(snapshot_error("manifest checksum length differs"));
        }
        let checksum = fs::read(&checksum_path)
            .map_err(|error| snapshot_io("read manifest checksum", &checksum_path, error))?;
        let expected = format!("{}\n", hex::encode(manifest.snapshot_id));
        if checksum != expected.as_bytes() {
            return Err(snapshot_error("manifest checksum is missing or differs"));
        }
        Ok(manifest)
    }

    /// Number of ABCI State Sync chunks used by this snapshot.
    ///
    /// Chunk zero contains the canonical manifest. Every later transport
    /// chunk maps one-to-one to a database chunk already committed by it.
    pub fn state_sync_chunk_count(&self) -> Result<u32> {
        let manifest_chunk_length = encode_manifest(self)?
            .len()
            .checked_add(STATE_SYNC_MANIFEST_MAGIC.len() + 4)
            .ok_or_else(|| snapshot_error("state-sync manifest chunk length overflow"))?;
        if manifest_chunk_length > STATE_SNAPSHOT_CHUNK_BYTES {
            return Err(snapshot_error(
                "snapshot manifest does not fit the 4 MiB state-sync chunk",
            ));
        }
        let count = self
            .total_chunks
            .checked_add(1)
            .ok_or_else(|| snapshot_error("state-sync chunk count overflow"))?;
        if count > MAX_STATE_SYNC_CHUNKS {
            return Err(snapshot_error(
                "snapshot exceeds the 100000 state-sync chunk limit",
            ));
        }
        u32::try_from(count).map_err(|_| snapshot_error("state-sync chunk count does not fit u32"))
    }

    /// Encode transport chunk zero containing the canonical snapshot manifest.
    pub fn state_sync_manifest_chunk(&self) -> Result<Vec<u8>> {
        let manifest = encode_manifest(self)?;
        let manifest_length = u32::try_from(manifest.len())
            .map_err(|_| snapshot_error("state-sync manifest length does not fit u32"))?;
        let mut chunk = Vec::with_capacity(STATE_SYNC_MANIFEST_MAGIC.len() + 4 + manifest.len());
        chunk.extend_from_slice(&STATE_SYNC_MANIFEST_MAGIC);
        chunk.extend_from_slice(&manifest_length.to_be_bytes());
        chunk.extend_from_slice(&manifest);
        if chunk.len() > STATE_SNAPSHOT_CHUNK_BYTES {
            return Err(snapshot_error(
                "snapshot manifest does not fit the 4 MiB state-sync chunk",
            ));
        }
        Ok(chunk)
    }

    /// Decode and validate transport chunk zero.
    pub fn from_state_sync_manifest_chunk(chunk: &[u8]) -> Result<Self> {
        if chunk.len() > STATE_SNAPSHOT_CHUNK_BYTES {
            return Err(snapshot_error("state-sync manifest chunk exceeds 4 MiB"));
        }
        let mut decoder = ManifestDecoder::new(chunk);
        if decoder.take_array::<16>()? != STATE_SYNC_MANIFEST_MAGIC {
            return Err(snapshot_error("state-sync manifest chunk magic differs"));
        }
        let manifest_length = usize::try_from(decoder.take_u32()?)
            .map_err(|_| snapshot_error("state-sync manifest length does not fit usize"))?;
        let manifest = decode_manifest(decoder.take(manifest_length)?)?;
        if decoder.remaining() != 0 {
            return Err(snapshot_error(
                "state-sync manifest chunk has trailing bytes",
            ));
        }
        manifest.state_sync_chunk_count()?;
        Ok(manifest)
    }

    /// Read and verify one transport chunk from an exported snapshot directory.
    pub fn load_state_sync_chunk(&self, snapshot_directory: &Path, index: u32) -> Result<Vec<u8>> {
        if index == 0 {
            return self.state_sync_manifest_chunk();
        }
        let (file, file_chunk_index, expected_hash, expected_length) =
            self.state_sync_data_chunk(index)?;
        let database = snapshot_directory.join(DATABASE_DIRECTORY);
        let path = join_portable_path(&database, &file.path)?;
        if file_length(&path)? != file.length {
            return Err(snapshot_error(format!(
                "snapshot file length differs for {}",
                file.path
            )));
        }
        let offset = u64::try_from(file_chunk_index)
            .map_err(|_| snapshot_error("state-sync file chunk index does not fit u64"))?
            .checked_mul(STATE_SNAPSHOT_CHUNK_BYTES as u64)
            .ok_or_else(|| snapshot_error("state-sync file chunk offset overflow"))?;
        let mut input = File::open(&path)
            .map_err(|error| snapshot_io("open state-sync snapshot file", &path, error))?;
        input
            .seek(SeekFrom::Start(offset))
            .map_err(|error| snapshot_io("seek state-sync snapshot file", &path, error))?;
        let mut chunk = vec![0u8; expected_length];
        input
            .read_exact(&mut chunk)
            .map_err(|error| snapshot_io("read state-sync snapshot chunk", &path, error))?;
        let actual_hash: Hash32 = Sha256::digest(&chunk).into();
        if actual_hash != *expected_hash {
            return Err(snapshot_error(format!(
                "snapshot chunk hash differs for {}",
                file.path
            )));
        }
        Ok(chunk)
    }

    /// Validate one received transport chunk against this manifest.
    pub fn validate_state_sync_chunk(&self, index: u32, chunk: &[u8]) -> Result<()> {
        if index == 0 {
            if &Self::from_state_sync_manifest_chunk(chunk)? != self {
                return Err(snapshot_error(
                    "received state-sync manifest differs from the offered snapshot",
                ));
            }
            return Ok(());
        }
        let (file, _, expected_hash, expected_length) = self.state_sync_data_chunk(index)?;
        if chunk.len() != expected_length {
            return Err(snapshot_error(format!(
                "state-sync chunk length differs for {}",
                file.path
            )));
        }
        let actual_hash: Hash32 = Sha256::digest(chunk).into();
        if actual_hash != *expected_hash {
            return Err(snapshot_error(format!(
                "state-sync chunk hash differs for {}",
                file.path
            )));
        }
        Ok(())
    }

    /// Rebuild an ordinary snapshot directory from ordered transport chunk files.
    /// The destination is atomically published only after every chunk is verified.
    pub fn materialize_state_sync_snapshot(
        &self,
        chunk_paths: &[PathBuf],
        destination: &Path,
    ) -> Result<()> {
        let expected_count = usize::try_from(self.state_sync_chunk_count()?)
            .map_err(|_| snapshot_error("state-sync chunk count does not fit usize"))?;
        if chunk_paths.len() != expected_count {
            return Err(snapshot_error("state-sync chunk file count differs"));
        }
        let manifest_chunk = fs::read(&chunk_paths[0]).map_err(|error| {
            snapshot_io(
                "read received state-sync manifest chunk",
                &chunk_paths[0],
                error,
            )
        })?;
        self.validate_state_sync_chunk(0, &manifest_chunk)?;

        ensure_destination_absent(destination)?;
        let mut staging = StagingDirectory::create_for(destination, "materialize")?;
        let database = staging.path().join(DATABASE_DIRECTORY);
        fs::create_dir(&database).map_err(|error| {
            snapshot_io("create materialized snapshot database", &database, error)
        })?;
        write_new_synced(&staging.path().join(MANIFEST_NAME), &encode_manifest(self)?)?;
        let checksum = format!("{}\n", hex::encode(self.snapshot_id));
        write_new_synced(
            &staging.path().join(MANIFEST_HASH_NAME),
            checksum.as_bytes(),
        )?;

        let mut transport_index = 1usize;
        for file in &self.files {
            let output_path = join_portable_path(&database, &file.path)?;
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    snapshot_io("create materialized snapshot file parent", parent, error)
                })?;
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output_path)
                .map_err(|error| {
                    snapshot_io("create materialized snapshot file", &output_path, error)
                })?;
            for _ in &file.chunks {
                let chunk_path = &chunk_paths[transport_index];
                let chunk = fs::read(chunk_path).map_err(|error| {
                    snapshot_io("read received state-sync data chunk", chunk_path, error)
                })?;
                let index = u32::try_from(transport_index)
                    .map_err(|_| snapshot_error("state-sync transport index does not fit u32"))?;
                self.validate_state_sync_chunk(index, &chunk)?;
                output.write_all(&chunk).map_err(|error| {
                    snapshot_io("write materialized snapshot chunk", &output_path, error)
                })?;
                transport_index += 1;
            }
            output.sync_all().map_err(|error| {
                snapshot_io("sync materialized snapshot file", &output_path, error)
            })?;
        }
        if transport_index != chunk_paths.len() {
            return Err(snapshot_error("state-sync transport has unused chunks"));
        }
        if StateSnapshotManifest::read_from(staging.path())? != *self {
            return Err(snapshot_error(
                "materialized snapshot manifest changed during publication",
            ));
        }
        publish_directory(staging.path(), destination)?;
        staging.disarm();
        Ok(())
    }

    fn state_sync_data_chunk(&self, index: u32) -> Result<(&SnapshotFile, usize, &Hash32, usize)> {
        let mut remaining = usize::try_from(index - 1)
            .map_err(|_| snapshot_error("state-sync chunk index does not fit usize"))?;
        for file in &self.files {
            if remaining < file.chunks.len() {
                let offset = u64::try_from(remaining)
                    .map_err(|_| snapshot_error("state-sync chunk offset does not fit u64"))?
                    .checked_mul(STATE_SNAPSHOT_CHUNK_BYTES as u64)
                    .ok_or_else(|| snapshot_error("state-sync chunk offset overflow"))?;
                let length = usize::try_from(
                    file.length
                        .checked_sub(offset)
                        .ok_or_else(|| snapshot_error("state-sync file chunk offset is invalid"))?
                        .min(STATE_SNAPSHOT_CHUNK_BYTES as u64),
                )
                .map_err(|_| snapshot_error("state-sync chunk length does not fit usize"))?;
                return Ok((file, remaining, &file.chunks[remaining], length));
            }
            remaining -= file.chunks.len();
        }
        Err(snapshot_error("state-sync chunk index is out of range"))
    }
}

impl PersistentState {
    /// Export the latest committed state as a validated, chunk-hashed snapshot directory.
    pub async fn export_snapshot(&self, destination: PathBuf) -> Result<StateSnapshotManifest> {
        let before = self.summary().await?;
        ensure_destination_outside_source(&self.database_path, &destination)?;
        let mut staging = StagingDirectory::create_for(&destination, "export")?;
        let checkpoint_path = staging.path().join(DATABASE_DIRECTORY);

        self.storage
            .create_checkpoint(checkpoint_path.clone())
            .await?;

        // Opening the checkpoint catches a checkpoint taken during the narrow
        // durable-write/cache-publication window and validates every BIT invariant.
        let checkpoint =
            PersistentState::open(checkpoint_path.clone(), self.config.clone()).await?;
        let checkpoint_summary = checkpoint.summary().await?;
        checkpoint.close().await;
        let after = self.summary().await?;
        if checkpoint_summary != before || after != before {
            return Err(snapshot_error(
                "state changed while the checkpoint was being exported",
            ));
        }

        let chain_context = self.config.chain_context;
        let staging_path = staging.path().to_path_buf();
        let manifest = tokio::task::spawn_blocking(move || {
            build_and_write_manifest(&staging_path, &checkpoint_summary, chain_context)
        })
        .await
        .map_err(|error| snapshot_error(format!("snapshot export task failed: {error}")))??;

        publish_directory(staging.path(), &destination)?;
        staging.disarm();
        Ok(manifest)
    }

    /// Restore a snapshot through an isolated directory and return the opened state.
    /// The destination must not already exist and is only published after full validation.
    pub async fn import_snapshot(
        snapshot_directory: PathBuf,
        destination: PathBuf,
        config: GenesisConfig,
    ) -> Result<Self> {
        config.validate()?;
        ensure_destination_absent(&destination)?;
        ensure_destination_outside_source(&snapshot_directory, &destination)?;

        let manifest_source = snapshot_directory.clone();
        let manifest =
            tokio::task::spawn_blocking(move || StateSnapshotManifest::read_from(&manifest_source))
                .await
                .map_err(|error| {
                    snapshot_error(format!("snapshot manifest task failed: {error}"))
                })??;
        if manifest.chain_context != config.chain_context {
            return Err(snapshot_error(
                "snapshot chain context differs from the requested configuration",
            ));
        }

        let mut staging = StagingDirectory::create_for(&destination, "import")?;
        let staged_database = staging.path().join(DATABASE_DIRECTORY);
        let source = snapshot_directory.clone();
        let manifest_for_copy = manifest.clone();
        let staged_for_copy = staged_database.clone();
        tokio::task::spawn_blocking(move || {
            verify_and_copy_database(&source, &staged_for_copy, &manifest_for_copy)
        })
        .await
        .map_err(|error| snapshot_error(format!("snapshot copy task failed: {error}")))??;

        let isolated = PersistentState::open(staged_database.clone(), config.clone()).await?;
        let restored_summary = isolated.summary().await?;
        let summary_result = validate_restored_summary(&restored_summary, &manifest);
        isolated.close().await;
        summary_result?;

        ensure_destination_absent(&destination)?;
        publish_directory(&staged_database, &destination)?;
        staging.disarm();
        let _ = fs::remove_dir(staging.path());

        let restored = PersistentState::open(destination, config).await?;
        validate_restored_summary(&restored.summary().await?, &manifest)?;
        Ok(restored)
    }
}

fn build_and_write_manifest(
    snapshot_directory: &Path,
    summary: &StateSummary,
    chain_context: Hash32,
) -> Result<StateSnapshotManifest> {
    let database = snapshot_directory.join(DATABASE_DIRECTORY);
    let paths = collect_database_files(&database)?;
    if paths.len() > MAX_SNAPSHOT_FILES {
        return Err(snapshot_error("snapshot contains too many database files"));
    }

    let mut files = Vec::with_capacity(paths.len());
    let mut total_bytes = 0u64;
    let mut total_chunks = 0u64;
    for path in paths {
        let relative = portable_relative_path(&database, &path)?;
        let length = file_length(&path)?;
        total_bytes = total_bytes
            .checked_add(length)
            .ok_or_else(|| snapshot_error("snapshot byte count overflow"))?;
        if total_bytes > MAX_SNAPSHOT_BYTES {
            return Err(snapshot_error("snapshot exceeds the 16 TiB limit"));
        }
        let chunks = hash_file_chunks(&path, length)?;
        total_chunks = total_chunks
            .checked_add(
                u64::try_from(chunks.len())
                    .map_err(|_| snapshot_error("snapshot chunk count does not fit in u64"))?,
            )
            .ok_or_else(|| snapshot_error("snapshot chunk count overflow"))?;
        files.push(SnapshotFile {
            path: relative,
            length,
            chunks,
        });
    }

    let file_count = u32::try_from(files.len())
        .map_err(|_| snapshot_error("snapshot file count does not fit in u32"))?;
    let mut manifest = StateSnapshotManifest {
        format_version: SNAPSHOT_FORMAT_VERSION,
        storage_schema_version: summary.storage_schema_version,
        state_height: summary.state_height,
        block_time_seconds: summary.block_time_seconds,
        storage_version: summary.storage_version,
        app_hash: summary.app_hash,
        shielded_tree_root: summary.shielded_tree_root,
        chain_context,
        monetary_policy_hash: summary.supply.monetary_policy_hash,
        file_count,
        total_bytes,
        total_chunks,
        snapshot_id: [0; 32],
        files,
    };
    let bytes = encode_manifest(&manifest)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MANIFEST_BYTES {
        return Err(snapshot_error("manifest exceeds the 64 MiB limit"));
    }
    manifest.snapshot_id = manifest_id(&bytes);

    write_new_synced(&snapshot_directory.join(MANIFEST_NAME), &bytes)?;
    let checksum = format!("{}\n", hex::encode(manifest.snapshot_id));
    write_new_synced(
        &snapshot_directory.join(MANIFEST_HASH_NAME),
        checksum.as_bytes(),
    )?;
    Ok(manifest)
}

fn verify_and_copy_database(
    snapshot_directory: &Path,
    destination_database: &Path,
    manifest: &StateSnapshotManifest,
) -> Result<()> {
    validate_snapshot_root(snapshot_directory)?;
    let source_database = snapshot_directory.join(DATABASE_DIRECTORY);
    let actual_paths = collect_database_files(&source_database)?;
    let actual_names = actual_paths
        .iter()
        .map(|path| portable_relative_path(&source_database, path))
        .collect::<Result<Vec<_>>>()?;
    let expected_names = manifest
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    if actual_names != expected_names {
        return Err(snapshot_error(
            "snapshot database file set differs from the manifest",
        ));
    }

    fs::create_dir(destination_database).map_err(|error| {
        snapshot_io(
            "create isolated snapshot database",
            destination_database,
            error,
        )
    })?;
    for file in &manifest.files {
        let source = join_portable_path(&source_database, &file.path)?;
        let destination = join_portable_path(destination_database, &file.path)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| snapshot_io("create snapshot file parent", parent, error))?;
        }
        copy_verified_file(&source, &destination, file)?;
    }
    Ok(())
}

fn copy_verified_file(source: &Path, destination: &Path, entry: &SnapshotFile) -> Result<()> {
    if file_length(source)? != entry.length {
        return Err(snapshot_error(format!(
            "snapshot file length differs for {}",
            entry.path
        )));
    }
    let mut input = File::open(source)
        .map_err(|error| snapshot_io("open snapshot source file", source, error))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| snapshot_io("create isolated snapshot file", destination, error))?;
    let mut buffer = vec![0u8; STATE_SNAPSHOT_CHUNK_BYTES];
    let mut remaining = entry.length;
    for expected_hash in &entry.chunks {
        let chunk_length = usize::try_from(remaining.min(STATE_SNAPSHOT_CHUNK_BYTES as u64))
            .expect("chunk length always fits usize");
        input
            .read_exact(&mut buffer[..chunk_length])
            .map_err(|error| snapshot_io("read snapshot chunk", source, error))?;
        let actual_hash: Hash32 = Sha256::digest(&buffer[..chunk_length]).into();
        if &actual_hash != expected_hash {
            return Err(snapshot_error(format!(
                "snapshot chunk hash differs for {}",
                entry.path
            )));
        }
        output
            .write_all(&buffer[..chunk_length])
            .map_err(|error| snapshot_io("write isolated snapshot chunk", destination, error))?;
        remaining -= chunk_length as u64;
    }
    if remaining != 0 {
        return Err(snapshot_error(format!(
            "snapshot chunk list is incomplete for {}",
            entry.path
        )));
    }
    let mut trailing = [0u8; 1];
    if input
        .read(&mut trailing)
        .map_err(|error| snapshot_io("check snapshot file boundary", source, error))?
        != 0
    {
        return Err(snapshot_error(format!(
            "snapshot file grew while importing {}",
            entry.path
        )));
    }
    output
        .sync_all()
        .map_err(|error| snapshot_io("sync isolated snapshot file", destination, error))?;
    Ok(())
}

fn hash_file_chunks(path: &Path, length: u64) -> Result<Vec<Hash32>> {
    let expected_chunks = expected_chunk_count(length)?;
    let mut chunks = Vec::with_capacity(expected_chunks);
    let mut file =
        File::open(path).map_err(|error| snapshot_io("open checkpoint file", path, error))?;
    let mut buffer = vec![0u8; STATE_SNAPSHOT_CHUNK_BYTES];
    let mut remaining = length;
    while remaining > 0 {
        let chunk_length = usize::try_from(remaining.min(STATE_SNAPSHOT_CHUNK_BYTES as u64))
            .expect("chunk length always fits usize");
        file.read_exact(&mut buffer[..chunk_length])
            .map_err(|error| snapshot_io("read checkpoint chunk", path, error))?;
        chunks.push(Sha256::digest(&buffer[..chunk_length]).into());
        remaining -= chunk_length as u64;
    }
    let mut trailing = [0u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| snapshot_io("check checkpoint file boundary", path, error))?
        != 0
    {
        return Err(snapshot_error(format!(
            "checkpoint file grew while exporting {}",
            path.display()
        )));
    }
    Ok(chunks)
}

fn collect_database_files(database: &Path) -> Result<Vec<PathBuf>> {
    let metadata = fs::symlink_metadata(database)
        .map_err(|error| snapshot_io("inspect snapshot database", database, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(snapshot_error("snapshot database is not a real directory"));
    }
    let mut files = Vec::new();
    let mut entries_seen = 0usize;
    collect_database_files_inner(database, &mut files, &mut entries_seen, 0)?;
    files.sort_by(|left, right| {
        portable_relative_path(database, left)
            .expect("collected path was already validated")
            .cmp(
                &portable_relative_path(database, right)
                    .expect("collected path was already validated"),
            )
    });
    if files.is_empty() {
        return Err(snapshot_error("snapshot database contains no files"));
    }
    Ok(files)
}

fn collect_database_files_inner(
    directory: &Path,
    files: &mut Vec<PathBuf>,
    entries_seen: &mut usize,
    depth: usize,
) -> Result<()> {
    if depth > MAX_SNAPSHOT_DEPTH {
        return Err(snapshot_error("snapshot database directory is too deep"));
    }
    let entries = fs::read_dir(directory)
        .map_err(|error| snapshot_io("read snapshot database directory", directory, error))?;
    for entry in entries {
        *entries_seen = entries_seen
            .checked_add(1)
            .ok_or_else(|| snapshot_error("snapshot entry count overflow"))?;
        if *entries_seen > MAX_SNAPSHOT_ENTRIES {
            return Err(snapshot_error("snapshot contains too many entries"));
        }
        let entry = entry.map_err(|error| {
            snapshot_error(format!(
                "read snapshot database entry in {}: {error}",
                directory.display()
            ))
        })?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| snapshot_io("inspect snapshot database entry", &path, error))?;
        if file_type.is_symlink() {
            return Err(snapshot_error(format!(
                "snapshot database contains a symlink: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            collect_database_files_inner(&path, files, entries_seen, depth + 1)?;
        } else if file_type.is_file() {
            files.push(path);
            if files.len() > MAX_SNAPSHOT_FILES {
                return Err(snapshot_error("snapshot contains too many database files"));
            }
        } else {
            return Err(snapshot_error(format!(
                "snapshot database contains an unsupported entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn encode_manifest(manifest: &StateSnapshotManifest) -> Result<Vec<u8>> {
    if manifest.format_version != SNAPSHOT_FORMAT_VERSION
        || manifest.storage_schema_version != STORAGE_SCHEMA_VERSION
        || usize::try_from(manifest.file_count).ok() != Some(manifest.files.len())
    {
        return Err(snapshot_error(
            "manifest metadata is internally inconsistent",
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&SNAPSHOT_MAGIC);
    output.extend_from_slice(&(STATE_SNAPSHOT_CHUNK_BYTES as u32).to_be_bytes());
    output.extend_from_slice(&manifest.storage_schema_version.to_be_bytes());
    output.extend_from_slice(&manifest.state_height.to_be_bytes());
    output.extend_from_slice(&manifest.block_time_seconds.to_be_bytes());
    output.extend_from_slice(&manifest.storage_version.to_be_bytes());
    output.extend_from_slice(&manifest.app_hash);
    output.extend_from_slice(&manifest.shielded_tree_root);
    output.extend_from_slice(&manifest.chain_context);
    output.extend_from_slice(&manifest.monetary_policy_hash);
    output.extend_from_slice(&manifest.total_bytes.to_be_bytes());
    output.extend_from_slice(&manifest.file_count.to_be_bytes());
    for file in &manifest.files {
        validate_portable_path(&file.path)?;
        let path = file.path.as_bytes();
        let path_length =
            u16::try_from(path.len()).map_err(|_| snapshot_error("snapshot path is too long"))?;
        let chunk_count = u32::try_from(file.chunks.len())
            .map_err(|_| snapshot_error("snapshot file has too many chunks"))?;
        if file.chunks.len() != expected_chunk_count(file.length)? {
            return Err(snapshot_error("snapshot file chunk count is inconsistent"));
        }
        output.extend_from_slice(&path_length.to_be_bytes());
        output.extend_from_slice(path);
        output.extend_from_slice(&file.length.to_be_bytes());
        output.extend_from_slice(&chunk_count.to_be_bytes());
        for chunk in &file.chunks {
            output.extend_from_slice(chunk);
        }
    }
    Ok(output)
}

fn decode_manifest(bytes: &[u8]) -> Result<StateSnapshotManifest> {
    let mut decoder = ManifestDecoder::new(bytes);
    if decoder.take_array::<16>()? != SNAPSHOT_MAGIC {
        return Err(snapshot_error("snapshot manifest magic differs"));
    }
    if decoder.take_u32()? != STATE_SNAPSHOT_CHUNK_BYTES as u32 {
        return Err(snapshot_error("snapshot chunk size is unsupported"));
    }
    let storage_schema_version = decoder.take_u32()?;
    if storage_schema_version != STORAGE_SCHEMA_VERSION {
        return Err(snapshot_error(format!(
            "snapshot schema {storage_schema_version} differs from supported schema {STORAGE_SCHEMA_VERSION}"
        )));
    }
    let state_height = decoder.take_u64()?;
    let block_time_seconds = decoder.take_u64()?;
    let storage_version = decoder.take_u64()?;
    let app_hash = decoder.take_array::<32>()?;
    let shielded_tree_root = decoder.take_array::<32>()?;
    let chain_context = decoder.take_array::<32>()?;
    let monetary_policy_hash = decoder.take_array::<32>()?;
    let total_bytes = decoder.take_u64()?;
    if total_bytes > MAX_SNAPSHOT_BYTES {
        return Err(snapshot_error("snapshot exceeds the 16 TiB limit"));
    }
    let file_count = decoder.take_u32()?;
    let file_count_usize = usize::try_from(file_count)
        .map_err(|_| snapshot_error("snapshot file count does not fit usize"))?;
    if file_count_usize == 0 || file_count_usize > MAX_SNAPSHOT_FILES {
        return Err(snapshot_error("snapshot file count is invalid"));
    }

    let mut files = Vec::with_capacity(file_count_usize);
    let mut calculated_bytes = 0u64;
    let mut total_chunks = 0u64;
    let mut previous_path: Option<String> = None;
    for _ in 0..file_count_usize {
        let path_length = usize::from(decoder.take_u16()?);
        if path_length == 0 {
            return Err(snapshot_error("snapshot file path is empty"));
        }
        let path = String::from_utf8(decoder.take(path_length)?.to_vec())
            .map_err(|_| snapshot_error("snapshot file path is not UTF-8"))?;
        validate_portable_path(&path)?;
        if previous_path
            .as_ref()
            .is_some_and(|previous| previous >= &path)
        {
            return Err(snapshot_error(
                "snapshot file paths are duplicated or not sorted",
            ));
        }
        previous_path = Some(path.clone());
        let length = decoder.take_u64()?;
        calculated_bytes = calculated_bytes
            .checked_add(length)
            .ok_or_else(|| snapshot_error("snapshot byte count overflow"))?;
        let chunk_count = decoder.take_u32()?;
        let chunk_count_usize = usize::try_from(chunk_count)
            .map_err(|_| snapshot_error("snapshot chunk count does not fit usize"))?;
        if chunk_count_usize != expected_chunk_count(length)? {
            return Err(snapshot_error(format!(
                "snapshot chunk count differs for {path}"
            )));
        }
        let chunk_bytes = chunk_count_usize
            .checked_mul(32)
            .ok_or_else(|| snapshot_error("snapshot chunk hash bytes overflow"))?;
        if decoder.remaining() < chunk_bytes {
            return Err(snapshot_error("snapshot chunk hash list is truncated"));
        }
        let mut chunks = Vec::with_capacity(chunk_count_usize);
        for _ in 0..chunk_count_usize {
            chunks.push(decoder.take_array::<32>()?);
        }
        total_chunks = total_chunks
            .checked_add(u64::from(chunk_count))
            .ok_or_else(|| snapshot_error("snapshot chunk count overflow"))?;
        files.push(SnapshotFile {
            path,
            length,
            chunks,
        });
    }
    if decoder.remaining() != 0 {
        return Err(snapshot_error("snapshot manifest has trailing bytes"));
    }
    if calculated_bytes != total_bytes {
        return Err(snapshot_error("snapshot total byte count differs"));
    }

    let manifest = StateSnapshotManifest {
        format_version: SNAPSHOT_FORMAT_VERSION,
        storage_schema_version,
        state_height,
        block_time_seconds,
        storage_version,
        app_hash,
        shielded_tree_root,
        chain_context,
        monetary_policy_hash,
        file_count,
        total_bytes,
        total_chunks,
        snapshot_id: manifest_id(bytes),
        files,
    };
    if encode_manifest(&manifest)? != bytes {
        return Err(snapshot_error("snapshot manifest is not canonical"));
    }
    Ok(manifest)
}

fn manifest_id(bytes: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(b"BIT-STATE-SNAPSHOT-ID-V1");
    hasher.update(bytes);
    hasher.finalize().into()
}

fn expected_chunk_count(length: u64) -> Result<usize> {
    let count = if length == 0 {
        0
    } else {
        (length - 1) / STATE_SNAPSHOT_CHUNK_BYTES as u64 + 1
    };
    usize::try_from(count).map_err(|_| snapshot_error("snapshot chunk count does not fit usize"))
}

fn validate_restored_summary(
    summary: &StateSummary,
    manifest: &StateSnapshotManifest,
) -> Result<()> {
    if summary.storage_schema_version != manifest.storage_schema_version
        || summary.state_height != manifest.state_height
        || summary.block_time_seconds != manifest.block_time_seconds
        || summary.storage_version != manifest.storage_version
        || summary.app_hash != manifest.app_hash
        || summary.shielded_tree_root != manifest.shielded_tree_root
        || summary.supply.monetary_policy_hash != manifest.monetary_policy_hash
    {
        return Err(snapshot_error(
            "restored state summary differs from the snapshot manifest",
        ));
    }
    Ok(())
}

fn validate_snapshot_root(snapshot_directory: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(snapshot_directory)
        .map_err(|error| snapshot_io("inspect snapshot directory", snapshot_directory, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(snapshot_error("snapshot path is not a real directory"));
    }
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(snapshot_directory)
        .map_err(|error| snapshot_io("read snapshot directory", snapshot_directory, error))?
    {
        let entry = entry.map_err(|error| {
            snapshot_error(format!(
                "read snapshot directory entry in {}: {error}",
                snapshot_directory.display()
            ))
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| snapshot_error("snapshot root entry is not UTF-8"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| snapshot_io("inspect snapshot root entry", &entry.path(), error))?;
        let valid = match name.as_str() {
            DATABASE_DIRECTORY => file_type.is_dir() && !file_type.is_symlink(),
            MANIFEST_NAME | MANIFEST_HASH_NAME => file_type.is_file() && !file_type.is_symlink(),
            _ => false,
        };
        if !valid || !names.insert(name) {
            return Err(snapshot_error("snapshot root contains an unexpected entry"));
        }
    }
    let expected = [DATABASE_DIRECTORY, MANIFEST_HASH_NAME, MANIFEST_NAME]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if names != expected {
        return Err(snapshot_error("snapshot root entries are incomplete"));
    }
    Ok(())
}

fn portable_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| snapshot_error("snapshot file is outside the database directory"))?;
    let mut segments = Vec::new();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(snapshot_error("snapshot file path is not relative"));
        };
        let segment = segment
            .to_str()
            .ok_or_else(|| snapshot_error("snapshot file path is not UTF-8"))?;
        segments.push(segment);
    }
    let portable = segments.join("/");
    validate_portable_path(&portable)?;
    Ok(portable)
}

fn validate_portable_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.'))
    {
        return Err(snapshot_error(format!(
            "snapshot file path is unsafe or non-portable: {path}"
        )));
    }
    Ok(())
}

fn join_portable_path(root: &Path, path: &str) -> Result<PathBuf> {
    validate_portable_path(path)?;
    let mut joined = root.to_path_buf();
    for segment in path.split('/') {
        joined.push(segment);
    }
    Ok(joined)
}

fn file_length(path: &Path) -> Result<u64> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| snapshot_io("inspect snapshot file", path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(snapshot_error(format!(
            "snapshot entry is not a real file: {}",
            path.display()
        )));
    }
    Ok(metadata.len())
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| snapshot_io("create snapshot metadata file", path, error))?;
    file.write_all(bytes)
        .map_err(|error| snapshot_io("write snapshot metadata file", path, error))?;
    file.sync_all()
        .map_err(|error| snapshot_io("sync snapshot metadata file", path, error))?;
    Ok(())
}

fn ensure_destination_absent(destination: &Path) -> Result<()> {
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(snapshot_io(
            "inspect snapshot destination",
            destination,
            error,
        )),
        Ok(_) => Err(snapshot_error(format!(
            "snapshot destination already exists: {}",
            destination.display()
        ))),
    }
}

fn ensure_destination_outside_source(source: &Path, destination: &Path) -> Result<()> {
    let source = fs::canonicalize(source)
        .map_err(|error| snapshot_io("canonicalize snapshot source", source, error))?;
    let parent = snapshot_parent(destination);
    fs::create_dir_all(parent)
        .map_err(|error| snapshot_io("create snapshot parent", parent, error))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| snapshot_io("canonicalize snapshot destination parent", parent, error))?;
    if parent.starts_with(source) {
        return Err(snapshot_error(
            "snapshot destination must be outside the source directory",
        ));
    }
    Ok(())
}

fn publish_directory(source: &Path, destination: &Path) -> Result<()> {
    ensure_destination_absent(destination)?;
    fs::rename(source, destination)
        .map_err(|error| snapshot_io("publish snapshot directory", destination, error))
}

fn snapshot_parent(destination: &Path) -> &Path {
    destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

struct StagingDirectory {
    path: PathBuf,
    armed: bool,
}

impl StagingDirectory {
    fn create_for(destination: &Path, operation: &str) -> Result<Self> {
        ensure_destination_absent(destination)?;
        let parent = snapshot_parent(destination);
        fs::create_dir_all(parent)
            .map_err(|error| snapshot_io("create snapshot parent", parent, error))?;
        for _ in 0..100 {
            let nonce = STAGING_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                ".bit-state-snapshot-{operation}-{}-{nonce}.tmp",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path, armed: true }),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(snapshot_io(
                        "create snapshot staging directory",
                        &path,
                        error,
                    ));
                }
            }
        }
        Err(snapshot_error(
            "could not allocate a unique snapshot staging directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

struct ManifestDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ManifestDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| snapshot_error("snapshot manifest offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| snapshot_error("snapshot manifest is truncated"))?;
        self.offset = end;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self
            .take(N)?
            .try_into()
            .expect("manifest decoder returned the requested length"))
    }

    fn take_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn take_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }
}

fn snapshot_error(message: impl Into<String>) -> Error {
    Error::Snapshot(message.into())
}

fn snapshot_io(operation: &str, path: &Path, error: std::io::Error) -> Error {
    snapshot_error(format!("{operation} {}: {error}", path.display()))
}
