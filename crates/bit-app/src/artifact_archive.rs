use crate::{BlockArtifacts, Error, Result};
use bit_state::PersistentState;
use bit_types::{CompactBlock, ExecutionSummary, MAX_BLOCK_ARTIFACT_BYTES};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const ARCHIVE_DIRECTORY: &str = "block-artifacts-v1";
const EXECUTION_FILE: &str = "execution.cbor";
const COMPACT_FILE: &str = "compact.cbor";

pub fn artifact_archive_path(state_path: &Path) -> PathBuf {
    state_path.join(ARCHIVE_DIRECTORY)
}

pub(crate) struct ArtifactArchive {
    pending: PathBuf,
    blocks: PathBuf,
}

pub(crate) struct StagedArtifacts {
    height: u64,
    directory: PathBuf,
}

impl ArtifactArchive {
    pub(crate) fn open(root: PathBuf) -> Result<Self> {
        let archive = Self {
            pending: root.join("pending"),
            blocks: root.join("blocks"),
        };
        create_directory(&archive.pending)?;
        create_directory(&archive.blocks)?;
        Ok(archive)
    }

    pub(crate) async fn recover(&self, state: &PersistentState) -> Result<()> {
        let current_height = state.summary().await?.state_height;
        self.reject_future_published_blocks(current_height)?;

        for entry in read_directory(&self.pending)? {
            let file_type = entry
                .file_type()
                .map_err(|error| io_error("inspect pending artifact", entry.path(), error))?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(Error::ArtifactArchive(
                    "pending artifact entry is not a plain directory".to_owned(),
                ));
            }
            let height = parse_height(&entry.file_name())?;
            let directory = entry.path();
            if height > current_height {
                remove_directory(&directory)?;
                continue;
            }
            let artifacts = load_directory(height, &directory)?;
            self.verify_committed_hashes(state, height, &artifacts)
                .await?;
            self.publish(StagedArtifacts { height, directory })?;
        }

        if current_height > 0 {
            if let Some(artifacts) = self.load(current_height)? {
                self.verify_committed_hashes(state, current_height, &artifacts)
                    .await?;
            }
        }
        Ok(())
    }

    pub(crate) fn stage(&self, artifacts: &BlockArtifacts) -> Result<StagedArtifacts> {
        let height = validate_artifacts(artifacts)?;
        let target = self.block_path(height);
        if target.exists() {
            return Err(Error::ArtifactArchive(format!(
                "artifact block {height} is already published"
            )));
        }
        let directory = self.pending.join(height_name(height));
        if directory.exists() {
            return Err(Error::ArtifactArchive(format!(
                "artifact block {height} already has a pending stage"
            )));
        }
        create_directory(&directory)?;
        let staged = (|| {
            write_new_synced(
                &directory.join(EXECUTION_FILE),
                &artifacts.execution_summary,
            )?;
            write_new_synced(&directory.join(COMPACT_FILE), &artifacts.compact_block)?;
            let stored = load_directory(height, &directory)?;
            if stored != *artifacts {
                return Err(Error::ArtifactArchive(format!(
                    "staged artifact block {height} differs after write"
                )));
            }
            Ok(StagedArtifacts {
                height,
                directory: directory.clone(),
            })
        })();
        if staged.is_err() {
            let _ = fs::remove_dir_all(&directory);
        }
        staged
    }

    pub(crate) fn publish(&self, staged: StagedArtifacts) -> Result<()> {
        let artifacts = load_directory(staged.height, &staged.directory)?;
        let target = self.block_path(staged.height);
        if target.exists() {
            let published = load_directory(staged.height, &target)?;
            if published != artifacts {
                return Err(Error::ArtifactArchive(format!(
                    "published artifact block {} conflicts with pending bytes",
                    staged.height
                )));
            }
            remove_directory(&staged.directory)?;
            return Ok(());
        }
        fs::rename(&staged.directory, &target)
            .map_err(|error| io_error("publish artifact block", target.clone(), error))?;
        load_directory(staged.height, &target)?;
        Ok(())
    }

    pub(crate) fn discard(&self, staged: &StagedArtifacts) -> Result<()> {
        remove_directory(&staged.directory)
    }

    pub(crate) fn load(&self, height: u64) -> Result<Option<BlockArtifacts>> {
        if height == 0 {
            return Ok(None);
        }
        let path = self.block_path(height);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(load_directory(height, &path)?))
    }

    async fn verify_committed_hashes(
        &self,
        state: &PersistentState,
        height: u64,
        artifacts: &BlockArtifacts,
    ) -> Result<()> {
        let execution = committed_hash(state, "execution/block", height).await?;
        let compact = committed_hash(state, "compact/hash", height).await?;
        if execution != artifacts.execution_hash || compact != artifacts.compact_hash {
            return Err(Error::ArtifactArchive(format!(
                "artifact block {height} differs from committed state hashes"
            )));
        }
        Ok(())
    }

    fn reject_future_published_blocks(&self, current_height: u64) -> Result<()> {
        for entry in read_directory(&self.blocks)? {
            let file_type = entry
                .file_type()
                .map_err(|error| io_error("inspect published artifact", entry.path(), error))?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(Error::ArtifactArchive(
                    "published artifact entry is not a plain directory".to_owned(),
                ));
            }
            let height = parse_height(&entry.file_name())?;
            if height > current_height {
                return Err(Error::ArtifactArchive(format!(
                    "published artifact block {height} is ahead of committed state {current_height}"
                )));
            }
        }
        Ok(())
    }

    fn block_path(&self, height: u64) -> PathBuf {
        self.blocks.join(height_name(height))
    }
}

async fn committed_hash(state: &PersistentState, prefix: &str, height: u64) -> Result<[u8; 32]> {
    let key = format!("{prefix}/{height:020}");
    let proof = state.query_latest_with_proof(&key).await?;
    proof.verify().map_err(|error| {
        Error::ArtifactArchive(format!(
            "state proof for artifact block {height} failed: {error}"
        ))
    })?;
    proof
        .value
        .ok_or_else(|| {
            Error::ArtifactArchive(format!(
                "committed artifact hash is missing for block {height}"
            ))
        })?
        .try_into()
        .map_err(|_| {
            Error::ArtifactArchive(format!(
                "committed artifact hash has the wrong length for block {height}"
            ))
        })
}

fn validate_artifacts(artifacts: &BlockArtifacts) -> Result<u64> {
    let execution = ExecutionSummary::decode_canonical(&artifacts.execution_summary)?;
    let compact = CompactBlock::decode_canonical(&artifacts.compact_block)?;
    if execution.hash()? != artifacts.execution_hash || compact.hash()? != artifacts.compact_hash {
        return Err(Error::ArtifactArchive(
            "artifact bytes do not match their domain hashes".to_owned(),
        ));
    }
    if execution.height != compact.height
        || execution.chain_context != compact.chain_context
        || execution.block_time_seconds != compact.block_time_seconds
        || execution.shielded_tree_root != compact.shielded_tree_root
        || execution.events != compact.events
    {
        return Err(Error::ArtifactArchive(
            "execution and compact artifacts describe different blocks".to_owned(),
        ));
    }
    let accepted: Vec<_> = execution
        .transactions
        .iter()
        .filter_map(|transaction| {
            transaction
                .accepted
                .as_ref()
                .map(|accepted| (transaction.index, accepted.tx_id))
        })
        .collect();
    if accepted.len() != compact.transactions.len()
        || accepted
            .iter()
            .zip(&compact.transactions)
            .any(|((index, tx_id), transaction)| {
                *index != transaction.index || *tx_id != transaction.tx_id
            })
    {
        return Err(Error::ArtifactArchive(
            "execution successes differ from compact transactions".to_owned(),
        ));
    }
    Ok(execution.height)
}

fn load_directory(height: u64, directory: &Path) -> Result<BlockArtifacts> {
    let execution_summary = read_bounded(&directory.join(EXECUTION_FILE))?;
    let compact_block = read_bounded(&directory.join(COMPACT_FILE))?;
    let execution = ExecutionSummary::decode_canonical(&execution_summary)?;
    let compact = CompactBlock::decode_canonical(&compact_block)?;
    let artifacts = BlockArtifacts {
        execution_hash: execution.hash()?,
        compact_hash: compact.hash()?,
        execution_summary,
        compact_block,
    };
    if validate_artifacts(&artifacts)? != height {
        return Err(Error::ArtifactArchive(format!(
            "artifact directory height differs from block {height}"
        )));
    }
    Ok(artifacts)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect artifact file", path.to_path_buf(), error))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(Error::ArtifactArchive(
            "artifact payload is not a plain file".to_owned(),
        ));
    }
    if metadata.len() > MAX_BLOCK_ARTIFACT_BYTES as u64 {
        return Err(Error::ArtifactArchive(
            "artifact payload exceeds the protocol size limit".to_owned(),
        ));
    }
    fs::read(path).map_err(|error| io_error("read artifact file", path.to_path_buf(), error))
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error("create artifact file", path.to_path_buf(), error))?;
    file.write_all(bytes)
        .map_err(|error| io_error("write artifact file", path.to_path_buf(), error))?;
    file.sync_all()
        .map_err(|error| io_error("sync artifact file", path.to_path_buf(), error))
}

fn create_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .map_err(|error| io_error("create artifact directory", path.to_path_buf(), error))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect artifact directory", path.to_path_buf(), error))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::ArtifactArchive(
            "artifact path is not a plain directory".to_owned(),
        ));
    }
    Ok(())
}

fn remove_directory(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(
            "remove artifact directory",
            path.to_path_buf(),
            error,
        )),
    }
}

fn read_directory(path: &Path) -> Result<Vec<fs::DirEntry>> {
    fs::read_dir(path)
        .map_err(|error| io_error("read artifact directory", path.to_path_buf(), error))?
        .map(|entry| {
            entry.map_err(|error| io_error("read artifact entry", path.to_path_buf(), error))
        })
        .collect()
}

fn height_name(height: u64) -> String {
    format!("{height:020}")
}

fn parse_height(name: &std::ffi::OsStr) -> Result<u64> {
    let name = name
        .to_str()
        .ok_or_else(|| Error::ArtifactArchive("artifact directory name is not UTF-8".to_owned()))?;
    if name.len() != 20 || !name.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::ArtifactArchive(
            "artifact directory name is not a canonical height".to_owned(),
        ));
    }
    let height: u64 = name
        .parse()
        .map_err(|_| Error::ArtifactArchive("artifact height exceeds u64".to_owned()))?;
    if height == 0 || height_name(height) != name {
        return Err(Error::ArtifactArchive(
            "artifact height must be positive and canonical".to_owned(),
        ));
    }
    Ok(height)
}

fn io_error(operation: &str, path: PathBuf, error: std::io::Error) -> Error {
    Error::ArtifactArchive(format!("{operation} at {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bit_types::{CompactBlock, ExecutionSummary};
    use tempfile::TempDir;

    fn artifacts(height: u64) -> BlockArtifacts {
        let execution = ExecutionSummary {
            chain_context: [1; 32],
            height,
            block_time_seconds: 9,
            shielded_tree_root: [2; 32],
            transactions: Vec::new(),
            events: Vec::new(),
        };
        let compact = CompactBlock {
            chain_context: execution.chain_context,
            height,
            block_time_seconds: execution.block_time_seconds,
            shielded_tree_root: execution.shielded_tree_root,
            transactions: Vec::new(),
            events: Vec::new(),
        };
        BlockArtifacts {
            execution_summary: execution.encode_canonical().unwrap(),
            execution_hash: execution.hash().unwrap(),
            compact_block: compact.encode_canonical().unwrap(),
            compact_hash: compact.hash().unwrap(),
        }
    }

    #[test]
    fn stage_is_hidden_publish_is_immutable_and_reads_are_validated() {
        let root = TempDir::new().unwrap();
        let archive = ArtifactArchive::open(root.path().join("archive")).unwrap();
        let expected = artifacts(7);
        let staged = archive.stage(&expected).unwrap();
        assert!(archive.load(7).unwrap().is_none());
        archive.publish(staged).unwrap();
        assert_eq!(archive.load(7).unwrap(), Some(expected));
        assert!(archive.stage(&artifacts(7)).is_err());

        let compact_path = archive.block_path(7).join(COMPACT_FILE);
        let mut bytes = fs::read(&compact_path).unwrap();
        bytes[0] ^= 1;
        fs::write(compact_path, bytes).unwrap();
        assert!(archive.load(7).is_err());
    }
}
