use bit_app::abci::{AbciApplication, AbciConfig};
use bit_genesis::{verify_bundle, GenesisInitChain};
use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs, io,
    net::ToSocketAddrs,
    path::{Component, Path, PathBuf},
    process::ExitCode,
};
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

const DEFAULT_READ_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const MAX_READ_BUFFER_BYTES: usize = 64 * 1024 * 1024;
const USAGE: &str = "usage: bit-node start --bundle BUNDLE_DIR --state-dir STATE_DIR --listen LOOPBACK:PORT [--derived-signatures FILE] [--read-buffer-bytes BYTES]";

type NodeResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Eq, PartialEq)]
struct StartOptions {
    bundle: PathBuf,
    derived_signatures: PathBuf,
    state_dir: PathBuf,
    listen: String,
    read_buffer_bytes: usize,
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bit-node: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<OsString>) -> NodeResult<()> {
    let options = parse_start_options(&args)?;
    require_loopback_listen(&options.listen)?;
    let bundle = resolve_path(&options.bundle)?;
    let state_dir = normalized_absolute(&options.state_dir)?;
    let state_safety_path = resolve_path(&state_dir)?;
    require_disjoint(&bundle, &state_safety_path)?;

    let runtime = tokio::runtime::Runtime::new()?;
    let verified = runtime.block_on(verify_bundle(&bundle, &options.derived_signatures))?;
    drop(runtime);

    fs::create_dir_all(&state_dir)?;
    let canonical_state = fs::canonicalize(&state_dir)?;
    require_disjoint(&bundle, &canonical_state)?;
    let config = abci_config(&verified.init_chain)?;
    let app = AbciApplication::open(state_dir, verified.genesis_config, config)?;
    eprintln!(
        "BIT node verified genesis {} / derived {}; listening {}",
        verified.report.identity_manifest_hash,
        verified.report.derived_manifest_hash,
        options.listen
    );
    app.bind(&options.listen, options.read_buffer_bytes)?
        .listen()?;
    Ok(())
}

fn parse_start_options(args: &[OsString]) -> NodeResult<StartOptions> {
    if args.first().and_then(|value| value.to_str()) != Some("start") || (args.len() - 1) % 2 != 0 {
        return Err(invalid(USAGE));
    }
    let mut options = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        let flag = pair[0]
            .to_str()
            .ok_or_else(|| invalid("option names must be UTF-8"))?;
        if ![
            "--bundle",
            "--derived-signatures",
            "--state-dir",
            "--listen",
            "--read-buffer-bytes",
        ]
        .contains(&flag)
        {
            return Err(invalid(format!("unknown option {flag}; {USAGE}")));
        }
        if pair[1].is_empty() || pair[1].to_string_lossy().starts_with("--") {
            return Err(invalid(format!("missing value for {flag}")));
        }
        if options.insert(flag, pair[1].clone()).is_some() {
            return Err(invalid(format!("duplicate option {flag}")));
        }
    }
    let bundle = required_path(&options, "--bundle")?;
    let state_dir = required_path(&options, "--state-dir")?;
    let listen = required_utf8(&options, "--listen")?;
    let derived_signatures = options
        .get("--derived-signatures")
        .map(PathBuf::from)
        .unwrap_or_else(|| bundle.join("derived-signatures.cbor"));
    let read_buffer_bytes = match options.get("--read-buffer-bytes") {
        Some(value) => value
            .to_str()
            .ok_or_else(|| invalid("--read-buffer-bytes must be UTF-8"))?
            .parse::<usize>()
            .map_err(|_| invalid("--read-buffer-bytes must be a decimal integer"))?,
        None => DEFAULT_READ_BUFFER_BYTES,
    };
    if read_buffer_bytes == 0 || read_buffer_bytes > MAX_READ_BUFFER_BYTES {
        return Err(invalid(
            "--read-buffer-bytes must be between 1 and 67108864",
        ));
    }
    Ok(StartOptions {
        bundle,
        derived_signatures,
        state_dir,
        listen,
        read_buffer_bytes,
    })
}

fn required_path(options: &BTreeMap<&str, OsString>, flag: &str) -> NodeResult<PathBuf> {
    options
        .get(flag)
        .map(PathBuf::from)
        .ok_or_else(|| invalid(format!("missing {flag}; {USAGE}")))
}

fn required_utf8(options: &BTreeMap<&str, OsString>, flag: &str) -> NodeResult<String> {
    options
        .get(flag)
        .and_then(|value| value.to_str())
        .map(str::to_owned)
        .ok_or_else(|| invalid(format!("missing or non-UTF-8 {flag}; {USAGE}")))
}

fn invalid(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

fn resolve_path(path: &Path) -> io::Result<PathBuf> {
    let normalized = normalized_absolute(path)?;
    if normalized.exists() {
        return fs::canonicalize(normalized);
    }
    let mut ancestor = normalized.as_path();
    let mut suffix = Vec::new();
    while !ancestor.exists() {
        let name = ancestor.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "path has no existing ancestor")
        })?;
        suffix.push(name.to_os_string());
        ancestor = ancestor.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "path has no existing ancestor")
        })?;
    }
    let mut resolved = fs::canonicalize(ancestor)?;
    for component in suffix.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn normalized_absolute(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    Ok(normalized)
}

fn require_disjoint(bundle: &Path, state_dir: &Path) -> NodeResult<()> {
    if bundle == state_dir || bundle.starts_with(state_dir) || state_dir.starts_with(bundle) {
        return Err(invalid(
            "--state-dir and --bundle must be separate, non-overlapping directories",
        ));
    }
    Ok(())
}

fn require_loopback_listen(listen: &str) -> NodeResult<()> {
    let addresses = listen
        .to_socket_addrs()
        .map_err(|error| invalid(format!("could not resolve --listen: {error}")))?
        .collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|address| !address.ip().is_loopback()) {
        return Err(invalid("--listen must resolve only to loopback addresses"));
    }
    Ok(())
}

fn abci_config(init: &GenesisInitChain) -> NodeResult<AbciConfig> {
    let validators = init
        .validators
        .iter()
        .map(|validator| {
            Ok(ValidatorUpdate {
                pub_key: Some(PublicKey {
                    sum: Some(public_key::Sum::Ed25519(
                        validator.consensus_pubkey.to_vec(),
                    )),
                }),
                power: i64::try_from(validator.power)
                    .map_err(|_| invalid("genesis validator power exceeds i64"))?,
            })
        })
        .collect::<NodeResult<Vec<_>>>()?;
    Ok(AbciConfig {
        application_name: "bit-node".to_owned(),
        application_version: env!("CARGO_PKG_VERSION").to_owned(),
        expected_init_chain: RequestInitChain {
            time: Some(Timestamp {
                seconds: init.genesis_time_seconds,
                nanos: 0,
            }),
            chain_id: init.chain_id.clone(),
            consensus_params: Some(ConsensusParams {
                block: Some(BlockParams {
                    max_bytes: init.max_block_bytes,
                    max_gas: init.max_gas,
                }),
                evidence: Some(EvidenceParams {
                    max_age_num_blocks: init.evidence_max_age_blocks,
                    max_age_duration: Some(Duration {
                        seconds: init.evidence_max_age_seconds,
                        nanos: 0,
                    }),
                    max_bytes: init.evidence_max_bytes,
                }),
                validator: Some(ValidatorParams {
                    pub_key_types: init.validator_key_types.clone(),
                }),
                version: Some(VersionParams {
                    app: init.protocol_version,
                }),
                abci: Some(AbciParams {
                    vote_extensions_enable_height: init.vote_extensions_enable_height,
                }),
            }),
            validators,
            app_state_bytes: init.app_state_json.clone().into(),
            initial_height: init.initial_height,
        },
        retain_height: 0,
        state_sync: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bit_genesis::GenesisInitValidator;

    #[test]
    fn start_options_are_strict_and_default_to_bundle_signature() {
        let options = parse_start_options(&[
            "start".into(),
            "--bundle".into(),
            "bundle".into(),
            "--state-dir".into(),
            "state".into(),
            "--listen".into(),
            "127.0.0.1:26658".into(),
        ])
        .unwrap();
        assert_eq!(
            options.derived_signatures,
            PathBuf::from("bundle/derived-signatures.cbor")
        );
        assert_eq!(options.read_buffer_bytes, DEFAULT_READ_BUFFER_BYTES);
        assert!(parse_start_options(&[
            "start".into(),
            "--bundle".into(),
            "bundle".into(),
            "--bundle".into(),
            "other".into(),
        ])
        .is_err());
        assert!(require_loopback_listen("127.0.0.1:26658").is_ok());
        assert!(require_loopback_listen("0.0.0.0:26658").is_err());
    }

    #[test]
    fn init_chain_mapping_preserves_verified_values() {
        let init = GenesisInitChain {
            genesis_time_seconds: 1_800_000_000,
            chain_id: "bit-test".to_owned(),
            initial_height: 1,
            max_block_bytes: 1_048_576,
            max_gas: -1,
            evidence_max_age_blocks: 100,
            evidence_max_age_seconds: 200,
            evidence_max_bytes: 65_536,
            validator_key_types: vec!["ed25519".to_owned()],
            protocol_version: 1,
            vote_extensions_enable_height: 0,
            validators: vec![GenesisInitValidator {
                consensus_pubkey: [7; 32],
                power: 4,
            }],
            app_state_json: br#"{"format":"BIT-APP-GENESIS"}"#.to_vec(),
        };
        let config = abci_config(&init).unwrap();
        let request = config.expected_init_chain;
        assert_eq!(request.chain_id, init.chain_id);
        assert_eq!(request.validators[0].power, 4);
        assert_eq!(request.app_state_bytes.as_ref(), init.app_state_json);
        assert_eq!(
            request.consensus_params.unwrap().block.unwrap().max_bytes,
            init.max_block_bytes
        );
    }

    #[test]
    fn bundle_and_state_paths_must_not_overlap() {
        let root = tempfile::tempdir().unwrap();
        let bundle = root.path().join("bundle");
        fs::create_dir(&bundle).unwrap();
        let bundle = resolve_path(&bundle).unwrap();
        let nested = resolve_path(&bundle.join("state")).unwrap();
        assert!(require_disjoint(&bundle, &nested).is_err());
        let sibling = resolve_path(&root.path().join("state")).unwrap();
        assert!(require_disjoint(&bundle, &sibling).is_ok());
    }
}
