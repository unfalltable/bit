use bit_genesis::{
    DerivedInputDocument, DerivedSignaturePackage, GenesisDerivedManifest, GenesisIdentityManifest,
    IdentityInputDocument, SignaturePackage, APPROVAL_VERSION, DERIVED_APPROVAL_VERSION,
    DERIVED_VERSION, IDENTITY_VERSION,
};
use bit_types::{genesis_claim_id, position_id, validator_id};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bit: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> DynResult<()> {
    match args.as_slice() {
        [group, command, rest @ ..] if group == "genesis" => match command.as_str() {
            "build" => genesis_build(rest),
            "verify" | "validate" => genesis_verify(rest),
            "inspect" => genesis_inspect(rest),
            "sign" => genesis_sign(rest),
            "build-derived" => genesis_build_derived(rest),
            "verify-derived" => genesis_verify_derived(rest),
            "inspect-derived" => genesis_inspect_derived(rest),
            "sign-derived" => genesis_sign_derived(rest),
            _ => Err(usage().into()),
        },
        [group, command, rest @ ..] if group == "release" && command == "preflight" => {
            release_preflight(rest)
        }
        [command, rest @ ..] if command == "release-preflight" => release_preflight(rest),
        [command] if command == "version" => {
            println!("bit {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err(usage().into()),
    }
}

fn genesis_build(args: &[String]) -> DynResult<()> {
    validate_options(args, &["--input", "--output"])?;
    let input = required_path(args, "--input")?;
    let output = required_path(args, "--output")?;
    reject_same_path(&input, &output)?;
    let manifest = read_identity(&input)?;
    let bytes = manifest.encode_canonical()?;
    write_new(&output, &bytes)?;
    print_manifest_report("built", &manifest, Some(&output), None)?;
    Ok(())
}

fn genesis_verify(args: &[String]) -> DynResult<()> {
    validate_options(args, &["--manifest", "--signatures"])?;
    let manifest_path = required_path(args, "--manifest")?;
    let bytes = fs::read(&manifest_path)?;
    let manifest = GenesisIdentityManifest::decode_canonical(&bytes)?;
    let signatures = optional_path(args, "--signatures")?;
    let approval_count = if let Some(path) = signatures {
        let package = SignaturePackage::decode_canonical(&fs::read(path)?)?;
        Some(package.verify(&manifest)?)
    } else {
        None
    };
    print_manifest_report("verified", &manifest, Some(&manifest_path), approval_count)?;
    Ok(())
}

fn genesis_inspect(args: &[String]) -> DynResult<()> {
    validate_options(args, &["--manifest"])?;
    let manifest_path = required_path(args, "--manifest")?;
    let manifest = GenesisIdentityManifest::decode_canonical(&fs::read(&manifest_path)?)?;
    print_manifest_report("inspected", &manifest, Some(&manifest_path), None)?;
    Ok(())
}

fn genesis_sign(args: &[String]) -> DynResult<()> {
    validate_options(args, &["--manifest", "--key-file", "--output", "--append"])?;
    let manifest_path = required_path(args, "--manifest")?;
    let key_path = required_path(args, "--key-file")?;
    let output = required_path(args, "--output")?;
    reject_same_path(&manifest_path, &output)?;
    reject_same_path(&key_path, &output)?;
    let manifest = GenesisIdentityManifest::decode_canonical(&fs::read(&manifest_path)?)?;
    let mut secret_key = read_secret_key(&key_path)?;
    let mut package = if let Some(path) = optional_path(args, "--append")? {
        SignaturePackage::decode_canonical(&fs::read(path)?)?
    } else {
        SignaturePackage {
            manifest_hash: manifest.hash()?,
            approvals: Vec::new(),
        }
    };
    let signer_result = package.add_signature(&manifest, secret_key);
    secret_key.fill(0);
    let signer = signer_result?;
    write_new(&output, &package.encode_canonical()?)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "signed",
            "signature_package_version": APPROVAL_VERSION,
            "manifest_hash": hex::encode(package.manifest_hash),
            "signer_pubkey": hex::encode(signer),
            "approval_count": package.approvals.len(),
            "threshold": manifest.approval_policy.threshold,
            "threshold_satisfied": package.approvals.len() >= usize::from(manifest.approval_policy.threshold),
            "output": output,
        }))?
    );
    Ok(())
}

fn genesis_build_derived(args: &[String]) -> DynResult<()> {
    validate_options(args, &["--manifest", "--input", "--output"])?;
    let manifest_path = required_path(args, "--manifest")?;
    let input = required_path(args, "--input")?;
    let output = required_path(args, "--output")?;
    reject_same_path(&manifest_path, &output)?;
    reject_same_path(&input, &output)?;
    let identity = read_manifest(&manifest_path)?;
    let derived = read_derived_input(&input, &identity)?;
    write_new(&output, &derived.encode_canonical(&identity)?)?;
    print_derived_report("built", &identity, &derived, Some(&output), None)?;
    Ok(())
}

fn genesis_verify_derived(args: &[String]) -> DynResult<()> {
    validate_options(args, &["--manifest", "--derived", "--signatures"])?;
    let manifest_path = required_path(args, "--manifest")?;
    let derived_path = required_path(args, "--derived")?;
    let identity = read_manifest(&manifest_path)?;
    let derived = read_derived(&derived_path, &identity)?;
    let signatures = optional_path(args, "--signatures")?;
    let approval_count = if let Some(path) = signatures {
        let package = DerivedSignaturePackage::decode_canonical(&fs::read(path)?)?;
        Some(package.verify(&identity, &derived)?)
    } else {
        None
    };
    print_derived_report(
        "verified",
        &identity,
        &derived,
        Some(&derived_path),
        approval_count,
    )?;
    Ok(())
}

fn genesis_inspect_derived(args: &[String]) -> DynResult<()> {
    validate_options(args, &["--manifest", "--derived"])?;
    let manifest_path = required_path(args, "--manifest")?;
    let derived_path = required_path(args, "--derived")?;
    let identity = read_manifest(&manifest_path)?;
    let derived = read_derived(&derived_path, &identity)?;
    print_derived_report("inspected", &identity, &derived, Some(&derived_path), None)?;
    Ok(())
}

fn genesis_sign_derived(args: &[String]) -> DynResult<()> {
    validate_options(
        args,
        &[
            "--manifest",
            "--derived",
            "--key-file",
            "--output",
            "--append",
        ],
    )?;
    let manifest_path = required_path(args, "--manifest")?;
    let derived_path = required_path(args, "--derived")?;
    let key_path = required_path(args, "--key-file")?;
    let output = required_path(args, "--output")?;
    reject_same_path(&manifest_path, &output)?;
    reject_same_path(&derived_path, &output)?;
    reject_same_path(&key_path, &output)?;
    let identity = read_manifest(&manifest_path)?;
    let derived = read_derived(&derived_path, &identity)?;
    let mut secret_key = read_secret_key(&key_path)?;
    let mut package = if let Some(path) = optional_path(args, "--append")? {
        DerivedSignaturePackage::decode_canonical(&fs::read(path)?)?
    } else {
        DerivedSignaturePackage {
            identity_manifest_hash: identity.hash()?,
            derived_manifest_hash: derived.hash(&identity)?,
            approvals: Vec::new(),
        }
    };
    let signer_result = package.add_signature(&identity, &derived, secret_key);
    secret_key.fill(0);
    let signer = signer_result?;
    write_new(&output, &package.encode_canonical()?)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "signed",
            "derived_signature_package_version": DERIVED_APPROVAL_VERSION,
            "identity_manifest_hash": hex::encode(package.identity_manifest_hash),
            "derived_manifest_hash": hex::encode(package.derived_manifest_hash),
            "signer_pubkey": hex::encode(signer),
            "approval_count": package.approvals.len(),
            "threshold": identity.approval_policy.threshold,
            "threshold_satisfied": package.approvals.len() >= usize::from(identity.approval_policy.threshold),
            "output": output,
        }))?
    );
    Ok(())
}

fn release_preflight(args: &[String]) -> DynResult<()> {
    validate_options(
        args,
        &[
            "--input",
            "--manifest",
            "--signatures",
            "--crypto-manifest",
            "--parameters",
            "--derived-manifest",
            "--derived-signatures",
            "--runtime-inputs",
            "--cometbft-genesis",
        ],
    )?;
    let input_path = required_path(args, "--input")?;
    let root: Value = serde_json::from_slice(&fs::read(&input_path)?)?;
    let mut blockers = Vec::new();
    require_json_string(&root, "network_type", Some("mainnet"), &mut blockers);
    require_json_string(&root, "status", None, &mut blockers);
    require_json_hash(&root, "genesis_manifest_hash", &mut blockers);
    require_json_hash(&root, "genesis_signature_package_sha256", &mut blockers);
    require_json_hash(&root, "genesis_derived_manifest_sha256", &mut blockers);
    require_json_hash(
        &root,
        "genesis_derived_signature_package_sha256",
        &mut blockers,
    );
    for field in [
        "checkpoint_publishers",
        "independent_endpoints",
        "external_security_reviews",
        "platform_signing_certificates",
        "release_artifacts",
    ] {
        require_nonempty_array(&root, field, &mut blockers);
    }
    require_hash_object(
        &root,
        "derived_genesis",
        "derived_manifest_hash",
        &mut blockers,
    );
    require_hash_object(
        &root,
        "derived_genesis",
        "runtime_inputs_sha256",
        &mut blockers,
    );
    require_hash_object(
        &root,
        "derived_genesis",
        "shielded_tree_root",
        &mut blockers,
    );
    require_hash_object(&root, "derived_genesis", "app_hash", &mut blockers);
    require_hash_object(
        &root,
        "derived_genesis",
        "genesis_execution_hash",
        &mut blockers,
    );
    require_hash_object(
        &root,
        "derived_genesis",
        "genesis_compact_hash",
        &mut blockers,
    );
    require_hash_object(
        &root,
        "derived_genesis",
        "cometbft_genesis_sha256",
        &mut blockers,
    );
    validate_initial_supply(&root, &mut blockers);
    validate_release_artifacts(&root, input_path.parent(), &mut blockers);

    let identity = match identity_from_value(&root) {
        Ok(identity) => match identity.into_manifest() {
            Ok(manifest) => Some(manifest),
            Err(error) => {
                blockers.push(format!("identity invalid: {error}"));
                None
            }
        },
        Err(error) => {
            blockers.push(format!("identity missing or malformed: {error}"));
            None
        }
    };

    let manifest_path = optional_path(args, "--manifest")?;
    let signatures_path = optional_path(args, "--signatures")?;
    let crypto_path = optional_path(args, "--crypto-manifest")?;
    let parameters_path = optional_path(args, "--parameters")?;
    let derived_manifest_path = optional_path(args, "--derived-manifest")?;
    let derived_signatures_path = optional_path(args, "--derived-signatures")?;
    let runtime_inputs_path = optional_path(args, "--runtime-inputs")?;
    let cometbft_genesis_path = optional_path(args, "--cometbft-genesis")?;
    let mut manifest_hash = None;
    if let Some(identity) = identity.as_ref() {
        let expected = identity.hash()?;
        manifest_hash = Some(hex::encode(expected));
        if root.get("genesis_manifest_hash").and_then(Value::as_str) != manifest_hash.as_deref() {
            blockers.push("genesis_manifest_hash does not match the identity manifest".to_owned());
        }
        validate_future_budget(&root, identity, &mut blockers);
        verify_source_checkout(&identity.source_commit, &mut blockers);
        match manifest_path {
            Some(path) => {
                match fs::read(&path)
                    .map_err(|error| error.to_string())
                    .and_then(|bytes| {
                        GenesisIdentityManifest::decode_canonical(&bytes)
                            .map(|manifest| (bytes, manifest))
                            .map_err(|error| error.to_string())
                    }) {
                    Ok((bytes, decoded)) => {
                        if decoded != *identity || bytes != identity.encode_canonical()? {
                            blockers.push(
                                "manifest bytes differ from signed identity input".to_owned(),
                            );
                        }
                    }
                    Err(error) => blockers.push(format!("manifest unreadable: {error}")),
                }
            }
            None => blockers.push("missing --manifest evidence".to_owned()),
        }
        match signatures_path {
            Some(path) => match fs::read(&path)
                .map_err(|error| error.to_string())
                .and_then(|bytes| {
                    let expected_package_hash = root
                        .get("genesis_signature_package_sha256")
                        .and_then(Value::as_str);
                    let actual_package_hash = hex::encode(Sha256::digest(&bytes));
                    if expected_package_hash != Some(actual_package_hash.as_str()) {
                        return Err("genesis_signature_package_sha256 mismatch".to_owned());
                    }
                    SignaturePackage::decode_canonical(&bytes).map_err(|error| error.to_string())
                })
                .and_then(|package| {
                    package
                        .verify(identity)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }) {
                Ok(()) => {}
                Err(error) => blockers.push(format!("genesis approvals invalid: {error}")),
            },
            None => blockers.push("missing --signatures evidence".to_owned()),
        }
        verify_file_hash(
            crypto_path,
            identity.crypto_manifest_sha256,
            "--crypto-manifest",
            &mut blockers,
        );
        verify_file_hash(
            parameters_path,
            identity.consensus_parameters_sha256,
            "--parameters",
            &mut blockers,
        );
        validate_derived_evidence(
            &root,
            identity,
            derived_manifest_path.as_ref(),
            derived_signatures_path.as_ref(),
            runtime_inputs_path.as_ref(),
            cometbft_genesis_path.as_ref(),
            &mut blockers,
        );
    } else {
        for (path, flag) in [
            (manifest_path, "--manifest"),
            (signatures_path, "--signatures"),
            (crypto_path, "--crypto-manifest"),
            (parameters_path, "--parameters"),
            (derived_manifest_path, "--derived-manifest"),
            (derived_signatures_path, "--derived-signatures"),
            (runtime_inputs_path, "--runtime-inputs"),
            (cometbft_genesis_path, "--cometbft-genesis"),
        ] {
            if path.is_none() {
                blockers.push(format!("missing {flag} evidence"));
            }
        }
    }

    let ready = blockers.is_empty();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": if ready { "PASS" } else { "BLOCKED" },
            "mainnet_ready": ready,
            "input": input_path,
            "manifest_hash": manifest_hash,
            "blockers": blockers,
            "warning": "PASS verifies the supplied machine evidence; independent operational, security, and legal acceptance remains external.",
        }))?
    );
    if ready {
        Ok(())
    } else {
        Err("release preflight is blocked".into())
    }
}

fn read_identity(path: &PathBuf) -> DynResult<GenesisIdentityManifest> {
    let root: Value = serde_json::from_slice(&fs::read(path)?)?;
    Ok(identity_from_value(&root)?.into_manifest()?)
}

fn read_manifest(path: &PathBuf) -> DynResult<GenesisIdentityManifest> {
    Ok(GenesisIdentityManifest::decode_canonical(&fs::read(path)?)?)
}

fn read_derived_input(
    path: &PathBuf,
    identity: &GenesisIdentityManifest,
) -> DynResult<GenesisDerivedManifest> {
    let root: Value = serde_json::from_slice(&fs::read(path)?)?;
    let value = root.get("derived_genesis").unwrap_or(&root).clone();
    let document: DerivedInputDocument = serde_json::from_value(value)?;
    Ok(document.into_manifest(identity)?)
}

fn read_derived(
    path: &PathBuf,
    identity: &GenesisIdentityManifest,
) -> DynResult<GenesisDerivedManifest> {
    Ok(GenesisDerivedManifest::decode_canonical(
        &fs::read(path)?,
        identity,
    )?)
}

fn identity_from_value(root: &Value) -> DynResult<IdentityInputDocument> {
    let value = root.get("identity").unwrap_or(root).clone();
    Ok(serde_json::from_value(value)?)
}

fn print_manifest_report(
    status: &str,
    manifest: &GenesisIdentityManifest,
    path: Option<&PathBuf>,
    approval_count: Option<usize>,
) -> DynResult<()> {
    let totals = manifest.allocation_totals()?;
    let chain = manifest.chain_context()?;
    let claims: Vec<_> = manifest
        .claims
        .iter()
        .map(|claim| {
            let allocation = manifest
                .allocations
                .iter()
                .find(|entry| entry.allocation_id == claim.allocation_id)
                .expect("validated claim allocation exists");
            json!({
                "allocation_id": hex::encode(claim.allocation_id),
                "claim_id": hex::encode(genesis_claim_id(&chain, &claim.claim_pubkey, allocation.amount)),
                "amount_atomic": allocation.amount.to_string(),
            })
        })
        .collect();
    let validators: Vec<_> = manifest
        .validators
        .iter()
        .map(|validator| {
            json!({
                "allocation_id": hex::encode(validator.allocation_id),
                "validator_id": hex::encode(validator_id(&chain, &validator.operator_pubkey)),
                "self_bond_position_id": hex::encode(position_id(&chain, &validator.owner_pubkey)),
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": status,
            "identity_version": IDENTITY_VERSION,
            "path": path,
            "chain_id": manifest.chain_id,
            "genesis_time_unix_seconds": manifest.genesis_time_unix_seconds,
            "manifest_hash": hex::encode(manifest.hash()?),
            "chain_context": hex::encode(chain),
            "monetary_policy_hash": hex::encode(manifest.monetary_policy.hash()?),
            "genesis_supply_atomic": manifest.monetary_policy.genesis_supply.to_string(),
            "future_budget_atomic": manifest.monetary_policy.future_budget().to_string(),
            "allocation_totals_atomic": {
                "genesis_claims": totals.genesis_claims.to_string(),
                "shielded_commitments": totals.shielded_commitments.to_string(),
                "validator_self_bonds": totals.validator_self_bonds.to_string(),
                "fee_reserve": totals.fee_reserve.to_string(),
            },
            "claim_count": manifest.claims.len(),
            "commitment_count": manifest.commitments.len(),
            "validator_count": manifest.validators.len(),
            "derived_claims": claims,
            "derived_validators": validators,
            "approval_threshold": manifest.approval_policy.threshold,
            "authorized_signer_count": manifest.approval_policy.signers.len(),
            "verified_approval_count": approval_count,
        }))?
    );
    Ok(())
}

fn print_derived_report(
    status: &str,
    identity: &GenesisIdentityManifest,
    derived: &GenesisDerivedManifest,
    path: Option<&PathBuf>,
    approval_count: Option<usize>,
) -> DynResult<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": status,
            "derived_version": DERIVED_VERSION,
            "path": path,
            "identity_manifest_hash": hex::encode(derived.identity_manifest_hash),
            "derived_manifest_hash": hex::encode(derived.hash(identity)?),
            "chain_context": hex::encode(derived.chain_context),
            "runtime_inputs_sha256": hex::encode(derived.runtime_inputs_sha256),
            "genesis_commitments_hash": hex::encode(derived.genesis_commitments_hash),
            "genesis_claims_hash": hex::encode(derived.genesis_claims_hash),
            "shielded_tree_root": hex::encode(derived.shielded_tree_root),
            "app_hash": hex::encode(derived.app_hash),
            "genesis_execution_hash": hex::encode(derived.genesis_execution_hash),
            "genesis_compact_hash": hex::encode(derived.genesis_compact_hash),
            "cometbft_genesis_sha256": hex::encode(derived.cometbft_genesis_sha256),
            "claim_count": derived.claims.len(),
            "validator_count": derived.validators.len(),
            "approval_threshold": identity.approval_policy.threshold,
            "verified_approval_count": approval_count,
        }))?
    );
    Ok(())
}

fn required_path(args: &[String], flag: &str) -> DynResult<PathBuf> {
    optional_path(args, flag)?.ok_or_else(|| format!("missing required {flag}").into())
}

fn validate_options(args: &[String], allowed: &[&str]) -> DynResult<()> {
    if args.len() % 2 != 0 {
        return Err("every option must have exactly one value".into());
    }
    for pair in args.chunks_exact(2) {
        if !allowed.contains(&pair[0].as_str()) {
            return Err(format!("unknown option: {}", pair[0]).into());
        }
        if pair[1].starts_with("--") {
            return Err(format!("missing value for {}", pair[0]).into());
        }
    }
    Ok(())
}

fn optional_path(args: &[String], flag: &str) -> DynResult<Option<PathBuf>> {
    let matches: Vec<_> = args
        .windows(2)
        .filter(|pair| pair[0] == flag)
        .map(|pair| PathBuf::from(&pair[1]))
        .collect();
    if matches.len() > 1 {
        return Err(format!("{flag} may only be provided once").into());
    }
    Ok(matches.into_iter().next())
}

fn reject_same_path(left: &PathBuf, right: &PathBuf) -> DynResult<()> {
    if absolute(left)? == absolute(right)? {
        return Err("input and output paths must differ".into());
    }
    Ok(())
}

fn absolute(path: &PathBuf) -> DynResult<PathBuf> {
    Ok(if path.is_absolute() {
        path.clone()
    } else {
        env::current_dir()?.join(path)
    })
}

fn write_new(path: &PathBuf, bytes: &[u8]) -> DynResult<()> {
    if path.exists() {
        return Err(format!("refusing to overwrite existing file: {}", path.display()).into());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn read_secret_key(path: &PathBuf) -> DynResult<[u8; 32]> {
    let mut bytes = fs::read(path)?;
    if bytes.len() == 32 {
        let key = bytes.as_slice().try_into().expect("length checked");
        bytes.fill(0);
        return Ok(key);
    }
    let valid = std::str::from_utf8(&bytes)
        .ok()
        .map(str::trim)
        .is_some_and(|text| {
            text.len() == 64
                && text.bytes().all(|byte| byte.is_ascii_hexdigit())
                && !text.bytes().any(|byte| byte.is_ascii_uppercase())
        });
    if !valid {
        bytes.fill(0);
        return Err("key file must contain 32 raw bytes or 64 lowercase hex characters".into());
    }
    let mut decoded = hex::decode(std::str::from_utf8(&bytes)?.trim())?;
    bytes.fill(0);
    let key = decoded
        .as_slice()
        .try_into()
        .map_err(|_| "secret key must be exactly 32 bytes")?;
    decoded.fill(0);
    Ok(key)
}

fn verify_file_hash(
    path: Option<PathBuf>,
    expected: [u8; 32],
    flag: &str,
    blockers: &mut Vec<String>,
) {
    match path {
        Some(path) => match fs::read(path) {
            Ok(bytes) if <[u8; 32]>::from(Sha256::digest(&bytes)) == expected => {}
            Ok(_) => blockers.push(format!("{flag} SHA-256 mismatch")),
            Err(error) => blockers.push(format!("{flag} unreadable: {error}")),
        },
        None => blockers.push(format!("missing {flag} evidence")),
    }
}

fn require_json_string(
    root: &Value,
    field: &str,
    expected: Option<&str>,
    blockers: &mut Vec<String>,
) {
    match root.get(field).and_then(Value::as_str) {
        Some(value) if !value.is_empty() && expected.is_none_or(|wanted| wanted == value) => {}
        _ => blockers.push(format!("{field} is missing or invalid")),
    }
}

fn require_json_hash(root: &Value, field: &str, blockers: &mut Vec<String>) {
    if !root
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(valid_hash)
    {
        blockers.push(format!("{field} must be a lowercase SHA-256 value"));
    }
}

fn require_nonempty_array(root: &Value, field: &str, blockers: &mut Vec<String>) {
    if root
        .get(field)
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        blockers.push(format!("{field} must contain real evidence"));
    }
}

fn require_hash_object(root: &Value, object: &str, field: &str, blockers: &mut Vec<String>) {
    let valid = root
        .get(object)
        .and_then(|value| value.get(field))
        .and_then(Value::as_str)
        .is_some_and(valid_hash);
    if !valid {
        blockers.push(format!(
            "{object}.{field} must be a lowercase SHA-256 value"
        ));
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !value.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn validate_initial_supply(root: &Value, blockers: &mut Vec<String>) {
    let Some(supply) = root.get("initial_supply_state") else {
        blockers.push("initial_supply_state is missing".to_owned());
        return;
    };
    for (field, expected) in [
        ("cumulative_minted_atomic", "0"),
        ("burned_atomic", "0"),
        ("forfeited_unissued_atomic", "0"),
        ("completed_epochs", "0"),
    ] {
        let valid = match supply.get(field) {
            Some(Value::String(text)) => text == expected,
            Some(Value::Number(number)) => number.to_string() == expected,
            _ => false,
        };
        if !valid {
            blockers.push(format!(
                "initial_supply_state.{field} must equal {expected}"
            ));
        }
    }
    if !supply
        .get("future_budget_atomic")
        .and_then(Value::as_str)
        .is_some_and(valid_decimal_amount)
    {
        blockers
            .push("initial_supply_state.future_budget_atomic must be a decimal string".to_owned());
    }
}

fn valid_decimal_amount(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && value.len() <= 37
}

fn validate_future_budget(
    root: &Value,
    identity: &GenesisIdentityManifest,
    blockers: &mut Vec<String>,
) {
    let expected = identity.monetary_policy.future_budget().to_string();
    if root
        .get("initial_supply_state")
        .and_then(|supply| supply.get("future_budget_atomic"))
        .and_then(Value::as_str)
        != Some(expected.as_str())
    {
        blockers.push("initial_supply_state.future_budget_atomic must equal M-G0".to_owned());
    }
}

fn validate_derived_evidence(
    root: &Value,
    identity: &GenesisIdentityManifest,
    derived_manifest_path: Option<&PathBuf>,
    derived_signatures_path: Option<&PathBuf>,
    runtime_inputs_path: Option<&PathBuf>,
    cometbft_genesis_path: Option<&PathBuf>,
    blockers: &mut Vec<String>,
) {
    let Some(derived_path) = derived_manifest_path else {
        blockers.push("missing --derived-manifest evidence".to_owned());
        if derived_signatures_path.is_none() {
            blockers.push("missing --derived-signatures evidence".to_owned());
        }
        if runtime_inputs_path.is_none() {
            blockers.push("missing --runtime-inputs evidence".to_owned());
        }
        if cometbft_genesis_path.is_none() {
            blockers.push("missing --cometbft-genesis evidence".to_owned());
        }
        return;
    };
    let derived_bytes = match fs::read(derived_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            blockers.push(format!("derived manifest unreadable: {error}"));
            return;
        }
    };
    let expected_file_hash = root
        .get("genesis_derived_manifest_sha256")
        .and_then(Value::as_str);
    let actual_file_hash = hex::encode(Sha256::digest(&derived_bytes));
    if expected_file_hash != Some(actual_file_hash.as_str()) {
        blockers.push("genesis_derived_manifest_sha256 mismatch".to_owned());
    }
    let derived = match GenesisDerivedManifest::decode_canonical(&derived_bytes, identity) {
        Ok(derived) => derived,
        Err(error) => {
            blockers.push(format!("derived manifest invalid: {error}"));
            return;
        }
    };
    let derived_hash = match derived.hash(identity) {
        Ok(value) => value,
        Err(error) => {
            blockers.push(format!("derived manifest hash failed: {error}"));
            return;
        }
    };
    for (field, actual) in [
        ("derived_manifest_hash", derived_hash),
        ("runtime_inputs_sha256", derived.runtime_inputs_sha256),
        ("shielded_tree_root", derived.shielded_tree_root),
        ("app_hash", derived.app_hash),
        ("genesis_execution_hash", derived.genesis_execution_hash),
        ("genesis_compact_hash", derived.genesis_compact_hash),
        ("cometbft_genesis_sha256", derived.cometbft_genesis_sha256),
    ] {
        if root
            .get("derived_genesis")
            .and_then(|value| value.get(field))
            .and_then(Value::as_str)
            != Some(hex::encode(actual).as_str())
        {
            blockers.push(format!("derived_genesis.{field} mismatch"));
        }
    }

    match derived_signatures_path {
        Some(path) => match fs::read(path) {
            Ok(bytes) => {
                let expected = root
                    .get("genesis_derived_signature_package_sha256")
                    .and_then(Value::as_str);
                let actual = hex::encode(Sha256::digest(&bytes));
                if expected != Some(actual.as_str()) {
                    blockers.push("genesis_derived_signature_package_sha256 mismatch".to_owned());
                }
                match DerivedSignaturePackage::decode_canonical(&bytes)
                    .and_then(|package| package.verify(identity, &derived))
                {
                    Ok(_) => {}
                    Err(error) => {
                        blockers.push(format!("derived approvals invalid: {error}"));
                    }
                }
            }
            Err(error) => blockers.push(format!("derived approvals unreadable: {error}")),
        },
        None => blockers.push("missing --derived-signatures evidence".to_owned()),
    }
    verify_optional_path_hash(
        runtime_inputs_path,
        derived.runtime_inputs_sha256,
        "--runtime-inputs",
        blockers,
    );
    verify_optional_path_hash(
        cometbft_genesis_path,
        derived.cometbft_genesis_sha256,
        "--cometbft-genesis",
        blockers,
    );
}

fn verify_optional_path_hash(
    path: Option<&PathBuf>,
    expected: [u8; 32],
    flag: &str,
    blockers: &mut Vec<String>,
) {
    match path {
        Some(path) => match fs::read(path) {
            Ok(bytes) if <[u8; 32]>::from(Sha256::digest(&bytes)) == expected => {}
            Ok(_) => blockers.push(format!("{flag} SHA-256 mismatch")),
            Err(error) => blockers.push(format!("{flag} unreadable: {error}")),
        },
        None => blockers.push(format!("missing {flag} evidence")),
    }
}

fn verify_source_checkout(expected: &[u8], blockers: &mut Vec<String>) {
    let head = Command::new("git").args(["rev-parse", "HEAD"]).output();
    match head {
        Ok(output) if output.status.success() => {
            let actual = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if actual != hex::encode(expected) {
                blockers.push("source_commit differs from the checked-out Git HEAD".to_owned());
            }
        }
        Ok(_) | Err(_) => blockers.push("could not verify the checked-out Git HEAD".to_owned()),
    }
    match Command::new("git").args(["status", "--porcelain"]).output() {
        Ok(output) if output.status.success() && output.stdout.is_empty() => {}
        Ok(output) if output.status.success() => {
            blockers.push("source checkout contains uncommitted changes".to_owned())
        }
        Ok(_) | Err(_) => blockers.push("could not verify source checkout cleanliness".to_owned()),
    }
}

fn validate_release_artifacts(root: &Value, base: Option<&Path>, blockers: &mut Vec<String>) {
    let Some(entries) = root.get("release_artifacts").and_then(Value::as_array) else {
        return;
    };
    for (index, entry) in entries.iter().enumerate() {
        let Some(path) = entry.get("path").and_then(Value::as_str) else {
            blockers.push(format!("release_artifacts[{index}].path is missing"));
            continue;
        };
        let Some(expected) = entry.get("sha256").and_then(Value::as_str) else {
            blockers.push(format!("release_artifacts[{index}].sha256 is missing"));
            continue;
        };
        if !valid_hash(expected) {
            blockers.push(format!("release_artifacts[{index}].sha256 is invalid"));
            continue;
        }
        let path = PathBuf::from(path);
        let resolved = if path.is_absolute() {
            path
        } else {
            base.unwrap_or_else(|| Path::new(".")).join(path)
        };
        match fs::read(&resolved) {
            Ok(bytes) if hex::encode(Sha256::digest(&bytes)) == expected => {}
            Ok(_) => blockers.push(format!("release_artifacts[{index}] SHA-256 mismatch")),
            Err(error) => blockers.push(format!(
                "release_artifacts[{index}] unreadable at {}: {error}",
                resolved.display()
            )),
        }
    }
}

fn usage() -> &'static str {
    "usage:\n  bit genesis build --input INPUT.json --output identity.cbor\n  bit genesis verify --manifest identity.cbor [--signatures approvals.cbor]\n  bit genesis inspect --manifest identity.cbor\n  bit genesis sign --manifest identity.cbor --key-file KEY --output approvals.cbor [--append OLD.cbor]\n  bit genesis build-derived --manifest identity.cbor --input DERIVED.json --output derived.cbor\n  bit genesis verify-derived --manifest identity.cbor --derived derived.cbor [--signatures approvals.cbor]\n  bit genesis inspect-derived --manifest identity.cbor --derived derived.cbor\n  bit genesis sign-derived --manifest identity.cbor --derived derived.cbor --key-file KEY --output approvals.cbor [--append OLD.cbor]\n  bit release preflight --input mainnet.json [--manifest identity.cbor --signatures approvals.cbor --crypto-manifest FILE --parameters FILE --derived-manifest derived.cbor --derived-signatures approvals.cbor --runtime-inputs FILE --cometbft-genesis genesis.json]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_template_shape_reports_blockers_without_panicking() {
        let root: Value =
            serde_json::from_str(include_str!("../../../config/mainnet-inputs.template.json"))
                .unwrap();
        let mut blockers = Vec::new();
        require_json_string(&root, "network_type", Some("mainnet"), &mut blockers);
        require_nonempty_array(&root, "independent_endpoints", &mut blockers);
        assert_eq!(blockers.len(), 1);
    }

    #[test]
    fn secret_key_reader_rejects_ambiguous_text() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        fs::write(&path, b"not a key").unwrap();
        assert!(read_secret_key(&path).is_err());
    }

    #[test]
    fn cli_rejects_unknown_or_missing_option_values() {
        assert!(run(vec![
            "genesis".to_owned(),
            "verify".to_owned(),
            "--manfiest".to_owned(),
            "identity.cbor".to_owned(),
        ])
        .is_err());
        assert!(run(vec![
            "genesis".to_owned(),
            "verify".to_owned(),
            "--manifest".to_owned(),
        ])
        .is_err());
    }

    #[test]
    fn preflight_verifies_derived_files_and_second_stage_threshold() {
        let directory = tempfile::tempdir().unwrap();
        let identity_fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/genesis-identity-input.test.json");
        let identity = read_identity(&identity_fixture).unwrap();
        let runtime_path = directory.path().join("runtime-inputs.json");
        let comet_path = directory.path().join("genesis.json");
        fs::write(&runtime_path, b"canonical runtime inputs").unwrap();
        fs::write(&comet_path, b"canonical CometBFT genesis").unwrap();

        let derived_fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/genesis-derived-input.test.json");
        let mut derived_value: Value =
            serde_json::from_slice(&fs::read(derived_fixture).unwrap()).unwrap();
        let derived_object = derived_value
            .get_mut("derived_genesis")
            .and_then(Value::as_object_mut)
            .unwrap();
        derived_object.insert(
            "runtime_inputs_sha256".to_owned(),
            Value::String(hex::encode(Sha256::digest(
                fs::read(&runtime_path).unwrap(),
            ))),
        );
        derived_object.insert(
            "cometbft_genesis_sha256".to_owned(),
            Value::String(hex::encode(Sha256::digest(fs::read(&comet_path).unwrap()))),
        );
        let document: DerivedInputDocument =
            serde_json::from_value(derived_value["derived_genesis"].clone()).unwrap();
        let derived = document.into_manifest(&identity).unwrap();
        let derived_bytes = derived.encode_canonical(&identity).unwrap();
        let derived_path = directory.path().join("derived.cbor");
        fs::write(&derived_path, &derived_bytes).unwrap();

        let mut package = DerivedSignaturePackage {
            identity_manifest_hash: identity.hash().unwrap(),
            derived_manifest_hash: derived.hash(&identity).unwrap(),
            approvals: Vec::new(),
        };
        package.add_signature(&identity, &derived, [5; 32]).unwrap();
        package.add_signature(&identity, &derived, [6; 32]).unwrap();
        let signature_bytes = package.encode_canonical().unwrap();
        let signatures_path = directory.path().join("derived-signatures.cbor");
        fs::write(&signatures_path, &signature_bytes).unwrap();

        let root = json!({
            "genesis_derived_manifest_sha256": hex::encode(Sha256::digest(&derived_bytes)),
            "genesis_derived_signature_package_sha256": hex::encode(Sha256::digest(&signature_bytes)),
            "derived_genesis": {
                "derived_manifest_hash": hex::encode(derived.hash(&identity).unwrap()),
                "runtime_inputs_sha256": hex::encode(derived.runtime_inputs_sha256),
                "shielded_tree_root": hex::encode(derived.shielded_tree_root),
                "app_hash": hex::encode(derived.app_hash),
                "genesis_execution_hash": hex::encode(derived.genesis_execution_hash),
                "genesis_compact_hash": hex::encode(derived.genesis_compact_hash),
                "cometbft_genesis_sha256": hex::encode(derived.cometbft_genesis_sha256),
            }
        });
        let mut blockers = Vec::new();
        validate_derived_evidence(
            &root,
            &identity,
            Some(&derived_path),
            Some(&signatures_path),
            Some(&runtime_path),
            Some(&comet_path),
            &mut blockers,
        );
        assert!(blockers.is_empty(), "unexpected blockers: {blockers:?}");
    }

    #[test]
    fn cli_build_verify_and_incremental_signing_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("identity.cbor");
        let first_package = directory.path().join("approval-one.cbor");
        let threshold_package = directory.path().join("approvals.cbor");
        let derived_manifest = directory.path().join("derived.cbor");
        let first_derived_package = directory.path().join("derived-approval-one.cbor");
        let threshold_derived_package = directory.path().join("derived-approvals.cbor");
        let first_key = directory.path().join("key-one");
        let second_key = directory.path().join("key-two");
        fs::write(&first_key, [5; 32]).unwrap();
        fs::write(&second_key, hex::encode([6; 32])).unwrap();
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/genesis-identity-input.test.json");
        let derived_fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/genesis-derived-input.test.json");

        run(vec![
            "genesis".to_owned(),
            "build".to_owned(),
            "--input".to_owned(),
            fixture.display().to_string(),
            "--output".to_owned(),
            manifest.display().to_string(),
        ])
        .unwrap();
        run(vec![
            "genesis".to_owned(),
            "sign".to_owned(),
            "--manifest".to_owned(),
            manifest.display().to_string(),
            "--key-file".to_owned(),
            first_key.display().to_string(),
            "--output".to_owned(),
            first_package.display().to_string(),
        ])
        .unwrap();
        run(vec![
            "genesis".to_owned(),
            "sign".to_owned(),
            "--manifest".to_owned(),
            manifest.display().to_string(),
            "--key-file".to_owned(),
            second_key.display().to_string(),
            "--append".to_owned(),
            first_package.display().to_string(),
            "--output".to_owned(),
            threshold_package.display().to_string(),
        ])
        .unwrap();
        run(vec![
            "genesis".to_owned(),
            "verify".to_owned(),
            "--manifest".to_owned(),
            manifest.display().to_string(),
            "--signatures".to_owned(),
            threshold_package.display().to_string(),
        ])
        .unwrap();
        run(vec![
            "genesis".to_owned(),
            "build-derived".to_owned(),
            "--manifest".to_owned(),
            manifest.display().to_string(),
            "--input".to_owned(),
            derived_fixture.display().to_string(),
            "--output".to_owned(),
            derived_manifest.display().to_string(),
        ])
        .unwrap();
        run(vec![
            "genesis".to_owned(),
            "sign-derived".to_owned(),
            "--manifest".to_owned(),
            manifest.display().to_string(),
            "--derived".to_owned(),
            derived_manifest.display().to_string(),
            "--key-file".to_owned(),
            first_key.display().to_string(),
            "--output".to_owned(),
            first_derived_package.display().to_string(),
        ])
        .unwrap();
        run(vec![
            "genesis".to_owned(),
            "sign-derived".to_owned(),
            "--manifest".to_owned(),
            manifest.display().to_string(),
            "--derived".to_owned(),
            derived_manifest.display().to_string(),
            "--key-file".to_owned(),
            second_key.display().to_string(),
            "--append".to_owned(),
            first_derived_package.display().to_string(),
            "--output".to_owned(),
            threshold_derived_package.display().to_string(),
        ])
        .unwrap();
        run(vec![
            "genesis".to_owned(),
            "verify-derived".to_owned(),
            "--manifest".to_owned(),
            manifest.display().to_string(),
            "--derived".to_owned(),
            derived_manifest.display().to_string(),
            "--signatures".to_owned(),
            threshold_derived_package.display().to_string(),
        ])
        .unwrap();

        assert_eq!(
            hex::encode(fs::read(manifest).unwrap()),
            serde_json::from_str::<Value>(include_str!(
                "../../../tests/vectors/genesis-identity-vectors.json"
            ))
            .unwrap()["canonical_identity_cbor_hex"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            hex::encode(fs::read(derived_manifest).unwrap()),
            serde_json::from_str::<Value>(include_str!(
                "../../../tests/vectors/genesis-identity-vectors.json"
            ))
            .unwrap()["canonical_derived_cbor_hex"]
                .as_str()
                .unwrap()
        );
    }
}
