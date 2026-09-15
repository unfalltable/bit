use bit_genesis::{
    materialize_bundle, verify_bundle, DerivedInputDocument, DerivedSignaturePackage,
    GenesisDerivedManifest, GenesisIdentityManifest, Hash32, IdentityInputDocument,
    RuntimeInputDocument, SignaturePackage, APPROVAL_VERSION, DERIVED_APPROVAL_VERSION,
    DERIVED_VERSION, IDENTITY_VERSION,
};
use bit_light_client::{
    AuthorityPolicy as CheckpointAuthorityPolicy, CheckpointPolicy, Error as CheckpointError,
    PolicySignaturePackage, SignedCheckpoint, TrustStatus,
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
            "inspect-runtime" | "validate-runtime" => genesis_inspect_runtime(rest),
            "materialize" => genesis_materialize(rest),
            "verify-bundle" => genesis_verify_bundle(rest),
            _ => Err(usage().into()),
        },
        [group, command, rest @ ..] if group == "release" && command == "preflight" => {
            release_preflight(rest)
        }
        [group, command, rest @ ..] if group == "network" => match command.as_str() {
            "verify-manifest" => genesis_verify(rest),
            "verify-checkpoint" => network_verify_checkpoint(rest),
            _ => Err(usage().into()),
        },
        [command, rest @ ..] if command == "release-preflight" => release_preflight(rest),
        [command] if command == "version" => {
            println!("bit {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err(usage().into()),
    }
}

fn network_verify_checkpoint(args: &[String]) -> DynResult<()> {
    validate_options(
        args,
        &[
            "--manifest",
            "--runtime-inputs",
            "--policy",
            "--policy-approvals",
            "--checkpoint",
            "--expected-checkpoint-hash",
            "--now",
        ],
    )?;
    let manifest_path = required_path(args, "--manifest")?;
    let runtime_path = required_path(args, "--runtime-inputs")?;
    let policy_path = required_path(args, "--policy")?;
    let policy_approvals_path = required_path(args, "--policy-approvals")?;
    let checkpoint_path = required_path(args, "--checkpoint")?;
    let expected_checkpoint_hash = required_hash(args, "--expected-checkpoint-hash")?;
    let now_seconds = required_u64(args, "--now")?;

    let manifest = GenesisIdentityManifest::decode_canonical(&fs::read(&manifest_path)?)?;
    let runtime_bytes = fs::read(&runtime_path)?;
    let runtime = RuntimeInputDocument::decode(&runtime_bytes)?;
    if Hash32::from(Sha256::digest(&runtime_bytes)) != manifest.consensus_parameters_sha256 {
        return Err("runtime inputs do not match the signed genesis identity".into());
    }
    let policy = CheckpointPolicy::decode_canonical(&fs::read(&policy_path)?)?;
    policy.verify_binding(
        &manifest.hash()?,
        &manifest.chain_context()?,
        &manifest.consensus_parameters_sha256,
    )?;
    let authority = CheckpointAuthorityPolicy {
        threshold: manifest.approval_policy.threshold,
        signers: manifest.approval_policy.signers.clone(),
    };
    let approvals = PolicySignaturePackage::decode_canonical(&fs::read(&policy_approvals_path)?)?;
    let signed = SignedCheckpoint::decode_canonical(&fs::read(&checkpoint_path)?)?;
    policy.validate_safety(runtime.staking.unbonding_seconds)?;
    let policy_approval_count = approvals.verify(&policy, &authority)?;
    let checkpoint_signature_count = signed.verify(&policy)?;
    let checkpoint_hash = signed.checkpoint.hash()?;
    if checkpoint_hash != expected_checkpoint_hash {
        return Err(CheckpointError::ConfirmationMismatch.into());
    }
    let status = signed.checkpoint.status(&policy, now_seconds)?;
    if status == TrustStatus::Expired {
        return Err(CheckpointError::IncomingExpired.into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "verified",
            "trust_status": status.as_str(),
            "genesis_manifest_hash": hex::encode(policy.genesis_manifest_hash),
            "chain_context": hex::encode(policy.chain_context),
            "policy_sequence": policy.sequence,
            "policy_hash": hex::encode(policy.hash()?),
            "policy_approval_count": policy_approval_count,
            "policy_approval_threshold": authority.threshold,
            "checkpoint_hash": hex::encode(checkpoint_hash),
            "checkpoint_signature_count": checkpoint_signature_count,
            "checkpoint_signature_threshold": policy.threshold,
            "header_height": signed.checkpoint.header_height,
            "header_hash": hex::encode(signed.checkpoint.header_hash),
            "state_height": signed.checkpoint.state_height,
            "app_hash": hex::encode(signed.checkpoint.app_hash),
            "issued_at_seconds": signed.checkpoint.issued_at_seconds,
            "expires_at_seconds": signed.checkpoint.expires_at_seconds,
            "now_seconds": now_seconds,
        }))?
    );
    Ok(())
}

fn genesis_inspect_runtime(args: &[String]) -> DynResult<()> {
    validate_options(args, &["--input"])?;
    let input = required_path(args, "--input")?;
    let bytes = fs::read(&input)?;
    let document = RuntimeInputDocument::decode(&bytes)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "validated",
            "format": document.format,
            "version": document.version,
            "runtime_inputs_sha256": hex::encode(Sha256::digest(&bytes)),
            "validator_count": document.validators.len(),
            "input": input,
        }))?
    );
    Ok(())
}

fn genesis_materialize(args: &[String]) -> DynResult<()> {
    validate_options(
        args,
        &["--manifest", "--signatures", "--runtime-inputs", "--output"],
    )?;
    let manifest = required_path(args, "--manifest")?;
    let signatures = required_path(args, "--signatures")?;
    let runtime_inputs = required_path(args, "--runtime-inputs")?;
    let output = required_path(args, "--output")?;
    for input in [&manifest, &signatures, &runtime_inputs] {
        reject_same_path(input, &output)?;
    }
    let runtime = tokio::runtime::Runtime::new()?;
    let report = runtime.block_on(materialize_bundle(
        &fs::read(&manifest)?,
        &fs::read(&signatures)?,
        &fs::read(&runtime_inputs)?,
        &output,
    ))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn genesis_verify_bundle(args: &[String]) -> DynResult<()> {
    validate_options(args, &["--bundle", "--derived-signatures"])?;
    let bundle = required_path(args, "--bundle")?;
    let derived_signatures = required_path(args, "--derived-signatures")?;
    let runtime = tokio::runtime::Runtime::new()?;
    let verified = runtime.block_on(verify_bundle(&bundle, &derived_signatures))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "verified",
            "bundle": bundle,
            "identity_manifest_hash": verified.report.identity_manifest_hash,
            "derived_manifest_hash": verified.report.derived_manifest_hash,
            "app_hash": verified.report.app_hash,
            "identity_approval_count": verified.report.identity_approval_count,
            "derived_approval_count": verified.derived_approval_count,
            "validator_count": verified.report.validator_count,
        }))?
    );
    Ok(())
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
            "--checkpoint-policy",
            "--checkpoint-policy-approvals",
            "--checkpoint",
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
        "checkpoint_policy_sha256",
        "checkpoint_policy_approval_package_sha256",
        "checkpoint_policy_hash",
        "trusted_checkpoint_package_sha256",
        "trusted_checkpoint_hash",
        "trusted_checkpoint_header_hash",
        "trusted_checkpoint_app_hash",
    ] {
        require_json_hash(&root, field, &mut blockers);
    }
    for field in [
        "checkpoint_policy_sequence",
        "checkpoint_signature_threshold",
        "checkpoint_trust_period_seconds",
        "checkpoint_expiry_warning_seconds",
        "trusted_checkpoint_header_height",
        "trusted_checkpoint_issued_at_seconds",
        "trusted_checkpoint_expires_at_seconds",
    ] {
        require_json_positive_u64(&root, field, &mut blockers);
    }
    require_json_u64(&root, "trusted_checkpoint_state_height", &mut blockers);
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
    let checkpoint_policy_path = optional_path(args, "--checkpoint-policy")?;
    let checkpoint_policy_approvals_path = optional_path(args, "--checkpoint-policy-approvals")?;
    let checkpoint_path = optional_path(args, "--checkpoint")?;
    let consensus_parameters_path = runtime_inputs_path.as_ref().or(parameters_path.as_ref());
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
            consensus_parameters_path.cloned(),
            identity.consensus_parameters_sha256,
            "--runtime-inputs",
            &mut blockers,
        );
        validate_derived_evidence(
            &root,
            identity,
            derived_manifest_path.as_ref(),
            derived_signatures_path.as_ref(),
            consensus_parameters_path,
            cometbft_genesis_path.as_ref(),
            &mut blockers,
        );
        validate_checkpoint_evidence(
            &root,
            identity,
            runtime_inputs_path.as_ref(),
            checkpoint_policy_path.as_ref(),
            checkpoint_policy_approvals_path.as_ref(),
            checkpoint_path.as_ref(),
            &mut blockers,
        );
    } else {
        for (path, flag) in [
            (manifest_path.as_ref(), "--manifest"),
            (signatures_path.as_ref(), "--signatures"),
            (crypto_path.as_ref(), "--crypto-manifest"),
            (derived_manifest_path.as_ref(), "--derived-manifest"),
            (derived_signatures_path.as_ref(), "--derived-signatures"),
            (cometbft_genesis_path.as_ref(), "--cometbft-genesis"),
            (checkpoint_policy_path.as_ref(), "--checkpoint-policy"),
            (
                checkpoint_policy_approvals_path.as_ref(),
                "--checkpoint-policy-approvals",
            ),
            (checkpoint_path.as_ref(), "--checkpoint"),
        ] {
            if path.is_none() {
                blockers.push(format!("missing {flag} evidence"));
            }
        }
        if consensus_parameters_path.is_none() {
            blockers.push("missing --runtime-inputs evidence".to_owned());
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

fn required_u64(args: &[String], flag: &str) -> DynResult<u64> {
    let value = optional_text(args, flag)?.ok_or_else(|| format!("missing required {flag}"))?;
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!("{flag} must be a canonical unsigned decimal integer").into());
    }
    value
        .parse()
        .map_err(|_| format!("{flag} exceeds uint64").into())
}

fn required_hash(args: &[String], flag: &str) -> DynResult<Hash32> {
    let value = optional_text(args, flag)?.ok_or_else(|| format!("missing required {flag}"))?;
    if !valid_hash(&value) {
        return Err(format!("{flag} must be exactly 64 lowercase hexadecimal characters").into());
    }
    Ok(hex::decode(value)?.try_into().expect("hash length checked"))
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
    Ok(optional_text(args, flag)?.map(PathBuf::from))
}

fn optional_text(args: &[String], flag: &str) -> DynResult<Option<String>> {
    let matches: Vec<_> = args
        .windows(2)
        .filter(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
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

fn require_json_positive_u64(root: &Value, field: &str, blockers: &mut Vec<String>) {
    if root
        .get(field)
        .and_then(Value::as_u64)
        .is_none_or(|value| value == 0)
    {
        blockers.push(format!("{field} must be a positive uint64"));
    }
}

fn require_json_u64(root: &Value, field: &str, blockers: &mut Vec<String>) {
    if root.get(field).and_then(Value::as_u64).is_none() {
        blockers.push(format!("{field} must be a uint64"));
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

fn validate_checkpoint_evidence(
    root: &Value,
    identity: &GenesisIdentityManifest,
    runtime_path: Option<&PathBuf>,
    policy_path: Option<&PathBuf>,
    approvals_path: Option<&PathBuf>,
    checkpoint_path: Option<&PathBuf>,
    blockers: &mut Vec<String>,
) {
    let result = (|| -> Result<(), String> {
        let runtime_path = runtime_path.ok_or("missing --runtime-inputs evidence")?;
        let policy_path = policy_path.ok_or("missing --checkpoint-policy evidence")?;
        let approvals_path =
            approvals_path.ok_or("missing --checkpoint-policy-approvals evidence")?;
        let checkpoint_path = checkpoint_path.ok_or("missing --checkpoint evidence")?;

        let runtime_bytes = fs::read(runtime_path).map_err(|error| error.to_string())?;
        let runtime =
            RuntimeInputDocument::decode(&runtime_bytes).map_err(|error| error.to_string())?;
        let runtime_hash: Hash32 = Sha256::digest(&runtime_bytes).into();
        if runtime_hash != identity.consensus_parameters_sha256 {
            return Err("runtime inputs differ from signed genesis parameters".to_owned());
        }

        let policy_bytes = fs::read(policy_path).map_err(|error| error.to_string())?;
        let policy =
            CheckpointPolicy::decode_canonical(&policy_bytes).map_err(|error| error.to_string())?;
        policy
            .verify_binding(
                &identity.hash().map_err(|error| error.to_string())?,
                &identity
                    .chain_context()
                    .map_err(|error| error.to_string())?,
                &identity.consensus_parameters_sha256,
            )
            .and_then(|()| policy.validate_safety(runtime.staking.unbonding_seconds))
            .map_err(|error| error.to_string())?;
        let policy_hash = policy.hash().map_err(|error| error.to_string())?;
        expect_json_hash(
            root,
            "checkpoint_policy_sha256",
            Sha256::digest(&policy_bytes).into(),
        )?;
        expect_json_hash(root, "checkpoint_policy_hash", policy_hash)?;
        expect_json_u64(root, "checkpoint_policy_sequence", policy.sequence)?;
        expect_json_u64(
            root,
            "checkpoint_signature_threshold",
            u64::from(policy.threshold),
        )?;
        expect_json_u64(
            root,
            "checkpoint_trust_period_seconds",
            policy.trust_period_seconds,
        )?;
        expect_json_u64(
            root,
            "checkpoint_expiry_warning_seconds",
            policy.expiry_warning_seconds,
        )?;
        let configured_publishers = root
            .get("checkpoint_publishers")
            .and_then(Value::as_array)
            .ok_or("checkpoint_publishers is not an array")?;
        let actual_publishers: Vec<_> = policy.publishers.iter().map(hex::encode).collect();
        if configured_publishers.len() != actual_publishers.len()
            || configured_publishers
                .iter()
                .zip(&actual_publishers)
                .any(|(configured, actual)| configured.as_str() != Some(actual))
        {
            return Err("checkpoint_publishers differs from the signed policy".to_owned());
        }

        let approvals_bytes = fs::read(approvals_path).map_err(|error| error.to_string())?;
        expect_json_hash(
            root,
            "checkpoint_policy_approval_package_sha256",
            Sha256::digest(&approvals_bytes).into(),
        )?;
        let approvals = PolicySignaturePackage::decode_canonical(&approvals_bytes)
            .map_err(|error| error.to_string())?;
        let authority = CheckpointAuthorityPolicy {
            threshold: identity.approval_policy.threshold,
            signers: identity.approval_policy.signers.clone(),
        };
        approvals
            .verify(&policy, &authority)
            .map_err(|error| error.to_string())?;

        let checkpoint_bytes = fs::read(checkpoint_path).map_err(|error| error.to_string())?;
        expect_json_hash(
            root,
            "trusted_checkpoint_package_sha256",
            Sha256::digest(&checkpoint_bytes).into(),
        )?;
        let signed = SignedCheckpoint::decode_canonical(&checkpoint_bytes)
            .map_err(|error| error.to_string())?;
        signed.verify(&policy).map_err(|error| error.to_string())?;
        let checkpoint = &signed.checkpoint;
        expect_json_hash(
            root,
            "trusted_checkpoint_hash",
            checkpoint.hash().map_err(|error| error.to_string())?,
        )?;
        expect_json_hash(
            root,
            "trusted_checkpoint_header_hash",
            checkpoint.header_hash,
        )?;
        expect_json_hash(root, "trusted_checkpoint_app_hash", checkpoint.app_hash)?;
        expect_json_u64(
            root,
            "trusted_checkpoint_header_height",
            checkpoint.header_height,
        )?;
        expect_json_u64(
            root,
            "trusted_checkpoint_state_height",
            checkpoint.state_height,
        )?;
        expect_json_u64(
            root,
            "trusted_checkpoint_issued_at_seconds",
            checkpoint.issued_at_seconds,
        )?;
        expect_json_u64(
            root,
            "trusted_checkpoint_expires_at_seconds",
            checkpoint.expires_at_seconds,
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        blockers.push(format!("checkpoint evidence invalid: {error}"));
    }
}

fn expect_json_hash(root: &Value, field: &str, expected: Hash32) -> Result<(), String> {
    let expected = hex::encode(expected);
    if root.get(field).and_then(Value::as_str) == Some(expected.as_str()) {
        Ok(())
    } else {
        Err(format!("{field} does not match supplied evidence"))
    }
}

fn expect_json_u64(root: &Value, field: &str, expected: u64) -> Result<(), String> {
    if root.get(field).and_then(Value::as_u64) == Some(expected) {
        Ok(())
    } else {
        Err(format!("{field} does not match supplied evidence"))
    }
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
    verify_runtime_input(runtime_inputs_path, derived.runtime_inputs_sha256, blockers);
    verify_optional_path_hash(
        cometbft_genesis_path,
        derived.cometbft_genesis_sha256,
        "--cometbft-genesis",
        blockers,
    );
}

fn verify_runtime_input(path: Option<&PathBuf>, expected: [u8; 32], blockers: &mut Vec<String>) {
    let Some(path) = path else {
        blockers.push("missing --runtime-inputs evidence".to_owned());
        return;
    };
    match fs::read(path) {
        Ok(bytes) if <[u8; 32]>::from(Sha256::digest(&bytes)) != expected => {
            blockers.push("--runtime-inputs SHA-256 mismatch".to_owned());
        }
        Ok(bytes) => {
            if let Err(error) = RuntimeInputDocument::decode(&bytes) {
                blockers.push(format!("--runtime-inputs invalid: {error}"));
            }
        }
        Err(error) => blockers.push(format!("--runtime-inputs unreadable: {error}")),
    }
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
    "usage:\n  bit genesis build --input INPUT.json --output identity.cbor\n  bit genesis verify --manifest identity.cbor [--signatures approvals.cbor]\n  bit genesis inspect --manifest identity.cbor\n  bit genesis sign --manifest identity.cbor --key-file KEY --output approvals.cbor [--append OLD.cbor]\n  bit genesis inspect-runtime --input runtime-inputs.json\n  bit genesis materialize --manifest identity.cbor --signatures approvals.cbor --runtime-inputs runtime-inputs.json --output BUNDLE_DIR\n  bit genesis verify-bundle --bundle BUNDLE_DIR --derived-signatures approvals.cbor\n  bit genesis build-derived --manifest identity.cbor --input DERIVED.json --output derived.cbor\n  bit genesis verify-derived --manifest identity.cbor --derived derived.cbor [--signatures approvals.cbor]\n  bit genesis inspect-derived --manifest identity.cbor --derived derived.cbor\n  bit genesis sign-derived --manifest identity.cbor --derived derived.cbor --key-file KEY --output approvals.cbor [--append OLD.cbor]\n  bit network verify-manifest --manifest identity.cbor [--signatures approvals.cbor]\n  bit network verify-checkpoint --manifest identity.cbor --runtime-inputs runtime-inputs.json --policy policy.cbor --policy-approvals approvals.cbor --checkpoint checkpoint.cbor --expected-checkpoint-hash HASH --now UNIX_SECONDS\n  bit release preflight --input mainnet.json [--manifest identity.cbor --signatures approvals.cbor --crypto-manifest FILE --derived-manifest derived.cbor --derived-signatures approvals.cbor --runtime-inputs FILE --cometbft-genesis genesis.json --checkpoint-policy policy.cbor --checkpoint-policy-approvals approvals.cbor --checkpoint checkpoint.cbor]"
}

#[cfg(test)]
mod tests {
    use super::*;
    use bit_genesis::{
        genesis_claims_hash, genesis_commitments_hash, DerivedClaim, DerivedValidator,
    };
    use bit_light_client::{Checkpoint, SignatureEntry};
    use bit_staking::consensus_address;
    use ed25519_consensus::SigningKey;

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
    fn cli_verifies_an_independently_confirmed_signed_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let identity_fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/genesis-identity-input.test.json");
        let runtime_fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/genesis-runtime-inputs.test.json");
        let identity = read_identity(&identity_fixture).unwrap();
        let identity_path = directory.path().join("identity.cbor");
        let runtime_path = directory.path().join("runtime.json");
        let policy_path = directory.path().join("policy.cbor");
        let approvals_path = directory.path().join("policy-approvals.cbor");
        let checkpoint_path = directory.path().join("checkpoint.cbor");
        fs::write(&identity_path, identity.encode_canonical().unwrap()).unwrap();
        fs::copy(&runtime_fixture, &runtime_path).unwrap();

        let mut publishers = vec![
            SigningKey::from([7; 32]).verification_key().to_bytes(),
            SigningKey::from([8; 32]).verification_key().to_bytes(),
            SigningKey::from([9; 32]).verification_key().to_bytes(),
        ];
        publishers.sort();
        let policy = CheckpointPolicy {
            genesis_manifest_hash: identity.hash().unwrap(),
            chain_context: identity.chain_context().unwrap(),
            consensus_parameters_sha256: identity.consensus_parameters_sha256,
            sequence: 1,
            previous_policy_hash: None,
            activates_at_seconds: 1_900_000_000,
            trust_period_seconds: 259_200,
            expiry_warning_seconds: 43_200,
            threshold: 2,
            publishers,
            revoke_previous_immediately: false,
        };
        let authority = CheckpointAuthorityPolicy {
            threshold: identity.approval_policy.threshold,
            signers: identity.approval_policy.signers.clone(),
        };
        let mut approvals = PolicySignaturePackage {
            genesis_manifest_hash: identity.hash().unwrap(),
            policy_hash: policy.hash().unwrap(),
            approvals: Vec::new(),
        };
        approvals
            .add_signature(&policy, &authority, [5; 32])
            .unwrap();
        approvals
            .add_signature(&policy, &authority, [6; 32])
            .unwrap();
        let checkpoint = Checkpoint {
            policy_hash: policy.hash().unwrap(),
            genesis_manifest_hash: identity.hash().unwrap(),
            chain_context: identity.chain_context().unwrap(),
            header_height: 100,
            header_hash: [0x44; 32],
            state_height: 99,
            app_hash: [0x55; 32],
            issued_at_seconds: 1_900_000_100,
            expires_at_seconds: 1_900_259_300,
        };
        let mut signed = SignedCheckpoint {
            checkpoint,
            signatures: Vec::<SignatureEntry>::new(),
        };
        signed.add_signature(&policy, [7; 32]).unwrap();
        signed.add_signature(&policy, [8; 32]).unwrap();
        let policy_bytes = policy.encode_canonical().unwrap();
        let approvals_bytes = approvals.encode_canonical().unwrap();
        let signed_bytes = signed.encode_canonical().unwrap();
        fs::write(&policy_path, &policy_bytes).unwrap();
        fs::write(&approvals_path, &approvals_bytes).unwrap();
        fs::write(&checkpoint_path, &signed_bytes).unwrap();
        let checkpoint_hash = hex::encode(signed.checkpoint.hash().unwrap());

        let preflight = json!({
            "checkpoint_policy_sha256": hex::encode(Sha256::digest(&policy_bytes)),
            "checkpoint_policy_approval_package_sha256": hex::encode(Sha256::digest(&approvals_bytes)),
            "checkpoint_policy_hash": hex::encode(policy.hash().unwrap()),
            "checkpoint_policy_sequence": policy.sequence,
            "checkpoint_signature_threshold": policy.threshold,
            "checkpoint_trust_period_seconds": policy.trust_period_seconds,
            "checkpoint_expiry_warning_seconds": policy.expiry_warning_seconds,
            "checkpoint_publishers": policy.publishers.iter().map(hex::encode).collect::<Vec<_>>(),
            "trusted_checkpoint_package_sha256": hex::encode(Sha256::digest(&signed_bytes)),
            "trusted_checkpoint_hash": checkpoint_hash.clone(),
            "trusted_checkpoint_header_height": signed.checkpoint.header_height,
            "trusted_checkpoint_header_hash": hex::encode(signed.checkpoint.header_hash),
            "trusted_checkpoint_state_height": signed.checkpoint.state_height,
            "trusted_checkpoint_app_hash": hex::encode(signed.checkpoint.app_hash),
            "trusted_checkpoint_issued_at_seconds": signed.checkpoint.issued_at_seconds,
            "trusted_checkpoint_expires_at_seconds": signed.checkpoint.expires_at_seconds,
        });
        let mut blockers = Vec::new();
        validate_checkpoint_evidence(
            &preflight,
            &identity,
            Some(&runtime_path),
            Some(&policy_path),
            Some(&approvals_path),
            Some(&checkpoint_path),
            &mut blockers,
        );
        assert!(blockers.is_empty(), "unexpected blockers: {blockers:?}");

        let args = vec![
            "network".to_owned(),
            "verify-checkpoint".to_owned(),
            "--manifest".to_owned(),
            identity_path.display().to_string(),
            "--runtime-inputs".to_owned(),
            runtime_path.display().to_string(),
            "--policy".to_owned(),
            policy_path.display().to_string(),
            "--policy-approvals".to_owned(),
            approvals_path.display().to_string(),
            "--checkpoint".to_owned(),
            checkpoint_path.display().to_string(),
            "--expected-checkpoint-hash".to_owned(),
            checkpoint_hash,
            "--now".to_owned(),
            "1900000101".to_owned(),
        ];
        run(args.clone()).unwrap();
        let mut wrong = args;
        let index = wrong
            .iter()
            .position(|value| value == "--expected-checkpoint-hash")
            .unwrap()
            + 1;
        wrong[index] = "00".repeat(32);
        assert!(run(wrong).is_err());
    }

    #[test]
    fn preflight_verifies_derived_files_and_second_stage_threshold() {
        let directory = tempfile::tempdir().unwrap();
        let identity_fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/genesis-identity-input.test.json");
        let identity = read_identity(&identity_fixture).unwrap();
        let runtime_path = directory.path().join("runtime-inputs.json");
        let comet_path = directory.path().join("genesis.json");
        let runtime_fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/genesis-runtime-inputs.test.json");
        fs::write(&runtime_path, fs::read(runtime_fixture).unwrap()).unwrap();
        fs::write(&comet_path, b"canonical CometBFT genesis").unwrap();
        let runtime_hash = Sha256::digest(fs::read(&runtime_path).unwrap()).into();
        assert_eq!(identity.consensus_parameters_sha256, runtime_hash);
        let identity_hash = identity.hash().unwrap();
        let chain = identity.chain_context().unwrap();
        let claims = identity
            .claims
            .iter()
            .map(|claim| {
                let amount = identity
                    .allocations
                    .iter()
                    .find(|entry| entry.allocation_id == claim.allocation_id)
                    .unwrap()
                    .amount;
                DerivedClaim {
                    allocation_id: claim.allocation_id,
                    claim_id: genesis_claim_id(&chain, &claim.claim_pubkey, amount),
                }
            })
            .collect::<Vec<_>>();
        let validators = identity
            .validators
            .iter()
            .map(|validator| DerivedValidator {
                allocation_id: validator.allocation_id,
                validator_id: validator_id(&chain, &validator.operator_pubkey),
                self_bond_position_id: position_id(&chain, &validator.owner_pubkey),
                consensus_address: consensus_address(&validator.consensus_pubkey),
                voting_power: 4,
            })
            .collect::<Vec<_>>();
        let derived = GenesisDerivedManifest {
            identity_manifest_hash: identity_hash,
            chain_context: chain,
            runtime_inputs_sha256: runtime_hash,
            genesis_commitments_hash: genesis_commitments_hash(&identity),
            genesis_claims_hash: genesis_claims_hash(&identity, &claims).unwrap(),
            claims,
            validators,
            shielded_tree_root: [0x77; 32],
            app_hash: [0x88; 32],
            genesis_execution_hash: [0x99; 32],
            genesis_compact_hash: [0xaa; 32],
            cometbft_genesis_sha256: Sha256::digest(fs::read(&comet_path).unwrap()).into(),
        };
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
