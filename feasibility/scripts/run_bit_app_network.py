"""Four CometBFT processes against the real BIT ABCI/JMT application.

The node executable uses accelerated epochs and a deterministic public fixture,
while exercising production Transfer, ClaimGenesis, Unbond, ClaimExit and
block-artifact encodings.
"""

from pathlib import Path
import base64
import datetime as dt
import hashlib
import json
import os
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
COMET = ROOT / ".tools/bin/cometbft.exe"
GO = ROOT / ".tools/go/bin/go.exe"
EVIDENCE_INJECTOR = ROOT / ".tools/bin/bit-evidence-injector.exe"
TARGET_DIR = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
APP = TARGET_DIR / "debug/examples/comet_network_probe.exe"
EXIT_FIXTURE = TARGET_DIR / "release/bit-exit-fixture.exe"
PROOF_PARAMETERS = ROOT / ".tools/downloads"
PROBE_EPOCH_BLOCKS = 5
PROBE_UNBONDING_BLOCKS = 8
PROBE_UNBONDING_SECONDS = 8
RUN = ROOT / "runtime" / (
    "bit-app-network-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
)
REPORT = ROOT / "reports/bit-app-network-result.json"
TRANSFER_SOURCE = ROOT / "reports/proof-stdout.json"
GENESIS_MANIFEST_HASH_HEX = "33" * 32
ENV = os.environ.copy()
ENV["PATH"] = os.pathsep.join(
    [
        str(ROOT / ".tools/rust/bin"),
        str(ROOT / ".tools/llvm-mingw-20250812-msvcrt-x86_64/bin"),
        ENV["PATH"],
    ]
)
PROCESSES = {}
HANDLES = []


def command(args, timeout=60):
    completed = subprocess.run(
        [str(value) for value in args],
        capture_output=True,
        text=True,
        env=ENV,
        creationflags=0x08000000,
        timeout=timeout,
    )
    if completed.returncode:
        raise RuntimeError(f"{args[1:]}: {completed.stderr}")
    return completed.stdout.strip()


def rpc(index, path):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{29700 + index}/{path}", timeout=2
    ) as response:
        data = json.load(response)
    if "error" in data:
        raise RuntimeError(data["error"])
    return data["result"]


def height(index):
    try:
        return int(rpc(index, "status")["sync_info"]["latest_block_height"])
    except (OSError, ValueError, RuntimeError):
        return 0


def spawn(name, args):
    output = (RUN / f"{name}-{time.time_ns()}.log").open("wb")
    HANDLES.append(output)
    PROCESSES[name] = subprocess.Popen(
        [str(value) for value in args],
        stdout=output,
        stderr=subprocess.STDOUT,
        env=ENV,
        creationflags=0x08000000,
    )


def stop(name):
    process = PROCESSES.pop(name, None)
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def start_pair(index):
    genesis = RUN / f"nodes/node{index}/config/genesis.json"
    spawn(
        f"app{index}",
        [
            APP,
            f"127.0.0.1:{29900 + index}",
            RUN / f"app{index}",
            genesis,
        ],
    )
    time.sleep(0.3)
    spawn(
        f"node{index}",
        [COMET, "start", "--home", RUN / f"nodes/node{index}"],
    )


def wait_height(target, indices=range(4), seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        heights = [height(index) for index in indices]
        failed = [
            name
            for name, process in PROCESSES.items()
            if process.poll() is not None
        ]
        if failed:
            raise RuntimeError(f"processes exited before height {target}: {failed}")
        if all(value >= target for value in heights):
            return heights
        time.sleep(0.3)
    raise TimeoutError(f"height {target} not reached: {heights}")


def wait_height_remainder(remainder, modulus, seconds=30):
    deadline = time.monotonic() + seconds
    observed = 0
    while time.monotonic() < deadline:
        observed = height(0)
        failed = [
            name for name, process in PROCESSES.items() if process.poll() is not None
        ]
        if failed:
            raise RuntimeError(f"processes exited while scheduling transaction: {failed}")
        if observed > 0 and observed % modulus == remainder:
            return observed
        time.sleep(0.1)
    raise TimeoutError(
        f"height congruent to {remainder} mod {modulus} not observed; latest {observed}"
    )


def wait_quorum_halt(indices=(0, 1, 3), settle_seconds=3, observe_seconds=3, seconds=60):
    """Wait for live nodes to converge, then prove their height stays fixed."""
    deadline = time.monotonic() + seconds
    stable_height = None
    stable_since = None
    while time.monotonic() < deadline:
        heights = [height(index) for index in indices]
        failed = [
            name for name, process in PROCESSES.items() if process.poll() is not None
        ]
        if failed:
            raise RuntimeError(f"processes exited while waiting for quorum halt: {failed}")
        now = time.monotonic()
        if heights[0] > 0 and len(set(heights)) == 1:
            if heights[0] != stable_height:
                stable_height = heights[0]
                stable_since = now
            elif stable_since is not None and now - stable_since >= settle_seconds:
                break
        else:
            stable_height = None
            stable_since = None
        time.sleep(0.2)
    else:
        raise AssertionError(f"chain did not halt without quorum: {heights}")

    observation_deadline = time.monotonic() + observe_seconds
    while time.monotonic() < observation_deadline:
        heights = [height(index) for index in indices]
        if any(value != stable_height for value in heights):
            raise AssertionError(
                f"chain advanced without more than two-thirds voting power: {heights}"
            )
        time.sleep(0.2)
    return stable_height


def validator_powers(height_value):
    validators = rpc(0, f"validators?height={height_value}&per_page=100")["validators"]
    return {
        base64.b64decode(validator["pub_key"]["value"]).hex(): int(
            validator["voting_power"]
        )
        for validator in validators
    }


def state_query(index, key, height_value=None):
    query_path = urllib.parse.quote('"/bit/state/key"')
    query_data = "0x" + key.encode("utf-8").hex()
    height_parameter = "" if height_value is None else f"&height={height_value}"
    response = rpc(
        index,
        f"abci_query?path={query_path}&data={query_data}&prove=true{height_parameter}",
    )["response"]
    if int(response["code"]) != 0 or not response.get("proofOps", {}).get("ops"):
        raise AssertionError(
            f"proved state query failed for {key} on node {index}: {response}"
        )
    if height_value is not None and int(response["height"]) != height_value:
        raise AssertionError(
            f"proved state query returned height {response['height']}, expected {height_value}"
        )
    value = response.get("value", "")
    return base64.b64decode(value) if value else b""


def artifact_hash(domain, payload):
    return hashlib.sha256(domain + len(payload).to_bytes(8, "big") + payload).hexdigest()


def archived_artifact(index, height_value, name):
    path = (
        RUN / f"app{index}/block-artifacts-v1/blocks/{height_value:020d}/{name}.cbor"
    )
    if not path.is_file():
        raise AssertionError(f"missing archived {name} artifact on application {index}")
    return path.read_bytes()


def load_transfer_fixture():
    report_bytes = TRANSFER_SOURCE.read_bytes()
    report = json.loads(report_bytes)
    transfer = report["complete_transfer"]
    envelope = bytes.fromhex(transfer["canonical_envelope_hex"])
    if len(envelope) != int(transfer["canonical_envelope_bytes"]):
        raise AssertionError("transfer fixture envelope length mismatch")
    tx_id = hashlib.sha256(envelope).hexdigest()
    if tx_id != transfer["tx_id"]:
        raise AssertionError("transfer fixture transaction ID mismatch")
    for name in (
        "genesis_commitments_hex",
        "nullifiers_hex",
        "output_commitments_hex",
    ):
        values = transfer[name]
        if len(values) != 2 or len(set(values)) != 2:
            raise AssertionError(f"transfer fixture {name} must contain two distinct values")
        if any(len(bytes.fromhex(value)) != 32 for value in values):
            raise AssertionError(f"transfer fixture {name} contains a non-32-byte value")
    claim = report.get("complete_claim_genesis")
    if not isinstance(claim, dict):
        raise AssertionError("proof report is missing the ClaimGenesis fixture")
    claim_envelope = bytes.fromhex(claim["canonical_envelope_hex"])
    if len(claim_envelope) != int(claim["canonical_envelope_bytes"]):
        raise AssertionError("ClaimGenesis fixture envelope length mismatch")
    claim_tx_id = hashlib.sha256(claim_envelope).hexdigest()
    if claim_tx_id != claim["tx_id"]:
        raise AssertionError("ClaimGenesis fixture transaction ID mismatch")
    if claim["anchor_hex"] != transfer["anchor_hex"] or claim["nullifiers_hex"]:
        raise AssertionError("ClaimGenesis fixture must use the genesis anchor and no Spends")
    for name in ("claim_id", "claim_pubkey"):
        if len(bytes.fromhex(claim[name])) != 32:
            raise AssertionError(f"ClaimGenesis fixture {name} must be 32 bytes")
    if len(claim["output_commitments_hex"]) != 2 or any(
        len(bytes.fromhex(value)) != 32 for value in claim["output_commitments_hex"]
    ):
        raise AssertionError("ClaimGenesis fixture must have two 32-byte outputs")
    if int(claim["claim_amount_atomic"]) <= int(claim["fee_atomic"]):
        raise AssertionError("ClaimGenesis fixture amount must exceed its fee")
    replay = claim.get("distinct_spent_claim_replay")
    if not isinstance(replay, dict):
        raise AssertionError("proof report is missing the distinct spent-claim replay")
    replay_envelope = bytes.fromhex(replay["canonical_envelope_hex"])
    if len(replay_envelope) != int(replay["canonical_envelope_bytes"]):
        raise AssertionError("spent-claim replay envelope length mismatch")
    replay_tx_id = hashlib.sha256(replay_envelope).hexdigest()
    if replay_tx_id != replay["tx_id"] or replay_tx_id == claim_tx_id:
        raise AssertionError("spent-claim replay transaction ID is invalid or not distinct")
    if not replay.get("stateless_authorization_verified"):
        raise AssertionError("spent-claim replay was not statelessly verified")
    return {
        "envelope": envelope,
        "tx_id": tx_id,
        "anchor": transfer["anchor_hex"],
        "genesis_commitments": transfer["genesis_commitments_hex"],
        "nullifiers": transfer["nullifiers_hex"],
        "output_commitments": transfer["output_commitments_hex"],
        "claim": {
            "envelope": claim_envelope,
            "tx_id": claim_tx_id,
            "claim_id": claim["claim_id"],
            "claim_pubkey": claim["claim_pubkey"],
            "amount": int(claim["claim_amount_atomic"]),
            "fee": int(claim["fee_atomic"]),
            "output_commitments": claim["output_commitments_hex"],
            "spent_replay_envelope": replay_envelope,
            "spent_replay_tx_id": replay_tx_id,
        },
        "source_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }


def generated_exit_fixture(mode, current_height, anchor, expected_release=None):
    args = [EXIT_FIXTURE, mode, PROOF_PARAMETERS, current_height, anchor]
    if expected_release is not None:
        args.append(expected_release)
    fixture = json.loads(command(args, timeout=120))
    envelope = bytes.fromhex(fixture["canonical_envelope_hex"])
    if len(envelope) != int(fixture["canonical_envelope_bytes"]):
        raise AssertionError(f"{mode} fixture envelope length mismatch")
    if hashlib.sha256(envelope).hexdigest() != fixture["tx_id"]:
        raise AssertionError(f"{mode} fixture transaction ID mismatch")
    for name in ("owner_pubkey", "position_id", "ticket_id"):
        if len(bytes.fromhex(fixture[name])) != 32:
            raise AssertionError(f"{mode} fixture {name} must be 32 bytes")
    if not all(
        fixture.get(name)
        for name in (
            "output_proof_verified",
            "stateless_authorization_verified",
            "binding_signature_verified",
        )
    ):
        raise AssertionError(f"{mode} fixture verification is incomplete")
    fixture["envelope"] = envelope
    return fixture


def decode_exit_ticket(value):
    if len(value) != 162 or value[0] != 1 or value[161] not in (0, 1):
        raise AssertionError("invalid persistent exit ticket")
    return {
        "ticket_id": value[1:33].hex(),
        "position_id": value[33:65].hex(),
        "owner_pubkey": value[65:97].hex(),
        "cohort_id": value[97:129].hex(),
        "units_atomic": int.from_bytes(value[129:145], "big"),
        "created_position_sequence": int.from_bytes(value[145:153], "big"),
        "sequence": int.from_bytes(value[153:161], "big"),
        "claimed": bool(value[161]),
    }


def decode_exit_cohort(value):
    if len(value) not in (123, 139) or value[0] != 1:
        raise AssertionError("invalid persistent exit cohort")
    has_times = value[113]
    if has_times not in (0, 1) or len(value) != (139 if has_times else 123):
        raise AssertionError("invalid persistent exit cohort time encoding")
    offset = 114
    exposure_end_time = None
    maturity_time = None
    if has_times:
        exposure_end_time = int.from_bytes(value[offset : offset + 8], "big")
        maturity_time = int.from_bytes(value[offset + 8 : offset + 16], "big")
        offset += 16
    status = value[offset + 8]
    if status not in (0, 1, 2):
        raise AssertionError("invalid persistent exit cohort status")
    return {
        "cohort_id": value[1:33].hex(),
        "validator_id": value[33:65].hex(),
        "exit_epoch": int.from_bytes(value[65:73], "big"),
        "assets_atomic": int.from_bytes(value[73:89], "big"),
        "total_units_atomic": int.from_bytes(value[89:105], "big"),
        "exposure_end_height": int.from_bytes(value[105:113], "big"),
        "exposure_end_time_seconds": exposure_end_time,
        "maturity_time_seconds": maturity_time,
        "maturity_height": int.from_bytes(value[offset : offset + 8], "big"),
        "status": status,
    }


def exit_cohort_values(cohort_id, height_value=None):
    return [
        state_query(index, f"staking/exits/cohorts/{cohort_id}", height_value)
        for index in range(4)
    ]


def wait_exit_status(cohort_id, expected_status, seconds=90):
    deadline = time.monotonic() + seconds
    observed = None
    while time.monotonic() < deadline:
        values = exit_cohort_values(cohort_id)
        if values[0] and len(set(values)) == 1:
            observed = decode_exit_cohort(values[0])
            if observed["status"] == expected_status:
                return values, observed
        time.sleep(0.2)
    raise TimeoutError(
        f"exit cohort {cohort_id} did not reach status {expected_status}: {observed}"
    )


def broadcast_transaction(fixture, label):
    response = rpc(0, "broadcast_tx_sync?tx=0x" + fixture["envelope"].hex())
    if int(response["code"]) != 0:
        raise AssertionError(f"CheckTx rejected {label}: {response}")
    if response["hash"].lower() != fixture["tx_id"]:
        raise AssertionError("CometBFT transaction hash differs from BIT transaction ID")


def wait_transaction(fixture, first_height, label="transaction", seconds=90):
    deadline = time.monotonic() + seconds
    checked_through = first_height - 1
    pending = None
    while time.monotonic() < deadline:
        if pending is not None:
            block_height, index = pending
            try:
                results = rpc(0, f"block_results?height={block_height}")
            except urllib.error.HTTPError:
                time.sleep(0.1)
                continue
            tx_results = results.get("txs_results") or []
            if index >= len(tx_results) or int(tx_results[index]["code"]) != 0:
                raise AssertionError(f"FinalizeBlock rejected {label}")
            return block_height, index, results
        latest = height(0)
        for block_height in range(checked_through + 1, latest + 1):
            block = rpc(0, f"block?height={block_height}")["block"]
            transactions = block.get("data", {}).get("txs") or []
            for index, encoded in enumerate(transactions):
                if base64.b64decode(encoded) != fixture["envelope"]:
                    continue
                pending = (block_height, index)
                break
            if pending is not None:
                break
        checked_through = max(checked_through, latest)
        time.sleep(0.3)
    raise TimeoutError(f"{label} was not included after height {first_height}")


def block_artifact_event(results, block_height):
    events = results.get("finalize_block_events") or []
    matches = [event for event in events if event.get("type") == "bit.block.v1"]
    if len(matches) != 1:
        raise AssertionError(f"expected one block artifact event, got {len(matches)}")
    attributes = {attribute["key"]: attribute["value"] for attribute in matches[0]["attributes"]}
    if attributes.get("height") != str(block_height):
        raise AssertionError("block artifact event height mismatch")
    for name in ("execution_hash", "compact_hash"):
        if len(bytes.fromhex(attributes[name])) != 32:
            raise AssertionError(f"invalid {name} in block artifact event")
    if int(attributes.get("compact_bytes", "0")) <= 0:
        raise AssertionError("compact block event reported an empty artifact")
    return attributes


def domain_hash(domain, value):
    return hashlib.sha256(domain + len(value).to_bytes(8, "big") + value).digest()


def bit_evidence_hash(chain_id, evidence):
    del chain_id
    chain_context = hashlib.sha256(
        b"bit/chain/v1" + bytes.fromhex(GENESIS_MANIFEST_HASH_HEX)
    ).digest()
    payload = b"".join(
        [
            b"BIT-EVIDENCE-V1",
            chain_context,
            b"\x01",
            bytes.fromhex(evidence["validator_address"]),
            int(evidence["validator_power"]).to_bytes(8, "big"),
            int(evidence["infraction_height"]).to_bytes(8, "big"),
            int(evidence["infraction_time_seconds"]).to_bytes(8, "big"),
            int(evidence["infraction_time_nanos"]).to_bytes(4, "big"),
            int(evidence["total_voting_power"]).to_bytes(8, "big"),
        ]
    )
    return hashlib.sha256(payload).hexdigest()


def wait_evidence_inclusion(first_height, validator_address, seconds=60):
    address = bytes.fromhex(validator_address)
    address_markers = {
        validator_address.lower(),
        base64.b64encode(address).decode("ascii").lower(),
    }
    deadline = time.monotonic() + seconds
    checked_through = first_height - 1
    while time.monotonic() < deadline:
        latest = height(0)
        for block_height in range(checked_through + 1, latest + 1):
            block = rpc(0, f"block?height={block_height}")["block"]
            evidence = block.get("evidence", {}).get("evidence", [])
            encoded_evidence = json.dumps(evidence, separators=(",", ":")).lower()
            if evidence and any(
                marker in encoded_evidence for marker in address_markers
            ):
                return block_height
        checked_through = max(checked_through, latest)
        time.sleep(0.3)
    raise TimeoutError(f"evidence was not included after height {first_height}")


def configure_network(fixture):
    command(
        [
            COMET,
            "testnet",
            "--v",
            "4",
            "--o",
            RUN / "nodes",
            "--populate-persistent-peers=false",
        ]
    )
    node_ids = [
        command([COMET, "show-node-id", "--home", RUN / f"nodes/node{i}"])
        for i in range(4)
    ]
    genesis_path = RUN / "nodes/node0/config/genesis.json"
    genesis = json.loads(genesis_path.read_text(encoding="utf-8"))
    genesis["chain_id"] = "bit-app-probe-" + RUN.name.rsplit("-", 1)[-1]
    genesis["genesis_time"] = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=3)
    ).isoformat().replace("+00:00", "Z")
    genesis["initial_height"] = "1"
    genesis["consensus_params"]["version"]["app"] = "1"
    genesis["consensus_params"]["abci"]["vote_extensions_enable_height"] = "0"
    genesis["app_state"] = {
        "bit_app_network_probe": 4,
        "genesis_claim": {
            "amount_atomic": str(fixture["claim"]["amount"]),
            "claim_id_hex": fixture["claim"]["claim_id"],
            "claim_pubkey_hex": fixture["claim"]["claim_pubkey"],
        },
        "genesis_commitments_hex": fixture["genesis_commitments"],
        "genesis_manifest_hash_hex": GENESIS_MANIFEST_HASH_HEX,
    }
    for validator in genesis["validators"]:
        validator["power"] = "10"
    genesis_bytes = json.dumps(genesis, separators=(",", ":"))

    for index in range(4):
        config_dir = RUN / f"nodes/node{index}/config"
        (config_dir / "genesis.json").write_text(genesis_bytes, encoding="utf-8")
        config = (config_dir / "config.toml").read_text(encoding="utf-8")
        peers = ",".join(
            f"{node_ids[peer]}@127.0.0.1:{29800 + peer}"
            for peer in range(4)
            if peer != index
        )
        replacements = {
            "proxy_app": f'"tcp://127.0.0.1:{29900 + index}"',
            "persistent_peers": json.dumps(peers),
            "allow_duplicate_ip": "true",
            "addr_book_strict": "false",
            "pex": "false",
            "timeout_propose": '"500ms"',
            "timeout_propose_delta": '"100ms"',
            "timeout_prevote": '"200ms"',
            "timeout_precommit": '"200ms"',
            "timeout_commit": '"500ms"',
            "log_level": '"error"',
            "indexer": '"null"',
        }
        for name, value in replacements.items():
            config, count = re.subn(
                rf"^{re.escape(name)} = .*$", f"{name} = {value}", config, flags=re.M
            )
            if count < 1:
                raise RuntimeError(f"missing CometBFT config key: {name}")
        config = config.replace(
            "tcp://127.0.0.1:26657", f"tcp://127.0.0.1:{29700 + index}"
        )
        config = config.replace(
            "tcp://0.0.0.0:26656", f"tcp://127.0.0.1:{29800 + index}"
        )
        config = config.replace(
            "tcp://127.0.0.1:26656", f"tcp://127.0.0.1:{29800 + index}"
        )
        (config_dir / "config.toml").write_text(config, encoding="utf-8")


def main():
    if (
        not APP.is_file()
        or not EXIT_FIXTURE.is_file()
        or not COMET.is_file()
        or not GO.is_file()
        or not EVIDENCE_INJECTOR.is_file()
        or not (PROOF_PARAMETERS / "output_pk.bin").is_file()
    ):
        raise RuntimeError("build the probes and bootstrap CometBFT before running")
    fixture = load_transfer_fixture()
    comet_self_reported_version = command([COMET, "version"])
    comet_build_info = command([GO, "version", "-m", COMET])
    module_match = re.search(
        r"^\s*mod\s+github\.com/cometbft/cometbft\s+(v[^\s]+)",
        comet_build_info,
        flags=re.M,
    )
    comet_module_version = module_match.group(1) if module_match else None
    if comet_module_version != "v0.38.23":
        raise RuntimeError(
            f"expected CometBFT module v0.38.23, got {comet_module_version}"
        )
    for port in list(range(29700, 29704)) + list(range(29800, 29804)) + list(
        range(29900, 29904)
    ):
        with socket.socket() as check:
            check.bind(("127.0.0.1", port))
    RUN.mkdir(parents=True)
    configure_network(fixture)
    for index in range(4):
        start_pair(index)

    wait_height(10)
    first_transfer_height = height(0) + 1
    broadcast_transaction(fixture, "Transfer")
    transfer_height, transfer_index, transfer_results = wait_transaction(
        fixture, first_transfer_height, "Transfer"
    )
    wait_height(transfer_height + 2)
    artifact_event = block_artifact_event(transfer_results, transfer_height)
    transaction_records = [
        state_query(index, f"transactions/applied/{fixture['tx_id']}", transfer_height)
        for index in range(4)
    ]
    if not transaction_records[0] or len(set(transaction_records)) != 1:
        raise AssertionError("proved transaction records differ across applications")
    nullifier_records = {
        nullifier: [
            state_query(index, f"shielded/nullifier/{nullifier}", transfer_height)
            for index in range(4)
        ]
        for nullifier in fixture["nullifiers"]
    }
    if any(
        not values[0] or len(set(values)) != 1
        for values in nullifier_records.values()
    ):
        raise AssertionError("proved nullifier records differ across applications")
    execution_hashes = [
        state_query(index, f"execution/block/{transfer_height:020}", transfer_height).hex()
        for index in range(4)
    ]
    compact_hashes = [
        state_query(index, f"compact/hash/{transfer_height:020}", transfer_height).hex()
        for index in range(4)
    ]
    if len(set(execution_hashes)) != 1 or execution_hashes[0] != artifact_event["execution_hash"]:
        raise AssertionError("execution artifact hash differs from proved state or ABCI event")
    if len(set(compact_hashes)) != 1 or compact_hashes[0] != artifact_event["compact_hash"]:
        raise AssertionError("compact artifact hash differs from proved state or ABCI event")
    execution_archives = [
        archived_artifact(index, transfer_height, "execution") for index in range(4)
    ]
    compact_archives = [
        archived_artifact(index, transfer_height, "compact") for index in range(4)
    ]
    if len(set(execution_archives)) != 1 or artifact_hash(
        b"bit/execution-summary/v1", execution_archives[0]
    ) != execution_hashes[0]:
        raise AssertionError("archived execution artifact differs across nodes or from state")
    if len(set(compact_archives)) != 1 or artifact_hash(
        b"bit/compact-block/v1", compact_archives[0]
    ) != compact_hashes[0]:
        raise AssertionError("archived compact artifact differs across nodes or from state")
    tree_roots = [
        state_query(index, "shielded/tree_root", transfer_height).hex()
        for index in range(4)
    ]
    if len(set(tree_roots)) != 1 or tree_roots[0] == fixture["anchor"]:
        raise AssertionError("output commitments did not advance a common shielded tree root")
    supply_audits = [
        state_query(index, "supply/audit_snapshot", transfer_height)
        for index in range(4)
    ]
    if not supply_audits[0] or len(set(supply_audits)) != 1:
        raise AssertionError("proved supply audit snapshots differ across applications")
    transfer_app_hashes = {
        rpc(index, f"block?height={transfer_height + 1}")["block"]["header"][
            "app_hash"
        ].lower()
        for index in range(4)
    }
    if len(transfer_app_hashes) != 1:
        raise AssertionError("application hash diverged after transfer execution")
    powers = {
        str(height_value): validator_powers(height_value)
        for height_value in (6, 7, 8)
    }
    if set(powers["6"].values()) != {10} or powers["7"] != powers["6"]:
        raise AssertionError(f"validator power changed before H+2: {powers}")
    if powers["8"].keys() != powers["6"].keys() or not all(
        power > 10 for power in powers["8"].values()
    ):
        raise AssertionError(f"validator update missing at H+2: {powers}")

    claim = fixture["claim"]
    scheduled_from_height = wait_height_remainder(1, 5)
    first_claim_height = scheduled_from_height + 1
    broadcast_transaction(claim, "ClaimGenesis")
    claim_height, claim_index, _ = wait_transaction(
        claim, first_claim_height, "ClaimGenesis"
    )
    if claim_height % 5 == 1:
        raise AssertionError("ClaimGenesis landed on an epoch settlement block")
    wait_height(claim_height + 2)
    claim_key = f"genesis/claims/{claim['claim_id']}"
    claim_records = [
        state_query(index, claim_key, claim_height) for index in range(4)
    ]
    expected_claim_record = b"".join(
        [
            b"\x01",
            bytes.fromhex(claim["claim_pubkey"]),
            claim["amount"].to_bytes(16, "big"),
            b"\x01",
            claim_height.to_bytes(8, "big"),
        ]
    )
    if len(set(claim_records)) != 1 or claim_records[0] != expected_claim_record:
        raise AssertionError("claimed genesis record differs across applications or from fixture")

    container_keys = {
        "unclaimed": "genesis/unclaimed_total",
        "shielded": "supply/shielded_total",
        "fees": "fees/reserve",
    }
    before_claim = {
        name: int.from_bytes(state_query(0, key, claim_height - 1), "big")
        for name, key in container_keys.items()
    }
    after_claim = {
        name: [
            int.from_bytes(state_query(index, key, claim_height), "big")
            for index in range(4)
        ]
        for name, key in container_keys.items()
    }
    if any(len(set(values)) != 1 for values in after_claim.values()):
        raise AssertionError("ClaimGenesis supply containers differ across applications")
    expected_deltas = {
        "unclaimed": -claim["amount"],
        "shielded": claim["amount"] - claim["fee"],
        "fees": claim["fee"],
    }
    for name, delta in expected_deltas.items():
        if after_claim[name][0] - before_claim[name] != delta:
            raise AssertionError(f"ClaimGenesis {name} delta is incorrect")
    claim_transaction_records = [
        state_query(index, f"transactions/applied/{claim['tx_id']}", claim_height)
        for index in range(4)
    ]
    if not claim_transaction_records[0] or len(set(claim_transaction_records)) != 1:
        raise AssertionError("ClaimGenesis transaction record differs across applications")
    spent_claim_replay = rpc(
        0, "broadcast_tx_sync?tx=0x" + claim["spent_replay_envelope"].hex()
    )
    if int(spent_claim_replay["code"]) == 0:
        raise AssertionError("distinct transaction for an already spent claim was accepted")
    if spent_claim_replay.get("hash", "").lower() != claim["spent_replay_tx_id"]:
        raise AssertionError("spent-claim replay response has the wrong transaction ID")
    claim_tree_roots = [
        state_query(index, "shielded/tree_root", claim_height).hex()
        for index in range(4)
    ]
    if len(set(claim_tree_roots)) != 1 or claim_tree_roots[0] == tree_roots[0]:
        raise AssertionError("ClaimGenesis outputs did not advance a common shielded tree root")
    claim_app_hashes = {
        rpc(index, f"block?height={claim_height + 1}")["block"]["header"][
            "app_hash"
        ].lower()
        for index in range(4)
    }
    if len(claim_app_hashes) != 1:
        raise AssertionError("application hash diverged after ClaimGenesis")

    unbond_generation_height = height(0)
    unbond = generated_exit_fixture(
        "unbond",
        unbond_generation_height,
        state_query(0, "shielded/tree_root").hex(),
    )
    scheduled_from_height = wait_height_remainder(2, PROBE_EPOCH_BLOCKS)
    first_unbond_height = scheduled_from_height + 1
    broadcast_transaction(unbond, "Unbond")
    unbond_height, unbond_index, _ = wait_transaction(
        unbond, first_unbond_height, "Unbond"
    )
    if unbond_height % PROBE_EPOCH_BLOCKS == 1:
        raise AssertionError("Unbond landed on an epoch settlement block")
    wait_height(unbond_height + 2)

    exit_container_keys = {
        "stake": "supply/stake_total",
        "exits": "supply/exit_total",
        "shielded": "supply/shielded_total",
        "fees": "fees/reserve",
    }
    before_unbond = {
        name: int.from_bytes(state_query(0, key, unbond_height - 1), "big")
        for name, key in exit_container_keys.items()
    }
    after_unbond = {
        name: [
            int.from_bytes(state_query(index, key, unbond_height), "big")
            for index in range(4)
        ]
        for name, key in exit_container_keys.items()
    }
    if any(len(set(values)) != 1 for values in after_unbond.values()):
        raise AssertionError("Unbond supply containers differ across applications")
    unbond_fee = int(unbond["fee_atomic"])
    unbond_gross = before_unbond["stake"] - after_unbond["stake"][0]
    exit_release = after_unbond["exits"][0] - before_unbond["exits"]
    if unbond_gross != exit_release + unbond_fee:
        raise AssertionError("Unbond stake, exit and fee deltas do not balance")
    if after_unbond["shielded"][0] != before_unbond["shielded"]:
        raise AssertionError("zero-value Unbond output changed shielded supply")
    if after_unbond["fees"][0] - before_unbond["fees"] != unbond_fee:
        raise AssertionError("Unbond fee reserve delta is incorrect")

    ticket_key = f"staking/exits/tickets/{unbond['ticket_id']}"
    ticket_values = [
        state_query(index, ticket_key, unbond_height) for index in range(4)
    ]
    if not ticket_values[0] or len(set(ticket_values)) != 1:
        raise AssertionError("Unbond exit ticket differs across applications")
    ticket = decode_exit_ticket(ticket_values[0])
    for name in ("ticket_id", "position_id", "owner_pubkey"):
        if ticket[name] != unbond[name]:
            raise AssertionError(f"Unbond exit ticket {name} differs from fixture")
    if (
        ticket["units_atomic"] != exit_release
        or ticket["created_position_sequence"] != 1
        or ticket["sequence"] != 0
        or ticket["claimed"]
    ):
        raise AssertionError("Unbond exit ticket state is incorrect")

    cohort_id = ticket["cohort_id"]
    cohort_values = exit_cohort_values(cohort_id, unbond_height)
    if not cohort_values[0] or len(set(cohort_values)) != 1:
        raise AssertionError("Unbond exit cohort differs across applications")
    pending_cohort = decode_exit_cohort(cohort_values[0])
    expected_exit_epoch = (unbond_height - 1) // PROBE_EPOCH_BLOCKS
    expected_exposure_height = (expected_exit_epoch + 1) * PROBE_EPOCH_BLOCKS + 2
    if (
        pending_cohort["cohort_id"] != cohort_id
        or pending_cohort["exit_epoch"] != expected_exit_epoch
        or pending_cohort["assets_atomic"] != exit_release
        or pending_cohort["total_units_atomic"] != exit_release
        or pending_cohort["exposure_end_height"] != expected_exposure_height
        or pending_cohort["exposure_end_time_seconds"] is not None
        or pending_cohort["maturity_time_seconds"] is not None
        or pending_cohort["maturity_height"]
        != expected_exposure_height + PROBE_UNBONDING_BLOCKS
        or pending_cohort["status"] != 0
    ):
        raise AssertionError(f"unexpected pending exit cohort: {pending_cohort}")
    unbond_transaction_records = [
        state_query(index, f"transactions/applied/{unbond['tx_id']}", unbond_height)
        for index in range(4)
    ]
    if not unbond_transaction_records[0] or len(set(unbond_transaction_records)) != 1:
        raise AssertionError("Unbond transaction record differs across applications")
    unbond_tree_roots = [
        state_query(index, "shielded/tree_root", unbond_height).hex()
        for index in range(4)
    ]
    if len(set(unbond_tree_roots)) != 1 or unbond_tree_roots[0] == claim_tree_roots[0]:
        raise AssertionError("Unbond output did not advance a common shielded tree root")

    _, unbonding_cohort = wait_exit_status(cohort_id, 1)
    if (
        unbonding_cohort["exposure_end_time_seconds"] is None
        or unbonding_cohort["maturity_time_seconds"]
        != unbonding_cohort["exposure_end_time_seconds"] + PROBE_UNBONDING_SECONDS
    ):
        raise AssertionError("Unbonding cohort time bounds are incorrect")
    unbonding_restart_height = height(0)
    if unbonding_restart_height >= unbonding_cohort["maturity_height"]:
        raise AssertionError("application restart was not initiated during Unbonding")
    stop("node0")
    stop("app0")
    start_pair(0)
    unbonding_resumed = wait_height(unbonding_restart_height + 3)
    if state_query(0, ticket_key, unbond_height) != ticket_values[0]:
        raise AssertionError("historical exit ticket changed after Unbonding restart")
    if exit_cohort_values(cohort_id, unbond_height)[0] != cohort_values[0]:
        raise AssertionError("historical exit cohort changed after Unbonding restart")

    mature_cohort_values, mature_cohort = wait_exit_status(cohort_id, 2)
    if (
        len(set(mature_cohort_values)) != 1
        or mature_cohort["assets_atomic"] != exit_release
        or mature_cohort["total_units_atomic"] != exit_release
    ):
        raise AssertionError("mature exit cohort differs across applications")

    claim_exit_generation_height = height(0)
    claim_exit = generated_exit_fixture(
        "claim",
        claim_exit_generation_height,
        state_query(0, "shielded/tree_root").hex(),
        exit_release,
    )
    scheduled_from_height = wait_height_remainder(2, PROBE_EPOCH_BLOCKS)
    first_claim_exit_height = scheduled_from_height + 1
    broadcast_transaction(claim_exit, "ClaimExit")
    claim_exit_height, claim_exit_index, _ = wait_transaction(
        claim_exit, first_claim_exit_height, "ClaimExit"
    )
    if claim_exit_height % PROBE_EPOCH_BLOCKS == 1:
        raise AssertionError("ClaimExit landed on an epoch settlement block")
    wait_height(claim_exit_height + 2)
    before_claim_exit = {
        name: int.from_bytes(state_query(0, key, claim_exit_height - 1), "big")
        for name, key in exit_container_keys.items()
    }
    after_claim_exit = {
        name: [
            int.from_bytes(state_query(index, key, claim_exit_height), "big")
            for index in range(4)
        ]
        for name, key in exit_container_keys.items()
    }
    if any(len(set(values)) != 1 for values in after_claim_exit.values()):
        raise AssertionError("ClaimExit supply containers differ across applications")
    claim_exit_fee = int(claim_exit["fee_atomic"])
    claim_exit_deltas = {
        "stake": 0,
        "exits": -exit_release,
        "shielded": exit_release - claim_exit_fee,
        "fees": claim_exit_fee,
    }
    for name, delta in claim_exit_deltas.items():
        if after_claim_exit[name][0] - before_claim_exit[name] != delta:
            raise AssertionError(f"ClaimExit {name} delta is incorrect")

    claimed_ticket_values = [
        state_query(index, ticket_key, claim_exit_height) for index in range(4)
    ]
    if len(set(claimed_ticket_values)) != 1:
        raise AssertionError("claimed exit ticket differs across applications")
    claimed_ticket = decode_exit_ticket(claimed_ticket_values[0])
    if (
        any(
            claimed_ticket[name] != ticket[name]
            for name in (
                "ticket_id",
                "position_id",
                "owner_pubkey",
                "cohort_id",
                "units_atomic",
                "created_position_sequence",
            )
        )
        or claimed_ticket["sequence"] != 1
        or not claimed_ticket["claimed"]
    ):
        raise AssertionError("ClaimExit did not consume the expected exit ticket")
    claimed_cohort_values = exit_cohort_values(cohort_id, claim_exit_height)
    if len(set(claimed_cohort_values)) != 1:
        raise AssertionError("claimed exit cohort differs across applications")
    claimed_cohort = decode_exit_cohort(claimed_cohort_values[0])
    if (
        any(
            claimed_cohort[name] != mature_cohort[name]
            for name in (
                "cohort_id",
                "validator_id",
                "exit_epoch",
                "exposure_end_height",
                "exposure_end_time_seconds",
                "maturity_time_seconds",
                "maturity_height",
                "status",
            )
        )
        or claimed_cohort["cohort_id"] != cohort_id
        or claimed_cohort["assets_atomic"] != 0
        or claimed_cohort["total_units_atomic"] != 0
        or claimed_cohort["status"] != 2
    ):
        raise AssertionError("ClaimExit did not drain the exit cohort")
    claim_exit_transaction_records = [
        state_query(
            index,
            f"transactions/applied/{claim_exit['tx_id']}",
            claim_exit_height,
        )
        for index in range(4)
    ]
    if not claim_exit_transaction_records[0] or len(set(claim_exit_transaction_records)) != 1:
        raise AssertionError("ClaimExit transaction record differs across applications")
    claim_exit_tree_roots = [
        state_query(index, "shielded/tree_root", claim_exit_height).hex()
        for index in range(4)
    ]
    if len(set(claim_exit_tree_roots)) != 1 or claim_exit_tree_roots[0] == unbond_tree_roots[0]:
        raise AssertionError("ClaimExit output did not advance a common shielded tree root")
    claim_exit_app_hashes = {
        rpc(index, f"block?height={claim_exit_height + 1}")["block"]["header"][
            "app_hash"
        ].lower()
        for index in range(4)
    }
    if len(claim_exit_app_hashes) != 1:
        raise AssertionError("application hash diverged after ClaimExit")
    claimed_ticket_replay = generated_exit_fixture(
        "claim",
        height(0),
        state_query(0, "shielded/tree_root").hex(),
        exit_release,
    )
    if claimed_ticket_replay["tx_id"] == claim_exit["tx_id"]:
        raise AssertionError("claimed-ticket replay must have a distinct transaction ID")
    claimed_ticket_replay_response = rpc(
        0,
        "broadcast_tx_sync?tx=0x" + claimed_ticket_replay["envelope"].hex(),
    )
    if int(claimed_ticket_replay_response["code"]) == 0:
        raise AssertionError("distinct transaction for a claimed exit ticket was accepted")
    if (
        claimed_ticket_replay_response.get("hash", "").lower()
        != claimed_ticket_replay["tx_id"]
    ):
        raise AssertionError("claimed-ticket replay response has the wrong transaction ID")

    restart_height = height(0)
    stop("node0")
    stop("app0")
    start_pair(0)
    resumed = wait_height(restart_height + 5)
    if archived_artifact(0, transfer_height, "execution") != execution_archives[0]:
        raise AssertionError("archived execution artifact changed after application restart")
    if archived_artifact(0, transfer_height, "compact") != compact_archives[0]:
        raise AssertionError("archived compact artifact changed after application restart")
    if state_query(
        0, f"compact/hash/{transfer_height:020}", transfer_height
    ).hex() != compact_hashes[0]:
        raise AssertionError("historical compact proof changed after application restart")
    if state_query(0, claim_key, claim_height) != expected_claim_record:
        raise AssertionError("ClaimGenesis record changed after application restart")
    if state_query(0, ticket_key, unbond_height) != ticket_values[0]:
        raise AssertionError("historical exit ticket changed after application restart")
    if state_query(0, ticket_key, claim_exit_height) != claimed_ticket_values[0]:
        raise AssertionError("claimed exit ticket changed after application restart")

    common_height = min(resumed) - 1
    headers = [rpc(i, f"block?height={common_height}")["block"]["header"] for i in range(4)]
    app_hashes = {header["app_hash"].lower() for header in headers}
    if len(app_hashes) != 1:
        raise AssertionError(f"application hash divergence at {common_height}")

    if not state_query(0, "meta/height"):
        raise AssertionError("latest meta/height proof was not returned")

    genesis_path = RUN / "nodes/node0/config/genesis.json"
    genesis = json.loads(genesis_path.read_text(encoding="utf-8"))
    evidence_height = min(height(index) for index in range(4)) - 2
    first_possible_inclusion = height(0) + 1
    evidence = json.loads(
        command(
            [
                EVIDENCE_INJECTOR,
                "--rpc",
                "http://127.0.0.1:29701",
                "--genesis",
                genesis_path,
                "--priv-validator-key",
                RUN / "nodes/node0/config/priv_validator_key.json",
                "--height",
                evidence_height,
            ]
        )
    )
    if int(evidence["infraction_height"]) != evidence_height:
        raise AssertionError("evidence injector returned the wrong height")
    evidence_inclusion_height = wait_evidence_inclusion(
        first_possible_inclusion, evidence["validator_address"]
    )
    wait_height(evidence_inclusion_height + 3)

    validator_address = evidence["validator_address"].lower()
    before_removal = rpc(
        0, f"validators?height={evidence_inclusion_height + 1}&per_page=100"
    )["validators"]
    after_removal = rpc(
        0, f"validators?height={evidence_inclusion_height + 2}&per_page=100"
    )["validators"]
    if not any(
        validator["address"].lower() == validator_address
        for validator in before_removal
    ):
        raise AssertionError("Byzantine validator disappeared before H+2")
    if any(
        validator["address"].lower() == validator_address
        for validator in after_removal
    ):
        raise AssertionError("Byzantine validator was not removed at H+2")
    if len(after_removal) != 3:
        raise AssertionError(f"unexpected post-slash validator count: {len(after_removal)}")

    bit_hash = bit_evidence_hash(genesis["chain_id"], evidence)
    evidence_values = [
        state_query(index, f"staking/evidence/{bit_hash}") for index in range(4)
    ]
    if not evidence_values[0] or len(set(evidence_values)) != 1:
        raise AssertionError("proved BIT evidence records differ across applications")
    burned_values = [state_query(index, "supply/burned") for index in range(4)]
    if len(set(burned_values)) != 1 or int.from_bytes(burned_values[0], "big") <= 0:
        raise AssertionError("slashed Burn is zero or differs across applications")
    post_evidence_height = evidence_inclusion_height + 2
    post_evidence_app_hashes = {
        rpc(index, f"block?height={post_evidence_height}")["block"]["header"][
            "app_hash"
        ].lower()
        for index in range(4)
    }
    if len(post_evidence_app_hashes) != 1:
        raise AssertionError("application hash diverged after evidence execution")

    stop("node2")
    halted_height = wait_quorum_halt()
    spawn("node2", [COMET, "start", "--home", RUN / "nodes/node2"])
    recovered = wait_height(halted_height + 4)

    return {
        "scope": "four CometBFT v0.38.23 processes using real bit-app, bit-state JMT/RocksDB, Groth16 Transfer, ClaimGenesis, Unbond and ClaimExit, canonical block artifacts, staking and emission",
        "runtime_dir": str(RUN),
        "toolchain": {
            "cometbft_module": comet_module_version,
            "cometbft_self_reported": comet_self_reported_version,
            "cometbft_sha256": hashlib.sha256(COMET.read_bytes()).hexdigest(),
            "application_sha256": hashlib.sha256(APP.read_bytes()).hexdigest(),
            "exit_fixture_sha256": hashlib.sha256(EXIT_FIXTURE.read_bytes()).hexdigest(),
            "evidence_injector_sha256": hashlib.sha256(
                EVIDENCE_INJECTOR.read_bytes()
            ).hexdigest(),
        },
        "checks": {
            "real_transfer": {
                "fixture_source_sha256": fixture["source_sha256"],
                "height": transfer_height,
                "index": transfer_index,
                "canonical_envelope_bytes": len(fixture["envelope"]),
                "tx_id": fixture["tx_id"],
                "nullifiers": fixture["nullifiers"],
                "output_commitments": fixture["output_commitments"],
                "transaction_record_proved_on_nodes": 4,
                "nullifier_records_proved_on_nodes": 4,
                "post_transfer_tree_root": tree_roots[0],
                "post_transfer_app_hash": next(iter(transfer_app_hashes)),
            },
            "canonical_block_artifacts": {
                "height": transfer_height,
                "execution_hash": execution_hashes[0],
                "compact_hash": compact_hashes[0],
                "execution_bytes": len(execution_archives[0]),
                "compact_bytes": int(artifact_event["compact_bytes"]),
                "state_proofs_and_abci_event_match_on_nodes": 4,
                "immutable_archives_match_on_nodes": 4,
                "archive_restart_readback": True,
                "historical_state_proofs_at_exact_height": 4,
                "historical_proof_after_restart": True,
            },
            "canonical_supply_audit": {
                "canonical_bytes": len(supply_audits[0]),
                "sha256": hashlib.sha256(supply_audits[0]).hexdigest(),
                "state_proved_on_nodes": 4,
            },
            "claim_genesis": {
                "height": claim_height,
                "index": claim_index,
                "tx_id": claim["tx_id"],
                "claim_id": claim["claim_id"],
                "claim_amount_atomic": str(claim["amount"]),
                "fee_atomic": str(claim["fee"]),
                "output_commitments": claim["output_commitments"],
                "transaction_and_claim_records_proved_on_nodes": 4,
                "container_deltas": {
                    name: str(delta) for name, delta in expected_deltas.items()
                },
                "post_claim_tree_root": claim_tree_roots[0],
                "post_claim_app_hash": claim_app_hashes.pop(),
                "distinct_spent_claim_replay": {
                    "tx_id": claim["spent_replay_tx_id"],
                    "check_tx_code": int(spent_claim_replay["code"]),
                    "rejected_by_bit_app": True,
                },
                "historical_proof_after_restart": True,
            },
            "real_exit": {
                "unbond_height": unbond_height,
                "unbond_index": unbond_index,
                "unbond_tx_id": unbond["tx_id"],
                "claim_exit_height": claim_exit_height,
                "claim_exit_index": claim_exit_index,
                "claim_exit_tx_id": claim_exit["tx_id"],
                "owner_pubkey": unbond["owner_pubkey"],
                "position_id": unbond["position_id"],
                "ticket_id": unbond["ticket_id"],
                "cohort_id": cohort_id,
                "shares_atomic": unbond["shares_atomic"],
                "gross_atomic": str(unbond_gross),
                "exit_release_atomic": str(exit_release),
                "unbond_fee_atomic": str(unbond_fee),
                "claim_exit_fee_atomic": str(claim_exit_fee),
                "claim_output_atomic": claim_exit["output_amount_atomic"],
                "zero_value_unbond_output_commitment": unbond[
                    "zero_value_output_commitment"
                ],
                "claim_output_commitments": claim_exit["output_commitments_hex"],
                "pending_cohort": pending_cohort,
                "mature_cohort": mature_cohort,
                "unbond_container_deltas": {
                    "stake": str(-unbond_gross),
                    "exits": str(exit_release),
                    "shielded": "0",
                    "fees": str(unbond_fee),
                },
                "claim_exit_container_deltas": {
                    name: str(delta) for name, delta in claim_exit_deltas.items()
                },
                "unbonding_restart_height": unbonding_restart_height,
                "unbonding_restart_resumed_heights": unbonding_resumed,
                "output_proofs_verified": True,
                "position_owner_authorizations_verified": True,
                "binding_signatures_verified": True,
                "transaction_ticket_and_cohort_records_proved_on_nodes": 4,
                "historical_pending_and_claimed_records_after_restart": True,
                "post_claim_exit_tree_root": claim_exit_tree_roots[0],
                "post_claim_exit_app_hash": claim_exit_app_hashes.pop(),
                "distinct_claimed_ticket_replay": {
                    "tx_id": claimed_ticket_replay["tx_id"],
                    "check_tx_code": int(claimed_ticket_replay_response["code"]),
                    "rejected_by_bit_app": True,
                },
            },
            "validator_powers_h6_h7_h8": powers,
            "h_plus_two_update": True,
            "process_restart_from_durable_jmt_height": restart_height,
            "resumed_heights": resumed,
            "same_app_hash_height": common_height,
            "same_app_hash": app_hashes.pop(),
            "latest_and_historical_ics23_proofs": True,
            "real_duplicate_vote_evidence": {
                **evidence,
                "inclusion_height": evidence_inclusion_height,
                "bit_evidence_hash": bit_hash,
                "validator_present_at_h_plus_one": True,
                "validator_removed_at_h_plus_two": True,
                "post_evidence_validator_count": len(after_removal),
                "burned_atomic": str(int.from_bytes(burned_values[0], "big")),
                "same_app_hash": post_evidence_app_hashes.pop(),
                "ics23_evidence_membership": True,
            },
            "quorum_halt_height": halted_height,
            "quorum_recovery_heights": recovered,
        },
        "limitations": [
            "accelerated five-block epochs, eight-block/eight-second unbonding and deterministic probe genesis",
            "upstream CometBFT FilePV signer, not the future independent BIT signer",
            "same physical host, not independent failure domains",
        ],
    }


if __name__ == "__main__":
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        result = main()
        result.update(
            status="PASS",
            started_at=started,
            finished_at=dt.datetime.now(dt.timezone.utc).isoformat(),
        )
        REPORT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        (RUN / "result.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        print(
            "Real BIT app four-node Transfer, ClaimGenesis, Unbond, ClaimExit, H+2, slashing, restart and quorum checks passed"
        )
    except Exception as error:
        failure = {
            "status": "FAIL",
            "started_at": started,
            "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "runtime_dir": str(RUN),
            "error": repr(error),
        }
        REPORT.write_text(json.dumps(failure, indent=2) + "\n", encoding="utf-8")
        if RUN.exists():
            (RUN / "result.json").write_text(
                json.dumps(failure, indent=2) + "\n", encoding="utf-8"
            )
        raise
    finally:
        for name in [name for name in list(PROCESSES) if name.startswith("node")]:
            stop(name)
        for name in [name for name in list(PROCESSES) if name.startswith("app")]:
            stop(name)
        for handle in HANDLES:
            handle.close()
