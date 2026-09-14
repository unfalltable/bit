"""Exercise official bit-node State Sync over a real three-node CometBFT network."""

from pathlib import Path
import base64
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
FEASIBILITY = ROOT / "feasibility"
COMET = FEASIBILITY / ".tools/bin/cometbft.exe"
GO = FEASIBILITY / ".tools/go/bin/go.exe"
TARGET_DIR = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
BIT = TARGET_DIR / "debug/bit.exe"
BIT_NODE = TARGET_DIR / "debug/bit-node.exe"
RUN = FEASIBILITY / "runtime" / (
    "bit-state-sync-"
    + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
)
REPORT = ROOT / "reports/state-sync-smoke.json"
IDENTITY_FIXTURE = ROOT / "tests/fixtures/genesis-identity-input.test.json"
RUNTIME_FIXTURE = ROOT / "tests/fixtures/genesis-runtime-inputs.test.json"
SNAPSHOT_INTERVAL = 5
APP_STATE_SYNC = {
    0: {"interval": SNAPSHOT_INTERVAL, "keep_recent": 100},
    2: {"interval": 1_000, "keep_recent": 3},
}
ENV = os.environ.copy()
ENV["PATH"] = os.pathsep.join(
    [
        str(FEASIBILITY / ".tools/rust/bin"),
        str(FEASIBILITY / ".tools/llvm-mingw-20250812-msvcrt-x86_64/bin"),
        ENV["PATH"],
    ]
)
PROCESSES = {}
LOG_PATHS = {}
HANDLES = []
PORTS = {}


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
        raise RuntimeError(
            f"command failed ({completed.returncode}): {args}\n"
            f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
        )
    return completed.stdout.strip()


def command_json(args, timeout=60):
    return json.loads(command(args, timeout=timeout))


def reserve_ports(count):
    reservations = []
    ports = []
    for _ in range(count):
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        ports.append(reservation.getsockname()[1])
        reservations.append(reservation)
    return ports, reservations


def rpc(index, path, timeout=2):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{PORTS[index]['rpc']}/{path}", timeout=timeout
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


def log_tail(name, limit=8000):
    path = LOG_PATHS.get(name)
    if path is None or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[-limit:]


def spawn(name, args):
    log_path = RUN / f"{name}-{time.time_ns()}.log"
    output = log_path.open("wb")
    HANDLES.append(output)
    LOG_PATHS[name] = log_path
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


def assert_processes_live(names=None):
    selected = PROCESSES.items() if names is None else ((name, PROCESSES[name]) for name in names)
    failed = [name for name, process in selected if process.poll() is not None]
    if failed:
        details = "\n".join(f"[{name}]\n{log_tail(name)}" for name in failed)
        raise RuntimeError(f"processes exited unexpectedly: {failed}\n{details}")


def wait_log(name, marker, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        process = PROCESSES[name]
        if process.poll() is not None:
            raise RuntimeError(f"{name} exited before readiness\n{log_tail(name)}")
        if marker in log_tail(name):
            return
        time.sleep(0.1)
    raise TimeoutError(f"{name} did not report readiness\n{log_tail(name)}")


def wait_heights(indices, minimum, seconds=90):
    deadline = time.monotonic() + seconds
    observed = [0 for _ in indices]
    names = [name for index in indices for name in (f"app{index}", f"node{index}")]
    while time.monotonic() < deadline:
        assert_processes_live(names)
        observed = [height(index) for index in indices]
        if all(value >= minimum for value in observed):
            return observed
        time.sleep(0.25)
    raise TimeoutError(f"nodes {indices} did not reach height {minimum}: {observed}")


def replace_config_value(config, name, value):
    config, count = re.subn(
        rf"^{re.escape(name)} = .*$", f"{name} = {value}", config, flags=re.M
    )
    if count != 1:
        raise RuntimeError(f"expected one CometBFT config key {name}, got {count}")
    return config


def replace_section_value(config, section, name, value):
    pattern = rf"(?ms)(^\[{re.escape(section)}\]\s.*?^){re.escape(name)} = .*?$"
    config, count = re.subn(pattern, rf"\g<1>{name} = {value}", config, count=1)
    if count != 1:
        raise RuntimeError(f"missing CometBFT [{section}] key {name}")
    return config


def configure_home(index, peers, state_sync=None):
    home = RUN / f"nodes/node{index}"
    config_path = home / "config/config.toml"
    config = config_path.read_text(encoding="utf-8")
    replacements = {
        "proxy_app": f'"tcp://127.0.0.1:{PORTS[index]["app"]}"',
        "persistent_peers": f'"{peers}"',
        "pex": "false",
        "allow_duplicate_ip": "true",
        "addr_book_strict": "false",
        "timeout_propose": '"500ms"',
        "timeout_propose_delta": '"100ms"',
        "timeout_prevote": '"200ms"',
        "timeout_precommit": '"200ms"',
        "timeout_commit": '"500ms"',
        "log_level": '"info"',
        "indexer": '"null"',
    }
    for name, value in replacements.items():
        config = replace_config_value(config, name, value)
    config = config.replace(
        "tcp://127.0.0.1:26657", f"tcp://127.0.0.1:{PORTS[index]['rpc']}"
    )
    config = config.replace(
        "tcp://0.0.0.0:26656", f"tcp://127.0.0.1:{PORTS[index]['p2p']}"
    )
    config = config.replace(
        "tcp://127.0.0.1:26656", f"tcp://127.0.0.1:{PORTS[index]['p2p']}"
    )
    if state_sync is not None:
        config = replace_section_value(config, "statesync", "enable", "true")
        config = replace_section_value(
            config, "statesync", "rpc_servers", f'"{state_sync["rpc_servers"]}"'
        )
        config = replace_section_value(
            config, "statesync", "trust_height", str(state_sync["trust_height"])
        )
        config = replace_section_value(
            config, "statesync", "trust_hash", f'"{state_sync["trust_hash"]}"'
        )
        config = replace_section_value(
            config, "statesync", "trust_period", '"168h0m0s"'
        )
        config = replace_section_value(
            config, "statesync", "discovery_time", '"6s"'
        )
        config = replace_section_value(
            config, "statesync", "chunk_request_timeout", '"5s"'
        )
    config_path.write_text(config, encoding="utf-8", newline="\n")
    return home


def build_bundle(node_home):
    generated_genesis = json.loads(
        (node_home / "config/genesis.json").read_text(encoding="utf-8")
    )
    validator_key = base64.b64decode(
        generated_genesis["validators"][0]["pub_key"]["value"]
    )
    if len(validator_key) != 32:
        raise AssertionError("CometBFT generated a non-Ed25519 validator key")

    root = json.loads(IDENTITY_FIXTURE.read_text(encoding="utf-8"))
    identity = root["identity"]
    identity["chain_id"] = "bit-state-sync-smoke-" + RUN.name.rsplit("-", 1)[-1]
    identity["genesis_time_unix_seconds"] = int(time.time()) - 3
    identity["initial_validators"][0]["consensus_pubkey"] = validator_key.hex()
    input_path = RUN / "identity-input.json"
    input_path.write_text(json.dumps(root, indent=2) + "\n", encoding="utf-8")

    key_5 = RUN / "public-test-key-5.bin"
    key_6 = RUN / "public-test-key-6.bin"
    key_5.write_bytes(bytes([5]) * 32)
    key_6.write_bytes(bytes([6]) * 32)
    identity_path = RUN / "identity.cbor"
    signature_1 = RUN / "identity-signature-1.cbor"
    signatures = RUN / "identity-signatures.cbor"
    bundle = RUN / "bundle"
    derived_signature_1 = RUN / "derived-signature-1.cbor"
    derived_signatures = bundle / "derived-signatures.cbor"

    command([BIT, "genesis", "build", "--input", input_path, "--output", identity_path])
    command(
        [
            BIT,
            "genesis",
            "sign",
            "--manifest",
            identity_path,
            "--key-file",
            key_5,
            "--output",
            signature_1,
        ]
    )
    command(
        [
            BIT,
            "genesis",
            "sign",
            "--manifest",
            identity_path,
            "--key-file",
            key_6,
            "--append",
            signature_1,
            "--output",
            signatures,
        ]
    )
    materialized = command_json(
        [
            BIT,
            "genesis",
            "materialize",
            "--manifest",
            identity_path,
            "--signatures",
            signatures,
            "--runtime-inputs",
            RUNTIME_FIXTURE,
            "--output",
            bundle,
        ],
        timeout=120,
    )
    command(
        [
            BIT,
            "genesis",
            "sign-derived",
            "--manifest",
            identity_path,
            "--derived",
            bundle / "derived.cbor",
            "--key-file",
            key_5,
            "--output",
            derived_signature_1,
        ]
    )
    command(
        [
            BIT,
            "genesis",
            "sign-derived",
            "--manifest",
            identity_path,
            "--derived",
            bundle / "derived.cbor",
            "--key-file",
            key_6,
            "--append",
            derived_signature_1,
            "--output",
            derived_signatures,
        ]
    )
    verified = command_json(
        [
            BIT,
            "genesis",
            "verify-bundle",
            "--bundle",
            bundle,
            "--derived-signatures",
            derived_signatures,
        ],
        timeout=120,
    )
    return bundle, materialized, verified


def start_app(index, bundle):
    args = [
        BIT_NODE,
        "start",
        "--bundle",
        bundle,
        "--state-dir",
        RUN / f"application-state-{index}",
        "--listen",
        f"127.0.0.1:{PORTS[index]['app']}",
    ]
    if state_sync := APP_STATE_SYNC.get(index):
        args.extend(
            [
                "--state-sync-dir",
                RUN / f"application-snapshots-{index}",
                "--state-sync-interval-blocks",
                str(state_sync["interval"]),
                "--state-sync-keep-recent",
                str(state_sync["keep_recent"]),
            ]
        )
    spawn(f"app{index}", args)
    wait_log(f"app{index}", "; listening ")


def start_comet(index):
    spawn(f"node{index}", [COMET, "start", "--home", RUN / f"nodes/node{index}"])


def snapshot_heights(index):
    root = RUN / f"application-snapshots-{index}"
    heights = []
    for path in root.glob("snapshot-v1-*"):
        if path.is_dir():
            heights.append(int(path.name.removeprefix("snapshot-v1-")))
    return sorted(heights)


def wait_source_snapshots(seconds=60):
    deadline = time.monotonic() + seconds
    observed = {}
    while time.monotonic() < deadline:
        assert_processes_live(["app0", "node0", "app1", "node1"])
        observed = {0: snapshot_heights(0)}
        eligible = [height_value for height_value in observed[0] if height_value >= 10]
        if eligible:
            return observed, max(eligible)
        time.sleep(0.25)
    raise TimeoutError(f"source snapshots were not published: {observed}")


def active_marker_path(index):
    return RUN / f"application-state-{index}.active-state-v1"


def decode_active_marker(path):
    data = path.read_bytes()
    if len(data) != 152 or data[:16] != b"BIT-ACTIVE-ST-V1":
        raise AssertionError("active state marker format differs")
    checksum = hashlib.sha256(b"BIT-ACTIVE-STATE-MARKER-HASH-V1" + data[:120]).digest()
    if checksum != data[120:]:
        raise AssertionError("active state marker checksum differs")
    return {
        "snapshot_id": data[16:48].hex(),
        "state_height": int.from_bytes(data[48:56], "big"),
        "app_hash": data[56:88].hex(),
        "chain_context": data[88:120].hex(),
    }


def wait_active_marker(index, seconds=90):
    deadline = time.monotonic() + seconds
    path = active_marker_path(index)
    while time.monotonic() < deadline:
        assert_processes_live([f"app{index}", f"node{index}"])
        if path.is_file():
            return decode_active_marker(path)
        time.sleep(0.1)
    raise TimeoutError(
        f"target did not activate a State Sync snapshot\n"
        f"[app]\n{log_tail(f'app{index}')}\n[node]\n{log_tail(f'node{index}') }"
    )


def state_query(index, key, query_height=None):
    query_path = urllib.parse.quote('"/bit/state/key"')
    query_data = "0x" + key.encode("utf-8").hex()
    suffix = "" if query_height is None else f"&height={query_height}"
    response = rpc(
        index,
        f"abci_query?path={query_path}&data={query_data}&prove=true{suffix}",
    )["response"]
    if int(response["code"]) != 0 or not response.get("proofOps", {}).get("ops"):
        raise AssertionError(f"proved state query failed for {key}: {response}")
    value = base64.b64decode(response.get("value", ""))
    return {
        "height": int(response["height"]),
        "value": value,
        "proof_ops": response["proofOps"],
    }


def main():
    required = [BIT, BIT_NODE, COMET, GO, IDENTITY_FIXTURE, RUNTIME_FIXTURE]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError(f"required build inputs are missing: {missing}")

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

    ports, reservations = reserve_ports(9)
    for index in range(3):
        PORTS[index] = dict(zip(("rpc", "p2p", "app"), ports[index * 3 : index * 3 + 3]))
    RUN.mkdir(parents=True)
    command(
        [
            COMET,
            "testnet",
            "--v",
            "1",
            "--o",
            RUN / "nodes",
            "--populate-persistent-peers=false",
        ]
    )
    for index in (1, 2):
        command([COMET, "init", "--home", RUN / f"nodes/node{index}"])
    bundle, materialized, verified = build_bundle(RUN / "nodes/node0")
    for index in range(3):
        shutil.copyfile(bundle / "genesis.json", RUN / f"nodes/node{index}/config/genesis.json")

    node_ids = {
        index: command([COMET, "show-node-id", "--home", RUN / f"nodes/node{index}"])
        for index in range(3)
    }
    peer = lambda index: f"{node_ids[index]}@127.0.0.1:{PORTS[index]['p2p']}"
    configure_home(0, peer(1))
    configure_home(1, peer(0))
    for reservation in reservations:
        reservation.close()

    for index in (0, 1):
        start_app(index, bundle)
    for index in (0, 1):
        start_comet(index)
    source_heights = wait_heights((0, 1), 12)
    source_snapshots, published_snapshot_height = wait_source_snapshots()

    trust_height = min(source_heights) - 2
    if trust_height <= published_snapshot_height:
        trust_height = published_snapshot_height + 1
        wait_heights((0, 1), trust_height + 1)
    trust_hashes = {
        rpc(index, f"block?height={trust_height}")["block_id"]["hash"].upper()
        for index in (0, 1)
    }
    if len(trust_hashes) != 1:
        raise AssertionError("the two State Sync RPC sources disagree on the trust block")
    trust_hash = trust_hashes.pop()
    rpc_servers = ",".join(
        f"http://127.0.0.1:{PORTS[index]['rpc']}" for index in (0, 1)
    )
    configure_home(
        2,
        ",".join((peer(0), peer(1))),
        {
            "rpc_servers": rpc_servers,
            "trust_height": trust_height,
            "trust_hash": trust_hash,
        },
    )
    state_sync_started = time.monotonic()
    start_app(2, bundle)
    start_comet(2)
    marker = wait_active_marker(2)
    state_sync_elapsed = time.monotonic() - state_sync_started
    catchup_target = max(height(0), height(1), marker["state_height"] + 2)
    target_heights = wait_heights((2,), catchup_target, seconds=90)

    source_snapshots = {0: snapshot_heights(0)}
    if marker["state_height"] not in source_snapshots[0]:
        raise AssertionError("target activated a snapshot not published by the snapshot source")
    wait_heights((0, 1), marker["state_height"] + 1)
    committed_header = rpc(0, f"block?height={marker['state_height'] + 1}")["block"]["header"]
    if committed_header["app_hash"].lower() != marker["app_hash"]:
        raise AssertionError("active snapshot app hash differs from the source light block")

    source_proof = state_query(0, "meta/genesis_manifest_hash", marker["state_height"])
    target_proof = state_query(2, "meta/genesis_manifest_hash", marker["state_height"])
    if source_proof["value"] != target_proof["value"]:
        raise AssertionError("source and target historical state values differ")
    if target_proof["value"].hex() != materialized["identity_manifest_hash"]:
        raise AssertionError("State Sync target restored the wrong genesis manifest hash")
    target_height_proof = state_query(2, "meta/height", marker["state_height"])
    if int.from_bytes(target_height_proof["value"], "big") != marker["state_height"]:
        raise AssertionError("State Sync target restored the wrong state height")

    marker_bytes = active_marker_path(2).read_bytes()
    historical_proof_before_restart = target_proof["proof_ops"]
    restart_height = target_heights[0]
    stop("node2")
    stop("app2")
    start_app(2, bundle)
    if active_marker_path(2).read_bytes() != marker_bytes:
        raise AssertionError("active State Sync marker changed during application restart")
    start_comet(2)
    resumed_height = wait_heights((2,), restart_height + 3)[0]
    historical_after_restart = state_query(
        2, "meta/genesis_manifest_hash", marker["state_height"]
    )
    if historical_after_restart["proof_ops"] != historical_proof_before_restart:
        raise AssertionError("historical State Sync proof changed after restart")

    return {
        "scope": "official bit-node snapshot publication and real CometBFT State Sync using two RPC trust sources, one P2P snapshot publisher, and one fresh target",
        "runtime_dir": str(RUN),
        "toolchain": {
            "cometbft_module": comet_module_version,
            "cometbft_self_reported": comet_self_reported_version,
            "cometbft_sha256": hashlib.sha256(COMET.read_bytes()).hexdigest(),
            "bit_sha256": hashlib.sha256(BIT.read_bytes()).hexdigest(),
            "bit_node_sha256": hashlib.sha256(BIT_NODE.read_bytes()).hexdigest(),
        },
        "checks": {
            "identity_manifest_hash": materialized["identity_manifest_hash"],
            "derived_manifest_hash": materialized["derived_manifest_hash"],
            "derived_approval_count": verified["derived_approval_count"],
            "snapshot_interval_blocks": SNAPSHOT_INTERVAL,
            "source_snapshot_heights": {
                str(index): heights for index, heights in source_snapshots.items()
            },
            "initial_published_snapshot_height": published_snapshot_height,
            "rpc_sources": 2,
            "snapshot_p2p_sources": 1,
            "trust_height": trust_height,
            "trust_hash": trust_hash.lower(),
            "rpc_sources_agreed_on_trust_block": True,
            "activated_snapshot": marker,
            "state_sync_elapsed_seconds": state_sync_elapsed,
            "target_caught_up_height": target_heights[0],
            "active_app_hash_matches_source_light_block": True,
            "historical_ics23_value_and_proof_after_restart": True,
            "restart_height": restart_height,
            "resumed_height": resumed_height,
        },
        "limitations": [
            "public deterministic genesis fixture and test approval keys",
            "three CometBFT processes share one physical host and failure domain",
            "upstream CometBFT FilePV signer rather than an independent BIT signer",
            "one designated P2P snapshot publisher; both source nodes independently serve the trusted light block",
            "bad-peer chunk refetch remains covered by the direct ABCI test rather than this live network run",
        ],
    }


if __name__ == "__main__":
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    REPORT.parent.mkdir(parents=True, exist_ok=True)
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
        print("Official BIT node real CometBFT State Sync and restart passed")
    except Exception as error:
        failure = {
            "status": "FAIL",
            "started_at": started,
            "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "runtime_dir": str(RUN),
            "error": repr(error),
            "process_logs": {
                name: log_tail(name) for name in LOG_PATHS if log_tail(name)
            },
        }
        REPORT.write_text(json.dumps(failure, indent=2) + "\n", encoding="utf-8")
        if RUN.exists():
            (RUN / "result.json").write_text(
                json.dumps(failure, indent=2) + "\n", encoding="utf-8"
            )
        raise
    finally:
        for name in list(PROCESSES):
            stop(name)
        for handle in HANDLES:
            handle.close()
