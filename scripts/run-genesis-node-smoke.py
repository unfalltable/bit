"""Build, approve, replay, and start a BIT genesis bundle with real CometBFT."""

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
    "bit-genesis-node-"
    + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
)
REPORT = ROOT / "reports/genesis-node-smoke.json"
IDENTITY_FIXTURE = ROOT / "tests/fixtures/genesis-identity-input.test.json"
RUNTIME_FIXTURE = ROOT / "tests/fixtures/genesis-runtime-inputs.test.json"
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


def rpc(path):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{PORTS['rpc']}/{path}", timeout=2
    ) as response:
        data = json.load(response)
    if "error" in data:
        raise RuntimeError(data["error"])
    return data["result"]


def height():
    try:
        return int(rpc("status")["sync_info"]["latest_block_height"])
    except (OSError, ValueError, RuntimeError):
        return 0


def log_tail(name, limit=6000):
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


def assert_processes_live():
    failed = [name for name, process in PROCESSES.items() if process.poll() is not None]
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


def wait_height(target, seconds=60):
    deadline = time.monotonic() + seconds
    observed = 0
    while time.monotonic() < deadline:
        assert_processes_live()
        observed = height()
        if observed >= target:
            return observed
        time.sleep(0.25)
    raise TimeoutError(f"height {target} not reached; latest was {observed}")


def replace_config_value(config, name, value):
    config, count = re.subn(
        rf"^{re.escape(name)} = .*$", f"{name} = {value}", config, flags=re.M
    )
    if count < 1:
        raise RuntimeError(f"missing CometBFT config key: {name}")
    return config


def configure_comet():
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
    node_home = RUN / "nodes/node0"
    config_path = node_home / "config/config.toml"
    config = config_path.read_text(encoding="utf-8")
    replacements = {
        "proxy_app": f'"tcp://127.0.0.1:{PORTS["app"]}"',
        "persistent_peers": '""',
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
        config = replace_config_value(config, name, value)
    config = config.replace(
        "tcp://127.0.0.1:26657", f"tcp://127.0.0.1:{PORTS['rpc']}"
    )
    config = config.replace(
        "tcp://0.0.0.0:26656", f"tcp://127.0.0.1:{PORTS['p2p']}"
    )
    config = config.replace(
        "tcp://127.0.0.1:26656", f"tcp://127.0.0.1:{PORTS['p2p']}"
    )
    config_path.write_text(config, encoding="utf-8", newline="\n")
    return node_home


def build_bundle(node_home):
    generated_genesis = json.loads(
        (node_home / "config/genesis.json").read_text(encoding="utf-8")
    )
    validator_key = base64.b64decode(generated_genesis["validators"][0]["pub_key"]["value"])
    if len(validator_key) != 32:
        raise AssertionError("CometBFT generated a non-Ed25519 validator key")
    private_validator = json.loads(
        (node_home / "config/priv_validator_key.json").read_text(encoding="utf-8")
    )
    if base64.b64decode(private_validator["pub_key"]["value"]) != validator_key:
        raise AssertionError("CometBFT validator public and private key files disagree")

    root = json.loads(IDENTITY_FIXTURE.read_text(encoding="utf-8"))
    identity = root["identity"]
    identity["chain_id"] = "bit-genesis-smoke-" + RUN.name.rsplit("-", 1)[-1]
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
    shutil.copyfile(bundle / "genesis.json", node_home / "config/genesis.json")
    return bundle, materialized, verified


def start_bit_node(bundle):
    spawn(
        "bit-node",
        [
            BIT_NODE,
            "start",
            "--bundle",
            bundle,
            "--state-dir",
            RUN / "application-state",
            "--listen",
            f"127.0.0.1:{PORTS['app']}",
        ],
    )


def state_query(key):
    query_path = urllib.parse.quote('"/bit/state/key"')
    query_data = "0x" + key.encode("utf-8").hex()
    response = rpc(f"abci_query?path={query_path}&data={query_data}&prove=true")[
        "response"
    ]
    if int(response["code"]) != 0 or not response.get("proofOps", {}).get("ops"):
        raise AssertionError(f"proved state query failed for {key}: {response}")
    value = response.get("value", "")
    return base64.b64decode(value) if value else b""


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

    ports, reservations = reserve_ports(3)
    PORTS.update(zip(("rpc", "p2p", "app"), ports))
    RUN.mkdir(parents=True)
    node_home = configure_comet()
    bundle, materialized, verified = build_bundle(node_home)
    for reservation in reservations:
        reservation.close()

    start_bit_node(bundle)
    wait_log("bit-node", "; listening ")
    spawn("cometbft", [COMET, "start", "--home", node_home])
    first_height = wait_height(4)
    block_one = rpc("block?height=1")["block"]["header"]
    if block_one["app_hash"].lower() != materialized["app_hash"]:
        raise AssertionError("block 1 header does not commit the replayed genesis app hash")
    validators = rpc("validators?height=1&per_page=100")["validators"]
    if len(validators) != 1 or int(validators[0]["voting_power"]) != 4:
        raise AssertionError(f"unexpected genesis validator set: {validators}")
    manifest_hash = state_query("meta/genesis_manifest_hash")
    if manifest_hash.hex() != materialized["identity_manifest_hash"]:
        raise AssertionError("proved genesis manifest hash differs from the verified bundle")

    restart_height = height()
    stop("cometbft")
    stop("bit-node")
    start_bit_node(bundle)
    wait_log("bit-node", "; listening ")
    spawn("cometbft", [COMET, "start", "--home", node_home])
    resumed_height = wait_height(restart_height + 3)
    if materialized["identity_approval_count"] != 2:
        raise AssertionError("materializer did not verify both identity approvals")
    if verified["derived_approval_count"] != 2:
        raise AssertionError("bundle verifier did not verify both derived approvals")

    return {
        "scope": "official bit-node genesis bundle replay, exact InitChain, real CometBFT blocks, proved state, and application restart",
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
            "genesis_app_hash": materialized["app_hash"],
            "identity_approval_count": materialized["identity_approval_count"],
            "derived_approval_count": verified["derived_approval_count"],
            "independent_bundle_replay": True,
            "exact_init_chain_accepted": True,
            "block_one_commits_genesis_app_hash": True,
            "genesis_validator_power": 4,
            "genesis_manifest_ics23_proof": True,
            "height_before_restart": restart_height,
            "height_after_restart": resumed_height,
            "initial_observed_height": first_height,
        },
        "limitations": [
            "public deterministic fixture and test approval keys",
            "single process host and one CometBFT validator",
            "production service management is outside this smoke test",
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
        print(
            "Official BIT node genesis replay, CometBFT InitChain, proof, and restart passed"
        )
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
