"""Four CometBFT processes against the real BIT ABCI/JMT application.

The node executable is an integration probe with accelerated epochs and
temporary block digests. User transactions and production compact encoding are
outside this experiment.
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

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
COMET = ROOT / ".tools/bin/cometbft.exe"
GO = ROOT / ".tools/go/bin/go.exe"
EVIDENCE_INJECTOR = ROOT / ".tools/bin/bit-evidence-injector.exe"
TARGET_DIR = Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target"))
APP = TARGET_DIR / "debug/examples/comet_network_probe.exe"
RUN = ROOT / "runtime" / (
    "bit-app-network-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
)
REPORT = ROOT / "reports/bit-app-network-result.json"
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


def command(args):
    completed = subprocess.run(
        [str(value) for value in args],
        capture_output=True,
        text=True,
        env=ENV,
        creationflags=0x08000000,
        timeout=60,
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


def validator_powers(height_value):
    validators = rpc(0, f"validators?height={height_value}&per_page=100")["validators"]
    return {
        base64.b64decode(validator["pub_key"]["value"]).hex(): int(
            validator["voting_power"]
        )
        for validator in validators
    }


def state_query(index, key):
    query_path = urllib.parse.quote('"/bit/state/key"')
    query_data = "0x" + key.encode("utf-8").hex()
    response = rpc(
        index,
        f"abci_query?path={query_path}&data={query_data}&prove=true",
    )["response"]
    if int(response["code"]) != 0 or not response.get("proofOps", {}).get("ops"):
        raise AssertionError(f"proved state query failed for {key} on node {index}")
    value = response.get("value", "")
    return base64.b64decode(value) if value else b""


def domain_hash(domain, value):
    return hashlib.sha256(domain + len(value).to_bytes(8, "big") + value).digest()


def bit_evidence_hash(chain_id, evidence):
    chain_context = domain_hash(
        b"BIT-COMET-NETWORK-PROBE-CHAIN-V1", chain_id.encode("utf-8")
    )
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


def configure_network():
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
    genesis["app_state"] = {"bit_app_network_probe": 1}
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
        or not COMET.is_file()
        or not GO.is_file()
        or not EVIDENCE_INJECTOR.is_file()
    ):
        raise RuntimeError("build the probe and bootstrap CometBFT before running")
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
    configure_network()
    for index in range(4):
        start_pair(index)

    wait_height(10)
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

    restart_height = height(0)
    stop("node0")
    stop("app0")
    start_pair(0)
    resumed = wait_height(restart_height + 5)

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
    time.sleep(2)
    halted_height = height(0)
    time.sleep(3)
    if height(0) != halted_height:
        raise AssertionError("chain advanced without more than two-thirds voting power")
    spawn("node2", [COMET, "start", "--home", RUN / "nodes/node2"])
    recovered = wait_height(halted_height + 4)

    return {
        "scope": "four CometBFT v0.38.23 processes using real bit-app, bit-state JMT/RocksDB, staking and emission",
        "runtime_dir": str(RUN),
        "toolchain": {
            "cometbft_module": comet_module_version,
            "cometbft_self_reported": comet_self_reported_version,
            "cometbft_sha256": hashlib.sha256(COMET.read_bytes()).hexdigest(),
            "application_sha256": hashlib.sha256(APP.read_bytes()).hexdigest(),
            "evidence_injector_sha256": hashlib.sha256(
                EVIDENCE_INJECTOR.read_bytes()
            ).hexdigest(),
        },
        "checks": {
            "validator_powers_h6_h7_h8": powers,
            "h_plus_two_update": True,
            "process_restart_from_durable_jmt_height": restart_height,
            "resumed_heights": resumed,
            "same_app_hash_height": common_height,
            "same_app_hash": app_hashes.pop(),
            "latest_ics23_proof": True,
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
            "accelerated five-block epochs and deterministic probe genesis",
            "temporary domain-separated request digests pending SPEC-03",
            "empty user-transaction blocks; real transfer remains covered by in-process and TCP tests",
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
            "Real BIT app four-node H+2, duplicate-vote slashing, JMT restart and quorum checks passed"
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
