set shell := ["powershell", "-NoProfile", "-Command"]

# Current S0/D-002/D-003/D-004/D-005 baseline. More full-product recipes will be added with their modules.
bootstrap:
    py -B feasibility/scripts/bootstrap_tools.py

fmt-check:
    . ./feasibility/scripts/rust_env.ps1; cargo fmt --all -- --check

lint:
    . ./feasibility/scripts/rust_env.ps1; $env:CARGO_TARGET_DIR=[IO.Path]::GetFullPath('./feasibility/target'); cargo clippy --workspace --all-targets --locked -- -D warnings

unit:
    . ./feasibility/scripts/rust_env.ps1; $env:CARGO_TARGET_DIR=[IO.Path]::GetFullPath('./feasibility/target'); cargo test --workspace --locked

crypto-vectors:
    py -B -m unittest discover -s reference -p 'test_*.py' -v

comet-app-network:
    . ./feasibility/scripts/rust_env.ps1; $env:CARGO_TARGET_DIR=[IO.Path]::GetFullPath('./feasibility/target'); cargo build -p bit-app --example comet_network_probe --locked; cargo build --manifest-path feasibility/proof-probe/Cargo.toml --bin bit-exit-fixture --release --locked; py -B feasibility/scripts/run_bit_app_network.py

supply-invariants: unit crypto-vectors

baseline:
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-baseline-checks.ps1

# Expected to fail closed until the real signed mainnet inputs are supplied.
release-preflight:
    . ./feasibility/scripts/rust_env.ps1; $env:CARGO_TARGET_DIR=[IO.Path]::GetFullPath('./feasibility/target'); $bitInput=if($env:BIT_MAINNET_INPUTS){$env:BIT_MAINNET_INPUTS}else{'config/mainnet-inputs.template.json'}; $bitArgs=@('run','-p','bit-genesis','--bin','bit','--locked','--','release','preflight','--input',$bitInput); foreach($bitEvidence in @(@('--manifest',$env:BIT_GENESIS_MANIFEST),@('--signatures',$env:BIT_GENESIS_SIGNATURES),@('--crypto-manifest',$env:BIT_CRYPTO_MANIFEST),@('--parameters',$env:BIT_CONSENSUS_PARAMETERS),@('--derived-manifest',$env:BIT_GENESIS_DERIVED_MANIFEST),@('--derived-signatures',$env:BIT_GENESIS_DERIVED_SIGNATURES),@('--runtime-inputs',$env:BIT_GENESIS_RUNTIME_INPUTS),@('--cometbft-genesis',$env:BIT_COMETBFT_GENESIS))){if($bitEvidence[1]){$bitArgs+=$bitEvidence}}; cargo @bitArgs
