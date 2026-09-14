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
    . ./feasibility/scripts/rust_env.ps1; cargo build -p bit-app --example comet_network_probe --locked; py -B feasibility/scripts/run_bit_app_network.py

supply-invariants: unit crypto-vectors

baseline:
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-baseline-checks.ps1
