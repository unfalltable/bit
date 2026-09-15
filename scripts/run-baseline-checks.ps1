$ErrorActionPreference = 'Continue'
$bitRoot = [IO.Path]::GetFullPath("$PSScriptRoot\..")
$bitReports = Join-Path $bitRoot 'reports'
New-Item -ItemType Directory -Force -Path $bitReports | Out-Null
. (Join-Path $bitRoot 'feasibility\scripts\rust_env.ps1')
$env:CARGO_TARGET_DIR = Join-Path $bitRoot 'feasibility\target'
$env:RAYON_NUM_THREADS = '4'
$env:CARGO_BUILD_JOBS = '1'
$env:GOMODCACHE = Join-Path $bitRoot 'feasibility\.tools\go-mod-cache'
$env:GOCACHE = Join-Path $bitRoot 'feasibility\.tools\go-cache'

$bitCnidariumRoot = Join-Path $bitRoot 'third_party\cnidarium'
$bitCnidariumManifest = Join-Path $bitCnidariumRoot 'UPSTREAM_SHA256SUMS'
foreach ($bitManifestLine in Get-Content -LiteralPath $bitCnidariumManifest) {
    if ($bitManifestLine -notmatch '^(?<hash>[0-9a-f]{64})  (?<path>.+)$') {
        throw "invalid Cnidarium source manifest line: $bitManifestLine"
    }
    $bitVendoredPath = Join-Path $bitCnidariumRoot $Matches.path
    $bitVendoredHash = (Get-FileHash -LiteralPath $bitVendoredPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($bitVendoredHash -cne $Matches.hash) {
        throw "vendored Cnidarium source hash mismatch: $($Matches.path)"
    }
}

$bitChecks = @()
function Invoke-BitCheck {
    param([string]$Name, [string]$Program, [string[]]$Arguments)
    $bitStarted = [DateTimeOffset]::UtcNow
    $bitLog = Join-Path $bitReports "$Name.log"
    New-Item -ItemType File -Force -Path $bitLog | Out-Null
    & $Program @Arguments 2>&1 | Tee-Object -FilePath $bitLog
    $bitCode = $LASTEXITCODE
    $bitLogText = [IO.File]::ReadAllText($bitLog) -replace '(?m)[\t ]+(?=\r?$)', ''
    $bitLogText = $bitLogText.TrimEnd("`r", "`n")
    if ($bitLogText.Length -gt 0) { $bitLogText += "`r`n" }
    [IO.File]::WriteAllText($bitLog, $bitLogText, [Text.UTF8Encoding]::new($false))
    $script:bitChecks += [ordered]@{
        name = $Name
        command = "$Program $($Arguments -join ' ')"
        started_at = $bitStarted.ToString('o')
        exit_code = $bitCode
        log = "reports/$Name.log"
        log_sha256 = (Get-FileHash -LiteralPath $bitLog -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    if ($bitCode -ne 0) { throw "$Name failed with exit code $bitCode" }
}

Push-Location $bitRoot
try {
    Invoke-BitCheck 'fmt-check' 'cargo' @('fmt', '--all', '--', '--check')
    Invoke-BitCheck 'cnidarium-fmt' 'rustfmt' @('--edition', '2021', '--check', 'third_party/cnidarium/src/lib.rs', 'third_party/cnidarium/src/storage.rs', 'third_party/cnidarium/src/tests.rs')
    Invoke-BitCheck 'cnidarium-clippy' 'cargo' @(
        'clippy', '--manifest-path', 'third_party/cnidarium/Cargo.toml',
        '--lib', '--no-default-features', '--features', 'bit-fault-injection', '--locked',
        '--', '-D', 'warnings',
        '-A', 'clippy::doc_lazy_continuation',
        '-A', 'clippy::needless_lifetimes',
        '-A', 'clippy::map_clone',
        '-A', 'clippy::unnecessary_get_then_check',
        '-A', 'clippy::question_mark'
    )
    Invoke-BitCheck 'cnidarium-unit' 'cargo' @('test', '--manifest-path', 'third_party/cnidarium/Cargo.toml', '--no-default-features', '--features', 'bit-fault-injection', '--locked')
    Invoke-BitCheck 'clippy' 'cargo' @('clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings')
    Invoke-BitCheck 'rust-unit' 'cargo' @('test', '--workspace', '--locked')
    Invoke-BitCheck 'python-oracle' 'py' @('-B', '-m', 'unittest', 'discover', '-s', 'reference', '-p', 'test_*.py', '-v')
    Invoke-BitCheck 'comet-evidence-build' (Join-Path $bitRoot 'feasibility\.tools\go\bin\go.exe') @('-C', (Join-Path $bitRoot 'feasibility\evidence-injector'), 'build', '-trimpath', '-o', (Join-Path $bitRoot 'feasibility\.tools\bin\bit-evidence-injector.exe'), '.')
    Invoke-BitCheck 'genesis-node-build' 'cargo' @('build', '-p', 'bit-genesis', '--bin', 'bit', '-p', 'bit-app', '--bin', 'bit-node', '--locked')
    Invoke-BitCheck 'genesis-node-smoke' 'py' @('-B', 'scripts/run-genesis-node-smoke.py')
    Invoke-BitCheck 'state-sync-network' 'py' @('-B', 'scripts/run-state-sync-smoke.py')
    Invoke-BitCheck 'comet-app-build' 'cargo' @('build', '-p', 'bit-app', '--example', 'comet_network_probe', '--locked')
    Invoke-BitCheck 'exit-fixture-build' 'cargo' @('build', '--manifest-path', 'feasibility/proof-probe/Cargo.toml', '--bin', 'bit-exit-fixture', '--release', '--locked')
    Invoke-BitCheck 'comet-app-network' 'py' @('-B', 'feasibility/scripts/run_bit_app_network.py')
} finally {
    Pop-Location
}

$bitRustLog = Get-Content -LiteralPath (Join-Path $bitReports 'rust-unit.log') -Raw
$bitCnidariumLog = Get-Content -LiteralPath (Join-Path $bitReports 'cnidarium-unit.log') -Raw
$bitPythonLog = Get-Content -LiteralPath (Join-Path $bitReports 'python-oracle.log') -Raw
$bitRustPassed = 0
foreach ($bitMatch in [regex]::Matches($bitRustLog, 'test result: ok\. (\d+) passed;')) {
    $bitRustPassed += [int]$bitMatch.Groups[1].Value
}
$bitCnidariumPassed = 0
foreach ($bitMatch in [regex]::Matches($bitCnidariumLog, 'test result: ok\. (\d+) passed;')) {
    $bitCnidariumPassed += [int]$bitMatch.Groups[1].Value
}
$bitPythonPassed = if ($bitPythonLog -match 'Ran (\d+) tests') { [int]$Matches[1] } else { 0 }
$bitReport = [ordered]@{
    status = 'PASS'
    scope = 'BIT active baseline only; not a complete chain or product acceptance'
    completed_at = [DateTimeOffset]::UtcNow.ToString('o')
    toolchain = (& rustc --version)
    checks = $bitChecks
    counts = [ordered]@{ rust_tests = $bitRustPassed; cnidarium_tests = $bitCnidariumPassed; python_oracle_tests = $bitPythonPassed }
    rayon_threads = 4
    cargo_build_jobs = 1
    mobile = 'SKIPPED_BY_USER'
    upstream_warnings = 'Present in pinned Penumbra dependencies; BIT crates pass clippy -D warnings'
    artifacts = @(
        [ordered]@{ path = 'reports/genesis-node-smoke.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'reports\genesis-node-smoke.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'reports/state-sync-smoke.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'reports\state-sync-smoke.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/reports/bit-app-network-result.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\reports\bit-app-network-result.json') -Algorithm SHA256).Hash.ToLowerInvariant() }
    )
    inputs = @(
        [ordered]@{ path = '.gitattributes'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot '.gitattributes') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'Cargo.lock'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'Cargo.lock') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'tests/vectors/emission-vectors.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'tests\vectors\emission-vectors.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'tests/vectors/transaction-vectors.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'tests\vectors\transaction-vectors.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'tests/vectors/block-artifact-vectors.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'tests\vectors\block-artifact-vectors.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'tests/vectors/supply-audit-vectors.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'tests\vectors\supply-audit-vectors.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'tests/vectors/genesis-identity-vectors.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'tests\vectors\genesis-identity-vectors.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'tests/vectors/genesis-materialized-vectors.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'tests\vectors\genesis-materialized-vectors.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'tests/vectors/checkpoint-vectors.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'tests\vectors\checkpoint-vectors.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crypto/manifest.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crypto\manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-types/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-types\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-types/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-types\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-types/src/cbor.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-types\src\cbor.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-types/src/tx.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-types\src\tx.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-types/src/block.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-types\src\block.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-types/src/supply.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-types\src\supply.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-types/src/envelope.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-types\src\envelope.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-genesis/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-genesis\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-genesis/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-genesis\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-genesis/src/materialize.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-genesis\src\materialize.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-genesis/src/main.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-genesis\src\main.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-shielded/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-shielded\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-shielded/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-shielded\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-transaction/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-transaction\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-transaction/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-transaction\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-emission/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-emission\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-emission/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-emission\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-staking/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-staking\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-staking/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-staking\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-state/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-state\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-state/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-state\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-state/src/state_snapshot.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-state\src\state_snapshot.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/src/main.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\src\main.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/src/abci.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\src\abci.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/src/artifact_archive.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\src\artifact_archive.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/src/artifacts.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\src\artifacts.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/src/safety.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\src\safety.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/src/state_sync.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\src\state_sync.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-gateway/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-gateway\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-gateway/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-gateway\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-light-client/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-light-client\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-light-client/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-light-client\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-light-client/src/verified_sync.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-light-client\src\verified_sync.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'contracts/openapi.yaml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'contracts\openapi.yaml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'contracts/genesis_identity.cddl'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'contracts\genesis_identity.cddl') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'contracts/checkpoint.cddl'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'contracts\checkpoint.cddl') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'config/mainnet-inputs.schema.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'config\mainnet-inputs.schema.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'config/genesis-runtime-inputs.schema.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'config\genesis-runtime-inputs.schema.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'config/mainnet-inputs.template.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'config\mainnet-inputs.template.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'tests/fixtures/genesis-identity-input.test.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'tests\fixtures\genesis-identity-input.test.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'tests/fixtures/genesis-derived-input.test.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'tests\fixtures\genesis-derived-input.test.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'tests/fixtures/genesis-runtime-inputs.test.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'tests\fixtures\genesis-runtime-inputs.test.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'justfile'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'justfile') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/examples/comet_network_probe.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\examples\comet_network_probe.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/examples/safety_halt_admin.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\examples\safety_halt_admin.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'reference/protocol_oracle.py'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'reference\protocol_oracle.py') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'reference/test_protocol_oracle.py'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'reference\test_protocol_oracle.py') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/proof-probe/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\proof-probe\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/proof-probe/Cargo.lock'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\proof-probe\Cargo.lock') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/proof-probe/src/main.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\proof-probe\src\main.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/proof-probe/src/bin/bit-exit-fixture.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\proof-probe\src\bin\bit-exit-fixture.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/reports/proof-stdout.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\reports\proof-stdout.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/evidence-injector/go.mod'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\evidence-injector\go.mod') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/evidence-injector/go.sum'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\evidence-injector\go.sum') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/evidence-injector/main.go'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\evidence-injector\main.go') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'third_party/cnidarium/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'third_party\cnidarium\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'third_party/cnidarium/Cargo.lock'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'third_party\cnidarium\Cargo.lock') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'third_party/cnidarium/BIT_PATCH.md'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'third_party\cnidarium\BIT_PATCH.md') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'third_party/cnidarium/UPSTREAM_SHA256SUMS'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'third_party\cnidarium\UPSTREAM_SHA256SUMS') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'third_party/cnidarium/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'third_party\cnidarium\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'third_party/cnidarium/src/storage.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'third_party\cnidarium\src\storage.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'third_party/cnidarium/src/tests.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'third_party\cnidarium\src\tests.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/scripts/run_bit_app_network.py'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\scripts\run_bit_app_network.py') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/scripts/rust_env.ps1'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\scripts\rust_env.ps1') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/scripts/bootstrap_tools.py'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\scripts\bootstrap_tools.py') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'scripts/run-genesis-node-smoke.py'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'scripts\run-genesis-node-smoke.py') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'scripts/run-state-sync-smoke.py'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'scripts\run-state-sync-smoke.py') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'scripts/run-baseline-checks.ps1'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'scripts\run-baseline-checks.ps1') -Algorithm SHA256).Hash.ToLowerInvariant() }
    )
}
$bitReportPath = Join-Path $bitReports 'development-baseline.json'
$bitReportJson = $bitReport | ConvertTo-Json -Depth 8 -Compress
[IO.File]::WriteAllText($bitReportPath, $bitReportJson, [Text.UTF8Encoding]::new($false))
& py -B -c "import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); data=json.loads(p.read_text(encoding='utf-8')); p.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')" $bitReportPath
if ($LASTEXITCODE -ne 0) { throw "could not format development baseline report" }
Write-Host "BIT baseline checks passed: $bitRustPassed BIT Rust tests, $bitCnidariumPassed Cnidarium tests, $bitPythonPassed Python oracle tests"
