$ErrorActionPreference = 'Continue'
$bitRoot = [IO.Path]::GetFullPath("$PSScriptRoot\..")
$bitReports = Join-Path $bitRoot 'reports'
New-Item -ItemType Directory -Force -Path $bitReports | Out-Null
. (Join-Path $bitRoot 'feasibility\scripts\rust_env.ps1')
$env:CARGO_TARGET_DIR = Join-Path $bitRoot 'feasibility\target'
$env:RAYON_NUM_THREADS = '4'
$env:CARGO_BUILD_JOBS = '1'

$bitChecks = @()
function Invoke-BitCheck {
    param([string]$Name, [string]$Program, [string[]]$Arguments)
    $bitStarted = [DateTimeOffset]::UtcNow
    $bitLog = Join-Path $bitReports "$Name.log"
    New-Item -ItemType File -Force -Path $bitLog | Out-Null
    & $Program @Arguments 2>&1 | Tee-Object -FilePath $bitLog
    $bitCode = $LASTEXITCODE
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
    Invoke-BitCheck 'clippy' 'cargo' @('clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings')
    Invoke-BitCheck 'rust-unit' 'cargo' @('test', '--workspace', '--locked')
    Invoke-BitCheck 'python-oracle' 'py' @('-B', '-m', 'unittest', 'discover', '-s', 'reference', '-p', 'test_*.py', '-v')
    Invoke-BitCheck 'comet-app-build' 'cargo' @('build', '-p', 'bit-app', '--example', 'comet_network_probe', '--locked')
    Invoke-BitCheck 'comet-app-network' 'py' @('-B', 'feasibility/scripts/run_bit_app_network.py')
} finally {
    Pop-Location
}

$bitRustLog = Get-Content -LiteralPath (Join-Path $bitReports 'rust-unit.log') -Raw
$bitPythonLog = Get-Content -LiteralPath (Join-Path $bitReports 'python-oracle.log') -Raw
$bitRustPassed = 0
foreach ($bitMatch in [regex]::Matches($bitRustLog, 'test result: ok\. (\d+) passed;')) {
    $bitRustPassed += [int]$bitMatch.Groups[1].Value
}
$bitPythonPassed = if ($bitPythonLog -match 'Ran (\d+) tests') { [int]$Matches[1] } else { 0 }
$bitReport = [ordered]@{
    status = 'PASS'
    scope = 'BIT active baseline only; not a complete chain or product acceptance'
    completed_at = [DateTimeOffset]::UtcNow.ToString('o')
    toolchain = (& rustc --version)
    checks = $bitChecks
    counts = [ordered]@{ rust_tests = $bitRustPassed; python_oracle_tests = $bitPythonPassed }
    rayon_threads = 4
    cargo_build_jobs = 1
    mobile = 'SKIPPED_BY_USER'
    upstream_warnings = 'Present in pinned Penumbra dependencies; BIT crates pass clippy -D warnings'
    artifacts = @(
        [ordered]@{ path = 'feasibility/reports/bit-app-network-result.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\reports\bit-app-network-result.json') -Algorithm SHA256).Hash.ToLowerInvariant() }
    )
    inputs = @(
        [ordered]@{ path = 'Cargo.lock'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'Cargo.lock') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'tests/vectors/emission-vectors.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'tests\vectors\emission-vectors.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'tests/vectors/transaction-vectors.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'tests\vectors\transaction-vectors.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crypto/manifest.json'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crypto\manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-types/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-types\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-types/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-types\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-types/src/envelope.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-types\src\envelope.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
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
        [ordered]@{ path = 'crates/bit-app/Cargo.toml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\Cargo.toml') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/src/lib.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\src\lib.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/src/abci.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\src\abci.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/src/safety.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\src\safety.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/examples/comet_network_probe.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\examples\comet_network_probe.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'crates/bit-app/examples/safety_halt_admin.rs'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'crates\bit-app\examples\safety_halt_admin.rs') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/scripts/run_bit_app_network.py'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\scripts\run_bit_app_network.py') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/scripts/rust_env.ps1'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\scripts\rust_env.ps1') -Algorithm SHA256).Hash.ToLowerInvariant() },
        [ordered]@{ path = 'feasibility/scripts/bootstrap_tools.py'; sha256 = (Get-FileHash -LiteralPath (Join-Path $bitRoot 'feasibility\scripts\bootstrap_tools.py') -Algorithm SHA256).Hash.ToLowerInvariant() }
    )
}
$bitReport | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $bitReports 'development-baseline.json') -Encoding utf8
Write-Host "BIT baseline checks passed: $bitRustPassed Rust tests, $bitPythonPassed Python oracle tests"
