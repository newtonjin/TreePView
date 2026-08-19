# Build the two binaries into this folder, or start the viewer in dev mode.
#
#   powershell -File bin\install.ps1              collector + viewer
#   powershell -File bin\install.ps1 -CollectorOnly
#   powershell -File bin\install.ps1 -ViewerOnly
#   powershell -File bin\install.ps1 -Dev [case.tpv]
#
# -Dev prints http://127.0.0.1:5173 and opens the desktop window. Extra
# arguments (a .tpv or a memory image) are forwarded to the viewer.

[CmdletBinding()]
param(
    [switch]$Dev,
    [switch]$CollectorOnly,
    [switch]$ViewerOnly,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = "Stop"
$Bin = $PSScriptRoot
$Root = Split-Path $Bin -Parent
$Viewer = Join-Path $Root "apps\tpv-viewer"
Set-Location $Root

function Need($cmd, $hint) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Error "$cmd is not on PATH. $hint"
    }
}

function Show-Hash($path, $label) {
    $item = Get-Item $path
    $hash = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
    Write-Host ("{0,-12} {1,10:N0} bytes  SHA-256  {2}" -f $label, $item.Length, $hash)
    Write-Host "             $($item.FullName)"
}

function Build-Collector {
    Need cargo "Install Rust from https://rustup.rs"
    Write-Host "building collector (release)..."
    cargo build --release -p tpv
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $src = if ($env:CARGO_TARGET_DIR) {
        Join-Path $env:CARGO_TARGET_DIR "release\tpv.exe"
    } else {
        Join-Path $Root "target\release\tpv.exe"
    }
    if (-not (Test-Path $src)) {
        Write-Error "cargo succeeded but $src is missing"
    }
    Copy-Item $src (Join-Path $Bin "tpv.exe") -Force
}

function Build-Viewer {
    Need cargo "Install Rust from https://rustup.rs"
    Need npm "Install Node.js LTS from https://nodejs.org"
    if (-not (Test-Path (Join-Path $Viewer "package.json"))) {
        Write-Error "viewer sources missing at $Viewer"
    }
    Push-Location $Viewer
    try {
        if (-not (Test-Path "node_modules")) {
            Write-Host "installing viewer dependencies..."
            npm install
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
        Write-Host "building viewer (release, no installer bundle)..."
        npx tauri build --no-bundle
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }

    $candidates = @(
        (Join-Path $Root "target\release\tpv-viewer.exe"),
        (Join-Path $Viewer "src-tauri\target\release\tpv-viewer.exe")
    )
    if ($env:CARGO_TARGET_DIR) {
        $candidates = @(Join-Path $env:CARGO_TARGET_DIR "release\tpv-viewer.exe") + $candidates
    }
    $src = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $src) {
        Write-Error "tauri build succeeded but tpv-viewer.exe was not found in:`n  $($candidates -join "`n  ")"
    }
    Copy-Item $src (Join-Path $Bin "TreePView.exe") -Force
}

if ($Dev) {
    Need npm "Install Node.js LTS from https://nodejs.org"
    Push-Location $Viewer
    try {
        if (-not (Test-Path "node_modules")) {
            Write-Host "installing viewer dependencies..."
            npm install
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
        Write-Host ""
        Write-Host "TreePView (dev)"
        Write-Host "  desktop window opens from Tauri"
        Write-Host "  UI server    http://127.0.0.1:5173/"
        Write-Host "  stop with Ctrl+C"
        Write-Host ""
        if ($Rest -and $Rest.Count -gt 0) {
            npx tauri dev -- @Rest
        } else {
            npm start
        }
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }
    exit 0
}

$doCollector = -not $ViewerOnly
$doViewer = -not $CollectorOnly
if ($CollectorOnly -and $ViewerOnly) {
    $doCollector = $true
    $doViewer = $true
}

if ($doCollector) { Build-Collector }
if ($doViewer) { Build-Viewer }

Write-Host ""
if ($doCollector -and (Test-Path (Join-Path $Bin "tpv.exe"))) {
    Show-Hash (Join-Path $Bin "tpv.exe") "tpv.exe"
}
if ($doViewer -and (Test-Path (Join-Path $Bin "TreePView.exe"))) {
    Show-Hash (Join-Path $Bin "TreePView.exe") "TreePView.exe"
}

Write-Host ""
Write-Host "collect (USB / examined host):"
Write-Host "  bin\tpv.exe collect --out E:\"
Write-Host "open (this PC):"
Write-Host "  bin\TreePView.exe"
Write-Host "  bin\TreePView.exe E:\case.tpv"
Write-Host "dev (this PC, live reload):"
Write-Host "  powershell -File bin\install.ps1 -Dev"
Write-Host "  -> http://127.0.0.1:5173/"
Write-Host ""
Write-Host "copy bin\tpv.exe to external media for collection; keep TreePView.exe on the analysis machine"
