# Gera os instaladores do fsmanager para Windows (MSI + NSIS).
# Empacota a UI (fsm-desktop) junto do fsm-mount.exe e do fsm.exe, de modo que a
# UI encontre o helper de montagem ao lado do executavel instalado.
#
#   powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1
#
# Requisitos: Rust, Node/npm, e (para o fsm-mount) o libclang do Visual Studio.
# WinFsp NAO e' empacotado — o app detecta e avisa o usuario se faltar.
$ErrorActionPreference = "Stop"

$root  = Split-Path -Parent $PSScriptRoot
$app   = Join-Path $root "apps\fsm-desktop"
$tauri = Join-Path $app  "src-tauri"
$bin   = Join-Path $tauri "binaries"

function Check($msg) { if ($LASTEXITCODE -ne 0) { Write-Error "falhou: $msg"; exit 1 } }

# libclang para o winfsp-sys/bindgen do fsm-mount (auto-detecta no Visual Studio).
if (-not $env:LIBCLANG_PATH) {
    $dll = Get-ChildItem "C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\Llvm\x64\bin\libclang.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($dll) { $env:LIBCLANG_PATH = Split-Path $dll.FullName; Write-Host "libclang: $env:LIBCLANG_PATH" -ForegroundColor DarkGray }
}

Write-Host "[1/5] fsm-mount (release)..." -ForegroundColor Cyan
Push-Location (Join-Path $root "crates\fsm-mount")
cargo build --release; Check "cargo build fsm-mount"
Pop-Location

Write-Host "[2/5] fsm CLI (release)..." -ForegroundColor Cyan
Push-Location $root
cargo build --release -p fsm-cli; Check "cargo build fsm-cli"
Pop-Location

Write-Host "[3/5] preparando binarios para o bundle..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force $bin | Out-Null
Copy-Item (Join-Path $root "crates\fsm-mount\target\release\fsm-mount.exe") $bin -Force
Copy-Item (Join-Path $root "target\release\fsm.exe") $bin -Force

Write-Host "[4/5] deps do frontend..." -ForegroundColor Cyan
Push-Location $app
if (-not (Test-Path "node_modules")) { npm install; Check "npm install" }

Write-Host "[5/5] tauri build (MSI + NSIS)..." -ForegroundColor Cyan
# O overlay installer.conf.json injeta o fsm-mount.exe/fsm.exe como resources
# (ficam ao lado do fsm-desktop.exe instalado).
npm run tauri build -- --config src-tauri/installer.conf.json; Check "tauri build"
Pop-Location

Write-Host "`nInstaladores gerados:" -ForegroundColor Green
Get-ChildItem (Join-Path $tauri "target\release\bundle") -Recurse -Include *.msi, *.exe -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host "  $($_.FullName)" -ForegroundColor White }
Write-Host "`nWinFsp nao vai no instalador: o app detecta e oferece o download se faltar." -ForegroundColor DarkGray
