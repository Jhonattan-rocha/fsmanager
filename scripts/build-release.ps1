<#
  build-release.ps1 — compila os 3 binários do fsmanager (release) e monta dist\.

  Uso:
    powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1

  Gera:
    dist\fsm-desktop.exe   (UI)
    dist\fsm-mount.exe     (montagem como drive, ao lado da UI)
    dist\fsm.exe           (CLI)
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Write-Host "== fsmanager :: build release ==" -ForegroundColor Cyan
Write-Host "raiz: $root"

function Check($what) {
    if ($LASTEXITCODE -ne 0) { throw "falha em: $what (exit $LASTEXITCODE)" }
}

# --- libclang (necessário só para o fsm-mount, por causa do winfsp-sys/bindgen) ---
if (-not $env:LIBCLANG_PATH) {
    $dll = Get-Item "C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\Llvm\x64\bin\libclang.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($dll) {
        $env:LIBCLANG_PATH = $dll.DirectoryName
        Write-Host "LIBCLANG_PATH detectado: $($env:LIBCLANG_PATH)" -ForegroundColor DarkGray
    } else {
        Write-Warning "libclang.dll não encontrado no Visual Studio. Defina LIBCLANG_PATH se o fsm-mount falhar."
    }
}

# --- 1) CLI ---
Write-Host "`n[1/3] fsm (CLI)..." -ForegroundColor Yellow
Push-Location $root
cargo build --release -p fsm-cli; Check "cargo build fsm-cli"
Pop-Location

# --- 2) mount ---
Write-Host "`n[2/3] fsm-mount (WinFsp)..." -ForegroundColor Yellow
Push-Location (Join-Path $root "crates\fsm-mount")
cargo build --release; Check "cargo build fsm-mount"
Pop-Location

# --- 3) UI (Tauri) ---
Write-Host "`n[3/3] fsm-desktop (UI Tauri)..." -ForegroundColor Yellow
Push-Location (Join-Path $root "apps\fsm-desktop")
if (-not (Test-Path "node_modules")) {
    npm install; Check "npm install"
}
npm run tauri build -- --no-bundle; Check "tauri build"
Pop-Location

# --- monta dist\ ---
$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force $dist | Out-Null
Copy-Item (Join-Path $root "target\release\fsm.exe") $dist -Force
Copy-Item (Join-Path $root "crates\fsm-mount\target\release\fsm-mount.exe") $dist -Force
Copy-Item (Join-Path $root "apps\fsm-desktop\src-tauri\target\release\fsm-desktop.exe") $dist -Force

Write-Host "`n== pronto! binários em: $dist ==" -ForegroundColor Green
Get-ChildItem $dist -Filter *.exe | ForEach-Object { "  {0,-20} {1,8:N1} MB" -f $_.Name, ($_.Length / 1MB) }
Write-Host "`nRode a UI:  $dist\fsm-desktop.exe" -ForegroundColor Cyan
