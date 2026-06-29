#!/usr/bin/env bash
# build-release.sh — compila os 3 binários do fsmanager (release) e monta dist/.
#
# Uso:   ./scripts/build-release.sh
#
# Requisitos (Linux):
#   - Rust + cargo
#   - Node.js + npm
#   - FUSE: libfuse3-dev (ou fuse3) + pkg-config        (para o fsm-mount)
#   - Tauri: webkit2gtk, etc. (ver docs do Tauri)        (para o fsm-desktop)
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
echo "== fsmanager :: build release =="
echo "raiz: $root"

# --- 1) CLI ---
echo; echo "[1/3] fsm (CLI)..."
( cd "$root" && cargo build --release -p fsm-cli )

# --- 2) mount (FUSE) ---
echo; echo "[2/3] fsm-mount (FUSE)..."
( cd "$root/crates/fsm-mount" && cargo build --release )

# --- 3) UI (Tauri) ---
echo; echo "[3/3] fsm-desktop (UI Tauri)..."
cd "$root/apps/fsm-desktop"
[ -d node_modules ] || npm install
npm run tauri build -- --no-bundle

# --- monta dist/ ---
dist="$root/dist"
mkdir -p "$dist"
cp "$root/target/release/fsm" "$dist/"
cp "$root/crates/fsm-mount/target/release/fsm-mount" "$dist/"
cp "$root/apps/fsm-desktop/src-tauri/target/release/fsm-desktop" "$dist/"

echo; echo "== pronto! binários em: $dist =="
ls -lh "$dist" | awk 'NR>1 {printf "  %-20s %s\n", $9, $5}'
echo; echo "Rode a UI:  $dist/fsm-desktop"
