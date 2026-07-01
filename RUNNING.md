# Como rodar o fsmanager

O projeto tem **3 binários**:

| Binário | O que é | Licença |
|---|---|---|
| `fsm-desktop` | A UI (Tauri) | MIT/Apache |
| `fsm-mount` | Monta o `.vault` como drive (WinFsp/FUSE) | GPL-3.0 |
| `fsm` | CLI | MIT/Apache |

> ⚠️ Os 3 devem ser buildados da **mesma versão do código** (mesmo formato on-disk).
> Misturar binários de versões diferentes causa erro do tipo
> *"versão de formato X não suportada"*.

## Modo desenvolvimento (UI)

O frontend é **React + TypeScript (Vite)**; o backend é Rust (Tauri). Os
comandos do backend não mudaram.

```sh
cd apps/fsm-desktop
npm install            # só na 1ª vez (puxa React + Vite)
npm run tauri dev      # sobe o Vite (porta 1420) e abre o app
```
`npm run tauri dev` roda o `beforeDevCommand` (Vite) automaticamente. A primeira
compilação Rust demora um pouco (as crates de compressão/hash são otimizadas
mesmo em dev, via `[profile.dev.package.*]`). Depois fica rápido, com HMR no
frontend.

## Build release (os 3 de uma vez)

### Windows
```powershell
# duplo-clique em build-release.bat, ou:
powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1
```
O script detecta o `libclang` do Visual Studio automaticamente (necessário só
para o `fsm-mount`, por causa do `winfsp-sys`). Requer **WinFsp instalado**.

### Linux
```sh
./scripts/build-release.sh
```
Requer `libfuse3-dev` + `pkg-config` (para o `fsm-mount`) e as dependências do
Tauri (webkit2gtk, etc.).

### Resultado
Ambos os scripts montam a pasta `dist/` com os exes **lado a lado**:
```
dist/
  fsm-desktop(.exe)
  fsm-mount(.exe)     <- a UI procura aqui automaticamente
  fsm(.exe)
```
Rode a UI: `dist/fsm-desktop`. O botão **"Montar como drive"** acha o
`fsm-mount` ao lado. (Alternativa: definir a env `FSM_MOUNT_BIN`.)

## CLI rápida

```sh
fsm init meu.vault                 # ou: init meu.vault -p senha (cifrado)
fsm add meu.vault arquivo.pdf
fsm ls meu.vault
fsm snapshot meu.vault create v1
fsm stats meu.vault
fsm gc meu.vault                   # compacta
fsm verify meu.vault               # checa integridade (exit≠0 se corrompido)
fsm repair meu.vault               # repara: trunca/remove arquivos danificados
```

## Montar como drive (CLI)

```sh
# Windows (precisa do WinFsp):
fsm-mount meu.vault X:

# Linux (precisa do FUSE):
fsm-mount meu.vault /mnt/fsm
```
Para cofre cifrado: `-p senha` (menos seguro — aparece na lista de processos),
`FSM_PASSWORD=senha` (env), ou `--password-stdin` (lê a senha do stdin; é o que a
UI usa, sem expor no argv). Ctrl+C desmonta. Use o binário **release** — em debug a compressão/hash são
muito mais lentas.
