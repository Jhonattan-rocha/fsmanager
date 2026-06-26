# fsmanager

Gerenciador de arquivos desktop multiplataforma (Windows/Linux) que funciona como
um **disco virtual em arquivo único**: todos os arquivos vivem dentro de um
container `*.vault`, com deduplicação, compressão, criptografia e versionamento.

## Pilares
- 🧬 **Deduplicação** por conteúdo (blocos endereçados por BLAKE3)
- ✂️ **Chunking FastCDC** — dedup sobrevive a edições/inserções
- 🗜️ **Compressão** zstd por bloco
- 🔐 **Cofre criptografado** — Argon2id + XChaCha20-Poly1305
- 📂 **Operações de FS** — add/ls/rm/mv + `gc` (compactação)
- 📸 **Snapshots** — versões nomeadas, restauráveis
- 🖥️ **UI desktop** (Tauri) e 🔌 **montagem como drive** (WinFsp/FUSE)

## Estrutura
| Componente | Papel |
|---|---|
| `crates/fsm-core` | Motor do container (formato, dedup, cripto, snapshots) |
| `crates/fsm-cli` | CLI `fsm` (criar/gerenciar containers) |
| `crates/fsm-mount` | Monta o `.vault` como drive (WinFsp/FUSE) — binário separado |
| `apps/fsm-desktop` | UI desktop (Tauri v2) |

Veja [DESIGN.md](DESIGN.md) para arquitetura, decisões e roadmap.

## Uso rápido (CLI)
```sh
cargo build
./target/debug/fsm init meu.vault            # ou: init meu.vault -p senha (cifrado)
./target/debug/fsm add meu.vault arquivo.pdf
./target/debug/fsm ls meu.vault
./target/debug/fsm snapshot meu.vault create v1
./target/debug/fsm stats meu.vault
```

## Licença

Copyright (C) 2026 RiseTec — <ti@risetec.com.br>

Este programa é **software livre** sob a **GNU General Public License v3.0**
(GPLv3) — veja [LICENSE](LICENSE). Você pode usar, estudar, compartilhar e
modificar o projeto, **desde que** qualquer versão distribuída (original ou
modificada) permaneça aberta e sob a mesma GPLv3, com o código-fonte disponível.

### Licença comercial (dual-licensing)
A GPLv3 **não impede** uso comercial, mas **exige** que derivados distribuídos
sejam abertos sob GPLv3. Se você quer **incorporar o fsmanager em um produto
proprietário/fechado** (sem as obrigações de copyleft do GPL), uma **licença
comercial** separada está disponível com o detentor do copyright.
Contato: **ti@risetec.com.br**.

> Observação: o crate `fsm-mount` linka a [winfsp-rs](https://github.com/SnowflakePowered/winfsp-rs)
> (GPLv3) no Windows, o que por si só já exigiria GPLv3 nesse binário. O projeto
> inteiro adota GPLv3 por escolha do autor.
