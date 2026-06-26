# fsmanager — Design

Gerenciador de arquivos desktop multiplataforma (Windows/Linux) que opera como
um **disco virtual em arquivo único**: todos os "mini-arquivos" vivem dentro de
um container `*.vault`.

## Diferenciais-alvo
1. 🔐 Cofre criptografado portátil
2. 🔌 Montar como drive real (WinFsp no Windows, FUSE no Linux)
3. 🗜️🧬 Economia de espaço (compressão zstd + deduplicação)
4. 📸 Versionamento / snapshots (copy-on-write)

## Primitiva central: blocos endereçados por conteúdo
Cada bloco é identificado por `blake3(conteúdo)`. Disso decorre:
- **Dedup** de graça (mesmo conteúdo → mesmo hash → guardado 1x).
- **Snapshots** baratos (uma geração = uma raiz que referencia blocos existentes).
- **Integridade** (o hash valida o bloco na leitura).
- **Compressão/criptografia** como estágios do pipeline por bloco.

> Trade-off dedup × cripto: criptografar antes de deduplicar mata o dedup.
> Para um cofre **pessoal**, deduplicamos dentro do container sob uma chave-mestra
> única (dedup cross-usuário não é objetivo), evitando os ataques da
> *convergent encryption*.

## Camadas
```
4:  CLI · UI (Tauri) · Mount (WinFsp/FUSE)
3:  Semântica de FS (paths, dirs, inodes, snapshots)
2:  Object store endereçado por conteúdo (blocos, árvores, commits)
1:  Pipeline de bloco (chunk → comprime → criptografa)
0:  I/O do container (header, região de dados, catálogo)
```

## Formato on-disk (v0)
```
[ HEADER (4 KiB) ]  magic, versão, chunk_size, offset+len do catálogo
[ DADOS          ]  blocos append-only
[ CATÁLOGO       ]  índice de blocos (dedup) + tabela de arquivos (bincode)
```
Durabilidade: grava catálogo → fsync → atualiza ponteiro no header → fsync.
Cair antes do header mantém o catálogo anterior válido. Cada catálogo gravado é
uma geração — semente do versionamento.

## Estado atual
- [x] Workspace Rust: `fsm-core` (motor) + `fsm-cli` (binário `fsm`).
- [x] Container: init, add, ls, cat, extract, stats.
- [x] Dedup por conteúdo + validação de integridade na leitura.
- [x] Compressão zstd no pipeline (flags por bloco; fallback p/ cru quando
      não compensa). `stats` separa dedup × compressão × total.
- [x] Criptografia: Argon2id (senha→chave) + XChaCha20-Poly1305 por bloco E no
      catálogo (nomes de arquivo não vazam). Token de verificação detecta senha
      errada. Formato v3. CLI: `init -p`, `--password`/env `FSM_PASSWORD`.
- [x] Semântica de FS: `rm` (arquivo) e `rm -r` (diretório/prefixo), `mv`
      (arquivo ou subárvore), `ls <prefixo>`, e `gc` (compact_to) que reescreve
      o container só com blocos alcançáveis — recupera removidos e gerações antigas.
- [x] Snapshots: `snapshot create/list/restore/delete`. Cada snapshot guarda só
      a árvore de metadados (dados compartilhados via content-addressing) e mantém
      seus blocos vivos. O `gc` calcula alcançabilidade sobre a árvore atual + todos
      os snapshots, então NÃO destrói histórico nomeado.
- [x] Chunking por conteúdo (FastCDC v2020, crate `fastcdc`): fronteiras pelo
      conteúdo (gear hash), avg 64 KiB (min/max derivados). Dedup sobrevive a
      inserções/edições — inserir 137 bytes no início de 1 MiB gerou só 1 bloco
      novo (46% dedup) vs ~0% do chunking fixo. Só afeta escrita. Formato v5.
- [x] UI desktop (Tauri v2, vanilla JS) em `apps/fsm-desktop`. Backend expõe o
      `fsm-core` via comandos; mantém UM vault aberto em estado compartilhado
      (reusa a chave Argon2). Diálogos nativos pelo lado Rust (plugin `dialog`),
      sem bindings JS — funciona em Windows e Linux. Telas: abrir/criar cofre,
      stats, lista de arquivos (extrair/remover), snapshots (criar/restaurar/
      apagar), e gc.
- [x] Camada de leitura para mount no `fsm-core`: `read_range` (leitura aleatória
      decodificando só os chunks do intervalo), `resolve` e `list_dir` (árvore de
      diretórios derivada dos caminhos planos).
- [x] Mount como drive — Windows/WinFsp (somente leitura), crate `fsm-mount`.
      `.vault` vira `X:\`; qualquer app lê os arquivos transparentemente
      (validado: dir/type/Get-FileHash batem com o original).
- [x] Mount FUSE/Linux (somente leitura) — módulo `unix` da `fsm-mount` (crate
      `fuser` 0.17). Mapeia o catálogo para uma árvore de inodes; `read`→`read_range`,
      `readdir`→`list_dir`. ESCRITO contra a API real, mas NÃO compilado/testado
      (host é Windows) — pendente verificação numa máquina Linux.

## Roadmap
1. **v0** motor + CLI com dedup. ✅
2. Pipeline: compressão zstd por bloco. ✅
3. Pipeline: criptografia XChaCha20-Poly1305 + KDF Argon2 (senha → chave-mestra). ✅
4. Semântica de FS: `rm`/`mv`/`ls <prefixo>`/`gc`. ✅
5. Snapshots: `create/list/restore/delete`, com `gc` respeitando os nomeados. ✅
6. Chunking por conteúdo (FastCDC) para melhor dedup em arquivos editados. ✅
7. UI (Tauri) — explorador visual (Opção A). ✅
8. Montagem como drive: Windows/WinFsp read-only ✅; FUSE/Linux read-only ✅ (a
   compilar/testar em Linux). Próximo: mount read-write (camada de escrita
   aleatória: cache de blocos sujos + re-chunk no flush) e botão "Montar" na UI.

## Mount (crates/fsm-mount) — binário separado
GPL-3.0 porque linka `winfsp` (GPLv3); por isso é um BINÁRIO À PARTE — `fsm-core`,
`fsm-cli` e a UI continuam MIT/Apache. Fora do workspace (exclude).
- Rodar (Windows): `fsm-mount <vault> X: [-p senha]`  (Ctrl+C desmonta)
- Rodar (Linux):   `fsm-mount <vault> /mnt/fsm [-p senha]`  (Ctrl+C desmonta)
- Build no Linux: requer `libfuse3-dev` (ou `fuse3`/`libfuse-dev`) + `pkg-config`,
  e o módulo FUSE no kernel. Não precisa de libclang (sem winfsp). NÃO foi
  compilado neste host Windows — validar em Linux.
- Build no Windows exige libclang (bindgen do winfsp-sys). Existe no Visual Studio:
  `LIBCLANG_PATH="C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\Llvm\x64\bin"`
  (caminho específico desta máquina; ajustar conforme a instalação).
- WinFsp precisa estar instalado (feature `system` acha a DLL pelo registro).
- Implementação read-only: `FileSystemContext` com get_security_by_name/open/
  get_file_info/read/read_directory/get_volume_info. `CoarseGuard` (serializado →
  só exige `Send`; `Mutex<Vault>` para mutabilidade).

## App desktop (apps/fsm-desktop)
Tauri v2 + frontend vanilla estático (`src/`, sem bundler — `withGlobalTauri`).
- Rodar em dev:  `cd apps/fsm-desktop && npm install && npm run tauri dev`
- Gerar binário: `npm run tauri build -- --no-bundle` (só o .exe, ~7 MB; pula o
  download dos empacotadores WiX/NSIS). Sem `--no-bundle` gera o instalador.
- `[profile.release]` em `src-tauri/Cargo.toml`: strip + opt-level="s" + lto.
- Backend: `src-tauri/src/lib.rs` (comandos que envolvem o `fsm-core`).
- Nota de ambiente: este host tem POUCO espaço em disco e o build debug do Tauri
  estourava disco + limite de PDB do linker. Resolvido com `[profile.dev]
  debug = false, strip = "debuginfo"` no `src-tauri/Cargo.toml`.

## Notas de segurança (pendências honestas)
- `--password` na linha de comando fica visível na lista de processos / histórico
  do shell. Para uso real: ler senha via prompt interativo (sem eco) ou só env.
- Argon2 usa parâmetros `default` da crate (~19 MiB, custo fixo). Parametrizar e
  gravar os parâmetros no header seria mais robusto a hardware futuro.
- Sem "rekey"/troca de senha ainda (exigiria re-selar catálogo + token).

## Como rodar
```sh
cargo build
./target/debug/fsm init meu.vault
./target/debug/fsm add meu.vault arquivo.pdf
./target/debug/fsm ls meu.vault
./target/debug/fsm stats meu.vault
./target/debug/fsm extract meu.vault /arquivo.pdf saida.pdf
```
