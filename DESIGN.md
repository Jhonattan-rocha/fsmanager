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

## Estado atual (v0)
- [x] Workspace Rust: `fsm-core` (motor) + `fsm-cli` (binário `fsm`).
- [x] Container: init, add, ls, cat, extract, stats.
- [x] Dedup por conteúdo + validação de integridade na leitura.
- [ ] Pipeline real: `block_pipeline`/`unblock_pipeline` são identidade (ganchos prontos).

## Roadmap
1. **v0** motor + CLI com dedup. ✅
2. Diretórios reais + remoção + journaling explícito (hoje o catálogo cresce append-only).
3. Pipeline: compressão zstd por bloco.
4. Pipeline: criptografia XChaCha20-Poly1305 + KDF Argon2 (senha → chave-mestra).
5. Snapshots: comando para nomear/listar/restaurar gerações; GC de blocos órfãos.
6. Chunking por conteúdo (CDC/FastCDC) para melhor dedup em arquivos editados.
7. UI (Tauri) — explorador visual (Opção A).
8. Montagem como drive (WinFsp/FUSE) — o diferencial matador (Opção B).

## Como rodar
```sh
cargo build
./target/debug/fsm init meu.vault
./target/debug/fsm add meu.vault arquivo.pdf
./target/debug/fsm ls meu.vault
./target/debug/fsm stats meu.vault
./target/debug/fsm extract meu.vault /arquivo.pdf saida.pdf
```
