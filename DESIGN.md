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

## Roadmap
1. **v0** motor + CLI com dedup. ✅
2. Pipeline: compressão zstd por bloco. ✅
3. Pipeline: criptografia XChaCha20-Poly1305 + KDF Argon2 (senha → chave-mestra). ✅
4. Semântica de FS: `rm`/`mv`/`ls <prefixo>`/`gc`. ✅
5. Snapshots: `create/list/restore/delete`, com `gc` respeitando os nomeados. ✅
6. Chunking por conteúdo (FastCDC) para melhor dedup em arquivos editados. ✅
7. UI (Tauri) — explorador visual (Opção A).
8. Montagem como drive (WinFsp/FUSE) — o diferencial matador (Opção B).

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
