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
[ CATÁLOGO       ]  índice de blocos (dedup) + tabela de arquivos (MessagePack)
```
Durabilidade: grava catálogo → fsync → atualiza ponteiro no header → fsync.
Cair antes do header mantém o catálogo anterior válido. Cada catálogo gravado é
uma geração — semente do versionamento.
Formato do catálogo (v9+): MessagePack com structs por NOME de campo — adicionar
um campo (`#[serde(default)]`) ou remover um NÃO quebra cofres existentes. Cofres
v8 (bincode legado) são lidos e MIGRADOS para v9 no primeiro commit.

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
      sem bindings JS — funciona em Windows e Linux.
- [x] UI EXPLORADOR: navegação por PASTAS (`list_dir`/`make_dir`), breadcrumbs,
      arrastar-e-soltar para adicionar na pasta atual (eventos `tauri://drag-*`),
      barra de progresso visual (evento `add-progress` throttled), menu de
      clique-direito (extrair/renomear/excluir), criação/renomeação INLINE (digita
      o nome na própria árvore), além de stats, snapshots e gc.
      Comandos pesados são `#[command(async)]` (fora da thread da UI) e as crates
      de compressão/hash são otimizadas mesmo em `tauri dev` (profile overrides).
      ⚠️ args de comando Tauri são camelCase no JS (Rust `dest_dir` → JS `destDir`).
- [x] UI MIGRADA PARA REACT + TYPESCRIPT (Vite): o frontend vanilla (~700 linhas
      de DOM manual) virou componentes React+TS. `tauri.conf.json` usa
      `devUrl`/`beforeDevCommand` (Vite na porta 1420) e `frontendDist=../dist`.
      O backend Rust NÃO mudou. Estrutura: `api.ts` (wrappers tipados de invoke +
      tipos dos DTOs), contexts `Toast`/`ContextMenu`, componentes `Workspace`
      (orquestra estado), `FileTable`, `Toolbar`, `StatsBar`, `BatchBar`,
      `SnapshotPanel`, `ManageModal`, `Progress`. Estilo: base global (variáveis +
      sistema de botões/inputs) + **CSS Modules por componente**. Drag interno
      compartilha estado via singleton de módulo `dragState`. `npm install` é
      pré-requisito do build (os scripts já chamam).
- [x] BUSCA RECURSIVA NO COFRE: `Vault::search(query)` varre todos os arquivos +
      pastas (explícitas e implícitas) casando o CAMINHO COMPLETO por substring
      (case-insensitive) — busca por nome ("relatorio") ou trecho de caminho
      ("docs/2020"). Comando `search` no backend; UI tem um toggle "Pasta | Cofre"
      no cabeçalho — em "Cofre" o mesmo campo busca em tudo (debounce 200ms) e
      mostra resultados com o caminho. Ações por resultado: 📖 abrir, 📂 ir para a
      pasta (revela + realça), ⬇️ extrair, 🗑️ excluir.
- [x] ABRIR ARQUIVO com o app padrão do SO: comando `open_file` extrai para
      `temp/fsmanager-open/<subárvore lógica>` e entrega ao sistema via
      `tauri-plugin-opener` (chamado do Rust, fora do IPC — sem permissão extra).
      Duplo-clique em arquivo ABRE; extrair virou ação explícita (botão ⬇️ / menu).
- [x] ABRIR-E-REGRAVAR: uma thread observadora (`spawn_watcher`, polling de 1s)
      acompanha os arquivos temporários abertos (registrados em `AppState.watches`)
      e, quando o usuário salva no app do SO (muda mtime/tamanho), reimporta o
      conteúdo de volta para o cofre (`write_file`+`commit`) e emite `vault-changed`
      → a UI atualiza e mostra "💾 salvo no cofre". Watches são limpos ao trocar/
      fechar/montar o cofre. Temp em subárvore lógica evita colisão de nomes iguais.
      Botão "👁️ Parar de observar (N)" na toolbar (`watch_count`/`stop_watching`).
- [x] FORMATO TOLERANTE + MIGRAÇÃO (longevidade): catálogo passou de `bincode`
      (posicional, quebrava a cada mudança de campo) para MessagePack com structs
      por NOME (`rmp_serde::to_vec_named`). `FORMAT_VERSION=9`, `MIN=8`. `open`
      aceita a faixa 8..=9 e desserializa conforme a versão do header; cofres v8
      são migrados para v9 no 1º commit (transparente). Dali pra frente, adicionar/
      remover campo não força bump nem recria vault. VALIDADO: teste de migração
      real v8→v9 (fabrica header+bincode, abre, migra, confirma v9 no disco) e
      teste de tolerância (campo ausente vira default; campo extra é ignorado).
- [x] ZEROIZAÇÃO DE SEGREDOS (segurança): a CHAVE-MESTRA (`EncState.key`) é zerada
      da memória ao fechar o cofre — `#[derive(ZeroizeOnDrop)]` no `EncState` (salt/
      verify são pulados: não são segredos). No backend, a senha da sessão
      (`OpenVault.password`) virou `Zeroizing<String>` — zera no drop, inclusive nos
      clones (mount/gc/rekey). Reduz a exposição da chave/senha em dumps de memória
      ou swap. As cifras (chacha20poly1305) já zeram suas cópias de chave por conta
      própria. Encriptação validada intacta (round-trip cifrado + testes do core).
- [x] TRAVA DE VAULT (integridade): ao abrir/criar um `.vault`, o `fsm-core`
      adquire uma TRAVA EXCLUSIVA do SO no próprio arquivo (`fs2::try_lock_exclusive`),
      liberada automaticamente ao fechar (drop do `Vault`) — inclusive se o processo
      cair (o SO solta). Impede que dois processos (UI + `fsm add`, duas instâncias,
      ou UI + drive montado) escrevam e corrompam o container. Erro claro: "o cofre
      já está aberto em outro processo (ou montado como drive)". `gc`/rekey/mount
      já faziam `drop` antes de reabrir, então encaixam. VALIDADO cross-process:
      com o vault montado, `fsm ls` no mesmo arquivo falha; após desmontar, volta.
- [x] SENHA FORA DO ARGV (segurança): a senha NUNCA é passada por argumento de
      linha de comando ao `fsm-mount` (seria visível em `Win32_Process`/ps). O
      backend passa `--password-stdin` e escreve a senha na 1ª linha do stdin
      (`write_all` de bytes crus); o `fsm-mount` a lê byte a byte (sem over-read,
      preservando o EOF do desmonte) e ignora BOM. `--password` (argv) e
      `FSM_PASSWORD` (env) seguem para uso manual via CLI. VALIDADO: cofre cifrado
      monta e lê pelo stdin, e a senha não aparece na cmdline do processo.
- [x] MONTAGEM BLINDADA: `mount_drive` (async) valida o ponto ANTES de fechar o
      vault (Windows: formato de letra + letra livre; Unix: diretório existe),
      trava contra montagens concorrentes (`AtomicBool` + guard), confirma que o
      processo subiu (a falha confiável é o `fsm-mount` SAIR — testado: sai com
      exit 1 + motivo no stderr) e, se falhar, REABRE o vault (`reopen_vault`) e
      reporta o motivo capturado do stderr. Nunca mata um mount vivo por timeout;
      no sucesso, drena o stderr numa thread (evita bloqueio por pipe cheio).
- [x] DESMONTE GRACIOSO (corrige letra "fantasma"): matar o `fsm-mount` à força
      (TerminateProcess) deixava a letra presa porque o WinFsp não desmontava.
      Agora o processo é iniciado com stdin em pipe e o `fsm-mount` desmonta ao
      receber EOF nesse stdin; `unmount_drive` (async) fecha o stdin, espera sair
      (até 5s) e só mata como fallback. A letra some como ejetar um pendrive.
- [x] PASTAS mostram tamanho/data AGREGADOS: `list_dir` soma os tamanhos dos
      arquivos sob cada subpasta e usa o mtime mais recente (antes era sempre "—").
- [x] UI BUSCA + ORDENAÇÃO + DRAG DE PASTAS: filtro por nome na pasta atual
      (substring, client-side, no cabeçalho do painel); ordenação clicável por
      coluna (Nome/Tamanho/Modificado, com seta ▲/▼, pastas sempre primeiro);
      drag-drop de PASTAS externas agora recursa — `collect_pairs` no backend
      expande a subárvore preservando a estrutura sob o destino (`add_dropped`
      não filtra mais só arquivos; comando `add_folder` abre seletor de pasta).
- [x] UI SELEÇÃO MÚLTIPLA + AÇÕES EM LOTE: clique/Ctrl-clique/Shift-clique
      seleciona; barra de lote (extrair/mover/excluir) + menu de contexto ciente
      da seleção. Comandos `remove_paths`/`move_paths`/`extract_files` fazem N
      itens em UMA transação (1 commit). MOVER entre pastas de 2 jeitos:
      drag-drop interno (HTML5 DnD: arrasta linhas para uma pasta/breadcrumb) e
      recortar/colar (Ctrl+X/Ctrl+V ou botões — fallback p/ webviews que blocam
      DnD interno). Atalhos: Esc limpa, Del exclui, Ctrl+A tudo. Backend trava
      mover pasta para dentro de si mesma. `move_paths` usa `rename` (re-chaveia).
- [x] Gerenciamento do cofre: COTA de tamanho (`set_quota`/`quota`, enforce no
      `write_block`) e SENHA (set/trocar/remover via `rekey_to` — reescreve
      re-encriptando; hash de conteúdo preservado). UI: painel "⚙️ Gerenciar".
      Formato v8 (campo `quota` no catálogo).
- [x] Verificação de integridade: `Vault::verify` lê e confere o BLAKE3 de cada
      bloco (e chunks órfãos), sem usar o cache. Exposto em `fsm verify` (CLI,
      exit≠0 se corrompido) e no painel "⚙️ Gerenciar → 🛡️ Integridade" da UI.
      Restaura sob demanda a garantia que tiramos do caminho de leitura por perf.
- [x] Reparo: `Vault::repair` remove blocos inválidos do índice e trunca cada
      arquivo no primeiro chunk ruim (ou remove se nada salvável). Deixa o cofre
      consistente (verify limpo) e salva o prefixo íntegro. `fsm repair` (CLI) e
      botão "🔧 Reparar" na UI. Rodar `gc` depois recupera o espaço.
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
- [x] Mount Windows/WinFsp READ-WRITE. Modelo: cada handle materializa o arquivo
      num buffer (`Vec<u8>`, lazy); write/truncate editam o buffer; em flush/cleanup,
      se sujo, re-chunka (FastCDC+dedup) via `write_file` e commita. Implementa
      create/write/overwrite/set_file_size/cleanup(delete)/set_delete/rename/flush.
      Camada de escrita do core (`write_file`, `create_dir`, `remove_empty_dir`,
      `resolve_ci`) + diretórios explícitos (formato v6). Validado: New-Item,
      Set/Get/Add-Content, Copy-Item (hash bate), Rename-Item, delete, mkdir, e
      PERSISTÊNCIA (reabrir o .vault). Funciona com Explorer/PowerShell/apps.
      LIMITAÇÃO conhecida: builtins do cmd.exe (`copy`/`ren`/`del`) têm
      idiossincrasia com WinFsp e falham; operações diretas (CreateFile) funcionam.
- [x] Mount FUSE/Linux READ-WRITE — módulo `unix` com estado mutável (tabela de
      inodes dinâmica + writers/buffers por inode). Implementa create/write/mkdir/
      unlink/rmdir/rename/setattr(truncate)/flush/fsync/release. ESCRITA STREAMING
      (StreamWriter por inode, como no Windows — não materializa arquivos grandes
      na RAM) e leitura herda o `read_range` `&self`. ESCRITO contra a API do
      `fuser` 0.17, NÃO compilado/testado (host Windows) — validar em Linux.
- [x] Botão "Montar como drive" na UI (Tauri). Comando `mount_drive` FECHA o vault
      na UI e inicia o `fsm-mount` como PROCESSO separado (não linka — preserva a
      separação de licença: UI é o app, `fsm-mount` é GPLv3). `unmount_drive` mata o
      processo. Resolve o binário por env `FSM_MOUNT_BIN`, ao lado do exe, ou
      subindo ancestrais até `crates/fsm-mount/target/{debug,release}`.

## Roadmap
1. **v0** motor + CLI com dedup. ✅
2. Pipeline: compressão zstd por bloco. ✅
3. Pipeline: criptografia XChaCha20-Poly1305 + KDF Argon2 (senha → chave-mestra). ✅
4. Semântica de FS: `rm`/`mv`/`ls <prefixo>`/`gc`. ✅
5. Snapshots: `create/list/restore/delete`, com `gc` respeitando os nomeados. ✅
6. Chunking por conteúdo (FastCDC) para melhor dedup em arquivos editados. ✅
7. UI (Tauri) — explorador visual (Opção A). ✅
8. Montagem como drive: Windows/WinFsp read-only ✅ e read-write ✅; FUSE/Linux
   read-only ✅ e read-write ✅ (a testar em Linux); botão "Montar" na UI ✅.
   Possíveis melhorias: lidar com os builtins do cmd.exe; spill de buffer grande
   para arquivo temporário (hoje materializa em RAM); resolução case-insensitive
   também no FUSE se desejado.

## Performance do mount (notas)
- USE O BINÁRIO RELEASE (`cargo build --release`): zstd/BLAKE3/FastCDC em debug são
  5–10× mais lentos — era a causa do "travou em 99%" ao copiar arquivos grandes.
- `FileEntry.chunks` guarda `ChunkRef { hash, len }` (tamanho inline) — `read_range`
  calcula offsets sem lookup no índice de blocos, evitando O(n²) por leitura. Formato v7.
- Cache LRU (FIFO) de blocos decodificados no `Vault` (128 MiB) — acelera leituras
  repetidas/aleatórias (ex.: WinRAR lendo o diretório do arquivo). Blocos são
  imutáveis (content-addressed) → nunca ficam obsoletos.
- `read_range` não re-verifica BLAKE3 (busca-se o bloco PELO hash; cifrados já têm
  Poly1305) — ganho de ~8%.
- Espaço livre do drive é ADAPTATIVO: reporta o livre real do disco do host
  (`GetDiskFreeSpaceExW`), não um valor fixo.
- ESCRITA STREAMING (`StreamWriter`): escrita sequencial (cópia) é chunkada
  incrementalmente conforme chega — memória limitada (~poucos chunks) e sem o
  "freeze" de re-chunkar tudo no fechamento. Escrita fora de ordem cai para
  materializado. No mount, `create`/`overwrite` abrem em streaming.
- LEITURA EM LOTE (`prefetch_blocks`): blocos fisicamente contíguos no `.vault`
  são lidos numa única syscall em vez de uma por bloco.
- Heurística de compressão por SAMPLE: testa zstd em 8 KB; se não comprime,
  grava o chunk cru sem tentar comprimir o resto (acelera muito dados já
  comprimidos: .rar/.jpg/.zip).
- LEITURAS PARALELAS: o `read_range` é `&self` (leitura POSICIONADA via
  `seek_read`/`read_at` — sem `seek` mutável) e o cache é `Mutex<BlockCache>`
  (Arc por bloco). O mount usa `RwLock<Vault>` (leituras compartilhadas, escritas
  exclusivas) + `FineGuard` (WinFsp despacha reads concorrentes). Medido:
  sequencial ~29 MB/s, 4 leituras paralelas ~43 MB/s agregado (era serializado).
- Throughput: o teto restante é o IPC do WinFsp + contenção no Mutex do cache.
  Futuro: menos cópias, mmap do `.vault`.

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
