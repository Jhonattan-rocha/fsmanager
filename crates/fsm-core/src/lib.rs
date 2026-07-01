//! fsm-core — motor do container virtual.
//!
//! Um container é UM arquivo único (`*.vault`) com este layout:
//!
//! ```text
//! [ HEADER  (4 KiB fixos) ]  magic, versão, chunk_size, ponteiro p/ catálogo,
//!                            flags, salt Argon2, token de verificação
//! [ REGIÃO DE DADOS       ]  blocos endereçados por conteúdo (append-only)
//! [ CATÁLOGO              ]  índice de blocos + tabela de arquivos (serializado,
//!                            cifrado quando o container tem senha)
//! ```
//!
//! ## Primitiva central: blocos endereçados por conteúdo
//! Cada bloco é identificado por `blake3(conteúdo original)`. Antes de gravar
//! verificamos se o hash já existe — se sim, não regravamos (DEDUP). O mesmo
//! endereço de conteúdo dá integridade (revalidamos na leitura) e é a base de
//! snapshots (cada catálogo gravado é uma geração).
//!
//! ## Pipeline de bloco
//! `chunk -> comprime (zstd, se compensar) -> criptografa (XChaCha20, se houver
//! senha)`. Cada bloco no disco começa por um byte de flags que diz quais
//! estágios foram aplicados, então a leitura é auto-descritiva.
//!
//! ## Criptografia
//! Senha -> Argon2id (KDF, com salt do header) -> chave-mestra de 32 bytes.
//! A chave nunca é gravada. Cada bloco e o catálogo são selados com
//! XChaCha20-Poly1305 (nonce aleatório de 192 bits + tag de autenticação).
//! Dedup acontece *dentro* do container sob a chave-mestra única — evitando os
//! ataques de confirmação da *convergent encryption*.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::{aead::Aead, Key, KeyInit, XChaCha20Poly1305, XNonce};
use fastcdc::v2020::StreamCDC;
use fs2::FileExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Assinatura do formato.
pub const MAGIC: &[u8; 8] = b"FSMVLT01";
/// Tamanho fixo do header em bytes.
pub const HEADER_SIZE: u64 = 4096;
/// Tamanho médio de chunk alvo do FastCDC (64 KiB). Min/max são derivados dele.
/// Fronteiras definidas pelo conteúdo: editar o meio de um arquivo não desloca
/// os blocos seguintes, então o dedup sobrevive a inserções/edições.
pub const DEFAULT_AVG_CHUNK: u32 = 64 * 1024;
/// Versão do formato on-disk.
/// Versão do formato GRAVADA. v9+ usa MessagePack com structs por NOME de campo:
/// adicionar um campo novo (com `#[serde(default)]`) ou remover um NÃO quebra
/// cofres existentes — a migração é transparente, sem bump de versão.
pub const FORMAT_VERSION: u32 = 9;
/// Versão mais antiga que ainda sabemos LER (migrada para a atual no 1º commit).
/// v8 = catálogo em bincode (legado, posicional).
pub const MIN_FORMAT_VERSION: u32 = 8;
/// Nível de compressão zstd padrão (1..=22; 3 é o equilíbrio do zstd).
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;

// --- Flags de bloco (1º byte de cada bloco gravado) ---
const FLAG_ZSTD: u8 = 0x01;
const FLAG_ENC: u8 = 0x02;

// --- Flags do header ---
const HFLAG_ENCRYPTED: u32 = 0x01;

/// Texto-claro de tamanho fixo selado no header para validar a senha na abertura.
const VERIFY_PLAINTEXT: &[u8; 16] = b"fsmanager-verify";

const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// Endereço de conteúdo: BLAKE3 de 32 bytes.
pub type Hash = [u8; 32];

/// Onde um bloco vive fisicamente dentro do arquivo container.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct BlockRef {
    /// Posição no arquivo do byte de flags (início do bloco gravado).
    pub offset: u64,
    /// Bytes ocupados no disco (inclui flags, nonce e tag quando aplicáveis).
    pub len: u32,
    /// Tamanho do conteúdo original (descomprimido) deste chunk.
    pub raw_len: u32,
}

/// Referência ordenada a um chunk: hash de conteúdo + tamanho descomprimido.
/// O tamanho inline evita lookups no índice de blocos ao calcular offsets na
/// leitura aleatória (caso contrário `read_range` fica O(n²)).
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct ChunkRef {
    pub hash: Hash,
    pub len: u32,
}

/// Escritor incremental (streaming) de um arquivo.
///
/// Para escrita SEQUENCIAL (caso da cópia), chunka conforme os dados chegam e
/// grava blocos na hora — memória limitada (~poucos chunks) e sem o "freeze" de
/// re-chunkar tudo no fechamento. Escrita fora de ordem cai para o modo
/// materializado (buffer completo).
pub struct StreamWriter {
    chunks: Vec<ChunkRef>,
    /// Cauda ainda não fragmentada (final do stream).
    pending: Vec<u8>,
    /// Próximo offset esperado para continuar o append sequencial.
    next_offset: u64,
    /// Tamanho lógico total escrito.
    size: u64,
    /// Buffer materializado (Some quando saiu do modo streaming).
    fallback: Option<Vec<u8>>,
    min: u32,
    avg: u32,
    max: u32,
}

impl StreamWriter {
    /// Tamanho lógico escrito até agora.
    pub fn len(&self) -> u64 {
        self.size
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

/// Metadados de um arquivo lógico guardado no container.
#[derive(Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub size: u64,
    pub mtime: i64,
    /// Chunks em ordem (hash + tamanho). Reconstroem o arquivo concatenados.
    pub chunks: Vec<ChunkRef>,
}

/// Uma versão nomeada da árvore de arquivos num instante.
///
/// É barato: guarda só os metadados (`files`); os dados continuam compartilhados
/// no índice `blocks` por endereço de conteúdo. Enquanto existir, mantém seus
/// blocos vivos para o `gc`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub name: String,
    /// Unix timestamp (segundos) de criação.
    pub created: i64,
    pub files: BTreeMap<String, FileEntry>,
    /// Diretórios explícitos (vazios) no instante do snapshot.
    #[serde(default)]
    pub dirs: BTreeSet<String>,
}

/// O índice persistido: mapa de dedup + tabela de arquivos + snapshots.
#[derive(Default, Serialize, Deserialize)]
pub struct Catalog {
    /// Índice de deduplicação: conteúdo -> localização física.
    pub blocks: HashMap<Hash, BlockRef>,
    /// Caminho lógico (estilo unix, "/foo/bar.txt") -> metadados (árvore atual).
    pub files: BTreeMap<String, FileEntry>,
    /// Versões nomeadas (point-in-time) da árvore.
    pub snapshots: Vec<Snapshot>,
    /// Diretórios explícitos (criados vazios via mount). Diretórios derivados
    /// de caminhos de arquivos continuam implícitos.
    #[serde(default)]
    pub dirs: BTreeSet<String>,
    /// Cota máxima de tamanho do `.vault` em bytes (None = sem limite).
    #[serde(default)]
    pub quota: Option<u64>,
}

/// Estado de criptografia de um container aberto (presente só se tem senha).
struct EncState {
    key: [u8; KEY_LEN],
    salt: [u8; SALT_LEN],
    /// Token de verificação selado (nonce || ciphertext), preservado no header.
    verify: Vec<u8>,
}

/// Um container aberto, com o catálogo carregado em memória.
pub struct Vault {
    file: File,
    path: PathBuf,
    chunk_size: u32,
    catalog: Catalog,
    /// Próxima posição livre para append na região de dados.
    next_append: u64,
    /// Nível de compressão zstd usado ao gravar blocos novos.
    zstd_level: i32,
    /// Estado de criptografia, se o container tiver senha.
    enc: Option<EncState>,
    /// Cache de blocos já decodificados (descomprimidos/decifrados), por hash.
    /// Blocos são imutáveis (content-addressed), então nunca ficam obsoletos.
    /// `Mutex` para permitir leitura compartilhada (`&self`) e paralela.
    cache: Mutex<BlockCache>,
}

/// Capacidade padrão do cache de blocos decodificados (128 MiB).
const DEFAULT_CACHE_CAP: usize = 128 << 20;

/// Cache LRU (FIFO) de blocos decodificados. Guarda `Arc` para clonar barato
/// fora do lock.
struct BlockCache {
    map: HashMap<Hash, Arc<Vec<u8>>>,
    order: VecDeque<Hash>,
    bytes: usize,
    cap: usize,
}

impl BlockCache {
    fn new(cap: usize) -> Self {
        BlockCache {
            map: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            cap,
        }
    }
    fn get(&self, hash: &Hash) -> Option<Arc<Vec<u8>>> {
        self.map.get(hash).cloned()
    }
    fn put(&mut self, hash: Hash, data: Arc<Vec<u8>>) {
        let n = data.len();
        if n > self.cap || self.map.contains_key(&hash) {
            return;
        }
        self.bytes += n;
        self.map.insert(hash, data);
        self.order.push_back(hash);
        while self.bytes > self.cap {
            match self.order.pop_front() {
                Some(old) => {
                    if let Some(v) = self.map.remove(&old) {
                        self.bytes -= v.len();
                    }
                }
                None => break,
            }
        }
    }
}

/// Lê exatamente `buf.len()` bytes de `file` a partir de `offset`, SEM mexer na
/// posição do arquivo (leitura posicionada) — permite leituras concorrentes.
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0usize;
        while done < buf.len() {
            let n = file.seek_read(&mut buf[done..], offset + done as u64)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "fim de arquivo inesperado",
                ));
            }
            done += n;
        }
        Ok(())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (file, buf, offset);
        unimplemented!("plataforma sem leitura posicionada")
    }
}

impl Vault {
    /// Cria um container novo e vazio, **sem** criptografia.
    pub fn create(path: impl AsRef<Path>, chunk_size: u32) -> Result<Vault> {
        Self::create_inner(path, chunk_size, None)
    }

    /// Cria um container novo e vazio **cifrado** com a senha informada.
    pub fn create_encrypted(
        path: impl AsRef<Path>,
        chunk_size: u32,
        password: &str,
    ) -> Result<Vault> {
        let salt: [u8; SALT_LEN] = random_bytes();
        let key = derive_key(password, &salt)?;
        let verify = seal(&key, VERIFY_PLAINTEXT)?;
        Self::create_inner(path, chunk_size, Some(EncState { key, salt, verify }))
    }

    fn create_inner(
        path: impl AsRef<Path>,
        chunk_size: u32,
        enc: Option<EncState>,
    ) -> Result<Vault> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            bail!("container já existe: {}", path.display());
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("criando {}", path.display()))?;
        // Trava exclusiva (liberada no drop): impede dois escritores no container.
        file.try_lock_exclusive().map_err(|_| {
            anyhow!("o cofre já está aberto em outro processo (ou montado como drive)")
        })?;

        let mut vault = Vault {
            file,
            path,
            chunk_size,
            catalog: Catalog::default(),
            next_append: HEADER_SIZE,
            zstd_level: DEFAULT_ZSTD_LEVEL,
            enc,
            cache: Mutex::new(BlockCache::new(DEFAULT_CACHE_CAP)),
        };
        vault.file.set_len(HEADER_SIZE)?;
        vault.commit()?;
        Ok(vault)
    }

    /// Abre um container existente. `password` é obrigatório se ele for cifrado.
    pub fn open(path: impl AsRef<Path>, password: Option<&str>) -> Result<Vault> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("abrindo {}", path.display()))?;
        // Trava exclusiva (liberada no drop): impede dois processos no mesmo cofre.
        file.try_lock_exclusive().map_err(|_| {
            anyhow!("o cofre já está aberto em outro processo (ou montado como drive)")
        })?;

        let mut header = [0u8; HEADER_SIZE as usize];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut header)
            .context("lendo header (arquivo curto/corrompido?)")?;

        if &header[0..8] != MAGIC {
            bail!("assinatura inválida — não é um container fsmanager");
        }
        let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
        if !(MIN_FORMAT_VERSION..=FORMAT_VERSION).contains(&version) {
            bail!(
                "versão de formato {version} não suportada (suportadas {MIN_FORMAT_VERSION}..={FORMAT_VERSION})"
            );
        }
        let chunk_size = u32::from_le_bytes(header[12..16].try_into().unwrap());
        let catalog_offset = u64::from_le_bytes(header[16..24].try_into().unwrap());
        let catalog_len = u64::from_le_bytes(header[24..32].try_into().unwrap());
        let hflags = u32::from_le_bytes(header[32..36].try_into().unwrap());

        // Resolve criptografia a partir do header.
        let enc = if hflags & HFLAG_ENCRYPTED != 0 {
            let password = password
                .context("este container é criptografado: informe a senha")?;
            let mut salt = [0u8; SALT_LEN];
            salt.copy_from_slice(&header[36..36 + SALT_LEN]);
            let verify_len =
                u32::from_le_bytes(header[52..56].try_into().unwrap()) as usize;
            let verify = header[56..56 + verify_len].to_vec();

            let key = derive_key(password, &salt)?;
            // Valida a senha selando/abrindo o token conhecido.
            let token = unseal(&key, &verify)
                .map_err(|_| anyhow!("senha incorreta"))?;
            if token != VERIFY_PLAINTEXT {
                bail!("senha incorreta");
            }
            Some(EncState { key, salt, verify })
        } else {
            None
        };

        // Lê e (se preciso) decifra o catálogo.
        let mut buf = vec![0u8; catalog_len as usize];
        file.seek(SeekFrom::Start(catalog_offset))?;
        file.read_exact(&mut buf).context("lendo catálogo")?;
        let raw = match &enc {
            Some(e) => unseal(&e.key, &buf).context("decifrando catálogo")?,
            None => buf,
        };
        let catalog: Catalog = decode_catalog(version, &raw)?;

        Ok(Vault {
            file,
            path,
            chunk_size,
            catalog,
            next_append: catalog_offset + catalog_len,
            zstd_level: DEFAULT_ZSTD_LEVEL,
            enc,
            cache: Mutex::new(BlockCache::new(DEFAULT_CACHE_CAP)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }
    pub fn is_encrypted(&self) -> bool {
        self.enc.is_some()
    }
    /// Ajusta o nível de compressão zstd para gravações subsequentes.
    pub fn set_zstd_level(&mut self, level: i32) {
        self.zstd_level = level;
    }

    /// Cota máxima do `.vault` em bytes (None = sem limite). Persiste no commit.
    pub fn set_quota(&mut self, quota: Option<u64>) {
        self.catalog.quota = quota;
    }
    pub fn quota(&self) -> Option<u64> {
        self.catalog.quota
    }
    /// Tamanho atual ocupado no arquivo (bytes), para comparar com a cota.
    pub fn used_bytes(&self) -> u64 {
        self.next_append
    }

    fn key(&self) -> Option<&[u8; KEY_LEN]> {
        self.enc.as_ref().map(|e| &e.key)
    }

    /// Adiciona/atualiza um arquivo do disco real no caminho lógico `dest`.
    /// Os blocos são gravados na hora; o catálogo só é persistido em [`commit`].
    pub fn add_file(&mut self, src: impl AsRef<Path>, dest: &str) -> Result<()> {
        self.add_file_progress(src, dest, |_done| {})
    }

    /// Como [`add_file`](Self::add_file), mas chama `progress(bytes_processados)`
    /// conforme cada chunk é gravado. A leitura é STREAMING (via `StreamCDC`):
    /// o arquivo é processado chunk a chunk, sem carregar tudo na memória.
    pub fn add_file_progress<F: FnMut(u64)>(
        &mut self,
        src: impl AsRef<Path>,
        dest: &str,
        mut progress: F,
    ) -> Result<()> {
        let src = src.as_ref();
        let meta = std::fs::metadata(src)
            .with_context(|| format!("lendo metadados de {}", src.display()))?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let f = File::open(src).with_context(|| format!("abrindo origem {}", src.display()))?;
        let (min, avg, max) = cdc_params(self.chunk_size);

        let mut chunks = Vec::new();
        let mut total: u64 = 0;
        // FastCDC streaming: lê e fatia o arquivo incrementalmente.
        for item in StreamCDC::new(f, min, avg, max) {
            let chunk = item.map_err(|e| anyhow!("fatiando {} (FastCDC): {e}", src.display()))?;
            total += chunk.length as u64;
            let hash = self.write_block(&chunk.data)?;
            chunks.push(ChunkRef {
                hash,
                len: chunk.length as u32,
            });
            progress(total);
        }

        let dest = normalize_path(dest);
        self.catalog.files.insert(
            dest,
            FileEntry {
                size: total,
                mtime,
                chunks,
            },
        );
        Ok(())
    }

    /// Grava (ou substitui) um arquivo lógico a partir de um buffer completo em
    /// memória. Re-chunka com FastCDC (dedup aplica) e atualiza o catálogo.
    /// Base da montagem read-write: o handle materializa o arquivo, edita, e no
    /// flush chama aqui.
    pub fn write_file(&mut self, logical: &str, data: &[u8], mtime: i64) -> Result<()> {
        let (min, avg, max) = cdc_params(self.chunk_size);
        let mut chunks = Vec::new();
        if !data.is_empty() {
            for chunk in fastcdc::v2020::FastCDC::new(data, min, avg, max) {
                let slice = &data[chunk.offset..chunk.offset + chunk.length];
                let hash = self.write_block(slice)?;
                chunks.push(ChunkRef {
                    hash,
                    len: chunk.length as u32,
                });
            }
        }
        let dest = normalize_path(logical);
        self.catalog.dirs.remove(&dest); // não pode ser dir e arquivo
        self.catalog.files.insert(
            dest,
            FileEntry {
                size: data.len() as u64,
                mtime,
                chunks,
            },
        );
        Ok(())
    }

    /// Inicia uma sessão de escrita streaming.
    pub fn stream_writer(&self) -> StreamWriter {
        let (min, avg, max) = cdc_params(self.chunk_size);
        StreamWriter {
            chunks: Vec::new(),
            pending: Vec::new(),
            next_offset: 0,
            size: 0,
            fallback: None,
            min,
            avg,
            max,
        }
    }

    /// Aplica uma escrita ao writer. Append sequencial chunka incrementalmente;
    /// escrita fora de ordem cai para o modo materializado.
    pub fn stream_write(&mut self, w: &mut StreamWriter, offset: u64, data: &[u8]) -> Result<()> {
        if let Some(buf) = &mut w.fallback {
            let end = offset as usize + data.len();
            if end > buf.len() {
                buf.resize(end, 0);
            }
            buf[offset as usize..end].copy_from_slice(data);
            w.size = w.size.max(end as u64);
            return Ok(());
        }
        if offset == w.next_offset {
            w.pending.extend_from_slice(data);
            w.next_offset += data.len() as u64;
            w.size = w.next_offset;
            // Só fragmenta quando há dados suficientes para cortes estáveis
            // (evita rodar FastCDC a cada escrita pequena).
            if w.pending.len() >= (w.max as usize) * 2 {
                self.flush_complete_chunks(w)?;
            }
            Ok(())
        } else {
            self.switch_to_fallback(w)?;
            let buf = w.fallback.as_mut().unwrap();
            let end = offset as usize + data.len();
            if end > buf.len() {
                buf.resize(end, 0);
            }
            buf[offset as usize..end].copy_from_slice(data);
            w.size = w.size.max(end as u64);
            Ok(())
        }
    }

    /// Emite os chunks completos do `pending`, mantendo a última cauda (que pode
    /// crescer com dados futuros, então sua fronteira ainda não é definitiva).
    fn flush_complete_chunks(&mut self, w: &mut StreamWriter) -> Result<()> {
        let cuts: Vec<(usize, usize)> = fastcdc::v2020::FastCDC::new(&w.pending, w.min, w.avg, w.max)
            .map(|c| (c.offset, c.length))
            .collect();
        if cuts.len() <= 1 {
            return Ok(());
        }
        let last_off = cuts[cuts.len() - 1].0;
        for &(off, len) in &cuts[..cuts.len() - 1] {
            let hash = self.write_block(&w.pending[off..off + len])?;
            w.chunks.push(ChunkRef {
                hash,
                len: len as u32,
            });
        }
        w.pending.drain(..last_off);
        Ok(())
    }

    /// Reconstrói o conteúdo já escrito num buffer materializado (saída do modo streaming).
    fn switch_to_fallback(&mut self, w: &mut StreamWriter) -> Result<()> {
        let buf = self.writer_content(w)?;
        w.fallback = Some(buf);
        w.chunks.clear();
        w.pending.clear();
        Ok(())
    }

    /// Conteúdo completo atual de um writer (chunks emitidos + cauda).
    fn writer_content(&self, w: &StreamWriter) -> Result<Vec<u8>> {
        if let Some(buf) = &w.fallback {
            return Ok(buf.clone());
        }
        let mut buf = Vec::with_capacity(w.size as usize);
        for cr in &w.chunks {
            let data = self.get_block(&cr.hash)?;
            buf.extend_from_slice(&data);
        }
        buf.extend_from_slice(&w.pending);
        Ok(buf)
    }

    /// Materializa um writer num buffer (para servir leituras no meio da escrita).
    pub fn writer_to_buffer(&self, w: StreamWriter) -> Result<Vec<u8>> {
        self.writer_content(&w)
    }

    /// Finaliza a escrita streaming: emite a cauda final e grava o `FileEntry`.
    pub fn finish_write(&mut self, mut w: StreamWriter, logical: &str, mtime: i64) -> Result<()> {
        if let Some(buf) = w.fallback.take() {
            return self.write_file(logical, &buf, mtime);
        }
        if !w.pending.is_empty() {
            for c in fastcdc::v2020::FastCDC::new(&w.pending, w.min, w.avg, w.max) {
                let hash = self.write_block(&w.pending[c.offset..c.offset + c.length])?;
                w.chunks.push(ChunkRef {
                    hash,
                    len: c.length as u32,
                });
            }
        }
        let dest = normalize_path(logical);
        self.catalog.dirs.remove(&dest);
        self.catalog.files.insert(
            dest,
            FileEntry {
                size: w.size,
                mtime,
                chunks: w.chunks,
            },
        );
        Ok(())
    }

    /// Cria um diretório explícito (vazio). Diretórios derivados de arquivos
    /// continuam implícitos e não precisam disto.
    pub fn create_dir(&mut self, logical: &str) -> Result<()> {
        let p = normalize_path(logical);
        if p == "/" {
            return Ok(());
        }
        if self.catalog.files.contains_key(&p) {
            bail!("já existe um arquivo em {p}");
        }
        self.catalog.dirs.insert(p);
        Ok(())
    }

    /// Remove um diretório explícito do catálogo (rmdir). Retorna `true` se existia.
    /// A verificação de "vazio" cabe à camada de montagem.
    pub fn remove_empty_dir(&mut self, logical: &str) -> Result<bool> {
        let p = normalize_path(logical);
        Ok(self.catalog.dirs.remove(&p))
    }

    /// Grava um bloco (deduplicando). Retorna o hash de conteúdo.
    fn write_block(&mut self, data: &[u8]) -> Result<Hash> {
        let hash = *blake3::hash(data).as_bytes();
        if self.catalog.blocks.contains_key(&hash) {
            return Ok(hash); // dedup: já existe, não regrava.
        }
        let stored = encode_block(data, self.zstd_level, self.key())?;
        // Aplica a cota de tamanho (se houver), sobre a posição no arquivo.
        if let Some(q) = self.catalog.quota {
            if self.next_append + stored.len() as u64 > q {
                bail!(
                    "cota de tamanho do cofre excedida (limite {} bytes)",
                    q
                );
            }
        }
        let offset = self.next_append;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&stored)?;
        self.next_append += stored.len() as u64;
        self.catalog.blocks.insert(
            hash,
            BlockRef {
                offset,
                len: stored.len() as u32,
                raw_len: data.len() as u32,
            },
        );
        Ok(hash)
    }

    /// Devolve o conteúdo decodificado de um bloco (do cache, ou lendo+decodificando).
    /// `&self` com leitura posicionada e cache com `Mutex` — seguro e paralelo.
    fn get_block(&self, hash: &Hash) -> Result<Arc<Vec<u8>>> {
        if let Some(arc) = self.cache.lock().unwrap().get(hash) {
            return Ok(arc);
        }
        let bref = *self
            .catalog
            .blocks
            .get(hash)
            .context("bloco referenciado ausente (container corrompido)")?;
        let mut buf = vec![0u8; bref.len as usize];
        read_exact_at(&self.file, &mut buf, bref.offset)?;
        // Sem re-verificar BLAKE3 (busca-se PELO hash; cifrados têm Poly1305).
        let data = Arc::new(decode_block(&buf, self.key())?);
        self.cache.lock().unwrap().put(*hash, data.clone());
        Ok(data)
    }

    /// Lê um arquivo lógico e escreve seu conteúdo em `out`.
    pub fn extract<W: Write>(&self, logical: &str, out: &mut W) -> Result<u64> {
        let logical = normalize_path(logical);
        let entry = self
            .catalog
            .files
            .get(&logical)
            .with_context(|| format!("arquivo não encontrado: {logical}"))?
            .clone();

        let mut written = 0u64;
        for cr in &entry.chunks {
            let data = self.get_block(&cr.hash)?;
            out.write_all(&data)?;
            written += data.len() as u64;
        }
        Ok(written)
    }

    /// Lê `len` bytes de um arquivo lógico a partir de `offset`. `&self`: permite
    /// leituras paralelas (leitura posicionada + cache com Mutex).
    pub fn read_range(&self, logical: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let logical = normalize_path(logical);
        let entry = self
            .catalog
            .files
            .get(&logical)
            .with_context(|| format!("arquivo não encontrado: {logical}"))?
            .clone();
        if offset >= entry.size || len == 0 {
            return Ok(Vec::new());
        }
        let end = (offset + len as u64).min(entry.size);

        // 1) Chunks que tocam o intervalo.
        let mut needed: Vec<(Hash, u64)> = Vec::new();
        let mut pos: u64 = 0;
        for cr in &entry.chunks {
            let chunk_start = pos;
            let chunk_end = pos + cr.len as u64;
            pos = chunk_end;
            if chunk_end <= offset {
                continue;
            }
            if chunk_start >= end {
                break;
            }
            needed.push((cr.hash, chunk_start));
        }

        // 2) Aquece o cache coalescendo IO de blocos contíguos (1 leitura por run).
        self.prefetch(&needed)?;

        // 3) Monta a saída a partir do cache (get_block re-lê se algo foi despejado).
        let mut out = Vec::with_capacity((end - offset) as usize);
        for (hash, chunk_start) in needed {
            let data = self.get_block(&hash)?;
            let from = offset.saturating_sub(chunk_start) as usize;
            let to = ((end - chunk_start) as usize).min(data.len());
            out.extend_from_slice(&data[from..to]);
        }
        Ok(out)
    }

    /// Decodifica os blocos `needed` ainda não em cache, lendo do `.vault` em
    /// lotes: runs fisicamente contíguos são lidos numa única leitura posicionada.
    fn prefetch(&self, needed: &[(Hash, u64)]) -> Result<()> {
        let cached = |h: &Hash| self.cache.lock().unwrap().get(h).is_some();
        let mut i = 0;
        while i < needed.len() {
            let h = needed[i].0;
            if cached(&h) {
                i += 1;
                continue;
            }
            let first = *self
                .catalog
                .blocks
                .get(&h)
                .context("bloco referenciado ausente (container corrompido)")?;
            let run_start = first.offset;
            let mut run_end = first.offset + first.len as u64;
            let mut run: Vec<(Hash, BlockRef)> = vec![(h, first)];
            let mut j = i + 1;
            while j < needed.len() {
                let h2 = needed[j].0;
                if cached(&h2) {
                    break;
                }
                let b2 = *self
                    .catalog
                    .blocks
                    .get(&h2)
                    .context("bloco referenciado ausente (container corrompido)")?;
                if b2.offset == run_end {
                    run_end = b2.offset + b2.len as u64;
                    run.push((h2, b2));
                    j += 1;
                } else {
                    break;
                }
            }
            let mut buf = vec![0u8; (run_end - run_start) as usize];
            read_exact_at(&self.file, &mut buf, run_start)?;
            for (bh, br) in run {
                let rel = (br.offset - run_start) as usize;
                let data = Arc::new(decode_block(&buf[rel..rel + br.len as usize], self.key())?);
                self.cache.lock().unwrap().put(bh, data);
            }
            i = j;
        }
        Ok(())
    }

    /// Resolve um caminho para diretório, arquivo ou inexistente (para `lookup`/`getattr`).
    pub fn resolve(&self, path: &str) -> Option<NodeKind> {
        let p = normalize_path(path);
        if p == "/" {
            return Some(NodeKind::Dir);
        }
        if let Some(e) = self.catalog.files.get(&p) {
            return Some(NodeKind::File {
                size: e.size,
                mtime: e.mtime,
            });
        }
        if self.catalog.dirs.contains(&p) {
            return Some(NodeKind::Dir);
        }
        let pre = format!("{p}/");
        if self.catalog.files.keys().any(|k| k.starts_with(&pre))
            || self.catalog.dirs.iter().any(|k| k.starts_with(&pre))
        {
            return Some(NodeKind::Dir);
        }
        None
    }

    /// Como [`resolve`](Self::resolve), mas case-insensitive (ASCII). Retorna o
    /// caminho REAL (com a grafia do catálogo) além do tipo. Necessário no mount
    /// Windows, onde o WinFsp consulta nomes em maiúsculas em volumes
    /// case-insensitive.
    pub fn resolve_ci(&self, path: &str) -> Option<(String, NodeKind)> {
        let q = normalize_path(path);
        if q == "/" {
            return Some(("/".to_string(), NodeKind::Dir));
        }
        // Caminho rápido: correspondência exata.
        if let Some(e) = self.catalog.files.get(&q) {
            return Some((q, NodeKind::File { size: e.size, mtime: e.mtime }));
        }
        if self.catalog.dirs.contains(&q) {
            return Some((q, NodeKind::Dir));
        }
        // Arquivo, ignorando caixa.
        for (k, e) in &self.catalog.files {
            if k.eq_ignore_ascii_case(&q) {
                return Some((k.clone(), NodeKind::File { size: e.size, mtime: e.mtime }));
            }
        }
        // Diretório explícito, ignorando caixa.
        for d in &self.catalog.dirs {
            if d.eq_ignore_ascii_case(&q) {
                return Some((d.clone(), NodeKind::Dir));
            }
        }
        // Diretório implícito (prefixo de algum caminho), ignorando caixa.
        for k in self.catalog.files.keys().chain(self.catalog.dirs.iter()) {
            if k.len() > q.len()
                && k.as_bytes()[q.len()] == b'/'
                && k[..q.len()].eq_ignore_ascii_case(&q)
            {
                return Some((k[..q.len()].to_string(), NodeKind::Dir));
            }
        }
        None
    }

    /// Lista os filhos imediatos de um diretório (para `readdir`).
    /// Diretórios são implícitos: derivados dos prefixos dos caminhos.
    pub fn list_dir(&self, path: &str) -> Vec<DirEntry> {
        let p = normalize_path(path);
        let pre = if p == "/" { "/".to_string() } else { format!("{p}/") };
        // Por subpasta imediata: (soma de tamanhos, mtime mais recente).
        let mut subdirs: BTreeMap<String, (u64, i64)> = BTreeMap::new();
        let mut entries: Vec<DirEntry> = Vec::new();
        for (k, e) in &self.catalog.files {
            if !k.starts_with(&pre) {
                continue;
            }
            let rest = &k[pre.len()..];
            if rest.is_empty() {
                continue;
            }
            match rest.find('/') {
                None => entries.push(DirEntry {
                    name: rest.to_string(),
                    is_dir: false,
                    size: e.size,
                    mtime: e.mtime,
                }),
                Some(i) => {
                    // Agrega o arquivo na subpasta imediata.
                    let agg = subdirs.entry(rest[..i].to_string()).or_insert((0, 0));
                    agg.0 = agg.0.saturating_add(e.size);
                    agg.1 = agg.1.max(e.mtime);
                }
            }
        }
        // Diretórios explícitos: garante presença (mesmo vazios, com 0/0).
        for d in &self.catalog.dirs {
            if !d.starts_with(&pre) {
                continue;
            }
            let rest = &d[pre.len()..];
            if rest.is_empty() {
                continue;
            }
            let name = match rest.find('/') {
                None => rest,
                Some(i) => &rest[..i],
            };
            subdirs.entry(name.to_string()).or_insert((0, 0));
        }
        for (name, (size, mtime)) in subdirs {
            entries.push(DirEntry {
                name,
                is_dir: true,
                size,
                mtime,
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }

    /// Busca RECURSIVA no cofre inteiro: retorna todo arquivo/pasta cujo CAMINHO
    /// contém `query` (case-insensitive). Casar o caminho inteiro permite buscar
    /// por nome ("relatorio") ou por trecho de caminho ("docs/2020"). Inclui
    /// pastas explícitas e implícitas (derivadas dos caminhos dos arquivos).
    pub fn search(&self, query: &str) -> Vec<SearchHit> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return Vec::new();
        }
        let path_has = |path: &str| path.to_lowercase().contains(&q);
        let mut hits: Vec<SearchHit> = Vec::new();

        // Arquivos.
        for (path, e) in &self.catalog.files {
            if path_has(path) {
                hits.push(SearchHit {
                    path: path.clone(),
                    is_dir: false,
                    size: e.size,
                    mtime: e.mtime,
                });
            }
        }

        // Pastas (explícitas + ancestrais implícitos), deduplicadas.
        let mut dirs: BTreeSet<String> = self.catalog.dirs.clone();
        for path in self.catalog.files.keys() {
            let mut p = path.as_str();
            while let Some(idx) = p.rfind('/') {
                if idx == 0 {
                    break;
                }
                let parent = &p[..idx];
                dirs.insert(parent.to_string());
                p = parent;
            }
        }
        for d in &dirs {
            if path_has(d) {
                hits.push(SearchHit {
                    path: d.clone(),
                    is_dir: true,
                    size: 0,
                    mtime: 0,
                });
            }
        }

        // Pastas primeiro, depois arquivos; cada grupo por caminho.
        hits.sort_by(|a, b| match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.path.cmp(&b.path),
        });
        hits
    }

    /// Remove um arquivo lógico do catálogo. Retorna `true` se existia.
    /// O espaço dos blocos só é recuperado em [`compact_to`].
    pub fn remove(&mut self, logical: &str) -> Result<bool> {
        let logical = normalize_path(logical);
        Ok(self.catalog.files.remove(&logical).is_some())
    }

    /// Remove recursivamente tudo sob o diretório `prefix`. Retorna a contagem.
    pub fn remove_dir(&mut self, prefix: &str) -> Result<usize> {
        let base = normalize_path(prefix);
        let pre = format!("{}/", base.trim_end_matches('/'));
        let victims: Vec<String> = self
            .catalog
            .files
            .keys()
            .filter(|k| **k == base || k.starts_with(&pre))
            .cloned()
            .collect();
        for k in &victims {
            self.catalog.files.remove(k);
        }
        self.catalog
            .dirs
            .retain(|d| !(*d == base || d.starts_with(&pre)));
        Ok(victims.len())
    }

    /// Move/renomeia um arquivo OU uma subárvore inteira (se `src` for um diretório).
    pub fn rename(&mut self, src: &str, dst: &str) -> Result<()> {
        let src = normalize_path(src);
        let dst = normalize_path(dst);

        // Caso 1: arquivo exato.
        if let Some(entry) = self.catalog.files.remove(&src) {
            self.catalog.dirs.remove(&dst);
            self.catalog.files.insert(dst, entry);
            return Ok(());
        }

        // Caso 2: diretório (explícito e/ou prefixo de arquivos/dirs).
        let pre = format!("{src}/");
        let is_dir = self.catalog.dirs.contains(&src)
            || self.catalog.files.keys().any(|k| k.starts_with(&pre))
            || self.catalog.dirs.iter().any(|k| k.starts_with(&pre));
        if !is_dir {
            bail!("origem não encontrada: {src}");
        }
        let dst_base = dst.trim_end_matches('/').to_string();

        // Move arquivos sob o prefixo.
        let file_moves: Vec<String> = self
            .catalog
            .files
            .keys()
            .filter(|k| k.starts_with(&pre))
            .cloned()
            .collect();
        for old in file_moves {
            let suffix = &old[pre.len()..];
            let entry = self.catalog.files.remove(&old).unwrap();
            self.catalog.files.insert(format!("{dst_base}/{suffix}"), entry);
        }
        // Move diretórios explícitos: o próprio src e os sob src/.
        let dir_moves: Vec<String> = self
            .catalog
            .dirs
            .iter()
            .filter(|d| **d == src || d.starts_with(&pre))
            .cloned()
            .collect();
        for old in dir_moves {
            self.catalog.dirs.remove(&old);
            let new = if old == src {
                dst.clone()
            } else {
                format!("{dst_base}/{}", &old[pre.len()..])
            };
            self.catalog.dirs.insert(new);
        }
        Ok(())
    }

    /// Cria um snapshot nomeado da árvore atual.
    pub fn snapshot_create(&mut self, name: &str) -> Result<()> {
        if name.trim().is_empty() {
            bail!("nome de snapshot vazio");
        }
        if self.catalog.snapshots.iter().any(|s| s.name == name) {
            bail!("snapshot já existe: {name}");
        }
        self.catalog.snapshots.push(Snapshot {
            name: name.to_string(),
            created: now_unix(),
            files: self.catalog.files.clone(),
            dirs: self.catalog.dirs.clone(),
        });
        Ok(())
    }

    /// Snapshots existentes (mais antigo → mais recente).
    pub fn snapshots(&self) -> &[Snapshot] {
        &self.catalog.snapshots
    }

    /// Substitui a árvore de arquivos atual pelo conteúdo de um snapshot.
    /// Os dados continuam disponíveis pois o snapshot mantinha os blocos vivos.
    pub fn snapshot_restore(&mut self, name: &str) -> Result<()> {
        let snap = self
            .catalog
            .snapshots
            .iter()
            .find(|s| s.name == name)
            .with_context(|| format!("snapshot não encontrado: {name}"))?;
        self.catalog.files = snap.files.clone();
        self.catalog.dirs = snap.dirs.clone();
        Ok(())
    }

    /// Apaga um snapshot. Retorna `true` se existia. Os blocos exclusivos dele
    /// só voltam ao espaço livre no próximo `gc`.
    pub fn snapshot_delete(&mut self, name: &str) -> Result<bool> {
        let before = self.catalog.snapshots.len();
        self.catalog.snapshots.retain(|s| s.name != name);
        Ok(self.catalog.snapshots.len() != before)
    }

    /// Verifica a integridade do container: lê e decodifica cada bloco único,
    /// confere o endereço de conteúdo (BLAKE3), e checa se todos os chunks
    /// referenciados existem. Não usa o cache (testa os bytes em disco).
    pub fn verify(&self) -> Result<VerifyReport> {
        let mut report = VerifyReport::default();
        const MAX_ERRORS: usize = 100;

        let hashes: Vec<Hash> = self.catalog.blocks.keys().copied().collect();
        for hash in hashes {
            let bref = self.catalog.blocks[&hash];
            let mut buf = vec![0u8; bref.len as usize];
            if read_exact_at(&self.file, &mut buf, bref.offset).is_err() {
                report.blocks_bad += 1;
                if report.errors.len() < MAX_ERRORS {
                    report.errors.push("bloco ilegível (leitura falhou)".to_string());
                }
                continue;
            }
            match decode_block(&buf, self.key()) {
                Ok(data) => {
                    if blake3::hash(&data).as_bytes() == &hash {
                        report.blocks_ok += 1;
                    } else {
                        report.blocks_bad += 1;
                        if report.errors.len() < MAX_ERRORS {
                            report.errors.push("bloco com conteúdo corrompido (hash não bate)".to_string());
                        }
                    }
                }
                Err(_) => {
                    report.blocks_bad += 1;
                    if report.errors.len() < MAX_ERRORS {
                        report.errors.push("bloco não decodifica (corrompido ou senha errada)".to_string());
                    }
                }
            }
        }

        // Chunks que apontam para blocos inexistentes.
        for (path, entry) in &self.catalog.files {
            for cr in &entry.chunks {
                if !self.catalog.blocks.contains_key(&cr.hash) {
                    report.missing_blocks += 1;
                    if report.errors.len() < MAX_ERRORS {
                        report.errors.push(format!("{path}: referência a bloco ausente"));
                    }
                }
            }
        }
        Ok(report)
    }

    /// Verifica se um bloco existe, lê e decodifica, e o hash bate.
    fn block_is_valid(&self, hash: &Hash) -> bool {
        let Some(bref) = self.catalog.blocks.get(hash).copied() else {
            return false;
        };
        let mut buf = vec![0u8; bref.len as usize];
        if read_exact_at(&self.file, &mut buf, bref.offset).is_err() {
            return false;
        }
        match decode_block(&buf, self.key()) {
            Ok(data) => blake3::hash(&data).as_bytes() == hash,
            Err(_) => false,
        }
    }

    /// Repara o container: para cada arquivo, mantém o prefixo de chunks íntegros
    /// e descarta a partir do primeiro bloco ruim/ausente (trunca). Arquivos sem
    /// nenhum chunk salvável são removidos. Chame [`commit`] depois (e `gc` para
    /// recuperar espaço). NÃO recupera o dado corrompido — só deixa o cofre
    /// consistente e salva o que dá.
    pub fn repair(&mut self) -> Result<RepairReport> {
        let mut report = RepairReport::default();

        // 1) Identifica blocos inválidos e remove do índice.
        let block_hashes: Vec<Hash> = self.catalog.blocks.keys().copied().collect();
        let mut bad: HashSet<Hash> = HashSet::new();
        for h in block_hashes {
            if !self.block_is_valid(&h) {
                bad.insert(h);
            }
        }
        for h in &bad {
            self.catalog.blocks.remove(h);
        }

        // 2) Trunca cada arquivo no primeiro chunk que referencia bloco ruim/ausente.
        let paths: Vec<String> = self.catalog.files.keys().cloned().collect();
        for path in paths {
            let entry = self.catalog.files[&path].clone();
            let mut good: Vec<ChunkRef> = Vec::new();
            let mut good_len = 0u64;
            let mut damaged = false;
            for cr in &entry.chunks {
                if bad.contains(&cr.hash) || !self.catalog.blocks.contains_key(&cr.hash) {
                    damaged = true;
                    break;
                }
                good.push(*cr);
                good_len += cr.len as u64;
            }
            if !damaged {
                continue;
            }
            report.files_damaged += 1;
            if good.is_empty() {
                self.catalog.files.remove(&path);
                report.removed.push(path);
            } else {
                let e = self.catalog.files.get_mut(&path).unwrap();
                e.chunks = good;
                e.size = good_len;
                report.truncated.push((path, good_len));
            }
        }
        Ok(report)
    }

    /// Reescreve o container em `dest` mantendo só os blocos alcançáveis pelos
    /// arquivos atuais — recupera espaço de removidos e de gerações antigas.
    /// Preserva a criptografia (mesma chave/salt) para a mesma senha continuar valendo.
    pub fn compact_to(&mut self, dest: impl AsRef<Path>) -> Result<CompactReport> {
        let dest = dest.as_ref();
        if dest.exists() {
            bail!("destino já existe: {}", dest.display());
        }
        let bytes_before = self.file.metadata()?.len();
        let blocks_before = self.catalog.blocks.len();

        // Hashes alcançáveis: árvore atual + todos os snapshots nomeados.
        let mut reachable: HashSet<Hash> = HashSet::new();
        for f in self.catalog.files.values() {
            for cr in &f.chunks {
                reachable.insert(cr.hash);
            }
        }
        for snap in &self.catalog.snapshots {
            for f in snap.files.values() {
                for cr in &f.chunks {
                    reachable.insert(cr.hash);
                }
            }
        }

        let mut newfile = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dest)
            .with_context(|| format!("criando {}", dest.display()))?;
        newfile.set_len(HEADER_SIZE)?;
        let mut next = HEADER_SIZE;
        let mut new_blocks: HashMap<Hash, BlockRef> = HashMap::new();
        let mut buf = Vec::new();

        for (hash, bref) in &self.catalog.blocks {
            if !reachable.contains(hash) {
                continue; // bloco órfão: descartado.
            }
            buf.resize(bref.len as usize, 0);
            self.file.seek(SeekFrom::Start(bref.offset))?;
            self.file.read_exact(&mut buf)?;
            newfile.seek(SeekFrom::Start(next))?;
            newfile.write_all(&buf)?;
            new_blocks.insert(
                *hash,
                BlockRef {
                    offset: next,
                    len: bref.len,
                    raw_len: bref.raw_len,
                },
            );
            next += bref.len as u64;
        }

        let new_catalog = Catalog {
            blocks: new_blocks,
            files: self.catalog.files.clone(),
            snapshots: self.catalog.snapshots.clone(),
            dirs: self.catalog.dirs.clone(),
            quota: self.catalog.quota,
        };
        let raw = encode_catalog(&new_catalog)?;
        let bytes = match &self.enc {
            Some(e) => seal(&e.key, &raw).context("cifrando catálogo")?,
            None => raw,
        };
        newfile.seek(SeekFrom::Start(next))?;
        newfile.write_all(&bytes)?;
        newfile.sync_data()?;

        let header = build_header(self.chunk_size, next, bytes.len() as u64, self.enc.as_ref());
        newfile.seek(SeekFrom::Start(0))?;
        newfile.write_all(&header)?;
        newfile.sync_all()?;

        Ok(CompactReport {
            blocks_before,
            blocks_after: new_catalog.blocks.len(),
            bytes_before,
            bytes_after: next + bytes.len() as u64,
        })
    }

    /// Reescreve o container em `dest` com uma nova senha (ou sem senha, se
    /// `new_password` for None), re-encriptando todos os blocos. O hash de
    /// conteúdo é preservado (é do texto-claro), então dedup/snapshots continuam.
    /// Use para DEFINIR, TROCAR ou REMOVER a senha do cofre.
    pub fn rekey_to(&mut self, dest: impl AsRef<Path>, new_password: Option<&str>) -> Result<()> {
        let dest = dest.as_ref();
        if dest.exists() {
            bail!("destino já existe: {}", dest.display());
        }
        // Novo estado de criptografia.
        let new_enc = match new_password {
            Some(pw) => {
                let salt: [u8; SALT_LEN] = random_bytes();
                let key = derive_key(pw, &salt)?;
                let verify = seal(&key, VERIFY_PLAINTEXT)?;
                Some(EncState { key, salt, verify })
            }
            None => None,
        };
        let new_key = new_enc.as_ref().map(|e| &e.key);

        // Blocos alcançáveis (árvore + snapshots).
        let mut reachable: HashSet<Hash> = HashSet::new();
        for f in self.catalog.files.values() {
            for cr in &f.chunks {
                reachable.insert(cr.hash);
            }
        }
        for snap in &self.catalog.snapshots {
            for f in snap.files.values() {
                for cr in &f.chunks {
                    reachable.insert(cr.hash);
                }
            }
        }

        let mut newfile = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dest)
            .with_context(|| format!("criando {}", dest.display()))?;
        newfile.set_len(HEADER_SIZE)?;
        let mut next = HEADER_SIZE;
        let mut new_blocks: HashMap<Hash, BlockRef> = HashMap::new();

        let block_hashes: Vec<Hash> = self.catalog.blocks.keys().copied().collect();
        for hash in block_hashes {
            if !reachable.contains(&hash) {
                continue;
            }
            // Decodifica com a chave ATUAL, re-encoda com a NOVA.
            let plain = self.get_block(&hash)?;
            let stored = encode_block(&plain, self.zstd_level, new_key)?;
            newfile.seek(SeekFrom::Start(next))?;
            newfile.write_all(&stored)?;
            new_blocks.insert(
                hash,
                BlockRef {
                    offset: next,
                    len: stored.len() as u32,
                    raw_len: plain.len() as u32,
                },
            );
            next += stored.len() as u64;
        }

        let new_catalog = Catalog {
            blocks: new_blocks,
            files: self.catalog.files.clone(),
            snapshots: self.catalog.snapshots.clone(),
            dirs: self.catalog.dirs.clone(),
            quota: self.catalog.quota,
        };
        let raw = encode_catalog(&new_catalog)?;
        let bytes = match &new_enc {
            Some(e) => seal(&e.key, &raw).context("cifrando catálogo")?,
            None => raw,
        };
        newfile.seek(SeekFrom::Start(next))?;
        newfile.write_all(&bytes)?;
        newfile.sync_data()?;

        let header = build_header(self.chunk_size, next, bytes.len() as u64, new_enc.as_ref());
        newfile.seek(SeekFrom::Start(0))?;
        newfile.write_all(&header)?;
        newfile.sync_all()?;
        Ok(())
    }

    /// Persiste o catálogo no fim do arquivo e atualiza o header.
    ///
    /// Ordem de durabilidade: grava catálogo → fsync → atualiza header → fsync.
    /// Se cair antes do header, o catálogo antigo continua válido.
    pub fn commit(&mut self) -> Result<()> {
        let raw = encode_catalog(&self.catalog)?;
        let bytes = match &self.enc {
            Some(e) => seal(&e.key, &raw).context("cifrando catálogo")?,
            None => raw,
        };
        let offset = self.next_append;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&bytes)?;
        self.file.sync_data()?;

        let header = build_header(self.chunk_size, offset, bytes.len() as u64, self.enc.as_ref());
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&header)?;
        self.file.sync_all()?;

        self.next_append = offset + bytes.len() as u64;
        Ok(())
    }

    /// Estatísticas de uso, separando ganho de dedup e de compressão.
    pub fn stats(&self) -> Stats {
        let logical: u64 = self.catalog.files.values().map(|f| f.size).sum();
        let unique_raw: u64 = self.catalog.blocks.values().map(|b| b.raw_len as u64).sum();
        let physical: u64 = self.catalog.blocks.values().map(|b| b.len as u64).sum();
        Stats {
            files: self.catalog.files.len(),
            unique_blocks: self.catalog.blocks.len(),
            logical_bytes: logical,
            unique_raw_bytes: unique_raw,
            physical_bytes: physical,
            encrypted: self.enc.is_some(),
            snapshots: self.catalog.snapshots.len(),
            quota: self.catalog.quota,
            used_bytes: self.next_append,
        }
    }
}

/// Estatísticas resumidas do container.
pub struct Stats {
    pub files: usize,
    pub unique_blocks: usize,
    /// Soma do tamanho lógico de todos os arquivos.
    pub logical_bytes: u64,
    /// Soma do tamanho original dos blocos *únicos* (após dedup, antes de comprimir).
    pub unique_raw_bytes: u64,
    /// Bytes realmente ocupados no disco (após dedup e compressão).
    pub physical_bytes: u64,
    pub encrypted: bool,
    pub snapshots: usize,
    /// Cota máxima do `.vault` em bytes (None = ilimitado).
    pub quota: Option<u64>,
    /// Tamanho atual do arquivo `.vault` (posição de append).
    pub used_bytes: u64,
}

/// O que um caminho representa no sistema de arquivos lógico.
pub enum NodeKind {
    Dir,
    File { size: u64, mtime: i64 },
}

/// Uma entrada de diretório (filho imediato), para `readdir`.
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: i64,
}

/// Resultado de [`Vault::search`]: caminho lógico completo de um acerto.
pub struct SearchHit {
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: i64,
}

/// Resultado de uma verificação de integridade ([`Vault::verify`]).
#[derive(Default)]
pub struct VerifyReport {
    /// Blocos únicos lidos e decodificados com sucesso.
    pub blocks_ok: usize,
    /// Blocos que falharam (não leem, não decodificam, ou hash não bate).
    pub blocks_bad: usize,
    /// Referências de chunk para blocos ausentes no índice.
    pub missing_blocks: usize,
    /// Descrições dos problemas encontrados (limitado).
    pub errors: Vec<String>,
}

impl VerifyReport {
    pub fn is_healthy(&self) -> bool {
        self.blocks_bad == 0 && self.missing_blocks == 0
    }
}

/// Resultado de um reparo ([`Vault::repair`]).
#[derive(Default)]
pub struct RepairReport {
    /// Arquivos que tinham algum bloco ruim/ausente.
    pub files_damaged: usize,
    /// Arquivos removidos (nada salvável).
    pub removed: Vec<String>,
    /// Arquivos truncados no prefixo íntegro: (caminho, novo tamanho).
    pub truncated: Vec<(String, u64)>,
}

/// Resultado de uma compactação ([`Vault::compact_to`]).
pub struct CompactReport {
    pub blocks_before: usize,
    pub blocks_after: usize,
    pub bytes_before: u64,
    pub bytes_after: u64,
}

impl CompactReport {
    pub fn reclaimed_bytes(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }
}

/// Serializa o catálogo no formato ATUAL (v9): MessagePack com structs mapeados
/// por NOME de campo. Isso torna o formato TOLERANTE: adicionar um campo novo
/// (com `#[serde(default)]`) ou remover um campo antigo não impede ler cofres
/// gravados por outra versão do app.
fn encode_catalog(catalog: &Catalog) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(catalog).context("serializando catálogo")
}

/// Desserializa o catálogo conforme a versão lida do header. v8 = bincode
/// (legado, posicional); v9 = MessagePack. Um cofre v8 é lido aqui e MIGRADO
/// para v9 automaticamente no próximo `commit` (que grava no formato atual).
fn decode_catalog(version: u32, raw: &[u8]) -> Result<Catalog> {
    match version {
        8 => bincode::deserialize(raw).context("desserializando catálogo (v8 legado)"),
        9 => rmp_serde::from_slice(raw).context("desserializando catálogo (v9)"),
        v => bail!("versão de formato {v} não suportada"),
    }
}

/// Monta o header de 4 KiB com os ponteiros e o estado de criptografia.
fn build_header(
    chunk_size: u32,
    catalog_offset: u64,
    catalog_len: u64,
    enc: Option<&EncState>,
) -> [u8; HEADER_SIZE as usize] {
    let mut header = [0u8; HEADER_SIZE as usize];
    header[0..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[12..16].copy_from_slice(&chunk_size.to_le_bytes());
    header[16..24].copy_from_slice(&catalog_offset.to_le_bytes());
    header[24..32].copy_from_slice(&catalog_len.to_le_bytes());
    if let Some(e) = enc {
        header[32..36].copy_from_slice(&HFLAG_ENCRYPTED.to_le_bytes());
        header[36..36 + SALT_LEN].copy_from_slice(&e.salt);
        header[52..56].copy_from_slice(&(e.verify.len() as u32).to_le_bytes());
        header[56..56 + e.verify.len()].copy_from_slice(&e.verify);
    }
    header
}

fn savings(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    1.0 - (part as f64 / whole as f64)
}

impl Stats {
    /// Economia só por deduplicação (blocos repetidos eliminados).
    pub fn dedup_savings(&self) -> f64 {
        savings(self.unique_raw_bytes, self.logical_bytes)
    }
    /// Economia só por compressão (sobre os blocos únicos).
    /// Com criptografia a tag/nonce adicionam alguns bytes por bloco.
    pub fn compression_savings(&self) -> f64 {
        savings(self.physical_bytes, self.unique_raw_bytes)
    }
    /// Economia total: do tamanho lógico ao tamanho em disco.
    pub fn total_savings(&self) -> f64 {
        savings(self.physical_bytes, self.logical_bytes)
    }
}

// ----------------------- pipeline de bloco -----------------------

/// Codifica um bloco: comprime (se compensar) e cifra (se houver chave).
/// 1º byte = flags; corpo = `[nonce][ciphertext]` quando cifrado.
fn encode_block(data: &[u8], level: i32, key: Option<&[u8; KEY_LEN]>) -> Result<Vec<u8>> {
    // Heurística barata: testa compressão num sample; se o sample mal comprime
    // (ex.: dados já comprimidos como .rar/.jpg/.zip), pula o zstd do chunk
    // inteiro e grava cru — evita desperdiçar CPU comprimindo o incompressível.
    let sample_len = data.len().min(8 * 1024);
    let sample_compressible = sample_len > 0 && {
        let test = zstd::stream::encode_all(&data[..sample_len], level)
            .context("testando compressão (sample)")?;
        test.len() < sample_len * 9 / 10 // ganho > ~10% no sample
    };

    let (mut flags, inner) = if sample_compressible {
        let compressed = zstd::stream::encode_all(data, level).context("comprimindo bloco")?;
        if compressed.len() < data.len() {
            (FLAG_ZSTD, compressed)
        } else {
            (0u8, data.to_vec())
        }
    } else {
        (0u8, data.to_vec()) // incompressível: grava cru, sem comprimir o chunk todo
    };
    let body = match key {
        Some(k) => {
            flags |= FLAG_ENC;
            seal(k, &inner)?
        }
        None => inner,
    };
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(flags);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Inverso de [`encode_block`]: lê as flags, decifra e descomprime conforme.
fn decode_block(stored: &[u8], key: Option<&[u8; KEY_LEN]>) -> Result<Vec<u8>> {
    let (flags, body) = stored
        .split_first()
        .context("bloco vazio (container corrompido)")?;
    let inner = if flags & FLAG_ENC != 0 {
        let k = key.context("bloco criptografado, mas o container foi aberto sem senha")?;
        unseal(k, body)?
    } else {
        body.to_vec()
    };
    let data = if flags & FLAG_ZSTD != 0 {
        zstd::stream::decode_all(inner.as_slice()).context("descomprimindo bloco")?
    } else {
        inner
    };
    Ok(data)
}

// ----------------------- criptografia -----------------------

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

/// Deriva a chave-mestra de 32 bytes a partir da senha (Argon2id).
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("derivação de chave (Argon2) falhou: {e}"))?;
    Ok(key)
}

/// Sela bytes com XChaCha20-Poly1305. Saída = `[nonce(24)][ciphertext+tag]`.
fn seal(key: &[u8; KEY_LEN], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plain)
        .map_err(|_| anyhow!("falha ao criptografar"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverso de [`seal`]. Erro indica senha incorreta ou dado corrompido (tag).
fn unseal(key: &[u8; KEY_LEN], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN {
        bail!("dado cifrado curto demais");
    }
    let (nonce, ct) = data.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| anyhow!("falha ao descriptografar (senha incorreta ou dado corrompido)"))
}

// ----------------------- utilidades -----------------------

/// Tempo atual em segundos desde a época Unix (0 se o relógio estiver antes dela).
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Deriva `(min, avg, max)` válidos para o FastCDC a partir do alvo médio,
/// respeitando os limites da crate (min≥64, avg≥256, max≤16 MiB).
fn cdc_params(target_avg: u32) -> (u32, u32, u32) {
    use fastcdc::v2020::{AVERAGE_MIN, MAXIMUM_MAX, MINIMUM_MIN};
    let avg = target_avg.clamp(AVERAGE_MIN, MAXIMUM_MAX / 4);
    let min = (avg / 4).max(MINIMUM_MIN);
    let max = (avg.saturating_mul(4)).min(MAXIMUM_MAX);
    (min, avg, max)
}

/// Normaliza caminho lógico: separadores `/`, prefixo `/`, sem `./` ou `\`.
fn normalize_path(p: &str) -> String {
    let p = p.replace('\\', "/");
    let trimmed = p.trim_start_matches("./").trim_start_matches('/');
    format!("/{trimmed}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fsm-test-{}-{}", tag, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn roundtrip_and_dedup() {
        let dir = tmp_dir("dedup");
        let vault_path = dir.join("t.vault");
        let _ = std::fs::remove_file(&vault_path);

        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        std::fs::write(&a, b"conteudo identico repetido").unwrap();
        std::fs::write(&b, b"conteudo identico repetido").unwrap();

        let mut v = Vault::create(&vault_path, 64).unwrap();
        v.add_file(&a, "a.bin").unwrap();
        v.add_file(&b, "b.bin").unwrap();
        v.commit().unwrap();

        let s = v.stats();
        assert_eq!(s.files, 2);
        assert_eq!(s.unique_blocks, 1, "dedup deveria colapsar blocos iguais");

        drop(v); // libera a trava antes de reabrir o mesmo cofre
        let v2 = Vault::open(&vault_path, None).unwrap();
        let mut out = Cursor::new(Vec::new());
        v2.extract("a.bin", &mut out).unwrap();
        assert_eq!(out.into_inner(), b"conteudo identico repetido");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rm_mv_and_gc_reclaim_space() {
        let dir = tmp_dir("gc");
        let vault_path = dir.join("g.vault");
        let compact_path = dir.join("g2.vault");
        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_file(&compact_path);

        // Conteúdo incompressível e único por arquivo (evita dedup/compressão
        // mascararem a recuperação de espaço).
        let mk = |seed: u32, n: usize| -> Vec<u8> {
            let mut x = seed | 1;
            (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    (x & 0xff) as u8
                })
                .collect()
        };
        let big = dir.join("big.bin");
        let keep = dir.join("keep.bin");
        std::fs::write(&big, mk(1, 50_000)).unwrap();
        std::fs::write(&keep, mk(2, 10_000)).unwrap();

        let mut v = Vault::create(&vault_path, 4096).unwrap();
        v.add_file(&big, "/lixo/big.bin").unwrap();
        v.add_file(&keep, "keep.bin").unwrap();
        v.commit().unwrap();
        let before = v.stats().unique_blocks;

        // mv: renomeia o que vamos manter.
        v.rename("keep.bin", "/docs/keep.bin").unwrap();
        // rm -r: remove o diretório inteiro do arquivo grande.
        let removed = v.remove_dir("/lixo").unwrap();
        assert_eq!(removed, 1);
        v.commit().unwrap();

        assert!(v.catalog().files.contains_key("/docs/keep.bin"));
        assert!(!v.catalog().files.contains_key("/lixo/big.bin"));

        // gc: deve descartar os blocos órfãos do arquivo grande.
        let report = v.compact_to(&compact_path).unwrap();
        assert!(report.blocks_after < before, "gc deveria remover blocos órfãos");
        assert!(report.reclaimed_bytes() > 30_000, "deveria recuperar o arquivo grande");

        // O container compactado ainda abre e o arquivo mantido bate.
        let v2 = Vault::open(&compact_path, None).unwrap();
        let mut out = Cursor::new(Vec::new());
        v2.extract("/docs/keep.bin", &mut out).unwrap();
        assert_eq!(out.into_inner(), std::fs::read(&keep).unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Gera bytes pseudo-aleatórios determinísticos (incompressíveis).
    fn pseudo_random(seed: u32, n: usize) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x & 0xff) as u8
            })
            .collect()
    }

    #[test]
    fn verify_detects_corruption() {
        let dir = tmp_dir("verify");
        let vp = dir.join("v.vault");
        let _ = std::fs::remove_file(&vp);
        let mut v = Vault::create(&vp, DEFAULT_AVG_CHUNK).unwrap();
        let f = dir.join("a.bin");
        std::fs::write(&f, pseudo_random(7, 100_000)).unwrap();
        v.add_file(&f, "a.bin").unwrap();
        v.commit().unwrap();

        let rep = v.verify().unwrap();
        assert!(rep.is_healthy());
        assert!(rep.blocks_ok > 0 && rep.blocks_bad == 0);
        drop(v);

        // Corrompe bytes na região de dados (após o header de 4 KiB).
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new().write(true).open(&vp).unwrap();
            file.seek(SeekFrom::Start(5000)).unwrap();
            file.write_all(&[0xFF; 128]).unwrap();
        }
        let v2 = Vault::open(&vp, None).unwrap();
        let rep2 = v2.verify().unwrap();
        assert!(!rep2.is_healthy());
        assert!(rep2.blocks_bad > 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn opens_and_migrates_a_v8_vault() {
        let dir = tmp_dir("migrate");
        let vp = dir.join("old.vault");
        let _ = std::fs::remove_file(&vp);

        // Fabrica um cofre v8 (legado): header v8 + catálogo em bincode, sem cifra.
        let mut cat = Catalog::default();
        cat.files.insert(
            "/legado.txt".into(),
            FileEntry { size: 0, mtime: 7, chunks: vec![] },
        );
        cat.dirs.insert("/pasta".into());
        let raw = bincode::serialize(&cat).unwrap();
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::File::create(&vp).unwrap();
            f.set_len(HEADER_SIZE).unwrap();
            f.seek(SeekFrom::Start(HEADER_SIZE)).unwrap();
            f.write_all(&raw).unwrap();
            let mut header = [0u8; HEADER_SIZE as usize];
            header[0..8].copy_from_slice(MAGIC);
            header[8..12].copy_from_slice(&8u32.to_le_bytes()); // versão 8
            header[12..16].copy_from_slice(&DEFAULT_AVG_CHUNK.to_le_bytes());
            header[16..24].copy_from_slice(&HEADER_SIZE.to_le_bytes());
            header[24..32].copy_from_slice(&(raw.len() as u64).to_le_bytes());
            f.seek(SeekFrom::Start(0)).unwrap();
            f.write_all(&header).unwrap();
        }

        // Abre (lê via bincode) e confirma os dados do cofre legado.
        let mut v = Vault::open(&vp, None).unwrap();
        assert!(v.resolve("/legado.txt").is_some());
        assert!(v.catalog().dirs.contains("/pasta"));
        v.commit().unwrap(); // reescreve no formato ATUAL (v9)
        drop(v);

        // Reabre: agora é v9 no disco, dados intactos.
        let v2 = Vault::open(&vp, None).unwrap();
        assert!(v2.resolve("/legado.txt").is_some());
        drop(v2);
        let disk = std::fs::read(&vp).unwrap();
        let ver = u32::from_le_bytes(disk[8..12].try_into().unwrap());
        assert_eq!(ver, FORMAT_VERSION, "deveria ter migrado para o formato atual");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v9_format_tolerates_added_and_removed_fields() {
        // Catálogo gravado por uma versão ANTIGA (sem o campo `quota`).
        #[derive(serde::Serialize)]
        struct OldCatalog {
            blocks: HashMap<Hash, BlockRef>,
            files: BTreeMap<String, FileEntry>,
            snapshots: Vec<Snapshot>,
            dirs: BTreeSet<String>,
        }
        let old = OldCatalog {
            blocks: HashMap::new(),
            files: BTreeMap::new(),
            snapshots: vec![],
            dirs: BTreeSet::new(),
        };
        let bytes = rmp_serde::to_vec_named(&old).unwrap();
        // A versão ATUAL lê sem erro; o campo ausente vira default (None).
        let cat: Catalog = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(cat.quota, None);

        // Catálogo de uma versão FUTURA (campo extra desconhecido) é lido, ignorando-o.
        #[derive(serde::Serialize)]
        struct NewerCatalog {
            blocks: HashMap<Hash, BlockRef>,
            files: BTreeMap<String, FileEntry>,
            snapshots: Vec<Snapshot>,
            dirs: BTreeSet<String>,
            quota: Option<u64>,
            campo_do_futuro: u64,
        }
        let newer = NewerCatalog {
            blocks: HashMap::new(),
            files: BTreeMap::new(),
            snapshots: vec![],
            dirs: BTreeSet::new(),
            quota: Some(42),
            campo_do_futuro: 999,
        };
        let bytes2 = rmp_serde::to_vec_named(&newer).unwrap();
        let cat2: Catalog = rmp_serde::from_slice(&bytes2).unwrap();
        assert_eq!(cat2.quota, Some(42));
    }

    #[test]
    fn second_open_is_blocked_by_lock() {
        let dir = tmp_dir("lock");
        let vp = dir.join("l.vault");
        let _ = std::fs::remove_file(&vp);
        let v = Vault::create(&vp, 64).unwrap();
        // Abrir o MESMO cofre uma 2ª vez deve falhar (trava exclusiva do SO).
        assert!(
            Vault::open(&vp, None).is_err(),
            "abrir o cofre 2x ao mesmo tempo deveria falhar pela trava"
        );
        drop(v); // fechou => libera a trava
        assert!(Vault::open(&vp, None).is_ok(), "após fechar, deveria abrir normal");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn search_finds_across_subfolders() {
        let dir = tmp_dir("search");
        let vp = dir.join("s.vault");
        let _ = std::fs::remove_file(&vp);
        let mut v = Vault::create(&vp, DEFAULT_AVG_CHUNK).unwrap();
        v.write_file("/docs/relatorio.pdf", b"a", 1).unwrap();
        v.write_file("/docs/2020/foto.jpg", b"b", 1).unwrap();
        v.write_file("/notas.txt", b"c", 1).unwrap();
        v.create_dir("/relatorios").unwrap();
        v.commit().unwrap();

        let hits = v.search("relat");
        let paths: Vec<&str> = hits.iter().map(|h| h.path.as_str()).collect();
        assert!(paths.contains(&"/docs/relatorio.pdf"));
        assert!(paths.contains(&"/relatorios"));
        assert!(hits[0].is_dir); // pastas primeiro

        let foto = v.search("FOTO"); // case-insensitive
        assert_eq!(foto.len(), 1);
        assert_eq!(foto[0].path, "/docs/2020/foto.jpg");
        assert!(!foto[0].is_dir);

        // "docs" casa a pasta (explícita via prefixo dos arquivos).
        let docs = v.search("docs");
        assert!(docs.iter().any(|h| h.path == "/docs" && h.is_dir));

        // Busca por TRECHO DE CAMINHO (não só nome).
        let frag = v.search("docs/2020");
        assert!(frag.iter().any(|h| h.path == "/docs/2020/foto.jpg"));
        assert!(frag.iter().any(|h| h.path == "/docs/2020" && h.is_dir));

        assert!(v.search("").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repair_truncates_then_verifies_clean() {
        let dir = tmp_dir("repair");
        let vp = dir.join("r.vault");
        let _ = std::fs::remove_file(&vp);
        let mut v = Vault::create(&vp, DEFAULT_AVG_CHUNK).unwrap();
        let data = pseudo_random(11, 300_000);
        let f = dir.join("a.bin");
        std::fs::write(&f, &data).unwrap();
        v.add_file(&f, "a.bin").unwrap();
        v.commit().unwrap();
        assert!(v.catalog().files["/a.bin"].chunks.len() >= 3);
        drop(v);

        // Corrompe um chunk depois do início (offset bem dentro da região de dados).
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new().write(true).open(&vp).unwrap();
            file.seek(SeekFrom::Start(4096 + 90_000)).unwrap();
            file.write_all(&[0xAA; 512]).unwrap();
        }
        let mut v2 = Vault::open(&vp, None).unwrap();
        assert!(!v2.verify().unwrap().is_healthy());

        let rep = v2.repair().unwrap();
        assert_eq!(rep.files_damaged, 1);
        v2.commit().unwrap();

        // Após reparar: verify limpo e o arquivo está truncado (ou removido).
        assert!(v2.verify().unwrap().is_healthy());
        if let Some(e) = v2.catalog().files.get("/a.bin") {
            assert!(e.size < data.len() as u64);
            // O prefixo salvo bate com o original.
            let got = v2.read_range("/a.bin", 0, e.size as usize).unwrap();
            assert_eq!(got, &data[..e.size as usize]);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quota_and_rekey() {
        let dir = tmp_dir("mng");
        let vp = dir.join("m.vault");
        let _ = std::fs::remove_file(&vp);
        let mut v = Vault::create(&vp, DEFAULT_AVG_CHUNK).unwrap();

        // Cota.
        v.set_quota(Some(100_000));
        assert_eq!(v.quota(), Some(100_000));

        let small = dir.join("s.txt");
        std::fs::write(&small, b"oi").unwrap();
        v.add_file(&small, "s.txt").unwrap(); // cabe
        v.commit().unwrap();

        let big = dir.join("big.bin");
        std::fs::write(&big, pseudo_random(1, 300_000)).unwrap();
        assert!(v.add_file(&big, "big.bin").is_err()); // estoura a cota

        // Rekey: DEFINIR senha.
        let rk = dir.join("m2.vault");
        v.rekey_to(&rk, Some("senha")).unwrap();
        let mut v2 = Vault::open(&rk, Some("senha")).unwrap();
        assert!(v2.is_encrypted());
        assert_eq!(v2.quota(), Some(100_000)); // cota preservada
        let mut out = Cursor::new(Vec::new());
        v2.extract("s.txt", &mut out).unwrap();
        assert_eq!(out.into_inner(), b"oi");
        assert!(Vault::open(&rk, None).is_err()); // sem senha falha

        // Rekey: REMOVER senha.
        let rk2 = dir.join("m3.vault");
        v2.rekey_to(&rk2, None).unwrap();
        let v3 = Vault::open(&rk2, None).unwrap();
        assert!(!v3.is_encrypted());
        let mut out = Cursor::new(Vec::new());
        v3.extract("s.txt", &mut out).unwrap();
        assert_eq!(out.into_inner(), b"oi");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stream_write_sequential_and_random_fallback() {
        let dir = tmp_dir("stream");
        let vault_path = dir.join("s.vault");
        let _ = std::fs::remove_file(&vault_path);
        let mut v = Vault::create(&vault_path, DEFAULT_AVG_CHUNK).unwrap();

        // Sequencial: escreve 500 KB em pedaços de 64 KB via streaming.
        let data = pseudo_random(3, 500_000);
        let mut w = v.stream_writer();
        let mut off = 0u64;
        for piece in data.chunks(64 * 1024) {
            v.stream_write(&mut w, off, piece).unwrap();
            off += piece.len() as u64;
        }
        assert_eq!(w.len(), data.len() as u64);
        v.finish_write(w, "/seq.bin", 1).unwrap();
        v.commit().unwrap();
        // Round-trip total e leitura aleatória no meio.
        assert_eq!(v.read_range("/seq.bin", 0, data.len()).unwrap(), data);
        assert_eq!(
            v.read_range("/seq.bin", 200_000, 50_000).unwrap(),
            &data[200_000..250_000]
        );

        // Fora de ordem: escreve offset 5 antes do 0 -> cai para materializado.
        let mut w2 = v.stream_writer();
        v.stream_write(&mut w2, 5, b"BBBBB").unwrap();
        v.stream_write(&mut w2, 0, b"AAAAA").unwrap();
        v.finish_write(w2, "/rnd.bin", 1).unwrap();
        v.commit().unwrap();
        assert_eq!(v.read_range("/rnd.bin", 0, 100).unwrap(), b"AAAAABBBBB");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_file_overwrite_and_explicit_dirs() {
        let dir = tmp_dir("rw");
        let vault_path = dir.join("rw.vault");
        let _ = std::fs::remove_file(&vault_path);

        let mut v = Vault::create(&vault_path, DEFAULT_AVG_CHUNK).unwrap();

        // Diretório vazio explícito (mkdir).
        v.create_dir("/novo").unwrap();
        assert!(matches!(v.resolve("/novo"), Some(NodeKind::Dir)));

        // Escreve um arquivo dentro dele a partir de um buffer.
        v.write_file("/novo/a.txt", b"primeira versao", 100).unwrap();
        v.commit().unwrap();
        assert_eq!(
            v.read_range("/novo/a.txt", 0, 4096).unwrap(),
            b"primeira versao"
        );

        // Sobrescreve (simula edição aleatória: buffer inteiro novo).
        v.write_file("/novo/a.txt", b"segunda versao, bem maior que a primeira", 200)
            .unwrap();
        v.commit().unwrap();
        assert_eq!(
            v.read_range("/novo/a.txt", 0, 4096).unwrap(),
            b"segunda versao, bem maior que a primeira"
        );
        assert!(matches!(
            v.resolve("/novo/a.txt"),
            Some(NodeKind::File { size: 40, .. })
        ));

        // Listagens veem o dir e o arquivo.
        assert!(v.list_dir("/").iter().any(|e| e.name == "novo" && e.is_dir));
        assert!(v
            .list_dir("/novo")
            .iter()
            .any(|e| e.name == "a.txt" && !e.is_dir));

        // Reabre: o diretório vazio explícito e o arquivo persistem.
        drop(v);
        let v2 = Vault::open(&vault_path, None).unwrap();
        assert!(matches!(v2.resolve("/novo"), Some(NodeKind::Dir)));
        assert!(matches!(v2.resolve("/novo/a.txt"), Some(NodeKind::File { .. })));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_ci_is_case_insensitive() {
        let dir = tmp_dir("ci");
        let vault_path = dir.join("ci.vault");
        let _ = std::fs::remove_file(&vault_path);

        let mut v = Vault::create(&vault_path, DEFAULT_AVG_CHUNK).unwrap();
        v.create_dir("/Docs").unwrap();
        v.write_file("/Docs/Arquivo.TXT", b"x", 1).unwrap();
        v.commit().unwrap();

        // Caixa diferente resolve para o caminho REAL.
        let (real, kind) = v.resolve_ci("/docs/arquivo.txt").unwrap();
        assert_eq!(real, "/Docs/Arquivo.TXT");
        assert!(matches!(kind, NodeKind::File { .. }));

        // Diretório explícito, caixa diferente.
        let (real, kind) = v.resolve_ci("/DOCS").unwrap();
        assert_eq!(real, "/Docs");
        assert!(matches!(kind, NodeKind::Dir));

        // Diretório implícito via prefixo, caixa diferente.
        v.write_file("/Outro/sub/f.bin", b"y", 1).unwrap();
        let (real, kind) = v.resolve_ci("/outro").unwrap();
        assert_eq!(real, "/Outro");
        assert!(matches!(kind, NodeKind::Dir));

        assert!(v.resolve_ci("/naoexiste").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_range_and_directory_listing() {
        let dir = tmp_dir("mount");
        let vault_path = dir.join("m.vault");
        let _ = std::fs::remove_file(&vault_path);

        // Arquivo grande (multi-chunk) para exercitar leitura aleatória.
        let big = pseudo_random(77, 300_000);
        let bigp = dir.join("big.bin");
        std::fs::write(&bigp, &big).unwrap();

        let note = dir.join("note.txt");
        std::fs::write(&note, b"oi").unwrap();

        let mut v = Vault::create(&vault_path, DEFAULT_AVG_CHUNK).unwrap();
        v.add_file(&bigp, "/docs/big.bin").unwrap();
        v.add_file(&note, "/note.txt").unwrap();
        v.commit().unwrap();

        // Leitura aleatória no meio do arquivo, cruzando fronteiras de chunk.
        let off = 130_000u64;
        let n = 90_000usize;
        let got = v.read_range("/docs/big.bin", off, n).unwrap();
        assert_eq!(got, &big[off as usize..off as usize + n]);

        // Leitura além do fim trunca no tamanho real.
        let tail = v.read_range("/docs/big.bin", 299_990, 1000).unwrap();
        assert_eq!(tail, &big[299_990..]);

        // resolve: dir, arquivo, inexistente.
        assert!(matches!(v.resolve("/"), Some(NodeKind::Dir)));
        assert!(matches!(v.resolve("/docs"), Some(NodeKind::Dir)));
        assert!(matches!(v.resolve("/docs/big.bin"), Some(NodeKind::File { .. })));
        assert!(v.resolve("/naoexiste").is_none());

        // list_dir da raiz: um subdir "docs" e o arquivo "note.txt".
        let root = v.list_dir("/");
        let names: Vec<_> = root.iter().map(|e| (e.name.as_str(), e.is_dir)).collect();
        assert_eq!(names, vec![("docs", true), ("note.txt", false)]);

        let docs = v.list_dir("/docs");
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].name, "big.bin");
        assert!(!docs[0].is_dir);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fastcdc_dedups_across_insertion() {
        let dir = tmp_dir("cdc");
        let vault_path = dir.join("c.vault");
        let _ = std::fs::remove_file(&vault_path);

        // Base de 1 MiB e uma versão com 137 bytes inseridos no INÍCIO.
        // Com chunking fixo, a inserção deslocaria tudo -> ~0 dedup.
        // Com FastCDC, as fronteiras re-sincronizam -> maioria dos blocos compartilhada.
        let base = pseudo_random(12_345, 1 << 20);
        let mut modified = pseudo_random(999, 137);
        modified.extend_from_slice(&base);

        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        std::fs::write(&a, &base).unwrap();
        std::fs::write(&b, &modified).unwrap();

        let mut v = Vault::create(&vault_path, DEFAULT_AVG_CHUNK).unwrap();
        v.add_file(&a, "a.bin").unwrap();
        let blocks_a = v.stats().unique_blocks;
        assert!(blocks_a > 4, "1 MiB deveria virar vários chunks (got {blocks_a})");

        v.add_file(&b, "b.bin").unwrap();
        let blocks_b = v.stats().unique_blocks;
        let added = blocks_b - blocks_a;

        // O arquivo modificado deve adicionar bem menos blocos do que recriaria
        // do zero — prova de que o dedup sobreviveu à inserção.
        assert!(
            added * 2 < blocks_a,
            "FastCDC deveria compartilhar a maioria dos blocos após inserção \
             (a={blocks_a}, novos em b={added})"
        );

        // E o round-trip do arquivo modificado tem que bater exatamente.
        let mut out = Cursor::new(Vec::new());
        v.extract("b.bin", &mut out).unwrap();
        assert_eq!(out.into_inner(), modified);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_restore_and_gc_preserves_history() {
        let dir = tmp_dir("snap");
        let vault_path = dir.join("s.vault");
        let compact_path = dir.join("s2.vault");
        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_file(&compact_path);

        let f = dir.join("doc.txt");
        std::fs::write(&f, b"versao um do documento").unwrap();

        let mut v = Vault::create(&vault_path, 64).unwrap();
        v.add_file(&f, "doc.txt").unwrap();
        v.snapshot_create("v1").unwrap();

        // Sobrescreve o arquivo com novo conteúdo.
        std::fs::write(&f, b"versao DOIS bem diferente do documento").unwrap();
        v.add_file(&f, "doc.txt").unwrap();
        v.commit().unwrap();

        assert_eq!(v.snapshots().len(), 1);

        // Restaura para v1 e confirma o conteúdo antigo.
        v.snapshot_restore("v1").unwrap();
        v.commit().unwrap();
        let mut out = Cursor::new(Vec::new());
        v.extract("doc.txt", &mut out).unwrap();
        assert_eq!(out.into_inner(), b"versao um do documento");

        // gc deve preservar os blocos do snapshot v1 (história intacta).
        drop(v); // libera a trava antes de reabrir
        let mut v2 = Vault::open(&vault_path, None).unwrap();
        v2.compact_to(&compact_path).unwrap();
        let v3 = Vault::open(&compact_path, None).unwrap();
        assert_eq!(v3.snapshots().len(), 1);
        let mut out = Cursor::new(Vec::new());
        v3.extract("doc.txt", &mut out).unwrap();
        assert_eq!(out.into_inner(), b"versao um do documento");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pipeline_compresses_and_falls_back_to_raw() {
        let compressible = vec![b'A'; 4096];
        let stored = encode_block(&compressible, DEFAULT_ZSTD_LEVEL, None).unwrap();
        assert_eq!(stored[0] & FLAG_ZSTD, FLAG_ZSTD);
        assert!(stored.len() < compressible.len());
        assert_eq!(decode_block(&stored, None).unwrap(), compressible);

        let mut incompressible = Vec::with_capacity(4096);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..4096 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            incompressible.push((x & 0xff) as u8);
        }
        let stored = encode_block(&incompressible, DEFAULT_ZSTD_LEVEL, None).unwrap();
        assert_eq!(stored[0] & FLAG_ZSTD, 0);
        assert_eq!(stored.len(), incompressible.len() + 1);
        assert_eq!(decode_block(&stored, None).unwrap(), incompressible);
    }

    #[test]
    fn encrypted_roundtrip_and_wrong_password() {
        let dir = tmp_dir("enc");
        let vault_path = dir.join("secret.vault");
        let _ = std::fs::remove_file(&vault_path);

        let secret = dir.join("segredo.txt");
        let payload = b"informacao confidencial muito importante".repeat(100);
        std::fs::write(&secret, &payload).unwrap();

        let mut v = Vault::create_encrypted(&vault_path, 1024, "senha-forte").unwrap();
        v.add_file(&secret, "segredo.txt").unwrap();
        v.commit().unwrap();
        drop(v);

        // Senha errada deve falhar.
        assert!(Vault::open(&vault_path, Some("senha-errada")).is_err());
        // Sem senha deve falhar.
        assert!(Vault::open(&vault_path, None).is_err());

        // Senha certa decifra e o conteúdo bate.
        let v2 = Vault::open(&vault_path, Some("senha-forte")).unwrap();
        assert!(v2.is_encrypted());
        let mut out = Cursor::new(Vec::new());
        v2.extract("segredo.txt", &mut out).unwrap();
        assert_eq!(out.into_inner(), payload);
        drop(v2); // libera a trava para ler o arquivo cru abaixo

        // O texto-claro NÃO deve aparecer cru no arquivo do container.
        let raw = std::fs::read(&vault_path).unwrap();
        let needle = b"informacao confidencial";
        let leaked = raw.windows(needle.len()).any(|w| w == needle);
        assert!(!leaked, "texto-claro vazou no container cifrado");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
