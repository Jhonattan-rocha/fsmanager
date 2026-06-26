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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::{aead::Aead, Key, KeyInit, XChaCha20Poly1305, XNonce};
use fastcdc::v2020::StreamCDC;
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
pub const FORMAT_VERSION: u32 = 5;
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

/// Metadados de um arquivo lógico guardado no container.
#[derive(Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub size: u64,
    pub mtime: i64,
    /// Hashes dos chunks, em ordem. Reconstroem o arquivo concatenados.
    pub chunks: Vec<Hash>,
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

        let mut vault = Vault {
            file,
            path,
            chunk_size,
            catalog: Catalog::default(),
            next_append: HEADER_SIZE,
            zstd_level: DEFAULT_ZSTD_LEVEL,
            enc,
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

        let mut header = [0u8; HEADER_SIZE as usize];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut header)
            .context("lendo header (arquivo curto/corrompido?)")?;

        if &header[0..8] != MAGIC {
            bail!("assinatura inválida — não é um container fsmanager");
        }
        let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
        if version != FORMAT_VERSION {
            bail!("versão de formato {version} não suportada (esperado {FORMAT_VERSION})");
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
        let catalog: Catalog =
            bincode::deserialize(&raw).context("desserializando catálogo")?;

        Ok(Vault {
            file,
            path,
            chunk_size,
            catalog,
            next_append: catalog_offset + catalog_len,
            zstd_level: DEFAULT_ZSTD_LEVEL,
            enc,
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

    fn key(&self) -> Option<&[u8; KEY_LEN]> {
        self.enc.as_ref().map(|e| &e.key)
    }

    /// Adiciona/atualiza um arquivo do disco real no caminho lógico `dest`.
    /// Os blocos são gravados na hora; o catálogo só é persistido em [`commit`].
    pub fn add_file(&mut self, src: impl AsRef<Path>, dest: &str) -> Result<()> {
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
        // FastCDC: fronteiras definidas pelo conteúdo (rolling hash gear).
        for item in StreamCDC::new(f, min, avg, max) {
            let chunk = item.map_err(|e| anyhow!("fatiando {} (FastCDC): {e}", src.display()))?;
            total += chunk.length as u64;
            let hash = self.write_block(&chunk.data)?;
            chunks.push(hash);
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

    /// Grava um bloco (deduplicando). Retorna o hash de conteúdo.
    fn write_block(&mut self, data: &[u8]) -> Result<Hash> {
        let hash = *blake3::hash(data).as_bytes();
        if self.catalog.blocks.contains_key(&hash) {
            return Ok(hash); // dedup: já existe, não regrava.
        }
        let stored = encode_block(data, self.zstd_level, self.key())?;
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

    /// Lê um arquivo lógico e escreve seu conteúdo em `out`.
    pub fn extract<W: Write>(&mut self, logical: &str, out: &mut W) -> Result<u64> {
        let logical = normalize_path(logical);
        let entry = self
            .catalog
            .files
            .get(&logical)
            .with_context(|| format!("arquivo não encontrado: {logical}"))?
            .clone();

        let mut written = 0u64;
        for hash in &entry.chunks {
            let bref = *self
                .catalog
                .blocks
                .get(hash)
                .context("bloco referenciado ausente (container corrompido)")?;
            let mut buf = vec![0u8; bref.len as usize];
            self.file.seek(SeekFrom::Start(bref.offset))?;
            self.file.read_exact(&mut buf)?;
            let data = decode_block(&buf, self.key())?;
            // Revalida integridade pelo endereço de conteúdo.
            if blake3::hash(&data).as_bytes() != hash {
                bail!("falha de integridade em bloco de {logical}");
            }
            out.write_all(&data)?;
            written += data.len() as u64;
        }
        Ok(written)
    }

    /// Lê `len` bytes de um arquivo lógico a partir de `offset`, decodificando
    /// apenas os chunks que tocam o intervalo. Base para o mount (leitura aleatória).
    pub fn read_range(&mut self, logical: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
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
        let mut out = Vec::with_capacity((end - offset) as usize);

        let mut pos: u64 = 0; // início do chunk corrente, em bytes lógicos
        for hash in &entry.chunks {
            let bref = *self
                .catalog
                .blocks
                .get(hash)
                .context("bloco referenciado ausente (container corrompido)")?;
            let chunk_start = pos;
            let chunk_end = pos + bref.raw_len as u64;
            pos = chunk_end;
            if chunk_end <= offset {
                continue; // chunk inteiramente antes do intervalo
            }
            if chunk_start >= end {
                break; // chunks seguintes estão além do intervalo
            }
            let mut buf = vec![0u8; bref.len as usize];
            self.file.seek(SeekFrom::Start(bref.offset))?;
            self.file.read_exact(&mut buf)?;
            let data = decode_block(&buf, self.key())?;
            if blake3::hash(&data).as_bytes() != hash {
                bail!("falha de integridade em bloco de {logical}");
            }
            let from = offset.saturating_sub(chunk_start) as usize;
            let to = ((end - chunk_start) as usize).min(data.len());
            out.extend_from_slice(&data[from..to]);
        }
        Ok(out)
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
        let pre = format!("{p}/");
        if self.catalog.files.keys().any(|k| k.starts_with(&pre)) {
            return Some(NodeKind::Dir);
        }
        None
    }

    /// Lista os filhos imediatos de um diretório (para `readdir`).
    /// Diretórios são implícitos: derivados dos prefixos dos caminhos.
    pub fn list_dir(&self, path: &str) -> Vec<DirEntry> {
        let p = normalize_path(path);
        let pre = if p == "/" { "/".to_string() } else { format!("{p}/") };
        let mut subdirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
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
                    subdirs.insert(rest[..i].to_string());
                }
            }
        }
        for d in subdirs {
            entries.push(DirEntry {
                name: d,
                is_dir: true,
                size: 0,
                mtime: 0,
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
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
        Ok(victims.len())
    }

    /// Move/renomeia um arquivo OU uma subárvore inteira (se `src` for um diretório).
    pub fn rename(&mut self, src: &str, dst: &str) -> Result<()> {
        let src = normalize_path(src);
        let dst = normalize_path(dst);

        // Caso 1: arquivo exato.
        if let Some(entry) = self.catalog.files.remove(&src) {
            self.catalog.files.insert(dst, entry);
            return Ok(());
        }

        // Caso 2: diretório (prefixo).
        let pre = format!("{}/", src.trim_end_matches('/'));
        let moves: Vec<String> = self
            .catalog
            .files
            .keys()
            .filter(|k| k.starts_with(&pre))
            .cloned()
            .collect();
        if moves.is_empty() {
            bail!("origem não encontrada: {src}");
        }
        let dst_base = dst.trim_end_matches('/').to_string();
        for old in moves {
            let suffix = &old[pre.len()..];
            let new = format!("{dst_base}/{suffix}");
            let entry = self.catalog.files.remove(&old).unwrap();
            self.catalog.files.insert(new, entry);
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
        Ok(())
    }

    /// Apaga um snapshot. Retorna `true` se existia. Os blocos exclusivos dele
    /// só voltam ao espaço livre no próximo `gc`.
    pub fn snapshot_delete(&mut self, name: &str) -> Result<bool> {
        let before = self.catalog.snapshots.len();
        self.catalog.snapshots.retain(|s| s.name != name);
        Ok(self.catalog.snapshots.len() != before)
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
            for h in &f.chunks {
                reachable.insert(*h);
            }
        }
        for snap in &self.catalog.snapshots {
            for f in snap.files.values() {
                for h in &f.chunks {
                    reachable.insert(*h);
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
        };
        let raw = bincode::serialize(&new_catalog).context("serializando catálogo")?;
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

    /// Persiste o catálogo no fim do arquivo e atualiza o header.
    ///
    /// Ordem de durabilidade: grava catálogo → fsync → atualiza header → fsync.
    /// Se cair antes do header, o catálogo antigo continua válido.
    pub fn commit(&mut self) -> Result<()> {
        let raw = bincode::serialize(&self.catalog).context("serializando catálogo")?;
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
    let compressed = zstd::stream::encode_all(data, level).context("comprimindo bloco")?;
    let (mut flags, inner) = if compressed.len() < data.len() {
        (FLAG_ZSTD, compressed)
    } else {
        (0u8, data.to_vec())
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

        let mut v2 = Vault::open(&vault_path, None).unwrap();
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
        let mut v2 = Vault::open(&compact_path, None).unwrap();
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
        let mut v2 = Vault::open(&vault_path, None).unwrap();
        v2.compact_to(&compact_path).unwrap();
        let mut v3 = Vault::open(&compact_path, None).unwrap();
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
        let mut v2 = Vault::open(&vault_path, Some("senha-forte")).unwrap();
        assert!(v2.is_encrypted());
        let mut out = Cursor::new(Vec::new());
        v2.extract("segredo.txt", &mut out).unwrap();
        assert_eq!(out.into_inner(), payload);

        // O texto-claro NÃO deve aparecer cru no arquivo do container.
        let raw = std::fs::read(&vault_path).unwrap();
        let needle = b"informacao confidencial";
        let leaked = raw.windows(needle.len()).any(|w| w == needle);
        assert!(!leaked, "texto-claro vazou no container cifrado");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
