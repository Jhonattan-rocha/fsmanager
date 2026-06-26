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

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::{aead::Aead, Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Assinatura do formato.
pub const MAGIC: &[u8; 8] = b"FSMVLT01";
/// Tamanho fixo do header em bytes.
pub const HEADER_SIZE: u64 = 4096;
/// Tamanho de chunk padrão (1 MiB). Arquivos são fatiados nesse tamanho.
pub const DEFAULT_CHUNK: u32 = 1 << 20;
/// Versão do formato on-disk.
pub const FORMAT_VERSION: u32 = 3;
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

/// O índice persistido: mapa de dedup + tabela de arquivos.
#[derive(Default, Serialize, Deserialize)]
pub struct Catalog {
    /// Índice de deduplicação: conteúdo -> localização física.
    pub blocks: HashMap<Hash, BlockRef>,
    /// Caminho lógico (estilo unix, "/foo/bar.txt") -> metadados.
    pub files: BTreeMap<String, FileEntry>,
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
        let mut f =
            File::open(src).with_context(|| format!("abrindo origem {}", src.display()))?;
        let meta = f.metadata()?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let mut chunks = Vec::new();
        let mut total: u64 = 0;
        let mut buf = vec![0u8; self.chunk_size as usize];
        loop {
            let n = read_full(&mut f, &mut buf)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            let hash = self.write_block(&buf[..n])?;
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

        let mut header = [0u8; HEADER_SIZE as usize];
        header[0..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        header[12..16].copy_from_slice(&self.chunk_size.to_le_bytes());
        header[16..24].copy_from_slice(&offset.to_le_bytes());
        header[24..32].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        if let Some(e) = &self.enc {
            header[32..36].copy_from_slice(&HFLAG_ENCRYPTED.to_le_bytes());
            header[36..36 + SALT_LEN].copy_from_slice(&e.salt);
            header[52..56].copy_from_slice(&(e.verify.len() as u32).to_le_bytes());
            header[56..56 + e.verify.len()].copy_from_slice(&e.verify);
        }
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

/// Lê até encher `buf` (ou EOF). Retorna bytes lidos.
fn read_full(f: &mut File, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = f.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
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
