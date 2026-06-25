//! fsm-core — motor do container virtual (v0).
//!
//! Um container é UM arquivo único (`*.vault`) com este layout:
//!
//! ```text
//! [ HEADER  (4 KiB fixos) ]  magic, versão, chunk_size, ponteiro p/ catálogo
//! [ REGIÃO DE DADOS       ]  blocos endereçados por conteúdo (append-only)
//! [ CATÁLOGO              ]  índice de blocos + tabela de arquivos (serializado)
//! ```
//!
//! ## Ideia central: blocos endereçados por conteúdo
//! Cada bloco é identificado por `blake3(conteúdo)`. Antes de gravar um bloco
//! verificamos se o hash já existe no catálogo — se sim, não regravamos
//! (DEDUPLICAÇÃO). Essa mesma primitiva é a base futura de:
//!   - snapshots/versionamento (cada catálogo gravado é uma "geração");
//!   - integridade (o hash valida o bloco);
//!   - compressão/criptografia (entram como estágios em [`block_pipeline`]).
//!
//! v0 grava os blocos crus. Os ganchos de compressão/criptografia estão
//! marcados com `TODO(pipeline)` para a próxima iteração.

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Assinatura do formato + versão embutida no final.
pub const MAGIC: &[u8; 8] = b"FSMVLT01";
/// Tamanho fixo do header em bytes.
pub const HEADER_SIZE: u64 = 4096;
/// Tamanho de chunk padrão (1 MiB). Arquivos são fatiados nesse tamanho.
pub const DEFAULT_CHUNK: u32 = 1 << 20;
/// Versão do formato on-disk.
pub const FORMAT_VERSION: u32 = 1;

/// Endereço de conteúdo: BLAKE3 de 32 bytes.
pub type Hash = [u8; 32];

/// Onde um bloco vive fisicamente dentro do arquivo container.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct BlockRef {
    pub offset: u64,
    pub len: u32,
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
///
/// Cada vez que persistimos um catálogo novo no fim do arquivo, criamos
/// efetivamente uma nova geração — a semente do versionamento.
#[derive(Default, Serialize, Deserialize)]
pub struct Catalog {
    /// Índice de deduplicação: conteúdo -> localização física.
    pub blocks: HashMap<Hash, BlockRef>,
    /// Caminho lógico (estilo unix, "/foo/bar.txt") -> metadados.
    pub files: BTreeMap<String, FileEntry>,
}

/// Um container aberto, com o catálogo carregado em memória.
pub struct Vault {
    file: File,
    path: PathBuf,
    chunk_size: u32,
    catalog: Catalog,
    /// Próxima posição livre para append na região de dados.
    next_append: u64,
}

impl Vault {
    /// Cria um container novo e vazio.
    pub fn create(path: impl AsRef<Path>, chunk_size: u32) -> Result<Vault> {
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
        };
        // Reserva o header e grava catálogo vazio + ponteiro.
        vault.file.set_len(HEADER_SIZE)?;
        vault.commit()?;
        Ok(vault)
    }

    /// Abre um container existente, carregando o catálogo atual.
    pub fn open(path: impl AsRef<Path>) -> Result<Vault> {
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

        let mut buf = vec![0u8; catalog_len as usize];
        file.seek(SeekFrom::Start(catalog_offset))?;
        file.read_exact(&mut buf).context("lendo catálogo")?;
        let catalog: Catalog =
            bincode::deserialize(&buf).context("desserializando catálogo")?;

        Ok(Vault {
            file,
            path,
            chunk_size,
            catalog,
            // Append começa após o catálogo atual — preserva gerações antigas.
            next_append: catalog_offset + catalog_len,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
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
        // TODO(pipeline): comprimir (zstd) e criptografar (XChaCha20) aqui,
        // gravando o resultado e guardando o tamanho real no BlockRef.
        let stored = block_pipeline(data);
        let offset = self.next_append;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&stored)?;
        self.next_append += stored.len() as u64;
        self.catalog.blocks.insert(
            hash,
            BlockRef {
                offset,
                len: stored.len() as u32,
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
            // TODO(pipeline): descriptografar + descomprimir aqui.
            let data = unblock_pipeline(&buf);
            // Valida integridade pelo endereço de conteúdo.
            if blake3::hash(&data).as_bytes() != hash {
                bail!("falha de integridade em bloco de {logical}");
            }
            out.write_all(&data)?;
            written += data.len() as u64;
        }
        Ok(written)
    }

    /// Persiste o catálogo no fim do arquivo e atualiza o ponteiro no header.
    ///
    /// Ordem de durabilidade: grava catálogo → fsync → atualiza header → fsync.
    /// Se cair antes do header, o catálogo antigo continua válido.
    pub fn commit(&mut self) -> Result<()> {
        let bytes = bincode::serialize(&self.catalog).context("serializando catálogo")?;
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
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&header)?;
        self.file.sync_all()?;

        self.next_append = offset + bytes.len() as u64;
        Ok(())
    }

    /// Estatísticas de uso e ganho de deduplicação.
    pub fn stats(&self) -> Stats {
        let logical: u64 = self.catalog.files.values().map(|f| f.size).sum();
        let physical: u64 = self.catalog.blocks.values().map(|b| b.len as u64).sum();
        Stats {
            files: self.catalog.files.len(),
            unique_blocks: self.catalog.blocks.len(),
            logical_bytes: logical,
            physical_bytes: physical,
        }
    }
}

/// Estatísticas resumidas do container.
pub struct Stats {
    pub files: usize,
    pub unique_blocks: usize,
    pub logical_bytes: u64,
    pub physical_bytes: u64,
}

impl Stats {
    /// Quanto foi economizado por dedup (0.0 = nada, 0.5 = metade).
    pub fn dedup_savings(&self) -> f64 {
        if self.logical_bytes == 0 {
            return 0.0;
        }
        1.0 - (self.physical_bytes as f64 / self.logical_bytes as f64)
    }
}

/// Estágio de gravação de bloco. v0: identidade.
/// TODO(pipeline): zstd::compress -> XChaCha20Poly1305::encrypt.
fn block_pipeline(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}

/// Inverso de [`block_pipeline`]. v0: identidade.
fn unblock_pipeline(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}

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

    #[test]
    fn roundtrip_and_dedup() {
        let dir = std::env::temp_dir().join(format!("fsm-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("t.vault");
        let _ = std::fs::remove_file(&vault_path);

        // Dois arquivos com conteúdo idêntico -> dedup deve guardar 1 bloco.
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

        // Reabre e extrai.
        let mut v2 = Vault::open(&vault_path).unwrap();
        let mut out = Cursor::new(Vec::new());
        v2.extract("a.bin", &mut out).unwrap();
        assert_eq!(out.into_inner(), b"conteudo identico repetido");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
