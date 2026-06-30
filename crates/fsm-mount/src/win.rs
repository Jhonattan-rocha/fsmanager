//! Filesystem read-write sobre o `fsm-core`, exposto via WinFsp.
//!
//! Modelo de escrita: cada handle de arquivo materializa o conteúdo num buffer
//! em memória (carregado sob demanda). Writes/truncates editam o buffer; em
//! `flush`/`cleanup`, se sujo, o buffer é re-chunkado (FastCDC + dedup) e gravado
//! via [`Vault::write_file`], seguido de commit.

use std::ffi::c_void;
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fsm_core::{NodeKind, StreamWriter, Vault};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
    VolumeInfo, WideNameInfo,
};
use winfsp::host::{FileSystemHost, FileSystemParams, FineGuard, VolumeParams};
use winfsp::U16CStr;
use windows::Win32::Foundation::{
    STATUS_DIRECTORY_NOT_EMPTY, STATUS_END_OF_FILE, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
};

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const ALLOC_UNIT: u64 = 4096;
/// Bit de `create_options` que indica abertura/criação de diretório.
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
/// Flag de `cleanup` que indica exclusão pendente.
const FSP_CLEANUP_DELETE: u32 = 0x01;

/// Contexto do filesystem montado.
struct FsmFs {
    /// `RwLock`: leituras compartilhadas (paralelas), escritas exclusivas.
    vault: RwLock<Vault>,
    sd: Vec<u8>,
    /// Diretório do host onde o `.vault` vive (para reportar espaço livre real).
    vault_dir: String,
    label: String,
}

/// Espaço livre real (bytes) no volume do host que contém `dir`.
fn host_free_bytes(dir: &str) -> u64 {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = dir.encode_utf16().chain(std::iter::once(0)).collect();
    let mut free_avail = 0u64;
    // SAFETY: ponteiro válido para string terminada em nul; saída opcional.
    let ok = unsafe {
        GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), Some(&mut free_avail), None, None).is_ok()
    };
    if ok {
        free_avail
    } else {
        4u64 << 30 // fallback
    }
}

/// Estado mutável de um handle aberto.
struct HState {
    /// Escritor streaming (criação/overwrite sequencial). Tem prioridade.
    writer: Option<StreamWriter>,
    /// Conteúdo materializado (modo aleatório / após carregar para editar).
    buf: Option<Vec<u8>>,
    /// Há alterações não persistidas.
    dirty: bool,
}

/// Handle de um arquivo/diretório aberto.
struct Handle {
    path: String,
    is_dir: bool,
    state: Mutex<HState>,
    dir_buffer: DirBuffer,
}

impl Handle {
    /// Handle só-leitura (ou base): nada materializado ainda.
    fn reading(path: String, is_dir: bool) -> Self {
        Self::with_state(path, is_dir, HState { writer: None, buf: None, dirty: false })
    }
    /// Handle de escrita streaming (create/overwrite).
    fn writing(path: String, writer: StreamWriter) -> Self {
        Self::with_state(
            path,
            false,
            HState { writer: Some(writer), buf: None, dirty: true },
        )
    }
    fn with_state(path: String, is_dir: bool, state: HState) -> Self {
        Handle {
            path,
            is_dir,
            state: Mutex::new(state),
            dir_buffer: DirBuffer::new(),
        }
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn to_filetime(unix_secs: i64) -> u64 {
    if unix_secs <= 0 {
        0
    } else {
        ((unix_secs as u64) + 11_644_473_600) * 10_000_000
    }
}

fn align_up(n: u64) -> u64 {
    n.div_ceil(ALLOC_UNIT) * ALLOC_UNIT
}

fn win_to_logical(name: &U16CStr) -> String {
    name.to_string_lossy().replace('\\', "/")
}

fn join_logical(parent: &str, leaf: &str) -> String {
    if parent == "/" {
        format!("/{leaf}")
    } else {
        format!("{parent}/{leaf}")
    }
}

/// Informa ao WinFsp o nome normalizado (caminho real, com a grafia correta),
/// senão ele usa maiúsculas e quebra rename/lookup posteriores.
fn set_norm(file_info: &mut OpenFileInfo, logical: &str) {
    let win = logical.replace('/', "\\"); // "/docs/a.txt" -> "\docs\a.txt"
    let wide: Vec<u16> = win.encode_utf16().collect();
    file_info.set_normalized_name(&wide, None);
}

/// Converte erro genérico em `FspError` (via io::Error).
fn io_fsp<E: std::fmt::Display>(e: E) -> winfsp::FspError {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string()).into()
}

fn fill_dir(fi: &mut FileInfo) {
    fi.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
    fi.file_size = 0;
    fi.allocation_size = 0;
}

fn fill_file(fi: &mut FileInfo, size: u64, mtime: i64) {
    fi.file_attributes = FILE_ATTRIBUTE_ARCHIVE;
    fi.file_size = size;
    fi.allocation_size = align_up(size);
    let t = to_filetime(mtime);
    fi.creation_time = t;
    fi.last_access_time = t;
    fi.last_write_time = t;
    fi.change_time = t;
}

fn fill_from_kind(fi: &mut FileInfo, kind: &NodeKind) {
    match kind {
        NodeKind::Dir => fill_dir(fi),
        NodeKind::File { size, mtime } => fill_file(fi, *size, *mtime),
    }
}

fn copy_sd(sd: &[u8], dst: Option<&mut [c_void]>) {
    if let Some(dst) = dst {
        if dst.len() >= sd.len() {
            // SAFETY: dst tem ao menos sd.len() bytes; regiões não se sobrepõem.
            unsafe {
                std::ptr::copy_nonoverlapping(sd.as_ptr(), dst.as_mut_ptr() as *mut u8, sd.len());
            }
        }
    }
}

impl FsmFs {
    /// Garante que `st.buf` contém o conteúdo atual (materializa o writer streaming
    /// ou carrega do vault). Sai do modo streaming.
    fn ensure_buf(&self, ctx: &Handle, st: &mut HState) -> winfsp::Result<()> {
        if st.buf.is_some() {
            return Ok(());
        }
        let v = self.vault.read().unwrap();
        let buf = if let Some(w) = st.writer.take() {
            v.writer_to_buffer(w).map_err(io_fsp)?
        } else {
            let size = match v.resolve(&ctx.path) {
                Some(NodeKind::File { size, .. }) => size,
                _ => 0,
            };
            v.read_range(&ctx.path, 0, size as usize).map_err(io_fsp)?
        };
        st.buf = Some(buf);
        Ok(())
    }

    /// Persiste as alterações: finaliza o writer streaming OU grava o buffer.
    fn persist(&self, ctx: &Handle, st: &mut HState) -> winfsp::Result<()> {
        let mut v = self.vault.write().unwrap();
        if let Some(w) = st.writer.take() {
            v.finish_write(w, &ctx.path, now_secs()).map_err(io_fsp)?;
            v.commit().map_err(io_fsp)?;
            st.dirty = false;
        } else if st.dirty {
            if let Some(buf) = &st.buf {
                v.write_file(&ctx.path, buf, now_secs()).map_err(io_fsp)?;
                v.commit().map_err(io_fsp)?;
            }
            st.dirty = false;
        }
        Ok(())
    }

    /// Tamanho atual do arquivo aberto (writer streaming, buffer, ou catálogo).
    fn cur_size(&self, ctx: &Handle, st: &HState) -> u64 {
        if let Some(w) = &st.writer {
            return w.len();
        }
        if let Some(b) = &st.buf {
            return b.len() as u64;
        }
        match self.vault.read().unwrap().resolve(&ctx.path) {
            Some(NodeKind::File { size, .. }) => size,
            _ => 0,
        }
    }
}

impl FileSystemContext for FsmFs {
    type FileContext = Handle;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        _resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let path = win_to_logical(file_name);
        let (_real, kind) = self
            .vault
            .read()
            .unwrap()
            .resolve_ci(&path)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let attributes = match kind {
            NodeKind::Dir => FILE_ATTRIBUTE_DIRECTORY,
            NodeKind::File { .. } => FILE_ATTRIBUTE_ARCHIVE,
        };
        copy_sd(&self.sd, security_descriptor);
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: self.sd.len() as u64,
            attributes,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Handle> {
        let path = win_to_logical(file_name);
        let (real, kind) = self
            .vault
            .read()
            .unwrap()
            .resolve_ci(&path)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let is_dir = matches!(kind, NodeKind::Dir);
        fill_from_kind(file_info.as_mut(), &kind);
        set_norm(file_info, &real);
        Ok(Handle::reading(real, is_dir))
    }

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Handle> {
        let path = win_to_logical(file_name);
        let is_dir = (create_options & FILE_DIRECTORY_FILE) != 0;

        let mut v = self.vault.write().unwrap();
        if v.resolve_ci(&path).is_some() {
            return Err(STATUS_OBJECT_NAME_COLLISION.into());
        }
        if is_dir {
            v.create_dir(&path).map_err(io_fsp)?;
            v.commit().map_err(io_fsp)?;
            drop(v);
            fill_dir(file_info.as_mut());
            set_norm(file_info, &path);
            Ok(Handle::reading(path, true))
        } else {
            // Cria o arquivo vazio (aparece no catálogo) e abre em modo streaming.
            v.write_file(&path, &[], now_secs()).map_err(io_fsp)?;
            v.commit().map_err(io_fsp)?;
            let writer = v.stream_writer();
            drop(v);
            fill_file(file_info.as_mut(), 0, now_secs());
            set_norm(file_info, &path);
            Ok(Handle::writing(path, writer))
        }
    }

    fn close(&self, _context: Handle) {}

    fn get_file_info(&self, context: &Handle, file_info: &mut FileInfo) -> winfsp::Result<()> {
        if context.is_dir {
            fill_dir(file_info);
            return Ok(());
        }
        let st = context.state.lock().unwrap();
        fill_file(file_info, self.cur_size(context, &st), now_secs());
        Ok(())
    }

    fn get_security(
        &self,
        _context: &Handle,
        security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        copy_sd(&self.sd, security_descriptor);
        Ok(self.sd.len() as u64)
    }

    fn get_volume_info(&self, out: &mut VolumeInfo) -> winfsp::Result<()> {
        // Adaptativo: livre = espaço real do host; total = usado + livre.
        let used = self.vault.read().unwrap().stats().logical_bytes;
        let free = host_free_bytes(&self.vault_dir);
        out.total_size = used + free;
        out.free_size = free;
        out.set_volume_label(&self.label);
        Ok(())
    }

    fn read(&self, context: &Handle, buffer: &mut [u8], offset: u64) -> winfsp::Result<u32> {
        if context.is_dir {
            return Err(STATUS_INVALID_PARAMETER.into());
        }
        let mut st = context.state.lock().unwrap();
        // Leitura no meio de uma escrita streaming: materializa para servir.
        if st.writer.is_some() {
            self.ensure_buf(context, &mut st)?;
        }
        if let Some(buf) = &st.buf {
            if offset as usize >= buf.len() {
                return Err(STATUS_END_OF_FILE.into());
            }
            let from = offset as usize;
            let to = (from + buffer.len()).min(buf.len());
            buffer[..to - from].copy_from_slice(&buf[from..to]);
            Ok((to - from) as u32)
        } else {
            drop(st);
            let data = self
                .vault
                .read()
                .unwrap()
                .read_range(&context.path, offset, buffer.len())
                .map_err(io_fsp)?;
            if data.is_empty() {
                return Err(STATUS_END_OF_FILE.into());
            }
            buffer[..data.len()].copy_from_slice(&data);
            Ok(data.len() as u32)
        }
    }

    fn write(
        &self,
        context: &Handle,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        if context.is_dir {
            return Err(STATUS_INVALID_PARAMETER.into());
        }
        let mut st = context.state.lock().unwrap();

        // Caminho STREAMING (criação/overwrite sequencial): chunka incremental.
        // Escrita fora de ordem cai para materializado dentro do stream_write.
        if st.writer.is_some() && !constrained_io {
            let at = if write_to_eof {
                st.writer.as_ref().unwrap().len()
            } else {
                offset
            };
            {
                let mut v = self.vault.write().unwrap();
                v.stream_write(st.writer.as_mut().unwrap(), at, buffer)
                    .map_err(io_fsp)?;
            }
            st.dirty = true;
            let size = st.writer.as_ref().unwrap().len();
            fill_file(file_info, size, now_secs());
            return Ok(buffer.len() as u32);
        }

        // Caminho MATERIALIZADO.
        self.ensure_buf(context, &mut st)?;
        let buf = st.buf.as_mut().unwrap();
        let len = buf.len() as u64;
        let at = if write_to_eof { len } else { offset };
        let written = if constrained_io {
            if at >= len {
                0
            } else {
                let end = (at + buffer.len() as u64).min(len);
                let n = (end - at) as usize;
                buf[at as usize..end as usize].copy_from_slice(&buffer[..n]);
                n
            }
        } else {
            let end = at + buffer.len() as u64;
            if end as usize > buf.len() {
                buf.resize(end as usize, 0);
            }
            buf[at as usize..end as usize].copy_from_slice(buffer);
            buffer.len()
        };
        st.dirty = true;
        let new_size = st.buf.as_ref().unwrap().len() as u64;
        fill_file(file_info, new_size, now_secs());
        Ok(written as u32)
    }

    fn overwrite(
        &self,
        context: &Handle,
        _file_attributes: u32,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if context.is_dir {
            return Err(STATUS_INVALID_PARAMETER.into());
        }
        // Overwrite (CREATE_ALWAYS/TRUNCATE): zera e reabre em streaming.
        let writer = self.vault.read().unwrap().stream_writer();
        let mut st = context.state.lock().unwrap();
        st.writer = Some(writer);
        st.buf = None;
        st.dirty = true;
        fill_file(file_info, 0, now_secs());
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Handle,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if context.is_dir {
            return Err(STATUS_INVALID_PARAMETER.into());
        }
        let mut st = context.state.lock().unwrap();
        // Em streaming, ignorar extensão/preallocação (N >= já escrito) e seguir
        // chunkando; só truncar de verdade (N menor) força materializar.
        let keep_streaming = match &st.writer {
            Some(w) => new_size >= w.len(),
            None => false,
        };
        if !keep_streaming {
            self.ensure_buf(context, &mut st)?;
            st.buf.as_mut().unwrap().resize(new_size as usize, 0);
            st.dirty = true;
        }
        fill_file(file_info, self.cur_size(context, &st), now_secs());
        Ok(())
    }

    fn set_basic_info(
        &self,
        context: &Handle,
        _file_attributes: u32,
        _creation_time: u64,
        _last_access_time: u64,
        _last_write_time: u64,
        _last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // v1: aceita sem persistir timestamps (write_file define mtime no flush).
        self.get_file_info(context, file_info)
    }

    fn set_delete(
        &self,
        context: &Handle,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        if delete_file && context.is_dir {
            // Recusa rmdir de diretório não vazio.
            if !self.vault.read().unwrap().list_dir(&context.path).is_empty() {
                return Err(STATUS_DIRECTORY_NOT_EMPTY.into());
            }
        }
        Ok(())
    }

    fn rename(
        &self,
        _context: &Handle,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let from = win_to_logical(file_name);
        let to = win_to_logical(new_file_name);
        let mut v = self.vault.write().unwrap();
        let real_from = v.resolve_ci(&from).map(|(p, _)| p).unwrap_or(from);
        v.rename(&real_from, &to).map_err(io_fsp)?;
        v.commit().map_err(io_fsp)?;
        Ok(())
    }

    fn flush(&self, context: Option<&Handle>, file_info: &mut FileInfo) -> winfsp::Result<()> {
        match context {
            Some(ctx) if !ctx.is_dir => {
                let mut st = ctx.state.lock().unwrap();
                // Streaming não é finalizado no flush (não dá para continuar
                // depois); persistimos só buffer materializado sujo.
                if st.writer.is_none() && st.dirty {
                    self.persist(ctx, &mut st)?;
                }
                fill_file(file_info, self.cur_size(ctx, &st), now_secs());
            }
            Some(_) => fill_dir(file_info),
            None => {
                let _ = self.vault.write().unwrap().commit();
            }
        }
        Ok(())
    }

    fn cleanup(&self, context: &Handle, _file_name: Option<&U16CStr>, flags: u32) {
        let mut st = context.state.lock().unwrap();
        if flags & FSP_CLEANUP_DELETE != 0 {
            let mut v = self.vault.write().unwrap();
            if context.is_dir {
                let _ = v.remove_empty_dir(&context.path);
            } else {
                let _ = v.remove(&context.path);
            }
            let _ = v.commit();
            st.writer = None;
            st.dirty = false;
        } else {
            let _ = self.persist(context, &mut st);
        }
    }

    fn get_dir_info_by_name(
        &self,
        context: &Handle,
        file_name: &U16CStr,
        out_dir_info: &mut DirInfo,
    ) -> winfsp::Result<()> {
        let leaf = file_name.to_string_lossy();
        let child = join_logical(&context.path, &leaf);
        let (real, kind) = self
            .vault
            .read()
            .unwrap()
            .resolve_ci(&child)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let real_leaf = real.rsplit('/').next().unwrap_or(real.as_str());
        out_dir_info.set_name(real_leaf)?;
        fill_from_kind(out_dir_info.file_info_mut(), &kind);
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Handle,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        if let Ok(lock) = context.dir_buffer.acquire(marker.is_none(), None) {
            let entries = self.vault.read().unwrap().list_dir(&context.path);
            for entry in entries {
                let mut info: DirInfo<255> = DirInfo::new();
                info.set_name(&entry.name)?;
                let fi = info.file_info_mut();
                if entry.is_dir {
                    fi.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
                } else {
                    fi.file_attributes = FILE_ATTRIBUTE_ARCHIVE;
                    fi.file_size = entry.size;
                    fi.allocation_size = align_up(entry.size);
                    let t = to_filetime(entry.mtime);
                    fi.creation_time = t;
                    fi.last_access_time = t;
                    fi.last_write_time = t;
                    fi.change_time = t;
                }
                lock.write(&mut info)?;
            }
        }
        Ok(context.dir_buffer.read(marker, buffer))
    }
}

/// Cria um security descriptor permissivo (acesso total a SYSTEM, Admins e todos).
fn make_security_descriptor() -> Result<Vec<u8>> {
    use windows::core::w;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;

    let sddl = w!("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)");
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let mut size = 0u32;
    // SAFETY: API padrão; psd recebe um SD self-relative que copiamos e liberamos.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, &mut psd, Some(&mut size))
            .context("criando security descriptor")?;
        let bytes = std::slice::from_raw_parts(psd.0 as *const u8, size as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(psd.0)));
        Ok(bytes)
    }
}

/// Monta o container `vault_path` em `mountpoint` (ex.: `X:`) com leitura E
/// escrita. Bloqueia até Ctrl+C, então desmonta.
pub fn mount(vault_path: &str, mountpoint: &str, password: Option<&str>) -> Result<()> {
    winfsp::winfsp_init().map_err(|e| anyhow::anyhow!("winfsp_init falhou: {e:?}"))?;

    let vault = Vault::open(vault_path, password).context("abrindo container")?;
    let vault_dir = std::path::Path::new(vault_path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| ".".to_string());

    let context = FsmFs {
        vault: RwLock::new(vault),
        sd: make_security_descriptor()?,
        vault_dir,
        label: "fsmanager".to_string(),
    };

    let mut params = VolumeParams::new();
    params
        .sector_size(ALLOC_UNIT as u16)
        .sectors_per_allocation_unit(1)
        .max_component_length(255)
        .file_info_timeout(1000)
        .case_sensitive_search(false)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .post_cleanup_when_modified_only(true)
        // Necessário para usar get_dir_info_by_name (consulta de 1 arquivo por nome).
        .pass_query_directory_filename(true)
        .volume_serial_number(0x4653_4D31) // "FSM1"
        .filesystem_name("fsmanager");

    let mut fsparams = FileSystemParams::default_params(params);
    fsparams.use_dir_info_by_name = true;
    // FineGuard: WinFsp despacha callbacks (incl. reads) em paralelo; com
    // RwLock<Vault> as leituras rodam concorrentes, escritas são exclusivas.
    let mut host = FileSystemHost::<FsmFs, FineGuard>::new_with_options(fsparams, context)
        .map_err(|e| anyhow::anyhow!("criando filesystem: {e:?}"))?;
    host.mount(mountpoint)
        .map_err(|e| anyhow::anyhow!("montando em {mountpoint}: {e:?}"))?;
    host.start()
        .map_err(|e| anyhow::anyhow!("iniciando dispatcher: {e:?}"))?;

    println!("montado em {mountpoint} (leitura e escrita). Ctrl+C para desmontar.");

    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .ok();
    let _ = rx.recv();

    println!("desmontando…");
    drop(host);
    Ok(())
}
