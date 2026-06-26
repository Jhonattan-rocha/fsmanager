//! Filesystem read-only sobre o `fsm-core`, exposto via WinFsp.

use std::ffi::c_void;
use std::sync::Mutex;

use anyhow::{Context, Result};
use fsm_core::{NodeKind, Vault};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
    VolumeInfo, WideNameInfo,
};
use winfsp::host::{CoarseGuard, FileSystemHost, VolumeParams};
use winfsp::U16CStr;
use windows::Win32::Foundation::{
    STATUS_END_OF_FILE, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND,
};

const FILE_ATTRIBUTE_READONLY: u32 = 0x01;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const ALLOC_UNIT: u64 = 4096;

/// Contexto do filesystem montado.
struct FsmFs {
    vault: Mutex<Vault>,
    /// Security descriptor (self-relative) compartilhado por todos os nós.
    sd: Vec<u8>,
    total: u64,
    label: String,
}

/// Handle de um arquivo/diretório aberto.
struct Handle {
    path: String,
    is_dir: bool,
    dir_buffer: DirBuffer,
}

fn to_filetime(unix_secs: i64) -> u64 {
    if unix_secs <= 0 {
        0
    } else {
        // 100ns desde 1601; offset Unix→Windows = 11.644.473.600 s.
        ((unix_secs as u64) + 11_644_473_600) * 10_000_000
    }
}

fn align_up(n: u64) -> u64 {
    n.div_ceil(ALLOC_UNIT) * ALLOC_UNIT
}

/// Converte o caminho do Windows (`\foo\bar`) para o caminho lógico (`/foo/bar`).
fn win_to_logical(name: &U16CStr) -> String {
    name.to_string_lossy().replace('\\', "/")
}

fn fill_info(fi: &mut FileInfo, kind: &NodeKind) {
    match kind {
        NodeKind::Dir => {
            fi.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
            fi.file_size = 0;
            fi.allocation_size = 0;
        }
        NodeKind::File { size, mtime } => {
            fi.file_attributes = FILE_ATTRIBUTE_READONLY;
            fi.file_size = *size;
            fi.allocation_size = align_up(*size);
            let t = to_filetime(*mtime);
            fi.creation_time = t;
            fi.last_access_time = t;
            fi.last_write_time = t;
            fi.change_time = t;
        }
    }
}

/// Copia o security descriptor para o buffer fornecido pelo WinFsp, se couber.
fn copy_sd(sd: &[u8], dst: Option<&mut [c_void]>) {
    if let Some(dst) = dst {
        if dst.len() >= sd.len() {
            // SAFETY: dst tem ao menos sd.len() bytes; ponteiros não se sobrepõem.
            unsafe {
                std::ptr::copy_nonoverlapping(sd.as_ptr(), dst.as_mut_ptr() as *mut u8, sd.len());
            }
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
        let kind = self
            .vault
            .lock()
            .unwrap()
            .resolve(&path)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let attributes = match kind {
            NodeKind::Dir => FILE_ATTRIBUTE_DIRECTORY,
            NodeKind::File { .. } => FILE_ATTRIBUTE_READONLY,
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
        let kind = self
            .vault
            .lock()
            .unwrap()
            .resolve(&path)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let is_dir = matches!(kind, NodeKind::Dir);
        fill_info(file_info.as_mut(), &kind);
        Ok(Handle {
            path,
            is_dir,
            dir_buffer: DirBuffer::new(),
        })
    }

    fn close(&self, _context: Handle) {}

    fn get_file_info(&self, context: &Handle, file_info: &mut FileInfo) -> winfsp::Result<()> {
        let kind = self
            .vault
            .lock()
            .unwrap()
            .resolve(&context.path)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        fill_info(file_info, &kind);
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
        out.total_size = self.total;
        out.free_size = 0; // somente leitura
        out.set_volume_label(&self.label);
        Ok(())
    }

    fn read(&self, context: &Handle, buffer: &mut [u8], offset: u64) -> winfsp::Result<u32> {
        if context.is_dir {
            return Err(STATUS_INVALID_PARAMETER.into());
        }
        let data = self
            .vault
            .lock()
            .unwrap()
            .read_range(&context.path, offset, buffer.len())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        if data.is_empty() {
            return Err(STATUS_END_OF_FILE.into());
        }
        buffer[..data.len()].copy_from_slice(&data);
        Ok(data.len() as u32)
    }

    fn read_directory(
        &self,
        context: &Handle,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        // Na primeira chamada (marker vazio) preenchemos o buffer da WinFsp.
        if let Ok(lock) = context.dir_buffer.acquire(marker.is_none(), None) {
            let entries = self.vault.lock().unwrap().list_dir(&context.path);
            for entry in entries {
                let mut info: DirInfo<255> = DirInfo::new();
                info.set_name(&entry.name)?;
                let fi = info.file_info_mut();
                if entry.is_dir {
                    fi.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
                } else {
                    fi.file_attributes = FILE_ATTRIBUTE_READONLY;
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
    // SAFETY: chamada padrão da API; psd é preenchido com um SD self-relative
    // alocado via LocalAlloc, que copiamos e liberamos em seguida.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, &mut psd, Some(&mut size))
            .context("criando security descriptor")?;
        let bytes = std::slice::from_raw_parts(psd.0 as *const u8, size as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(psd.0)));
        Ok(bytes)
    }
}

/// Monta o container `vault_path` em `mountpoint` (ex.: `X:`) somente leitura.
/// Bloqueia até Ctrl+C, então desmonta.
pub fn mount(vault_path: &str, mountpoint: &str, password: Option<&str>) -> Result<()> {
    winfsp::winfsp_init().map_err(|e| anyhow::anyhow!("winfsp_init falhou: {e:?}"))?;

    let vault = Vault::open(vault_path, password).context("abrindo container")?;
    let st = vault.stats();
    let total = st.logical_bytes.max(1 << 20);

    let context = FsmFs {
        vault: Mutex::new(vault),
        sd: make_security_descriptor()?,
        total,
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
        .read_only_volume(true)
        .post_cleanup_when_modified_only(true)
        .volume_serial_number(0x4653_4D31) // "FSM1"
        .filesystem_name("fsmanager");

    let mut host = FileSystemHost::<FsmFs, CoarseGuard>::new(params, context)
        .map_err(|e| anyhow::anyhow!("criando filesystem: {e:?}"))?;
    host.mount(mountpoint)
        .map_err(|e| anyhow::anyhow!("montando em {mountpoint}: {e:?}"))?;
    host.start()
        .map_err(|e| anyhow::anyhow!("iniciando dispatcher: {e:?}"))?;

    println!("montado em {mountpoint} (somente leitura). Ctrl+C para desmontar.");

    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .ok();
    let _ = rx.recv();

    println!("desmontando…");
    drop(host); // Drop faz unmount + stop do dispatcher.
    Ok(())
}
