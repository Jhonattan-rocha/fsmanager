//! Filesystem read-write sobre o `fsm-core`, exposto via FUSE (Linux/Unix).
//!
//! Tabela de inodes dinâmica (cresce/encolhe com create/unlink). Cada arquivo
//! aberto para escrita materializa o conteúdo num buffer; em `release`/`flush`,
//! se sujo, re-chunka (FastCDC+dedup) via [`Vault::write_file`] e commita.
//!
//! Como o host de desenvolvimento é Windows, este módulo é compilado/testado
//! apenas em Linux.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fsm_core::{NodeKind, Vault};
use fuser::{
    BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, LockOwner, MountOption, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow, WriteFlags,
};

const TTL: Duration = Duration::from_secs(1);
const BLOCK: u64 = 512;

/// Buffer materializado de um arquivo aberto para escrita.
struct FileBuf {
    data: Vec<u8>,
    dirty: bool,
}

struct Inner {
    vault: Vault,
    ino_to_path: HashMap<u64, String>,
    path_to_ino: HashMap<String, u64>,
    next_ino: u64,
    buffers: HashMap<u64, FileBuf>,
    open_count: HashMap<u64, u32>,
    uid: u32,
    gid: u32,
}

struct FsmFuse {
    inner: Mutex<Inner>,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn to_system_time(secs: i64) -> SystemTime {
    if secs <= 0 {
        UNIX_EPOCH
    } else {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

impl Inner {
    fn new(vault: Vault) -> Self {
        // Tabela inicial: raiz + arquivos + diretórios (explícitos e implícitos).
        let mut paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        paths.insert("/".to_string());
        let cat = vault.catalog();
        let all = cat.files.keys().chain(cat.dirs.iter());
        for key in all {
            paths.insert(key.clone());
            let mut p = key.as_str();
            while let Some(idx) = p.rfind('/') {
                let parent = if idx == 0 { "/" } else { &p[..idx] };
                paths.insert(parent.to_string());
                if parent == "/" {
                    break;
                }
                p = parent;
            }
        }
        let mut ino_to_path = HashMap::new();
        let mut path_to_ino = HashMap::new();
        for (i, path) in paths.into_iter().enumerate() {
            let ino = (i + 1) as u64;
            ino_to_path.insert(ino, path.clone());
            path_to_ino.insert(path, ino);
        }
        let next_ino = (ino_to_path.len() + 1) as u64;
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Inner {
            vault,
            ino_to_path,
            path_to_ino,
            next_ino,
            buffers: HashMap::new(),
            open_count: HashMap::new(),
            uid,
            gid,
        }
    }

    /// Inode de um caminho, criando um novo se necessário.
    fn intern(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.ino_to_path.insert(ino, path.to_string());
        self.path_to_ino.insert(path.to_string(), ino);
        ino
    }

    /// Remove um inode e seus mapeamentos (após unlink/rmdir).
    fn forget(&mut self, path: &str) {
        if let Some(ino) = self.path_to_ino.remove(path) {
            self.ino_to_path.remove(&ino);
            self.buffers.remove(&ino);
            self.open_count.remove(&ino);
        }
    }

    /// Atualiza mapeamentos de caminho de `old` e descendentes após rename.
    fn rename_paths(&mut self, old: &str, new: &str) {
        let pre = format!("{old}/");
        let affected: Vec<(u64, String)> = self
            .ino_to_path
            .iter()
            .filter(|(_, p)| p.as_str() == old || p.starts_with(&pre))
            .map(|(i, p)| (*i, p.clone()))
            .collect();
        for (ino, p) in affected {
            let np = if p == old {
                new.to_string()
            } else {
                format!("{new}/{}", &p[pre.len()..])
            };
            self.path_to_ino.remove(&p);
            self.ino_to_path.insert(ino, np.clone());
            self.path_to_ino.insert(np, ino);
        }
    }

    fn build_attr(&self, ino: u64, size: u64, mtime: i64, kind: FileType) -> FileAttr {
        let t = to_system_time(mtime);
        let (perm, nlink) = match kind {
            FileType::Directory => (0o755, 2),
            _ => (0o644, 1),
        };
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(BLOCK),
            atime: t,
            mtime: t,
            ctime: t,
            crtime: t,
            kind,
            perm,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            flags: 0,
            blksize: BLOCK as u32,
        }
    }

    /// Atributos de um inode: prioriza o buffer materializado (tamanho atual).
    fn attr_of(&self, ino: u64, path: &str) -> Option<FileAttr> {
        if let Some(b) = self.buffers.get(&ino) {
            return Some(self.build_attr(ino, b.data.len() as u64, now_secs(), FileType::RegularFile));
        }
        match self.vault.resolve(path)? {
            NodeKind::Dir => Some(self.build_attr(ino, 0, 0, FileType::Directory)),
            NodeKind::File { size, mtime } => {
                Some(self.build_attr(ino, size, mtime, FileType::RegularFile))
            }
        }
    }

    /// Garante que o buffer do inode está carregado com o conteúdo atual.
    fn ensure_buffer(&mut self, ino: u64, path: &str) {
        if self.buffers.contains_key(&ino) {
            return;
        }
        let size = match self.vault.resolve(path) {
            Some(NodeKind::File { size, .. }) => size,
            _ => 0,
        };
        let data = self.vault.read_range(path, 0, size as usize).unwrap_or_default();
        self.buffers.insert(ino, FileBuf { data, dirty: false });
    }

    /// Persiste o buffer sujo no container.
    fn flush_ino(&mut self, ino: u64) {
        let path = match self.ino_to_path.get(&ino) {
            Some(p) => p.clone(),
            None => return,
        };
        let dirty = self.buffers.get(&ino).map(|b| b.dirty).unwrap_or(false);
        if dirty {
            let data = self.buffers.get(&ino).unwrap().data.clone();
            if self.vault.write_file(&path, &data, now_secs()).is_ok() {
                let _ = self.vault.commit();
                if let Some(b) = self.buffers.get_mut(&ino) {
                    b.dirty = false;
                }
            }
        }
    }
}

impl Filesystem for FsmFuse {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let mut inner = self.inner.lock().unwrap();
        let Some(parent_path) = inner.ino_to_path.get(&u64::from(parent)).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let child = join(&parent_path, &name.to_string_lossy());
        if inner.vault.resolve(&child).is_none() {
            reply.error(Errno::ENOENT);
            return;
        }
        let ino = inner.intern(&child);
        match inner.attr_of(ino, &child) {
            Some(attr) => reply.entry(&TTL, &attr, Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let inner = self.inner.lock().unwrap();
        let ino = u64::from(ino);
        match inner.ino_to_path.get(&ino).cloned() {
            Some(path) => match inner.attr_of(ino, &path) {
                Some(attr) => reply.attr(&TTL, &attr),
                None => reply.error(Errno::ENOENT),
            },
            None => reply.error(Errno::ENOENT),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let mut inner = self.inner.lock().unwrap();
        let ino = u64::from(ino);
        if !inner.ino_to_path.contains_key(&ino) {
            reply.error(Errno::ENOENT);
            return;
        }
        *inner.open_count.entry(ino).or_insert(0) += 1;
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let ino = u64::from(ino);
        let remaining = {
            let c = inner.open_count.entry(ino).or_insert(1);
            *c = c.saturating_sub(1);
            *c
        };
        if remaining == 0 {
            inner.open_count.remove(&ino);
            inner.flush_ino(ino);
            inner.buffers.remove(&ino);
        }
        reply.ok();
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let ino = u64::from(ino);
        let Some(path) = inner.ino_to_path.get(&ino).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(b) = inner.buffers.get(&ino) {
            let from = (offset as usize).min(b.data.len());
            let to = (from + size as usize).min(b.data.len());
            reply.data(&b.data[from..to]);
        } else {
            match inner.vault.read_range(&path, offset, size as usize) {
                Ok(data) => reply.data(&data),
                Err(_) => reply.error(Errno::EIO),
            }
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let ino = u64::from(ino);
        let Some(path) = inner.ino_to_path.get(&ino).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        inner.ensure_buffer(ino, &path);
        let end = offset as usize + data.len();
        let b = inner.buffers.get_mut(&ino).unwrap();
        if end > b.data.len() {
            b.data.resize(end, 0);
        }
        b.data[offset as usize..end].copy_from_slice(data);
        b.dirty = true;
        reply.written(data.len() as u32);
    }

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let Some(parent_path) = inner.ino_to_path.get(&u64::from(parent)).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let child = join(&parent_path, &name.to_string_lossy());
        if inner.vault.resolve(&child).is_some() {
            reply.error(Errno::EEXIST);
            return;
        }
        if inner.vault.write_file(&child, &[], now_secs()).is_err() {
            reply.error(Errno::EIO);
            return;
        }
        let _ = inner.vault.commit();
        let ino = inner.intern(&child);
        inner.buffers.insert(ino, FileBuf { data: Vec::new(), dirty: false });
        *inner.open_count.entry(ino).or_insert(0) += 1;
        let attr = inner.build_attr(ino, 0, now_secs(), FileType::RegularFile);
        reply.created(&TTL, &attr, Generation(0), FileHandle(0), FopenFlags::empty());
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let Some(parent_path) = inner.ino_to_path.get(&u64::from(parent)).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let child = join(&parent_path, &name.to_string_lossy());
        if inner.vault.resolve(&child).is_some() {
            reply.error(Errno::EEXIST);
            return;
        }
        if inner.vault.create_dir(&child).is_err() {
            reply.error(Errno::EIO);
            return;
        }
        let _ = inner.vault.commit();
        let ino = inner.intern(&child);
        let attr = inner.build_attr(ino, 0, now_secs(), FileType::Directory);
        reply.entry(&TTL, &attr, Generation(0));
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let mut inner = self.inner.lock().unwrap();
        let Some(parent_path) = inner.ino_to_path.get(&u64::from(parent)).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let child = join(&parent_path, &name.to_string_lossy());
        match inner.vault.resolve(&child) {
            Some(NodeKind::File { .. }) => {
                let _ = inner.vault.remove(&child);
                let _ = inner.vault.commit();
                inner.forget(&child);
                reply.ok();
            }
            Some(NodeKind::Dir) => reply.error(Errno::EISDIR),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let mut inner = self.inner.lock().unwrap();
        let Some(parent_path) = inner.ino_to_path.get(&u64::from(parent)).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let child = join(&parent_path, &name.to_string_lossy());
        match inner.vault.resolve(&child) {
            Some(NodeKind::Dir) => {
                if !inner.vault.list_dir(&child).is_empty() {
                    reply.error(Errno::ENOTEMPTY);
                    return;
                }
                let _ = inner.vault.remove_empty_dir(&child);
                let _ = inner.vault.commit();
                inner.forget(&child);
                reply.ok();
            }
            Some(NodeKind::File { .. }) => reply.error(Errno::ENOTDIR),
            None => reply.error(Errno::ENOENT),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let (Some(pp), Some(np)) = (
            inner.ino_to_path.get(&u64::from(parent)).cloned(),
            inner.ino_to_path.get(&u64::from(newparent)).cloned(),
        ) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let from = join(&pp, &name.to_string_lossy());
        let to = join(&np, &newname.to_string_lossy());
        if inner.vault.rename(&from, &to).is_err() {
            reply.error(Errno::ENOENT);
            return;
        }
        let _ = inner.vault.commit();
        inner.rename_paths(&from, &to);
        reply.ok();
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let ino = u64::from(ino);
        let Some(path) = inner.ino_to_path.get(&ino).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(sz) = size {
            inner.ensure_buffer(ino, &path);
            if let Some(b) = inner.buffers.get_mut(&ino) {
                b.data.resize(sz as usize, 0);
                b.dirty = true;
            }
        }
        match inner.attr_of(ino, &path) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.flush_ino(u64::from(ino));
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.flush_ino(u64::from(ino));
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let ino = u64::from(ino);
        let Some(path) = inner.ino_to_path.get(&ino).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let parent_ino = if path == "/" {
            ino
        } else {
            let idx = path.rfind('/').unwrap();
            let parent = if idx == 0 { "/" } else { &path[..idx] };
            *inner.path_to_ino.get(parent).unwrap_or(&1)
        };

        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".to_string()),
            (parent_ino, FileType::Directory, "..".to_string()),
        ];
        for e in inner.vault.list_dir(&path) {
            let child = join(&path, &e.name);
            let cino = inner.intern(&child);
            let ft = if e.is_dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            entries.push((cino, ft, e.name));
        }

        for (i, (cino, ft, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(cino), (i + 1) as u64, ft, &name) {
                break;
            }
        }
        reply.ok();
    }
}

/// Monta o container `vault_path` em `mountpoint` (ex.: `/mnt/fsm`) com leitura
/// E escrita. Bloqueia até Ctrl+C, então desmonta.
pub fn mount(vault_path: &str, mountpoint: &str, password: Option<&str>) -> Result<()> {
    let vault = Vault::open(vault_path, password).context("abrindo container")?;
    let fs = FsmFuse {
        inner: Mutex::new(Inner::new(vault)),
    };

    let mut cfg = Config::default();
    cfg.mount_options = vec![
        MountOption::FSName("fsmanager".to_string()),
        MountOption::DefaultPermissions,
    ];

    let session = fuser::spawn_mount2(fs, mountpoint, &cfg).context("montando via FUSE")?;
    println!("montado em {mountpoint} (leitura e escrita). Ctrl+C para desmontar.");

    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .ok();
    let _ = rx.recv();

    println!("desmontando…");
    drop(session);
    Ok(())
}
