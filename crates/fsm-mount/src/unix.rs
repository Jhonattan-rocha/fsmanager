//! Filesystem read-only sobre o `fsm-core`, exposto via FUSE (Linux/Unix).
//!
//! Mapeia o catálogo do vault (caminhos planos) para uma árvore de inodes:
//! inode 1 = raiz; cada arquivo e cada diretório implícito recebe um inode.
//! `read` delega ao [`Vault::read_range`]; `readdir` ao [`Vault::list_dir`].

use std::collections::{BTreeSet, HashMap};
use std::ffi::OsStr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fsm_core::{NodeKind, Vault};
use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner,
    MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
};

const TTL: Duration = Duration::from_secs(1);
const BLOCK: u64 = 512;

struct FsmFuse {
    vault: Mutex<Vault>,
    ino_to_path: HashMap<u64, String>,
    path_to_ino: HashMap<String, u64>,
    uid: u32,
    gid: u32,
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

impl FsmFuse {
    fn new(vault: Vault) -> Self {
        // Coleta todos os caminhos: raiz + arquivos + diretórios implícitos.
        let mut paths: BTreeSet<String> = BTreeSet::new();
        paths.insert("/".to_string());
        for key in vault.catalog().files.keys() {
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

        // Atribui inodes; "/" fica em primeiro (ordenação) => inode 1.
        let mut ino_to_path = HashMap::new();
        let mut path_to_ino = HashMap::new();
        for (i, path) in paths.into_iter().enumerate() {
            let ino = (i + 1) as u64;
            ino_to_path.insert(ino, path.clone());
            path_to_ino.insert(path, ino);
        }

        // SAFETY: getuid/getgid não têm efeitos colaterais e sempre retornam.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };

        FsmFuse {
            vault: Mutex::new(vault),
            ino_to_path,
            path_to_ino,
            uid,
            gid,
        }
    }

    fn attr(&self, ino: u64, kind: &NodeKind) -> FileAttr {
        let (size, mtime, ftype, perm, nlink) = match kind {
            NodeKind::Dir => (0u64, 0i64, FileType::Directory, 0o555, 2),
            NodeKind::File { size, mtime } => (*size, *mtime, FileType::RegularFile, 0o444, 1),
        };
        let t = to_system_time(mtime);
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(BLOCK),
            atime: t,
            mtime: t,
            ctime: t,
            crtime: t,
            kind: ftype,
            perm,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            flags: 0,
            blksize: BLOCK as u32,
        }
    }

    fn resolve_kind(&self, path: &str) -> Option<NodeKind> {
        self.vault.lock().unwrap().resolve(path)
    }
}

impl Filesystem for FsmFuse {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_path) = self.ino_to_path.get(&u64::from(parent)).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let child = join(&parent_path, &name.to_string_lossy());
        match (self.path_to_ino.get(&child), self.resolve_kind(&child)) {
            (Some(&ino), Some(kind)) => {
                reply.entry(&TTL, &self.attr(ino, &kind), Generation(0));
            }
            _ => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let ino = u64::from(ino);
        match self.ino_to_path.get(&ino).cloned() {
            Some(path) => match self.resolve_kind(&path) {
                Some(kind) => reply.attr(&TTL, &self.attr(ino, &kind)),
                None => reply.error(Errno::ENOENT),
            },
            None => reply.error(Errno::ENOENT),
        }
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
        let Some(path) = self.ino_to_path.get(&u64::from(ino)).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self
            .vault
            .lock()
            .unwrap()
            .read_range(&path, offset, size as usize)
        {
            Ok(data) => reply.data(&data), // vazio = EOF
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let ino = u64::from(ino);
        let Some(path) = self.ino_to_path.get(&ino).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };

        // "." e ".." primeiro, depois os filhos.
        let parent_ino = if path == "/" {
            ino
        } else {
            let idx = path.rfind('/').unwrap();
            let parent = if idx == 0 { "/" } else { &path[..idx] };
            *self.path_to_ino.get(parent).unwrap_or(&1)
        };

        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".to_string()),
            (parent_ino, FileType::Directory, "..".to_string()),
        ];
        for e in self.vault.lock().unwrap().list_dir(&path) {
            let child = join(&path, &e.name);
            if let Some(&cino) = self.path_to_ino.get(&child) {
                let ft = if e.is_dir {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                entries.push((cino, ft, e.name));
            }
        }

        for (i, (cino, ft, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            // O offset do próximo item é o índice seguinte.
            if reply.add(INodeNo(cino), (i + 1) as u64, ft, &name) {
                break; // buffer cheio
            }
        }
        reply.ok();
    }
}

/// Monta o container `vault_path` em `mountpoint` (ex.: `/mnt/fsm`) somente
/// leitura. Bloqueia até Ctrl+C, então desmonta.
pub fn mount(vault_path: &str, mountpoint: &str, password: Option<&str>) -> Result<()> {
    let vault = Vault::open(vault_path, password).context("abrindo container")?;
    let fs = FsmFuse::new(vault);

    // Config é #[non_exhaustive]: construir via default e mutar os campos.
    let mut cfg = Config::default();
    cfg.mount_options = vec![
        MountOption::RO,
        MountOption::FSName("fsmanager".to_string()),
        MountOption::DefaultPermissions,
    ];

    let session = fuser::spawn_mount2(fs, mountpoint, &cfg).context("montando via FUSE")?;
    println!("montado em {mountpoint} (somente leitura). Ctrl+C para desmontar.");

    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .ok();
    let _ = rx.recv();

    println!("desmontando…");
    drop(session); // BackgroundSession::drop desmonta.
    Ok(())
}
