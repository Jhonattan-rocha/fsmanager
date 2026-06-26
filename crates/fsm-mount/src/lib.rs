//! Montagem do container fsmanager como drive.
//!
//! - Windows: WinFsp (módulo [`win`]).
//! - Linux/outros: ainda não implementado (FUSE pendente).

#[cfg(windows)]
mod win;
#[cfg(windows)]
pub use win::mount;

/// Stub para plataformas sem implementação de montagem.
#[cfg(not(windows))]
pub fn mount(_vault_path: &str, _mountpoint: &str, _password: Option<&str>) -> anyhow::Result<()> {
    anyhow::bail!("montagem ainda não implementada nesta plataforma (FUSE/Linux pendente)")
}
