//! Montagem do container fsmanager como drive.
//!
//! - Windows: WinFsp (módulo [`win`]).
//! - Linux/Unix: FUSE (módulo [`unix`]).

#[cfg(windows)]
mod win;
#[cfg(windows)]
pub use win::mount;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::mount;

/// Stub para plataformas sem implementação de montagem.
#[cfg(not(any(windows, unix)))]
pub fn mount(_vault_path: &str, _mountpoint: &str, _password: Option<&str>) -> anyhow::Result<()> {
    anyhow::bail!("montagem não suportada nesta plataforma")
}
