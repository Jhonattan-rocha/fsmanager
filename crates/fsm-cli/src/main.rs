//! fsm — CLI do gerenciador de container virtual.

use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use fsm_core::{Vault, DEFAULT_CHUNK};

#[derive(Parser)]
#[command(name = "fsm", version, about = "Gerenciador de container virtual (arquivo único)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Cria um container novo e vazio.
    Init {
        /// Caminho do container (ex: meu.vault)
        vault: PathBuf,
        /// Tamanho de chunk em bytes (padrão: 1 MiB)
        #[arg(long)]
        chunk: Option<u32>,
        /// Cria um container CIFRADO com esta senha (ou via env FSM_PASSWORD).
        #[arg(long, short = 'p')]
        password: Option<String>,
    },
    /// Adiciona um arquivo do disco ao container.
    Add {
        vault: PathBuf,
        /// Arquivo de origem no disco real
        src: PathBuf,
        /// Caminho lógico dentro do container (padrão: nome do arquivo)
        #[arg(long = "as")]
        dest: Option<String>,
        /// Nível de compressão zstd (1..=22). Padrão: 3.
        #[arg(long)]
        level: Option<i32>,
        /// Senha (se o container for cifrado). Também via env FSM_PASSWORD.
        #[arg(long, short = 'p')]
        password: Option<String>,
    },
    /// Lista os arquivos guardados.
    Ls {
        vault: PathBuf,
        #[arg(long, short = 'p')]
        password: Option<String>,
    },
    /// Extrai um arquivo lógico para stdout.
    Cat {
        vault: PathBuf,
        path: String,
        #[arg(long, short = 'p')]
        password: Option<String>,
    },
    /// Extrai um arquivo lógico para um arquivo do disco.
    Extract {
        vault: PathBuf,
        path: String,
        out: PathBuf,
        #[arg(long, short = 'p')]
        password: Option<String>,
    },
    /// Mostra estatísticas (uso, dedup, compressão).
    Stats {
        vault: PathBuf,
        #[arg(long, short = 'p')]
        password: Option<String>,
    },
}

/// Resolve a senha: flag explícita ou variável de ambiente FSM_PASSWORD.
fn resolve_pw(flag: Option<String>) -> Option<String> {
    flag.or_else(|| std::env::var("FSM_PASSWORD").ok())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init {
            vault,
            chunk,
            password,
        } => {
            let chunk = chunk.unwrap_or(DEFAULT_CHUNK);
            match resolve_pw(password) {
                Some(pw) => {
                    Vault::create_encrypted(&vault, chunk, &pw)?;
                    println!("container CIFRADO criado: {}", vault.display());
                }
                None => {
                    Vault::create(&vault, chunk)?;
                    println!("container criado: {}", vault.display());
                }
            }
        }
        Cmd::Add {
            vault,
            src,
            dest,
            level,
            password,
        } => {
            let dest = dest.unwrap_or_else(|| {
                src.file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "arquivo".into())
            });
            let pw = resolve_pw(password);
            let mut v = Vault::open(&vault, pw.as_deref())?;
            if let Some(l) = level {
                v.set_zstd_level(l);
            }
            v.add_file(&src, &dest)?;
            v.commit()?;
            println!("adicionado: {} -> {}", src.display(), dest);
        }
        Cmd::Ls { vault, password } => {
            let pw = resolve_pw(password);
            let v = Vault::open(&vault, pw.as_deref())?;
            for (path, entry) in &v.catalog().files {
                println!("{:>12}  {}", entry.size, path);
            }
        }
        Cmd::Cat {
            vault,
            path,
            password,
        } => {
            let pw = resolve_pw(password);
            let mut v = Vault::open(&vault, pw.as_deref())?;
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            v.extract(&path, &mut lock)?;
            lock.flush()?;
        }
        Cmd::Extract {
            vault,
            path,
            out,
            password,
        } => {
            let pw = resolve_pw(password);
            let mut v = Vault::open(&vault, pw.as_deref())?;
            let mut f = std::fs::File::create(&out)?;
            let n = v.extract(&path, &mut f)?;
            println!("extraído {} bytes -> {}", n, out.display());
        }
        Cmd::Stats { vault, password } => {
            let pw = resolve_pw(password);
            let v = Vault::open(&vault, pw.as_deref())?;
            let s = v.stats();
            println!("arquivos:           {}", s.files);
            println!("blocos únicos:      {}", s.unique_blocks);
            println!("cifrado:            {}", if s.encrypted { "sim" } else { "não" });
            println!("tamanho lógico:     {} bytes", s.logical_bytes);
            println!("após dedup:         {} bytes", s.unique_raw_bytes);
            println!("em disco (físico):  {} bytes", s.physical_bytes);
            println!("economia dedup:     {:.1}%", s.dedup_savings() * 100.0);
            println!("economia compressão:{:.1}%", s.compression_savings() * 100.0);
            println!("economia total:     {:.1}%", s.total_savings() * 100.0);
        }
    }
    Ok(())
}
