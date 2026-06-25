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
    },
    /// Adiciona um arquivo do disco ao container.
    Add {
        vault: PathBuf,
        /// Arquivo de origem no disco real
        src: PathBuf,
        /// Caminho lógico dentro do container (padrão: nome do arquivo)
        #[arg(long = "as")]
        dest: Option<String>,
    },
    /// Lista os arquivos guardados.
    Ls { vault: PathBuf },
    /// Extrai um arquivo lógico para stdout.
    Cat { vault: PathBuf, path: String },
    /// Extrai um arquivo lógico para um arquivo do disco.
    Extract {
        vault: PathBuf,
        path: String,
        out: PathBuf,
    },
    /// Mostra estatísticas (uso, dedup).
    Stats { vault: PathBuf },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { vault, chunk } => {
            Vault::create(&vault, chunk.unwrap_or(DEFAULT_CHUNK))?;
            println!("container criado: {}", vault.display());
        }
        Cmd::Add { vault, src, dest } => {
            let dest = dest.unwrap_or_else(|| {
                src.file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "arquivo".into())
            });
            let mut v = Vault::open(&vault)?;
            v.add_file(&src, &dest)?;
            v.commit()?;
            println!("adicionado: {} -> {}", src.display(), dest);
        }
        Cmd::Ls { vault } => {
            let v = Vault::open(&vault)?;
            for (path, entry) in &v.catalog().files {
                println!("{:>12}  {}", entry.size, path);
            }
        }
        Cmd::Cat { vault, path } => {
            let mut v = Vault::open(&vault)?;
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            v.extract(&path, &mut lock)?;
            lock.flush()?;
        }
        Cmd::Extract { vault, path, out } => {
            let mut v = Vault::open(&vault)?;
            let mut f = std::fs::File::create(&out)?;
            let n = v.extract(&path, &mut f)?;
            println!("extraído {} bytes -> {}", n, out.display());
        }
        Cmd::Stats { vault } => {
            let v = Vault::open(&vault)?;
            let s = v.stats();
            println!("arquivos:        {}", s.files);
            println!("blocos únicos:   {}", s.unique_blocks);
            println!("tamanho lógico:  {} bytes", s.logical_bytes);
            println!("tamanho físico:  {} bytes", s.physical_bytes);
            println!("economia dedup:  {:.1}%", s.dedup_savings() * 100.0);
        }
    }
    Ok(())
}
