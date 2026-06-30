//! fsm — CLI do gerenciador de container virtual.

use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::time::{Duration, UNIX_EPOCH};
use fsm_core::{Vault, DEFAULT_AVG_CHUNK};

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
        /// Tamanho médio de chunk do FastCDC em bytes (padrão: 64 KiB)
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
    /// Lista os arquivos guardados (opcionalmente sob um prefixo).
    Ls {
        vault: PathBuf,
        /// Prefixo/diretório para filtrar (ex: /docs)
        prefix: Option<String>,
        #[arg(long, short = 'p')]
        password: Option<String>,
    },
    /// Remove um arquivo (ou um diretório inteiro com -r).
    Rm {
        vault: PathBuf,
        path: String,
        /// Remove recursivamente um diretório.
        #[arg(long, short = 'r')]
        recursive: bool,
        #[arg(long, short = 'p')]
        password: Option<String>,
    },
    /// Move/renomeia um arquivo ou diretório dentro do container.
    Mv {
        vault: PathBuf,
        src: String,
        dst: String,
        #[arg(long, short = 'p')]
        password: Option<String>,
    },
    /// Compacta o container, recuperando espaço de removidos e gerações antigas.
    Gc {
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
    /// Gerencia snapshots (versões nomeadas da árvore).
    Snapshot {
        vault: PathBuf,
        #[arg(long, short = 'p')]
        password: Option<String>,
        #[command(subcommand)]
        action: SnapAction,
    },
    /// Verifica a integridade do container (hash de cada bloco).
    Verify {
        vault: PathBuf,
        #[arg(long, short = 'p')]
        password: Option<String>,
    },
}

#[derive(Subcommand)]
enum SnapAction {
    /// Cria um snapshot da árvore atual.
    Create { name: String },
    /// Lista os snapshots existentes.
    List,
    /// Restaura a árvore atual para um snapshot.
    Restore { name: String },
    /// Apaga um snapshot (espaço volta no próximo gc).
    Delete { name: String },
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
            let chunk = chunk.unwrap_or(DEFAULT_AVG_CHUNK);
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
        Cmd::Ls {
            vault,
            prefix,
            password,
        } => {
            let pw = resolve_pw(password);
            let v = Vault::open(&vault, pw.as_deref())?;
            let filter = prefix.map(|p| {
                let p = p.replace('\\', "/");
                format!("/{}", p.trim_start_matches('/'))
            });
            for (path, entry) in &v.catalog().files {
                if let Some(f) = &filter {
                    if path != f && !path.starts_with(&format!("{}/", f.trim_end_matches('/'))) {
                        continue;
                    }
                }
                println!("{:>12}  {}", entry.size, path);
            }
        }
        Cmd::Rm {
            vault,
            path,
            recursive,
            password,
        } => {
            let pw = resolve_pw(password);
            let mut v = Vault::open(&vault, pw.as_deref())?;
            if recursive {
                let n = v.remove_dir(&path)?;
                v.commit()?;
                println!("removidos {n} arquivo(s) sob {path}");
            } else if v.remove(&path)? {
                v.commit()?;
                println!("removido: {path}");
            } else {
                anyhow::bail!("não encontrado: {path} (use -r para remover diretório)");
            }
        }
        Cmd::Mv {
            vault,
            src,
            dst,
            password,
        } => {
            let pw = resolve_pw(password);
            let mut v = Vault::open(&vault, pw.as_deref())?;
            v.rename(&src, &dst)?;
            v.commit()?;
            println!("movido: {src} -> {dst}");
        }
        Cmd::Gc { vault, password } => {
            let pw = resolve_pw(password);
            let mut v = Vault::open(&vault, pw.as_deref())?;
            let tmp = PathBuf::from(format!("{}.compacting", vault.display()));
            if tmp.exists() {
                std::fs::remove_file(&tmp)?;
            }
            let report = v.compact_to(&tmp)?;
            drop(v); // fecha o handle do original antes de substituir
            std::fs::rename(&tmp, &vault)?;
            println!(
                "compactado: {} -> {} bytes ({} recuperados); blocos {} -> {}",
                report.bytes_before,
                report.bytes_after,
                report.reclaimed_bytes(),
                report.blocks_before,
                report.blocks_after
            );
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
            println!("snapshots:          {}", s.snapshots);
            println!("cifrado:            {}", if s.encrypted { "sim" } else { "não" });
            println!("tamanho lógico:     {} bytes", s.logical_bytes);
            println!("após dedup:         {} bytes", s.unique_raw_bytes);
            println!("em disco (físico):  {} bytes", s.physical_bytes);
            println!("economia dedup:     {:.1}%", s.dedup_savings() * 100.0);
            println!("economia compressão:{:.1}%", s.compression_savings() * 100.0);
            println!("economia total:     {:.1}%", s.total_savings() * 100.0);
        }
        Cmd::Snapshot {
            vault,
            password,
            action,
        } => {
            let pw = resolve_pw(password);
            let mut v = Vault::open(&vault, pw.as_deref())?;
            match action {
                SnapAction::Create { name } => {
                    v.snapshot_create(&name)?;
                    v.commit()?;
                    println!("snapshot criado: {name}");
                }
                SnapAction::List => {
                    if v.snapshots().is_empty() {
                        println!("(nenhum snapshot)");
                    }
                    for s in v.snapshots() {
                        let total: u64 = s.files.values().map(|f| f.size).sum();
                        println!(
                            "{:<20} {:>4} arquivo(s)  {:>12} bytes  {}",
                            s.name,
                            s.files.len(),
                            total,
                            fmt_time(s.created)
                        );
                    }
                }
                SnapAction::Restore { name } => {
                    v.snapshot_restore(&name)?;
                    v.commit()?;
                    println!("árvore restaurada para o snapshot: {name}");
                }
                SnapAction::Delete { name } => {
                    if v.snapshot_delete(&name)? {
                        v.commit()?;
                        println!("snapshot apagado: {name} (rode 'gc' para liberar espaço)");
                    } else {
                        anyhow::bail!("snapshot não encontrado: {name}");
                    }
                }
            }
        }
        Cmd::Verify { vault, password } => {
            let pw = resolve_pw(password);
            let mut v = Vault::open(&vault, pw.as_deref())?;
            let r = v.verify()?;
            println!("blocos OK:        {}", r.blocks_ok);
            println!("blocos ruins:     {}", r.blocks_bad);
            println!("blocos ausentes:  {}", r.missing_blocks);
            if r.is_healthy() {
                println!("\n✓ íntegro");
            } else {
                println!("\n✗ PROBLEMAS encontrados:");
                for e in r.errors.iter().take(20) {
                    println!("  - {e}");
                }
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

/// Formata um unix timestamp (UTC) como `AAAA-MM-DD HH:MM:SS` sem dependências.
fn fmt_time(secs: i64) -> String {
    if secs <= 0 {
        return "-".into();
    }
    let st = UNIX_EPOCH + Duration::from_secs(secs as u64);
    let total = secs as u64;
    let (s, m, h) = (total % 60, total / 60 % 60, total / 3600 % 24);
    let days = (total / 86_400) as i64;
    // Algoritmo civil de Howard Hinnant (days desde a época -> data).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    let _ = st;
    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}
