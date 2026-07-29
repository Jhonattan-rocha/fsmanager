//! fsm — CLI do gerenciador de container virtual.

use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::time::{Duration, Instant, UNIX_EPOCH};
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
    /// Repara: trunca arquivos com blocos corrompidos e recupera o íntegro.
    Repair {
        vault: PathBuf,
        #[arg(long, short = 'p')]
        password: Option<String>,
    },
    /// Define, remove ou mostra a cota de tamanho do cofre (em MB).
    Quota {
        vault: PathBuf,
        /// Novo limite em MB (omita para apenas mostrar a cota atual).
        mb: Option<u64>,
        /// Remove a cota (sem limite).
        #[arg(long)]
        clear: bool,
        #[arg(long, short = 'p')]
        password: Option<String>,
    },
    /// Mede o throughput do motor (escrita/leitura/dedup) num cofre temporário.
    Bench {
        /// Tamanho do payload de teste em MB (padrão: 200).
        #[arg(long, default_value_t = 200)]
        size: usize,
        /// Testa com o cofre CIFRADO (mede o custo do XChaCha20/Argon2).
        #[arg(long)]
        encrypted: bool,
    },
    /// Copia arquivos de um cofre para outro (cria o destino se não existir).
    Transfer {
        /// Cofre de ORIGEM
        src: PathBuf,
        /// Cofre de DESTINO (criado se não existir)
        dst: PathBuf,
        /// Copia só a subárvore sob este caminho (padrão: tudo).
        #[arg(long, default_value = "/")]
        path: String,
        /// Senha do cofre de ORIGEM.
        #[arg(long)]
        src_password: Option<String>,
        /// Senha do cofre de DESTINO (também usada ao CRIAR um destino cifrado).
        #[arg(long)]
        dst_password: Option<String>,
    },
    /// Faz backup do cofre para um arquivo (incremental por padrão; --full força completo).
    Backup {
        vault: PathBuf,
        /// Arquivo de destino do backup (um .vault idêntico e abrível).
        dest: PathBuf,
        /// Força um backup COMPLETO (ignora o incremental).
        #[arg(long)]
        full: bool,
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

/// Gera `n` bytes pseudo-aleatórios (incompressíveis) via xorshift — rápido e
/// sem dependência, para o payload do `bench`.
fn gen_pseudo_random(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    for chunk in out.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let b = x.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
    out
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
        Cmd::Repair { vault, password } => {
            let pw = resolve_pw(password);
            let mut v = Vault::open(&vault, pw.as_deref())?;
            let r = v.repair()?;
            v.commit()?;
            if r.files_damaged == 0 {
                println!("✓ nada a reparar — cofre íntegro");
            } else {
                println!("{} arquivo(s) danificado(s):", r.files_damaged);
                for (p, sz) in &r.truncated {
                    println!("  truncado: {p} -> {sz} bytes");
                }
                for p in &r.removed {
                    println!("  removido: {p}");
                }
                println!("\nrode 'gc' para liberar o espaço dos blocos descartados.");
            }
        }
        Cmd::Quota { vault, mb, clear, password } => {
            let pw = resolve_pw(password);
            let mut v = Vault::open(&vault, pw.as_deref())?;
            let used_mb = v.used_bytes() / (1024 * 1024);
            if clear {
                v.set_quota(None);
                v.commit()?;
                println!("cota removida (sem limite). usado: {used_mb} MB");
            } else if let Some(mb) = mb {
                v.set_quota(Some(mb.saturating_mul(1024 * 1024)));
                v.commit()?;
                println!("cota definida: {mb} MB. usado: {used_mb} MB");
            } else {
                match v.quota() {
                    Some(b) => println!("cota: {} MB (usado: {used_mb} MB)", b / (1024 * 1024)),
                    None => println!("cota: sem limite (usado: {used_mb} MB)"),
                }
            }
        }
        Cmd::Bench { size, encrypted } => {
            let bytes_total = size * 1024 * 1024;
            let dir = std::env::temp_dir().join(format!("fsm-bench-{}", std::process::id()));
            std::fs::create_dir_all(&dir)?;
            let vp = dir.join("bench.vault");
            let _ = std::fs::remove_file(&vp);

            println!(
                "payload: {size} MB pseudo-aleatório (incompressível) · cofre {}",
                if encrypted { "CIFRADO" } else { "sem cifra" }
            );
            let payload = gen_pseudo_random(bytes_total);

            let mut v = if encrypted {
                Vault::create_encrypted(&vp, DEFAULT_AVG_CHUNK, "bench-pw")?
            } else {
                Vault::create(&vp, DEFAULT_AVG_CHUNK)?
            };
            let mb = size as f64;

            // Escrita.
            let t = Instant::now();
            v.write_file("/bench.bin", &payload, 0)?;
            v.commit()?;
            let w = t.elapsed().as_secs_f64();

            // Dedup: grava o MESMO conteúdo de novo (deve deduplicar, quase de graça).
            let t2 = Instant::now();
            v.write_file("/bench_copy.bin", &payload, 0)?;
            v.commit()?;
            let d = t2.elapsed().as_secs_f64();

            // Leitura (descarta a saída).
            let t3 = Instant::now();
            let mut sink = std::io::sink();
            v.extract("/bench.bin", &mut sink)?;
            let r = t3.elapsed().as_secs_f64();

            let s = v.stats();
            drop(v);
            let _ = std::fs::remove_dir_all(&dir);

            let rate = |secs: f64| if secs > 0.0 { mb / secs } else { f64::INFINITY };
            println!();
            println!("escrita:          {:>7.1} MB/s  ({:.2}s)", rate(w), w);
            println!("dedup (2ª cópia): {:>7.1} MB/s  ({:.2}s)", rate(d), d);
            println!("leitura:          {:>7.1} MB/s  ({:.2}s)", rate(r), r);
            println!();
            println!(
                "físico no disco:  {:.1} MB  (para {:.0} MB lógicos × 2 cópias)",
                s.physical_bytes as f64 / (1024.0 * 1024.0),
                mb
            );
            println!("economia dedup:   {:.1}%", s.dedup_savings() * 100.0);
            println!("economia compr.:  {:.1}%", s.compression_savings() * 100.0);
            println!("economia total:   {:.1}%", s.total_savings() * 100.0);
        }
        Cmd::Transfer {
            src,
            dst,
            path,
            src_password,
            dst_password,
        } => {
            let src_v = Vault::open(&src, src_password.as_deref())?;
            let mut dst_v = if dst.exists() {
                Vault::open(&dst, dst_password.as_deref())?
            } else if let Some(pw) = &dst_password {
                Vault::create_encrypted(&dst, DEFAULT_AVG_CHUNK, pw)?
            } else {
                Vault::create(&dst, DEFAULT_AVG_CHUNK)?
            };
            let n = dst_v.transfer_from(&src_v, &path)?;
            dst_v.commit()?;
            println!(
                "transferidos {n} arquivo(s) de {} para {}",
                src.display(),
                dst.display()
            );
        }
        Cmd::Backup {
            vault,
            dest,
            full,
            password,
        } => {
            let pw = resolve_pw(password);
            let v = Vault::open(&vault, pw.as_deref())?;
            let r = v.backup_to(&dest, full)?;
            let mb = |b: u64| b as f64 / (1024.0 * 1024.0);
            println!("backup: {} -> {}", vault.display(), dest.display());
            println!("  tipo:    {}", if r.full { "COMPLETO" } else { "incremental" });
            println!("  copiado: {:.1} MB de {:.1} MB total", mb(r.bytes_copied), mb(r.total));
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
