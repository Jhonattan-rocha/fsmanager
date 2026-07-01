//! fsm-mount — monta um container fsmanager como drive.

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "fsm-mount",
    about = "Monta um container fsmanager como drive (somente leitura)"
)]
struct Cli {
    /// Caminho do container .vault
    vault: String,
    /// Ponto de montagem (ex.: X: no Windows, /mnt/fsm no Linux)
    mountpoint: String,
    /// Senha, se o container for cifrado (ou via env FSM_PASSWORD).
    /// ATENÇÃO: passar a senha aqui a expõe na lista de processos. Prefira
    /// `--password-stdin` (usado pela UI), que a lê do stdin sem tocar no argv.
    #[arg(long, short = 'p')]
    password: Option<String>,
    /// Lê a senha da PRIMEIRA LINHA do stdin (não aparece na lista de processos).
    #[arg(long)]
    password_stdin: bool,
}

/// Lê a primeira linha do stdin byte a byte (sem bufferizar além do `\n`, para
/// não consumir o restante do stream — que o desmonte gracioso usa como EOF).
fn read_password_line() -> Option<String> {
    use std::io::Read;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    let mut stdin = std::io::stdin().lock();
    loop {
        match stdin.read(&mut byte) {
            Ok(0) | Err(_) => break, // EOF/erro
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
            }
        }
    }
    // Tira BOM UTF-8 (se algum chamador o escrever) e o \r de fim de linha.
    let s = String::from_utf8_lossy(&buf)
        .trim_start_matches('\u{feff}')
        .trim_end_matches('\r')
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let pw = if cli.password_stdin {
        read_password_line()
    } else {
        cli.password.or_else(|| std::env::var("FSM_PASSWORD").ok())
    };
    fsm_mount::mount(&cli.vault, &cli.mountpoint, pw.as_deref())
}
