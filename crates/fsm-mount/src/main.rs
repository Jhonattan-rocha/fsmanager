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
    /// Senha, se o container for cifrado (ou via env FSM_PASSWORD)
    #[arg(long, short = 'p')]
    password: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let pw = cli.password.or_else(|| std::env::var("FSM_PASSWORD").ok());
    fsm_mount::mount(&cli.vault, &cli.mountpoint, pw.as_deref())
}
