//! Backend Tauri do fsmanager: expõe o `fsm-core` para a UI.
//!
//! Mantém UM vault aberto em estado compartilhado (`Mutex<Option<OpenVault>>`)
//! para reusar a chave derivada (Argon2) entre operações — abrir um cofre
//! cifrado a cada clique seria inviável.

use std::path::Path;
use std::sync::Mutex;

use fsm_core::{NodeKind, Vault, DEFAULT_AVG_CHUNK};
use serde::Serialize;
use tauri::{Emitter, State};
use tauri_plugin_dialog::DialogExt;

/// Vault aberto + contexto necessário para reabrir após `gc`.
struct OpenVault {
    path: String,
    password: Option<String>,
    vault: Vault,
}

#[derive(Default)]
struct AppState {
    open: Mutex<Option<OpenVault>>,
    mount: Mutex<Option<MountProc>>,
}

/// Processo `fsm-mount` em execução (binário GPLv3 separado, invocado como processo).
struct MountProc {
    child: std::process::Child,
    mountpoint: String,
}

// ----------------------- DTOs para a UI -----------------------

#[derive(Serialize)]
struct DirEntryDto {
    name: String,
    is_dir: bool,
    size: u64,
    mtime: i64,
}

#[derive(Serialize)]
struct SnapshotDto {
    name: String,
    created: i64,
    files: usize,
    size: u64,
}

#[derive(Serialize)]
struct StatsDto {
    files: usize,
    unique_blocks: usize,
    snapshots: usize,
    encrypted: bool,
    logical_bytes: u64,
    unique_raw_bytes: u64,
    physical_bytes: u64,
    dedup_savings: f64,
    compression_savings: f64,
    total_savings: f64,
    quota: Option<u64>,
    used_bytes: u64,
}

/// Progresso de adição de arquivo, emitido como evento `add-progress`.
#[derive(Serialize, Clone)]
struct AddProgress {
    file: String,
    done: u64,
    total: u64,
}

/// Estado geral do vault (stats + snapshots). A navegação de arquivos é por
/// pasta, via `list_dir`.
#[derive(Serialize)]
struct VaultInfo {
    path: String,
    stats: StatsDto,
    snapshots: Vec<SnapshotDto>,
}

// ----------------------- helpers -----------------------

fn s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn stats_dto(v: &Vault) -> StatsDto {
    let st = v.stats();
    StatsDto {
        files: st.files,
        unique_blocks: st.unique_blocks,
        snapshots: st.snapshots,
        encrypted: st.encrypted,
        logical_bytes: st.logical_bytes,
        unique_raw_bytes: st.unique_raw_bytes,
        physical_bytes: st.physical_bytes,
        dedup_savings: st.dedup_savings(),
        compression_savings: st.compression_savings(),
        total_savings: st.total_savings(),
        quota: st.quota,
        used_bytes: st.used_bytes,
    }
}

fn build_info(path: &str, v: &Vault) -> VaultInfo {
    let snapshots = v
        .snapshots()
        .iter()
        .map(|sn| SnapshotDto {
            name: sn.name.clone(),
            created: sn.created,
            files: sn.files.len(),
            size: sn.files.values().map(|f| f.size).sum(),
        })
        .collect();
    VaultInfo {
        path: path.to_string(),
        stats: stats_dto(v),
        snapshots,
    }
}

/// Executa `f` sobre o vault aberto.
fn with_vault<T>(
    state: &State<AppState>,
    f: impl FnOnce(&mut Vault) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = state.open.lock().unwrap();
    let ov = guard.as_mut().ok_or("nenhum container aberto")?;
    f(&mut ov.vault)
}

fn empty_to_none(p: Option<String>) -> Option<String> {
    p.filter(|x| !x.is_empty())
}

/// Junta um diretório lógico com um nome de arquivo/pasta.
fn join_logical(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", dir.trim_end_matches('/'))
    }
}

/// Adiciona `sources` (caminhos do disco) dentro de `dest_dir`, emitindo
/// progresso. Retorna quantos arquivos foram adicionados.
/// Coleta pares (caminho-em-disco, caminho-lógico) para um item solto,
/// RECURSIVAMENTE em pastas — preservando a subárvore dentro de `dest_dir`.
fn collect_pairs(src: &Path, dest_dir: &str, out: &mut Vec<(String, String)>) {
    if src.is_file() {
        let name = src
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "arquivo".into());
        out.push((src.to_string_lossy().into_owned(), join_logical(dest_dir, &name)));
    } else if src.is_dir() {
        let folder = src
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "pasta".into());
        let sub = join_logical(dest_dir, &folder);
        if let Ok(rd) = std::fs::read_dir(src) {
            for entry in rd.flatten() {
                collect_pairs(&entry.path(), &sub, out);
            }
        }
    }
}

fn add_sources(
    app: &tauri::AppHandle,
    ov: &mut OpenVault,
    sources: &[String],
    dest_dir: &str,
) -> Result<usize, String> {
    // Expande pastas em seus arquivos (recursivo), preservando a estrutura.
    let mut pairs: Vec<(String, String)> = Vec::new();
    for src in sources {
        collect_pairs(Path::new(src), dest_dir, &mut pairs);
    }
    for (disk, logical) in &pairs {
        let fname = Path::new(logical)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "arquivo".into());
        let total = std::fs::metadata(disk).map(|m| m.len()).unwrap_or(0);
        let app2 = app.clone();
        let label = fname.clone();
        let mut last_emit = 0u64;
        ov.vault
            .add_file_progress(disk, logical, |done| {
                if done.saturating_sub(last_emit) >= 4 * 1024 * 1024 || done >= total {
                    last_emit = done;
                    let _ = app2.emit(
                        "add-progress",
                        AddProgress {
                            file: label.clone(),
                            done,
                            total,
                        },
                    );
                }
            })
            .map_err(s)?;
    }
    ov.vault.commit().map_err(s)?;
    Ok(pairs.len())
}

// ----------------------- comandos -----------------------

#[tauri::command(async)]
fn create_vault(
    app: tauri::AppHandle,
    state: State<AppState>,
    password: Option<String>,
) -> Result<VaultInfo, String> {
    let chosen = app
        .dialog()
        .file()
        .add_filter("Container fsmanager", &["vault"])
        .set_file_name("novo.vault")
        .blocking_save_file();
    let path = match chosen {
        Some(p) => p.to_string(),
        None => return Err("criação cancelada".into()),
    };
    let pw = empty_to_none(password);
    let vault = match &pw {
        Some(p) => Vault::create_encrypted(&path, DEFAULT_AVG_CHUNK, p),
        None => Vault::create(&path, DEFAULT_AVG_CHUNK),
    }
    .map_err(s)?;
    let info = build_info(&path, &vault);
    *state.open.lock().unwrap() = Some(OpenVault { path, password: pw, vault });
    Ok(info)
}

#[tauri::command(async)]
fn open_vault(
    app: tauri::AppHandle,
    state: State<AppState>,
    password: Option<String>,
) -> Result<VaultInfo, String> {
    let chosen = app
        .dialog()
        .file()
        .add_filter("Container fsmanager", &["vault"])
        .blocking_pick_file();
    let path = match chosen {
        Some(p) => p.to_string(),
        None => return Err("abertura cancelada".into()),
    };
    let pw = empty_to_none(password);
    let vault = Vault::open(&path, pw.as_deref()).map_err(s)?;
    let info = build_info(&path, &vault);
    *state.open.lock().unwrap() = Some(OpenVault { path, password: pw, vault });
    Ok(info)
}

#[tauri::command]
fn close_vault(state: State<AppState>) -> Result<(), String> {
    *state.open.lock().unwrap() = None;
    Ok(())
}

#[tauri::command]
fn get_info(state: State<AppState>) -> Result<VaultInfo, String> {
    let guard = state.open.lock().unwrap();
    let ov = guard.as_ref().ok_or("nenhum container aberto")?;
    Ok(build_info(&ov.path, &ov.vault))
}

/// Lista os filhos imediatos (pastas + arquivos) de um diretório lógico.
#[tauri::command]
fn list_dir(state: State<AppState>, path: String) -> Result<Vec<DirEntryDto>, String> {
    with_vault(&state, |v| {
        Ok(v.list_dir(&path)
            .into_iter()
            .map(|e| DirEntryDto {
                name: e.name,
                is_dir: e.is_dir,
                size: e.size,
                mtime: e.mtime,
            })
            .collect())
    })
}

/// Cria uma pasta (diretório explícito).
#[tauri::command]
fn make_dir(state: State<AppState>, path: String) -> Result<(), String> {
    with_vault(&state, |v| {
        v.create_dir(&path).map_err(s)?;
        v.commit().map_err(s)
    })
}

#[derive(Serialize)]
struct SearchHitDto {
    path: String,
    is_dir: bool,
    size: u64,
    mtime: i64,
}

/// Busca recursiva no cofre inteiro por nome (substring, case-insensitive).
#[tauri::command]
fn search(state: State<AppState>, query: String) -> Result<Vec<SearchHitDto>, String> {
    with_vault(&state, |v| {
        Ok(v.search(&query)
            .into_iter()
            .map(|h| SearchHitDto {
                path: h.path,
                is_dir: h.is_dir,
                size: h.size,
                mtime: h.mtime,
            })
            .collect())
    })
}

/// Cria um arquivo vazio (não sobrescreve um item existente).
#[tauri::command]
fn new_file(state: State<AppState>, path: String) -> Result<(), String> {
    with_vault(&state, |v| {
        if v.resolve(&path).is_some() {
            return Err("já existe um item com esse nome".into());
        }
        let mtime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        v.write_file(&path, &[], mtime).map_err(s)?;
        v.commit().map_err(s)
    })
}

/// Abre um seletor de arquivos e adiciona os escolhidos dentro de `dest_dir`.
#[tauri::command(async)]
fn add_files(
    app: tauri::AppHandle,
    state: State<AppState>,
    dest_dir: String,
) -> Result<usize, String> {
    let picked = app.dialog().file().blocking_pick_files();
    let files = match picked {
        Some(fs) if !fs.is_empty() => fs,
        _ => return Ok(0), // cancelado: no-op silencioso
    };
    let sources: Vec<String> = files.iter().map(|f| f.to_string()).collect();
    let mut guard = state.open.lock().unwrap();
    let ov = guard.as_mut().ok_or("nenhum container aberto")?;
    add_sources(&app, ov, &sources, &dest_dir)
}

/// Abre um seletor de PASTA e adiciona seu conteúdo (recursivo) em `dest_dir`.
#[tauri::command(async)]
fn add_folder(
    app: tauri::AppHandle,
    state: State<AppState>,
    dest_dir: String,
) -> Result<usize, String> {
    let chosen = app.dialog().file().blocking_pick_folder();
    let folder = match chosen {
        Some(p) => p.to_string(),
        None => return Ok(0),
    };
    let mut guard = state.open.lock().unwrap();
    let ov = guard.as_mut().ok_or("nenhum container aberto")?;
    add_sources(&app, ov, &[folder], &dest_dir)
}

/// Adiciona arquivos arrastados (drag-and-drop) dentro de `dest_dir`.
#[tauri::command(async)]
fn add_dropped(
    app: tauri::AppHandle,
    state: State<AppState>,
    paths: Vec<String>,
    dest_dir: String,
) -> Result<usize, String> {
    // Aceita arquivos E pastas — pastas são adicionadas recursivamente.
    if paths.is_empty() {
        return Ok(0);
    }
    let mut guard = state.open.lock().unwrap();
    let ov = guard.as_mut().ok_or("nenhum container aberto")?;
    add_sources(&app, ov, &paths, &dest_dir)
}

#[tauri::command(async)]
fn extract_file(
    app: tauri::AppHandle,
    state: State<AppState>,
    logical: String,
) -> Result<Option<String>, String> {
    let default_name = logical.rsplit('/').next().unwrap_or("arquivo").to_string();
    let chosen = app
        .dialog()
        .file()
        .set_file_name(&default_name)
        .blocking_save_file();
    let out = match chosen {
        Some(p) => p.to_string(),
        None => return Ok(None), // usuário cancelou
    };
    let mut guard = state.open.lock().unwrap();
    let ov = guard.as_mut().ok_or("nenhum container aberto")?;
    let mut f = std::fs::File::create(&out).map_err(s)?;
    ov.vault.extract(&logical, &mut f).map_err(s)?;
    Ok(Some(out))
}

/// Abre um arquivo do cofre com o app padrão do SO. Extrai para um arquivo
/// temporário (em `temp/fsmanager-open/`) e o entrega ao sistema.
/// Obs.: o sistema abre uma CÓPIA — editar lá não regrava no cofre.
#[tauri::command(async)]
fn open_file(
    app: tauri::AppHandle,
    state: State<AppState>,
    logical: String,
) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let name = logical.rsplit('/').next().unwrap_or("arquivo").to_string();
    let dir = std::env::temp_dir().join("fsmanager-open");
    std::fs::create_dir_all(&dir).map_err(s)?;
    let out = dir.join(&name);
    {
        let guard = state.open.lock().unwrap();
        let ov = guard.as_ref().ok_or("nenhum container aberto")?;
        let mut f = std::fs::File::create(&out).map_err(s)?;
        ov.vault.extract(&logical, &mut f).map_err(s)?;
    }
    app.opener()
        .open_path(out.to_string_lossy().to_string(), None::<&str>)
        .map_err(s)?;
    Ok(())
}

#[tauri::command]
fn remove_path(state: State<AppState>, logical: String, recursive: bool) -> Result<(), String> {
    with_vault(&state, |v| {
        if recursive {
            v.remove_dir(&logical).map_err(s)?;
        } else if !v.remove(&logical).map_err(s)? {
            return Err(format!("não encontrado: {logical}"));
        }
        v.commit().map_err(s)
    })
}

#[tauri::command]
fn rename_path(state: State<AppState>, from: String, to: String) -> Result<(), String> {
    with_vault(&state, |v| {
        v.rename(&from, &to).map_err(s)?;
        v.commit().map_err(s)
    })
}

/// Remove vários caminhos (arquivos ou pastas) numa única transação.
#[tauri::command]
fn remove_paths(state: State<AppState>, paths: Vec<String>) -> Result<(), String> {
    with_vault(&state, |v| {
        for p in &paths {
            match v.resolve(p) {
                Some(NodeKind::Dir) => {
                    v.remove_dir(p).map_err(s)?;
                }
                Some(NodeKind::File { .. }) => {
                    v.remove(p).map_err(s)?;
                }
                None => {}
            }
        }
        v.commit().map_err(s)
    })
}

/// Move vários caminhos para dentro de `dest_dir` (rename de cada um).
#[tauri::command]
fn move_paths(
    state: State<AppState>,
    paths: Vec<String>,
    dest_dir: String,
) -> Result<(), String> {
    with_vault(&state, |v| {
        for p in &paths {
            // Não mover uma pasta para dentro dela mesma / de um descendente.
            let prefix = format!("{p}/");
            if dest_dir == *p || dest_dir.starts_with(&prefix) {
                continue;
            }
            let name = p.rsplit('/').next().unwrap_or("item");
            let to = join_logical(&dest_dir, name);
            if to == *p {
                continue;
            }
            v.rename(p, &to).map_err(s)?;
        }
        v.commit().map_err(s)
    })
}

/// Extrai vários arquivos para uma pasta do disco (preservando os nomes).
#[tauri::command(async)]
fn extract_files(
    app: tauri::AppHandle,
    state: State<AppState>,
    paths: Vec<String>,
) -> Result<Option<String>, String> {
    let chosen = app.dialog().file().blocking_pick_folder();
    let dest = match chosen {
        Some(p) => p.to_string(),
        None => return Ok(None),
    };
    let guard = state.open.lock().unwrap();
    let ov = guard.as_ref().ok_or("nenhum container aberto")?;
    for p in &paths {
        let name = p.rsplit('/').next().unwrap_or("arquivo");
        let out = Path::new(&dest).join(name);
        let mut f = std::fs::File::create(&out).map_err(s)?;
        ov.vault.extract(p, &mut f).map_err(s)?;
    }
    Ok(Some(dest))
}

#[tauri::command]
fn snapshot_create(state: State<AppState>, name: String) -> Result<(), String> {
    with_vault(&state, |v| {
        v.snapshot_create(&name).map_err(s)?;
        v.commit().map_err(s)
    })
}

#[tauri::command]
fn snapshot_restore(state: State<AppState>, name: String) -> Result<(), String> {
    with_vault(&state, |v| {
        v.snapshot_restore(&name).map_err(s)?;
        v.commit().map_err(s)
    })
}

#[tauri::command]
fn snapshot_delete(state: State<AppState>, name: String) -> Result<(), String> {
    with_vault(&state, |v| {
        if !v.snapshot_delete(&name).map_err(s)? {
            return Err(format!("snapshot não encontrado: {name}"));
        }
        v.commit().map_err(s)
    })
}

/// Compacta o container: escreve em arquivo temporário, substitui e reabre.
#[tauri::command(async)]
fn gc_vault(state: State<AppState>) -> Result<(), String> {
    let mut guard = state.open.lock().unwrap();
    let ov = guard.take().ok_or("nenhum container aberto")?;
    let OpenVault { path, password, mut vault } = ov;

    let tmp = format!("{path}.compacting");
    if Path::new(&tmp).exists() {
        std::fs::remove_file(&tmp).map_err(s)?;
    }
    let result = vault.compact_to(&tmp);
    drop(vault); // fecha o handle do original antes de substituir

    if let Err(e) = result {
        // Restaura o estado anterior em caso de falha.
        let reopened = Vault::open(&path, password.as_deref()).map_err(s)?;
        *guard = Some(OpenVault { path, password, vault: reopened });
        return Err(s(e));
    }

    std::fs::rename(&tmp, &path).map_err(s)?;
    let vault = Vault::open(&path, password.as_deref()).map_err(s)?;
    *guard = Some(OpenVault { path, password, vault });
    Ok(())
}

/// Define ou limpa a cota de tamanho do cofre (bytes; `None` = sem limite).
#[tauri::command]
fn set_quota(state: State<AppState>, bytes: Option<u64>) -> Result<(), String> {
    with_vault(&state, |v| {
        v.set_quota(bytes);
        v.commit().map_err(s)
    })
}

/// Define, troca ou remove a senha do cofre (rekey: re-encripta tudo).
/// `new_password` vazio/None = remover senha.
#[tauri::command(async)]
fn change_password(
    state: State<AppState>,
    new_password: Option<String>,
) -> Result<(), String> {
    let mut guard = state.open.lock().unwrap();
    let ov = guard.take().ok_or("nenhum container aberto")?;
    let OpenVault { path, password, mut vault } = ov;
    let new_pw = empty_to_none(new_password);

    let tmp = format!("{path}.rekeying");
    if Path::new(&tmp).exists() {
        std::fs::remove_file(&tmp).map_err(s)?;
    }
    let result = vault.rekey_to(&tmp, new_pw.as_deref());
    drop(vault); // fecha o handle do original antes de substituir

    if let Err(e) = result {
        let reopened = Vault::open(&path, password.as_deref()).map_err(s)?;
        *guard = Some(OpenVault { path, password, vault: reopened });
        return Err(s(e));
    }
    std::fs::rename(&tmp, &path).map_err(s)?;
    let vault = Vault::open(&path, new_pw.as_deref()).map_err(s)?;
    *guard = Some(OpenVault {
        path,
        password: new_pw,
        vault,
    });
    Ok(())
}

#[derive(Serialize)]
struct VerifyDto {
    healthy: bool,
    blocks_ok: usize,
    blocks_bad: usize,
    missing_blocks: usize,
    errors: Vec<String>,
}

/// Verifica a integridade do cofre (hash de cada bloco).
#[tauri::command(async)]
fn verify_vault(state: State<AppState>) -> Result<VerifyDto, String> {
    with_vault(&state, |v| {
        let r = v.verify().map_err(s)?;
        Ok(VerifyDto {
            healthy: r.is_healthy(),
            blocks_ok: r.blocks_ok,
            blocks_bad: r.blocks_bad,
            missing_blocks: r.missing_blocks,
            errors: r.errors.into_iter().take(20).collect(),
        })
    })
}

#[derive(Serialize)]
struct RepairDto {
    files_damaged: usize,
    truncated: Vec<(String, u64)>,
    removed: Vec<String>,
}

/// Repara o cofre: trunca/remove arquivos com blocos corrompidos e commita.
#[tauri::command(async)]
fn repair_vault(state: State<AppState>) -> Result<RepairDto, String> {
    with_vault(&state, |v| {
        let r = v.repair().map_err(s)?;
        v.commit().map_err(s)?;
        Ok(RepairDto {
            files_damaged: r.files_damaged,
            truncated: r.truncated,
            removed: r.removed,
        })
    })
}

/// Localiza o binário `fsm-mount` (env `FSM_MOUNT_BIN`, ao lado do exe, ou alvos de dev).
fn resolve_mount_bin() -> Result<std::path::PathBuf, String> {
    let name = if cfg!(windows) {
        "fsm-mount.exe"
    } else {
        "fsm-mount"
    };
    if let Ok(p) = std::env::var("FSM_MOUNT_BIN") {
        let pb = std::path::PathBuf::from(p);
        if pb.exists() {
            return Ok(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let dir = exe.parent();
        // 1) ao lado do exe (caso de produção: empacotados juntos).
        if let Some(d) = dir {
            let sibling = d.join(name);
            if sibling.exists() {
                return Ok(sibling);
            }
        }
        // 2) dev: sobe pelos ancestrais procurando crates/fsm-mount/target/{debug,release}.
        let mut cur = dir;
        for _ in 0..8 {
            let Some(d) = cur else { break };
            for prof in ["debug", "release"] {
                let cand = d
                    .join("crates/fsm-mount/target")
                    .join(prof)
                    .join(name);
                if cand.exists() {
                    return Ok(cand);
                }
            }
            cur = d.parent();
        }
    }
    Err(format!(
        "binário {name} não encontrado — defina a variável de ambiente FSM_MOUNT_BIN"
    ))
}

/// Monta o vault aberto como drive: FECHA o vault na UI (libera o arquivo) e
/// inicia o `fsm-mount` como processo separado no ponto de montagem dado.
#[tauri::command]
fn mount_drive(state: State<AppState>, mountpoint: String) -> Result<String, String> {
    if state.mount.lock().unwrap().is_some() {
        return Err("já existe um drive montado".into());
    }
    let (vault_path, password) = {
        let guard = state.open.lock().unwrap();
        let ov = guard.as_ref().ok_or("nenhum container aberto")?;
        (ov.path.clone(), ov.password.clone())
    };
    let bin = resolve_mount_bin()?;

    // Fecha o vault na UI ANTES de montar (evita dois escritores no mesmo arquivo).
    *state.open.lock().unwrap() = None;

    let mut cmd = std::process::Command::new(&bin);
    cmd.arg(&vault_path).arg(&mountpoint);
    if let Some(pw) = &password {
        cmd.arg("--password").arg(pw);
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("falha ao iniciar {}: {e}", bin.display()))?;
    *state.mount.lock().unwrap() = Some(MountProc {
        child,
        mountpoint: mountpoint.clone(),
    });
    Ok(mountpoint)
}

/// Desmonta o drive: encerra o processo `fsm-mount`.
#[tauri::command]
fn unmount_drive(state: State<AppState>) -> Result<(), String> {
    if let Some(mut m) = state.mount.lock().unwrap().take() {
        let _ = m.child.kill();
        let _ = m.child.wait();
    }
    Ok(())
}

/// Ponto de montagem atual, se houver drive montado.
#[tauri::command]
fn mount_status(state: State<AppState>) -> Option<String> {
    state
        .mount
        .lock()
        .unwrap()
        .as_ref()
        .map(|m| m.mountpoint.clone())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            create_vault,
            open_vault,
            close_vault,
            get_info,
            list_dir,
            make_dir,
            new_file,
            search,
            add_files,
            add_folder,
            add_dropped,
            extract_file,
            extract_files,
            open_file,
            remove_path,
            remove_paths,
            move_paths,
            rename_path,
            snapshot_create,
            snapshot_restore,
            snapshot_delete,
            gc_vault,
            set_quota,
            change_password,
            verify_vault,
            repair_vault,
            mount_drive,
            unmount_drive,
            mount_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
