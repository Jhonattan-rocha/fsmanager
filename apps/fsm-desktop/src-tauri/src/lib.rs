//! Backend Tauri do fsmanager: expõe o `fsm-core` para a UI.
//!
//! Mantém UM vault aberto em estado compartilhado (`Mutex<Option<OpenVault>>`)
//! para reusar a chave derivada (Argon2) entre operações — abrir um cofre
//! cifrado a cada clique seria inviável.

use std::path::Path;
use std::sync::Mutex;

use fsm_core::{Vault, DEFAULT_AVG_CHUNK};
use serde::Serialize;
use tauri::State;
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
}

// ----------------------- DTOs para a UI -----------------------

#[derive(Serialize)]
struct FileDto {
    path: String,
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
}

/// Tudo o que a UI precisa para renderizar o estado atual do vault.
#[derive(Serialize)]
struct VaultInfo {
    path: String,
    stats: StatsDto,
    files: Vec<FileDto>,
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
    }
}

fn build_info(path: &str, v: &Vault) -> VaultInfo {
    let files = v
        .catalog()
        .files
        .iter()
        .map(|(p, e)| FileDto {
            path: p.clone(),
            size: e.size,
            mtime: e.mtime,
        })
        .collect();
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
        files,
        snapshots,
    }
}

/// Aplica `f` ao vault aberto e devolve o estado atualizado.
fn mutate(state: &State<AppState>, f: impl FnOnce(&mut Vault) -> Result<(), String>) -> Result<VaultInfo, String> {
    let mut guard = state.open.lock().unwrap();
    let ov = guard.as_mut().ok_or("nenhum container aberto")?;
    f(&mut ov.vault)?;
    Ok(build_info(&ov.path, &ov.vault))
}

fn empty_to_none(p: Option<String>) -> Option<String> {
    p.filter(|x| !x.is_empty())
}

// ----------------------- comandos -----------------------

#[tauri::command]
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

#[tauri::command]
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
    mutate(&state, |_| Ok(()))
}

#[tauri::command]
fn add_files(app: tauri::AppHandle, state: State<AppState>) -> Result<VaultInfo, String> {
    let picked = app.dialog().file().blocking_pick_files();
    let files = match picked {
        Some(fs) if !fs.is_empty() => fs,
        _ => return Err("nenhum arquivo selecionado".into()),
    };
    mutate(&state, |v| {
        for fp in &files {
            let src = fp.to_string();
            let dest = Path::new(&src)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "arquivo".into());
            v.add_file(&src, &dest).map_err(s)?;
        }
        v.commit().map_err(s)
    })
}

#[tauri::command]
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

#[tauri::command]
fn remove_path(
    state: State<AppState>,
    logical: String,
    recursive: bool,
) -> Result<VaultInfo, String> {
    mutate(&state, |v| {
        if recursive {
            v.remove_dir(&logical).map_err(s)?;
        } else if !v.remove(&logical).map_err(s)? {
            return Err(format!("não encontrado: {logical}"));
        }
        v.commit().map_err(s)
    })
}

#[tauri::command]
fn rename_path(state: State<AppState>, from: String, to: String) -> Result<VaultInfo, String> {
    mutate(&state, |v| {
        v.rename(&from, &to).map_err(s)?;
        v.commit().map_err(s)
    })
}

#[tauri::command]
fn snapshot_create(state: State<AppState>, name: String) -> Result<VaultInfo, String> {
    mutate(&state, |v| {
        v.snapshot_create(&name).map_err(s)?;
        v.commit().map_err(s)
    })
}

#[tauri::command]
fn snapshot_restore(state: State<AppState>, name: String) -> Result<VaultInfo, String> {
    mutate(&state, |v| {
        v.snapshot_restore(&name).map_err(s)?;
        v.commit().map_err(s)
    })
}

#[tauri::command]
fn snapshot_delete(state: State<AppState>, name: String) -> Result<VaultInfo, String> {
    mutate(&state, |v| {
        if !v.snapshot_delete(&name).map_err(s)? {
            return Err(format!("snapshot não encontrado: {name}"));
        }
        v.commit().map_err(s)
    })
}

/// Compacta o container: escreve em arquivo temporário, substitui e reabre.
#[tauri::command]
fn gc_vault(state: State<AppState>) -> Result<VaultInfo, String> {
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
    let info = build_info(&path, &vault);
    *guard = Some(OpenVault { path, password, vault });
    Ok(info)
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
            add_files,
            extract_file,
            remove_path,
            rename_path,
            snapshot_create,
            snapshot_restore,
            snapshot_delete,
            gc_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
