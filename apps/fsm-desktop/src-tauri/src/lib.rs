//! Backend Tauri do fsmanager: expõe o `fsm-core` para a UI.
//!
//! Mantém UM vault aberto em estado compartilhado (`Mutex<Option<OpenVault>>`)
//! para reusar a chave derivada (Argon2) entre operações — abrir um cofre
//! cifrado a cada clique seria inviável.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use fsm_core::{NodeKind, Vault, DEFAULT_AVG_CHUNK};
use serde::Serialize;
use zeroize::Zeroizing;
use tauri::{Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

/// Vault aberto + contexto necessário para reabrir após `gc`.
/// A senha fica em `Zeroizing<String>`: é zerada da memória quando descartada
/// (fechar o cofre, trocar de vault, gc/rekey) — inclusive nos clones.
struct OpenVault {
    path: String,
    password: Option<Zeroizing<String>>,
    vault: Vault,
}

/// Arquivo aberto pelo SO (open_file) sendo observado para reimportar ao salvar.
struct WatchEntry {
    logical: String,
    mtime: Option<SystemTime>,
    size: u64,
}

#[derive(Default)]
struct AppState {
    open: Mutex<Option<OpenVault>>,
    mount: Mutex<Option<MountProc>>,
    /// Trava contra montagens concorrentes (entre checar e efetivar o mount).
    mounting: AtomicBool,
    /// caminho-temp -> info do arquivo aberto, para o "abrir-e-regravar".
    watches: Mutex<HashMap<PathBuf, WatchEntry>>,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

/// Decodifica percent-encoding (%20 etc.) — para caminhos vindos como URI.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(h) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(h);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Normaliza um caminho vindo do drag-drop do SO. Alguns ambientes entregam
/// URIs `file://` em vez de caminhos nativos — nesse caso o `is_dir()` falha
/// e nada é copiado. Aqui convertemos de volta para um caminho do disco.
fn normalize_drop_path(p: &str) -> String {
    let p = p.trim();
    if let Some(rest) = p.strip_prefix("file://") {
        // Windows: file:///C:/x -> C:/x (tira a barra extra); Unix: file:///x -> /x
        let rest = if cfg!(windows) {
            rest.strip_prefix('/').unwrap_or(rest)
        } else {
            rest
        };
        return percent_decode(rest);
    }
    p.to_string()
}

/// Registra os caminhos recebidos de um drop (diagnóstico) em
/// `temp/fsmanager-drop.log`.
fn log_drop(paths: &[String]) {
    use std::io::Write;
    let logf = std::env::temp_dir().join("fsmanager-drop.log");
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(logf) {
        for p in paths {
            let pt = Path::new(p);
            let _ = writeln!(
                file,
                "drop path={p:?} is_file={} is_dir={}",
                pt.is_file(),
                pt.is_dir()
            );
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
    state.watches.lock().unwrap().clear();
    *state.open.lock().unwrap() = Some(OpenVault {
        path,
        password: pw.map(Zeroizing::new),
        vault,
    });
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
    state.watches.lock().unwrap().clear();
    *state.open.lock().unwrap() = Some(OpenVault {
        path,
        password: pw.map(Zeroizing::new),
        vault,
    });
    Ok(info)
}

#[tauri::command]
fn close_vault(state: State<AppState>) -> Result<(), String> {
    state.watches.lock().unwrap().clear();
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
        v.write_file(&path, &[], now_secs()).map_err(s)?;
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
    // Normaliza (trata URIs file://) e registra para diagnóstico.
    let paths: Vec<String> = paths.iter().map(|p| normalize_drop_path(p)).collect();
    log_drop(&paths);
    let unreadable: Vec<String> = paths
        .iter()
        .filter(|p| {
            let pt = Path::new(p.as_str());
            !pt.is_file() && !pt.is_dir()
        })
        .cloned()
        .collect();

    let mut guard = state.open.lock().unwrap();
    let ov = guard.as_mut().ok_or("nenhum container aberto")?;
    let n = add_sources(&app, ov, &paths, &dest_dir)?;

    // Se nada entrou e havia caminhos ilegíveis, reporta (não fica silencioso).
    if n == 0 && !unreadable.is_empty() {
        return Err(format!(
            "não consegui ler o(s) caminho(s) solto(s): {}",
            unreadable.join(" | ")
        ));
    }
    Ok(n)
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
    let dir = std::env::temp_dir().join("fsmanager-open");
    // Recria a subárvore lógica no temp: evita colisão entre nomes iguais de
    // pastas diferentes e preserva o nome real do arquivo para o app do SO.
    let rel = logical.trim_start_matches('/');
    let out = dir.join(rel);
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(s)?;
    }
    {
        let guard = state.open.lock().unwrap();
        let ov = guard.as_ref().ok_or("nenhum container aberto")?;
        let mut f = std::fs::File::create(&out).map_err(s)?;
        ov.vault.extract(&logical, &mut f).map_err(s)?;
    }
    // Registra para "abrir-e-regravar": a thread observadora reimporta ao salvar.
    let key = std::fs::canonicalize(&out).unwrap_or_else(|_| out.clone());
    if let Ok(meta) = std::fs::metadata(&out) {
        state.watches.lock().unwrap().insert(
            key,
            WatchEntry {
                logical: logical.clone(),
                mtime: meta.modified().ok(),
                size: meta.len(),
            },
        );
    }
    app.opener()
        .open_path(out.to_string_lossy().to_string(), None::<&str>)
        .map_err(s)?;
    Ok(())
}

/// Quantos arquivos abertos estão sendo observados (abrir-e-regravar).
#[tauri::command]
fn watch_count(state: State<AppState>) -> usize {
    state.watches.lock().unwrap().len()
}

/// Para de observar todos os arquivos abertos (não reimporta mais ao salvar).
#[tauri::command]
fn stop_watching(state: State<AppState>) {
    state.watches.lock().unwrap().clear();
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
        let reopened = Vault::open(&path, password.as_ref().map(|z| z.as_str())).map_err(s)?;
        *guard = Some(OpenVault { path, password, vault: reopened });
        return Err(s(e));
    }

    std::fs::rename(&tmp, &path).map_err(s)?;
    let vault = Vault::open(&path, password.as_ref().map(|z| z.as_str())).map_err(s)?;
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
        let reopened = Vault::open(&path, password.as_ref().map(|z| z.as_str())).map_err(s)?;
        *guard = Some(OpenVault { path, password, vault: reopened });
        return Err(s(e));
    }
    std::fs::rename(&tmp, &path).map_err(s)?;
    let vault = Vault::open(&path, new_pw.as_deref()).map_err(s)?;
    *guard = Some(OpenVault {
        path,
        password: new_pw.map(Zeroizing::new),
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
        // 1) ao lado do exe ou em resources/ (caso de produção: empacotados juntos).
        if let Some(d) = dir {
            let sibling = d.join(name);
            if sibling.exists() {
                return Ok(sibling);
            }
            let in_resources = d.join("resources").join(name);
            if in_resources.exists() {
                return Ok(in_resources);
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

/// Valida e normaliza o ponto de montagem ANTES de fechar o vault.
#[cfg(windows)]
fn validate_mountpoint(mp: &str) -> Result<String, String> {
    let t = mp.trim().trim_end_matches(['\\', '/']);
    let letter = t
        .chars()
        .next()
        .ok_or("informe uma letra de drive (ex.: X:)")?;
    let ok_shape =
        letter.is_ascii_alphabetic() && (t.len() == 1 || (t.len() == 2 && t.ends_with(':')));
    if !ok_shape {
        return Err(format!("ponto de montagem inválido: '{mp}' — use uma letra como X:"));
    }
    let letter = letter.to_ascii_uppercase();
    if Path::new(&format!("{letter}:\\")).exists() {
        return Err(format!("a letra {letter}: já está em uso — escolha outra"));
    }
    Ok(format!("{letter}:"))
}

/// Valida o ponto de montagem no Unix: precisa ser um diretório existente.
#[cfg(unix)]
fn validate_mountpoint(mp: &str) -> Result<String, String> {
    if !Path::new(mp).is_dir() {
        return Err(format!(
            "o diretório de montagem '{mp}' não existe — crie-o antes de montar"
        ));
    }
    Ok(mp.to_string())
}

/// Confirmação rápida de que o mount subiu (fast-path; sucesso definitivo é
/// "o processo não saiu com erro").
#[cfg(windows)]
fn mount_ready(mp: &str) -> bool {
    mp.chars()
        .next()
        .map(|l| Path::new(&format!("{}:\\", l.to_ascii_uppercase())).exists())
        .unwrap_or(false)
}
#[cfg(unix)]
fn mount_ready(mp: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|s| s.lines().any(|l| l.split(' ').nth(1) == Some(mp)))
        .unwrap_or(false)
}

fn read_child_stderr(child: &mut std::process::Child) -> String {
    use std::io::Read;
    let mut buf = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut buf);
    }
    buf.trim().to_string()
}

/// Reabre o vault (usado para restaurar o estado se a montagem falhar).
fn reopen_vault(state: &AppState, path: &str, password: &Option<Zeroizing<String>>) {
    if let Ok(v) = Vault::open(path, password.as_ref().map(|z| z.as_str())) {
        *state.open.lock().unwrap() = Some(OpenVault {
            path: path.to_string(),
            password: password.clone(),
            vault: v,
        });
    }
}

/// Garante que a flag `mounting` volte a `false` em qualquer caminho de saída.
struct MountingGuard<'a>(&'a AtomicBool);
impl Drop for MountingGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Monta o vault aberto como drive, de forma BLINDADA: valida o ponto antes de
/// fechar o vault, confirma que o processo subiu (senão reabre o vault e reporta
/// o motivo), e trava contra montagens concorrentes.
#[tauri::command(async)]
fn mount_drive(state: State<AppState>, mountpoint: String) -> Result<String, String> {
    // Trava: só uma montagem por vez (reset garantido pelo guard).
    if state
        .mounting
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("já há uma montagem em andamento".into());
    }
    let _mg = MountingGuard(&state.mounting);

    if state.mount.lock().unwrap().is_some() {
        return Err("já existe um drive montado".into());
    }
    // Valida/normaliza o ponto ANTES de fechar o vault (não deixa o usuário no limbo).
    let mountpoint = validate_mountpoint(&mountpoint)?;
    let (vault_path, password) = {
        let guard = state.open.lock().unwrap();
        let ov = guard.as_ref().ok_or("nenhum container aberto")?;
        (ov.path.clone(), ov.password.clone())
    };
    let bin = resolve_mount_bin()?;

    // Fecha o vault ANTES de montar (evita dois escritores no mesmo arquivo).
    state.watches.lock().unwrap().clear();
    *state.open.lock().unwrap() = None;

    let mut cmd = std::process::Command::new(&bin);
    cmd.arg(&vault_path).arg(&mountpoint);
    // A senha NUNCA vai pelo argv (seria visível na lista de processos): vai pela
    // 1ª linha do stdin. `--password-stdin` faz o fsm-mount lê-la de lá.
    if password.is_some() {
        cmd.arg("--password-stdin");
    }
    // stdin em pipe (senha + desmonte gracioso); stderr em pipe (motivo de falha).
    cmd.stdin(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            reopen_vault(&state, &vault_path, &password);
            return Err(format!("falha ao iniciar {}: {e}", bin.display()));
        }
    };
    // Entrega a senha pela 1ª linha do stdin (mantém o pipe aberto p/ o desmonte).
    if let Some(pw) = &password {
        if let Some(stdin) = child.stdin.as_mut() {
            use std::io::Write;
            let _ = stdin.write_all(pw.as_bytes());
            let _ = stdin.write_all(b"\n");
            let _ = stdin.flush();
        }
    }

    // Confirma que subiu. A falha confiável é o processo SAIR (mount/dispatcher
    // deu erro); nunca matamos um mount vivo por timeout.
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        std::thread::sleep(Duration::from_millis(120));
        if let Ok(Some(_)) = child.try_wait() {
            let why = read_child_stderr(&mut child);
            let _ = child.wait();
            reopen_vault(&state, &vault_path, &password);
            let msg = if why.is_empty() {
                "o processo de montagem encerrou inesperadamente (o WinFsp está instalado?)"
                    .to_string()
            } else {
                why
            };
            return Err(format!("falha ao montar em {mountpoint}: {msg}"));
        }
        if mount_ready(&mountpoint) || Instant::now() >= deadline {
            break; // confirmado, ou vivo após o timeout => assume montado
        }
    }

    // Sucesso: drena o stderr (evita bloqueio por pipe cheio) e guarda o processo.
    if let Some(mut err) = child.stderr.take() {
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut err, &mut std::io::sink());
        });
    }
    *state.mount.lock().unwrap() = Some(MountProc {
        child,
        mountpoint: mountpoint.clone(),
    });
    Ok(mountpoint)
}

/// Desmonta o drive de forma GRACIOSA: fecha o stdin do `fsm-mount` (ele
/// desmonta o WinFsp e libera a letra), espera sair, e só mata como fallback.
#[tauri::command(async)]
fn unmount_drive(state: State<AppState>) -> Result<(), String> {
    // Tira do estado primeiro (não segura o Mutex durante a espera).
    let m = state.mount.lock().unwrap().take();
    if let Some(mut m) = m {
        // Fecha o stdin → fsm-mount recebe EOF e desmonta limpo.
        drop(m.child.stdin.take());
        // Espera o desmonte limpo (até 5s); se travar, mata como último recurso.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match m.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => {
                    let _ = m.child.kill();
                    break;
                }
            }
        }
        let _ = m.child.wait();
    }
    Ok(())
}

/// Verifica se o pré-requisito de montagem está presente: WinFsp no Windows,
/// FUSE (fusermount) no Linux. A UI avisa o usuário antes de tentar montar.
#[cfg(windows)]
fn mount_prereq_present() -> bool {
    // 1) Chave de registro do WinFsp.
    if let Ok(o) = std::process::Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\WOW6432Node\WinFsp"])
        .output()
    {
        if o.status.success() {
            return true;
        }
    }
    // 2) Diretório de instalação padrão.
    Path::new(r"C:\Program Files (x86)\WinFsp\bin").exists()
        || Path::new(r"C:\Program Files\WinFsp\bin").exists()
}
#[cfg(unix)]
fn mount_prereq_present() -> bool {
    ["/bin/fusermount3", "/usr/bin/fusermount3", "/bin/fusermount", "/usr/bin/fusermount"]
        .iter()
        .any(|p| Path::new(p).exists())
}

/// `true` se dá para montar como drive nesta máquina (WinFsp/FUSE presente).
#[tauri::command]
fn mount_prereq_ok() -> bool {
    mount_prereq_present()
}

/// Abre uma URL no navegador padrão (ex.: página de download do WinFsp).
#[tauri::command(async)]
fn open_url(app: tauri::AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener().open_url(url, None::<&str>).map_err(s)
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

/// Thread observadora do "abrir-e-regravar": a cada 1s checa os arquivos
/// temporários abertos via `open_file` e, se mudaram (o usuário salvou no app
/// do SO), reimporta o conteúdo de volta para o cofre e avisa a UI.
fn spawn_watcher(app: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(1000));
        let state = app.state::<AppState>();
        let mut changed: Vec<(String, Vec<u8>)> = Vec::new();
        {
            let mut watches = state.watches.lock().unwrap();
            for (path, w) in watches.iter_mut() {
                let Ok(meta) = std::fs::metadata(path) else {
                    continue;
                };
                let size = meta.len();
                let mtime = meta.modified().ok();
                if size != w.size || mtime != w.mtime {
                    w.size = size;
                    w.mtime = mtime;
                    if let Ok(bytes) = std::fs::read(path) {
                        changed.push((w.logical.clone(), bytes));
                    }
                }
            }
        }
        if changed.is_empty() {
            continue;
        }
        let mut guard = state.open.lock().unwrap();
        let Some(ov) = guard.as_mut() else {
            continue; // cofre fechado: ignora
        };
        let mut saved: Vec<String> = Vec::new();
        for (logical, bytes) in changed {
            if ov.vault.write_file(&logical, &bytes, now_secs()).is_ok() {
                saved.push(logical);
            }
        }
        if !saved.is_empty() {
            let _ = ov.vault.commit();
        }
        drop(guard);
        for logical in saved {
            let _ = app.emit("vault-changed", &logical);
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            spawn_watcher(app.handle().clone());
            Ok(())
        })
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
            watch_count,
            stop_watching,
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
            mount_prereq_ok,
            open_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_pairs_recurses_folder() {
        let base = std::env::temp_dir().join("fsm-cp-test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("Teste/sub")).unwrap();
        std::fs::write(base.join("Teste/a.txt"), b"a").unwrap();
        std::fs::write(base.join("Teste/sub/b.txt"), b"b").unwrap();

        let mut out = Vec::new();
        collect_pairs(&base.join("Teste"), "/", &mut out);
        let logicals: Vec<&str> = out.iter().map(|(_, l)| l.as_str()).collect();
        assert!(logicals.contains(&"/Teste/a.txt"), "faltou a.txt: {logicals:?}");
        assert!(logicals.contains(&"/Teste/sub/b.txt"), "faltou sub/b.txt: {logicals:?}");
        assert_eq!(out.len(), 2);

        // Drop dentro de uma subpasta do cofre.
        let mut out2 = Vec::new();
        collect_pairs(&base.join("Teste"), "/docs", &mut out2);
        assert!(out2.iter().any(|(_, l)| l == "/docs/Teste/a.txt"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn normalize_drop_path_handles_uri() {
        // Caminho nativo passa intacto.
        assert_eq!(normalize_drop_path("C:\\Users\\x\\Teste"), "C:\\Users\\x\\Teste");
        // URI com percent-encoding vira caminho de disco.
        #[cfg(windows)]
        assert_eq!(
            normalize_drop_path("file:///C:/Users/x/Nova%20Pasta"),
            "C:/Users/x/Nova Pasta"
        );
        #[cfg(unix)]
        assert_eq!(normalize_drop_path("file:///home/x/a%20b"), "/home/x/a b");
    }
}
