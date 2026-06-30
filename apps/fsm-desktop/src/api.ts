// Camada de acesso ao backend Tauri (fsm-core), tipada.
// Os comandos recebem args em camelCase (Tauri converte para snake_case no Rust).
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface Stats {
  files: number;
  unique_blocks: number;
  snapshots: number;
  encrypted: boolean;
  logical_bytes: number;
  unique_raw_bytes: number;
  physical_bytes: number;
  dedup_savings: number;
  compression_savings: number;
  total_savings: number;
  quota: number | null;
  used_bytes: number;
}

export interface Snapshot {
  name: string;
  created: number;
  files: number;
  size: number;
}

export interface VaultInfo {
  path: string;
  stats: Stats;
  snapshots: Snapshot[];
}

export interface DirEntry {
  name: string;
  is_dir: boolean;
  size: number;
  mtime: number;
}

export interface VerifyResult {
  healthy: boolean;
  blocks_ok: number;
  blocks_bad: number;
  missing_blocks: number;
  errors: string[];
}

export interface RepairResult {
  files_damaged: number;
  truncated: [string, number][];
  removed: string[];
}

export interface AddProgress {
  file: string;
  done: number;
  total: number;
}

export const api = {
  createVault: (password: string | null) => invoke<VaultInfo>("create_vault", { password }),
  openVault: (password: string | null) => invoke<VaultInfo>("open_vault", { password }),
  closeVault: () => invoke<void>("close_vault"),
  getInfo: () => invoke<VaultInfo>("get_info"),

  listDir: (path: string) => invoke<DirEntry[]>("list_dir", { path }),
  makeDir: (path: string) => invoke<void>("make_dir", { path }),
  newFile: (path: string) => invoke<void>("new_file", { path }),

  addFiles: (destDir: string) => invoke<number>("add_files", { destDir }),
  addFolder: (destDir: string) => invoke<number>("add_folder", { destDir }),
  addDropped: (paths: string[], destDir: string) => invoke<number>("add_dropped", { paths, destDir }),

  extractFile: (logical: string) => invoke<string | null>("extract_file", { logical }),
  extractFiles: (paths: string[]) => invoke<string | null>("extract_files", { paths }),

  removePath: (logical: string, recursive: boolean) => invoke<void>("remove_path", { logical, recursive }),
  removePaths: (paths: string[]) => invoke<void>("remove_paths", { paths }),
  movePaths: (paths: string[], destDir: string) => invoke<void>("move_paths", { paths, destDir }),
  renamePath: (from: string, to: string) => invoke<void>("rename_path", { from, to }),

  snapshotCreate: (name: string) => invoke<void>("snapshot_create", { name }),
  snapshotRestore: (name: string) => invoke<void>("snapshot_restore", { name }),
  snapshotDelete: (name: string) => invoke<void>("snapshot_delete", { name }),

  gcVault: () => invoke<void>("gc_vault"),
  setQuota: (bytes: number | null) => invoke<void>("set_quota", { bytes }),
  changePassword: (newPassword: string | null) => invoke<void>("change_password", { newPassword }),
  verifyVault: () => invoke<VerifyResult>("verify_vault"),
  repairVault: () => invoke<RepairResult>("repair_vault"),

  mountDrive: (mountpoint: string) => invoke<string>("mount_drive", { mountpoint }),
  unmountDrive: () => invoke<void>("unmount_drive"),
  mountStatus: () => invoke<string | null>("mount_status"),
};

export function onAddProgress(cb: (p: AddProgress) => void): Promise<UnlistenFn> {
  return listen<AddProgress>("add-progress", (e) => cb(e.payload));
}

// Eventos de drag-and-drop do SO (nomes variam entre versões do Tauri).
export type DragPayload = { paths?: string[] } | string[];
export function onOsDrag(handlers: {
  enter?: () => void;
  leave?: () => void;
  drop?: (paths: string[]) => void;
}): Promise<UnlistenFn[]> {
  const subs: Promise<UnlistenFn>[] = [];
  const add = (events: string[], fn: (payload: DragPayload) => void) => {
    for (const ev of events) subs.push(listen<DragPayload>(ev, (e) => fn(e.payload)));
  };
  if (handlers.enter) add(["tauri://drag-enter", "tauri://file-drop-hover"], handlers.enter);
  if (handlers.leave) add(["tauri://drag-leave", "tauri://file-drop-cancelled"], handlers.leave);
  if (handlers.drop) {
    add(["tauri://drag-drop", "tauri://file-drop"], (p) => {
      const paths = Array.isArray(p) ? p : p?.paths ?? [];
      if (paths.length) handlers.drop!(paths);
    });
  }
  return Promise.all(subs);
}

// Formatação compartilhada.
export function fmtBytes(n: number | null | undefined): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  let x = n;
  do {
    x /= 1024;
    i++;
  } while (x >= 1024 && i < u.length - 1);
  return `${x.toFixed(1)} ${u[i]}`;
}
export function fmtPct(x: number): string {
  return `${(x * 100).toFixed(1)}%`;
}
export function fmtDate(secs: number): string {
  if (!secs) return "—";
  return new Date(secs * 1000).toLocaleString("pt-BR");
}
export function joinPath(dir: string, name: string): string {
  return dir === "/" ? `/${name}` : `${dir}/${name}`;
}
export function errMsg(e: unknown): string {
  return typeof e === "string" ? e : (e as { message?: string })?.message || String(e);
}
