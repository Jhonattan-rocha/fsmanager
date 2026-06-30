import { useEffect, useRef, useState, type DragEvent, type MouseEvent } from "react";
import { fmtBytes, fmtDate, joinPath, type DirEntry } from "../api";
import { dragState } from "../dragState";
import type { NewKind, SortKey } from "./Workspace";
import styles from "./FileTable.module.css";

type SelectMods = { shiftKey: boolean; ctrlKey: boolean; metaKey: boolean };

interface Props {
  entries: DirEntry[];
  selected: Set<string>;
  currentPath: string;
  sort: { key: SortKey; dir: "asc" | "desc" };
  onSort: (key: SortKey) => void;
  pendingNew: NewKind | null;
  renaming: string | null;
  onSelect: (name: string, mods: SelectMods) => void;
  onOpen: (name: string) => void;
  onOpenFile: (name: string) => void;
  onExtract: (name: string) => void;
  onStartRename: (name: string) => void;
  onRemove: (name: string, isDir: boolean) => void;
  onMoveTo: (paths: string[], destDir: string) => void;
  onCommitNew: (kind: NewKind, name: string) => void;
  onCancelNew: () => void;
  onCommitRename: (oldName: string, newName: string) => void;
  onCancelRename: () => void;
  onRowMenu: (x: number, y: number, name: string, isDir: boolean) => void;
  onBackgroundMenu: (x: number, y: number) => void;
}

function InlineInput({
  initial,
  placeholder,
  onCommit,
  onCancel,
}: {
  initial: string;
  placeholder: string;
  onCommit: (v: string) => void;
  onCancel: () => void;
}) {
  const ref = useRef<HTMLInputElement>(null);
  const done = useRef(false);
  useEffect(() => {
    ref.current?.focus();
    ref.current?.select();
  }, []);
  const finish = (save: boolean) => {
    if (done.current) return;
    done.current = true;
    if (save) onCommit(ref.current?.value ?? "");
    else onCancel();
  };
  return (
    <input
      ref={ref}
      className={styles.inlineEdit}
      defaultValue={initial}
      placeholder={placeholder}
      onClick={(e) => e.stopPropagation()}
      onKeyDown={(e) => {
        if (e.key === "Enter") finish(true);
        else if (e.key === "Escape") finish(false);
      }}
      onBlur={() => finish(true)}
    />
  );
}

export default function FileTable(p: Props) {
  const [dropTarget, setDropTarget] = useState<string | null>(null);
  const arrow = (key: SortKey) => (p.sort.key === key ? (p.sort.dir === "asc" ? " ▲" : " ▼") : "");

  const onDragStart = (name: string) => {
    const names = p.selected.has(name) ? [...p.selected] : [name];
    if (!p.selected.has(name)) p.onSelect(name, { shiftKey: false, ctrlKey: false, metaKey: false });
    dragState.items = names.map((n) => joinPath(p.currentPath, n));
  };
  const onRowDragOver = (e: DragEvent, name: string) => {
    if (!dragState.items.length || p.selected.has(name)) return;
    e.preventDefault();
    if (dropTarget !== name) setDropTarget(name);
  };
  const onRowDrop = (e: DragEvent, name: string) => {
    setDropTarget(null);
    if (!dragState.items.length || p.selected.has(name)) return;
    e.preventDefault();
    const items = dragState.items;
    dragState.items = [];
    p.onMoveTo(items, joinPath(p.currentPath, name));
  };

  const onContextMenu = (e: MouseEvent) => {
    e.preventDefault();
    const tr = (e.target as HTMLElement).closest("tr[data-name]") as HTMLElement | null;
    if (tr) p.onRowMenu(e.clientX, e.clientY, tr.dataset.name!, tr.dataset.dir === "1");
    else p.onBackgroundMenu(e.clientX, e.clientY);
  };

  return (
    <div
      className={styles.tableWrap}
      onContextMenu={onContextMenu}
      onDragEnd={() => {
        dragState.items = [];
        setDropTarget(null);
      }}
    >
      <table>
        <thead>
          <tr>
            <th className={styles.sortable} onClick={() => p.onSort("name")}>
              Nome{arrow("name")}
            </th>
            <th className={`${styles.num} ${styles.sortable}`} onClick={() => p.onSort("size")}>
              Tamanho{arrow("size")}
            </th>
            <th className={`${styles.num} ${styles.sortable}`} onClick={() => p.onSort("mtime")}>
              Modificado{arrow("mtime")}
            </th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {p.pendingNew && (
            <tr className={styles.editingRow}>
              <td className={`${styles.name} ${p.pendingNew === "dir" ? styles.isDir : ""}`}>
                {p.pendingNew === "dir" ? "📁" : "📄"}{" "}
                <InlineInput
                  initial=""
                  placeholder={p.pendingNew === "dir" ? "nome da pasta" : "nome do arquivo"}
                  onCommit={(v) => p.onCommitNew(p.pendingNew!, v)}
                  onCancel={p.onCancelNew}
                />
              </td>
              <td className={styles.num}>—</td>
              <td className={styles.num}>—</td>
              <td></td>
            </tr>
          )}
          {p.entries.length === 0 && !p.pendingNew && (
            <tr>
              <td colSpan={4} className={styles.empty}>
                pasta vazia — arraste arquivos aqui ou use ➕ Adicionar
              </td>
            </tr>
          )}
          {p.entries.map((e) => {
            const isSel = p.selected.has(e.name);
            const isRen = p.renaming === e.name;
            return (
              <tr
                key={e.name}
                draggable
                data-name={e.name}
                data-dir={e.is_dir ? 1 : 0}
                className={`${isSel ? styles.selected : ""} ${dropTarget === e.name ? styles.dropTarget : ""}`}
                onClick={(ev) => {
                  if (!isRen) p.onSelect(e.name, ev);
                }}
                onDoubleClick={() => {
                  if (!isRen) (e.is_dir ? p.onOpen(e.name) : p.onOpenFile(e.name));
                }}
                onDragStart={() => onDragStart(e.name)}
                onDragOver={e.is_dir ? (ev) => onRowDragOver(ev, e.name) : undefined}
                onDrop={e.is_dir ? (ev) => onRowDrop(ev, e.name) : undefined}
              >
                <td className={`${styles.name} ${e.is_dir ? styles.isDir : ""}`}>
                  {e.is_dir ? "📁" : "📄"}{" "}
                  {isRen ? (
                    <InlineInput
                      initial={e.name}
                      placeholder=""
                      onCommit={(v) => p.onCommitRename(e.name, v)}
                      onCancel={p.onCancelRename}
                    />
                  ) : (
                    e.name
                  )}
                </td>
                <td className={styles.num}>{e.is_dir && e.size === 0 ? "—" : fmtBytes(e.size)}</td>
                <td className={`${styles.num} ${styles.dim}`}>{fmtDate(e.mtime)}</td>
                <td className={styles.rowActions}>
                  {!e.is_dir && (
                    <button
                      className="small"
                      title="Abrir"
                      onClick={(ev) => {
                        ev.stopPropagation();
                        p.onOpenFile(e.name);
                      }}
                    >
                      📖
                    </button>
                  )}
                  {!e.is_dir && (
                    <button
                      className="small"
                      title="Extrair"
                      onClick={(ev) => {
                        ev.stopPropagation();
                        p.onExtract(e.name);
                      }}
                    >
                      ⬇️
                    </button>
                  )}
                  <button
                    className="small"
                    onClick={(ev) => {
                      ev.stopPropagation();
                      p.onStartRename(e.name);
                    }}
                  >
                    ✏️
                  </button>
                  <button
                    className="small danger"
                    onClick={(ev) => {
                      ev.stopPropagation();
                      p.onRemove(e.name, e.is_dir);
                    }}
                  >
                    🗑️
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
