import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  errMsg,
  fmtBytes,
  joinPath,
  onAddProgress,
  onOsDrag,
  type DirEntry,
  type SearchHit,
  type VaultInfo,
} from "../api";
import { useToast } from "../contexts/ToastContext";
import { useContextMenu } from "../contexts/ContextMenuContext";
import Toolbar from "./Toolbar";
import StatsBar from "./StatsBar";
import BatchBar from "./BatchBar";
import FileTable from "./FileTable";
import SearchView from "./SearchView";
import SnapshotPanel from "./SnapshotPanel";
import ManageModal from "./ManageModal";
import Progress from "./Progress";
import styles from "./Workspace.module.css";

export type NewKind = "dir" | "file";
export type SortKey = "name" | "size" | "mtime";

interface Props {
  initialInfo: VaultInfo;
  onClosed: () => void;
  onMounted: (mp: string) => void;
}

export default function Workspace({ initialInfo, onClosed, onMounted }: Props) {
  const [info, setInfo] = useState<VaultInfo>(initialInfo);
  const [path, setPath] = useState("/");
  const [entries, setEntries] = useState<DirEntry[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [clipboard, setClipboard] = useState<string[]>([]);
  const [manageOpen, setManageOpen] = useState(false);
  const [progress, setProgress] = useState<{ label: string; pct: number } | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [pendingNew, setPendingNew] = useState<NewKind | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({ key: "name", dir: "asc" });
  const [scope, setScope] = useState<"folder" | "vault">("folder");
  const [results, setResults] = useState<SearchHit[]>([]);

  const toast = useToast();
  const openMenu = useContextMenu();
  const pathRef = useRef("/");
  const lastClicked = useRef<string | null>(null);

  // Pastas sempre primeiro; dentro do grupo, ordena pela coluna ativa.
  const sorted = useMemo(() => {
    const arr = [...entries];
    arr.sort((a, b) => {
      if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
      let r = 0;
      if (sort.key === "name") r = a.name.localeCompare(b.name);
      else if (sort.key === "size") r = a.size - b.size;
      else r = a.mtime - b.mtime;
      if (r === 0) r = a.name.localeCompare(b.name);
      return sort.dir === "asc" ? r : -r;
    });
    return arr;
  }, [entries, sort]);

  // Filtro por nome (substring, case-insensitive) na pasta atual.
  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return q ? sorted.filter((e) => e.name.toLowerCase().includes(q)) : sorted;
  }, [sorted, filter]);

  const onSort = (key: SortKey) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }));

  // Busca recursiva no cofre (escopo "vault"), com debounce de 200ms.
  useEffect(() => {
    if (scope !== "vault") return;
    const q = filter.trim();
    if (!q) {
      setResults([]);
      return;
    }
    let alive = true;
    const t = window.setTimeout(() => {
      api
        .search(q)
        .then((r) => alive && setResults(r))
        .catch(() => {});
    }, 200);
    return () => {
      alive = false;
      window.clearTimeout(t);
    };
  }, [filter, scope]);
  const runSearch = () => {
    const q = filter.trim();
    if (scope === "vault" && q) api.search(q).then(setResults).catch(() => {});
  };

  const refresh = useCallback(async (p?: string) => {
    const target = p ?? pathRef.current;
    const e = await api.listDir(target);
    setEntries(e);
    setInfo(await api.getInfo());
    setSelected((prev) => new Set([...prev].filter((n) => e.some((x) => x.name === n))));
  }, []);

  const guarded = useCallback(
    async (fn: () => Promise<void>) => {
      try {
        await fn();
      } catch (e) {
        const m = errMsg(e);
        if (m.includes("cancel")) return;
        toast(m, { error: true });
      }
    },
    [toast]
  );

  const setPathSynced = (p: string) => {
    pathRef.current = p;
    setPath(p);
  };
  const clearSel = () => {
    setSelected(new Set());
    lastClicked.current = null;
  };
  const navigate = (p: string) => {
    clearSel();
    setFilter("");
    const np = p || "/";
    setPathSynced(np);
    refresh(np);
  };

  // ---- carregamento inicial + eventos do SO ----
  useEffect(() => {
    refresh("/");
    let active = true;
    const unsubs: (() => void)[] = [];
    const track = (u: () => void) => (active ? unsubs.push(u) : u());
    onAddProgress((p) => {
      const pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
      setProgress({
        label: `Adicionando ${p.file} — ${pct}% (${fmtBytes(p.done)} / ${fmtBytes(p.total)})`,
        pct,
      });
    }).then(track);
    onOsDrag({
      enter: () => setDragOver(true),
      leave: () => setDragOver(false),
      drop: (paths) => {
        setDragOver(false);
        guarded(async () => {
          setProgress({ label: "Adicionando…", pct: 0 });
          try {
            const n = await api.addDropped(paths, pathRef.current);
            await refresh();
            if (n > 0) toast(`${n} item(ns) adicionado(s)`);
          } finally {
            setProgress(null);
          }
        });
      },
    }).then((us) => us.forEach(track));
    return () => {
      active = false;
      unsubs.forEach((u) => u());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---- seleção ----
  const handleSelect = (name: string, e: { shiftKey: boolean; ctrlKey: boolean; metaKey: boolean }) => {
    const names = visible.map((x) => x.name);
    setSelected((prev) => {
      const next = new Set(prev);
      if (e.shiftKey && lastClicked.current) {
        const a = names.indexOf(lastClicked.current);
        const b = names.indexOf(name);
        if (a >= 0 && b >= 0) {
          if (!e.ctrlKey && !e.metaKey) next.clear();
          const [lo, hi] = a < b ? [a, b] : [b, a];
          for (let i = lo; i <= hi; i++) next.add(names[i]);
        }
      } else if (e.ctrlKey || e.metaKey) {
        next.has(name) ? next.delete(name) : next.add(name);
        lastClicked.current = name;
      } else {
        next.clear();
        next.add(name);
        lastClicked.current = name;
      }
      return next;
    });
  };
  const selectedPaths = () => [...selected].map((n) => joinPath(path, n));
  const selectAll = () => setSelected(new Set(visible.map((x) => x.name)));

  // ---- ações sobre caminhos explícitos ----
  const extractPaths = (paths: string[]) =>
    paths.length &&
    guarded(async () => {
      toast(`⏳ extraindo ${paths.length} arquivo(s)…`, { sticky: true });
      const dest = await api.extractFiles(paths);
      if (dest) toast(`${paths.length} arquivo(s) extraído(s) para ${dest}`);
    });
  const removeMany = (paths: string[]) =>
    paths.length &&
    guarded(async () => {
      if (!confirm(`Excluir ${paths.length} item(ns)? Pastas serão removidas com todo o conteúdo.`)) return;
      await api.removePaths(paths);
      clearSel();
      await refresh();
      toast(`${paths.length} item(ns) removido(s)`);
    });
  const cutPaths = (paths: string[]) => {
    if (!paths.length) return;
    setClipboard(paths);
    toast(`✂️ ${paths.length} item(ns) recortado(s) — abra a pasta destino e clique em 📋 Colar`);
    clearSel();
  };
  const moveTo = (paths: string[], destDir: string) =>
    guarded(async () => {
      await api.movePaths(paths, destDir);
      clearSel();
      await refresh();
      toast("movido");
    });
  const doPaste = () => {
    if (!clipboard.length) return;
    const items = clipboard;
    guarded(async () => {
      await api.movePaths(items, path);
      setClipboard([]);
      await refresh();
      toast(`${items.length} item(ns) movido(s) para cá`);
    });
  };

  const doExtractMany = () => extractPaths(selectedPaths());
  const doRemoveMany = () => removeMany(selectedPaths());
  const doCut = () => cutPaths(selectedPaths());

  // ---- ações de item único ----
  const openEntry = (name: string) => navigate(joinPath(path, name));
  const extractOne = (name: string) =>
    guarded(async () => {
      const saved = await api.extractFile(joinPath(path, name));
      if (saved) toast(`extraído para ${saved}`);
    });
  const removeOne = (name: string, isDir: boolean) =>
    guarded(async () => {
      const what = isDir ? `a pasta "${name}" e tudo dentro dela` : `"${name}"`;
      if (!confirm(`Remover ${what}?`)) return;
      await api.removePath(joinPath(path, name), isDir);
      await refresh();
      toast("removido");
    });

  // ---- resultados de busca (caminhos completos) ----
  const revealHit = (p: string, isDir: boolean) => {
    setScope("folder");
    if (isDir) {
      navigate(p);
      return;
    }
    const idx = p.lastIndexOf("/");
    const parent = idx > 0 ? p.slice(0, idx) : "/";
    const base = p.slice(idx + 1);
    navigate(parent);
    setFilter(base); // realça o item na pasta
  };
  const extractHit = (p: string) =>
    guarded(async () => {
      const saved = await api.extractFile(p);
      if (saved) toast(`extraído para ${saved}`);
    });
  const removeHit = (p: string, isDir: boolean) =>
    guarded(async () => {
      const what = isDir ? `a pasta "${p}" e tudo dentro dela` : `"${p}"`;
      if (!confirm(`Remover ${what}?`)) return;
      await api.removePath(p, isDir);
      await refresh();
      runSearch();
      toast("removido");
    });

  // ---- criação / renomeação inline ----
  const commitNew = (kind: NewKind, name: string) => {
    setPendingNew(null);
    const nm = name.trim();
    if (!nm) return;
    guarded(async () => {
      const full = joinPath(path, nm);
      if (kind === "dir") await api.makeDir(full);
      else await api.newFile(full);
      await refresh();
      toast(kind === "dir" ? "pasta criada" : "arquivo criado");
    });
  };
  const commitRename = (oldName: string, newName: string) => {
    setRenaming(null);
    const nm = newName.trim();
    if (!nm || nm === oldName) return;
    guarded(async () => {
      await api.renamePath(joinPath(path, oldName), joinPath(path, nm));
      await refresh();
      toast("renomeado");
    });
  };

  // ---- toolbar ----
  const addFilesHere = () =>
    guarded(async () => {
      setProgress({ label: "Adicionando…", pct: 0 });
      try {
        const n = await api.addFiles(path);
        await refresh();
        if (n > 0) toast(`${n} arquivo(s) adicionado(s)`);
      } finally {
        setProgress(null);
      }
    });
  const addFolderHere = () =>
    guarded(async () => {
      setProgress({ label: "Adicionando pasta…", pct: 0 });
      try {
        const n = await api.addFolder(path);
        await refresh();
        if (n > 0) toast(`${n} arquivo(s) da pasta adicionado(s)`);
      } finally {
        setProgress(null);
      }
    });
  const doMount = () =>
    guarded(async () => {
      const isWin = navigator.userAgent.includes("Windows");
      const def = isWin ? "X:" : "/mnt/fsm";
      const hint = isWin ? "Letra de drive (ex: X:)" : "Diretório de montagem (ex: /mnt/fsm — deve existir)";
      const mp = prompt(hint, def);
      if (!mp) return;
      const at = await api.mountDrive(mp);
      onMounted(at);
      toast(`montado em ${at}`);
    });
  const doGc = () =>
    guarded(async () => {
      toast("⏳ Compactando…", { sticky: true });
      await api.gcVault();
      await refresh();
      toast("container compactado");
    });
  const doClose = () =>
    guarded(async () => {
      await api.closeVault();
      onClosed();
    });

  // ---- snapshots ----
  const doSnapCreate = () =>
    guarded(async () => {
      const name = prompt("Nome do snapshot:");
      if (!name) return;
      await api.snapshotCreate(name);
      await refresh();
      toast(`snapshot "${name}" criado`);
    });
  const doSnapRestore = (name: string) =>
    guarded(async () => {
      if (!confirm(`Restaurar a árvore para o snapshot "${name}"? Isso substitui os arquivos atuais.`)) return;
      await api.snapshotRestore(name);
      navigate("/");
      toast(`restaurado para "${name}"`);
    });
  const doSnapDelete = (name: string) =>
    guarded(async () => {
      if (!confirm(`Apagar o snapshot "${name}"?`)) return;
      await api.snapshotDelete(name);
      await refresh();
      toast("snapshot apagado");
    });

  // ---- menus de contexto ----
  const openRowMenu = (x: number, y: number, name: string, isDir: boolean) => {
    const inSel = selected.has(name);
    const multi = inSel && selected.size > 1;
    if (!inSel) {
      setSelected(new Set([name]));
      lastClicked.current = name;
    }
    if (multi) {
      const targets = selectedPaths();
      openMenu(x, y, [
        { label: `⬇️ Extrair ${selected.size} itens`, onClick: () => extractPaths(targets) },
        { label: `✂️ Mover ${selected.size} itens`, onClick: () => cutPaths(targets) },
        { label: `🗑️ Excluir ${selected.size} itens`, danger: true, onClick: () => removeMany(targets) },
      ]);
      return;
    }
    const one = [joinPath(path, name)];
    openMenu(
      x,
      y,
      isDir
        ? [
            { label: "📂 Abrir", onClick: () => openEntry(name) },
            { label: "✏️ Renomear", onClick: () => setRenaming(name) },
            { label: "✂️ Mover", onClick: () => cutPaths(one) },
            { label: "🗑️ Excluir", danger: true, onClick: () => removeOne(name, true) },
          ]
        : [
            { label: "⬇️ Extrair", onClick: () => extractOne(name) },
            { label: "✏️ Renomear", onClick: () => setRenaming(name) },
            { label: "✂️ Mover", onClick: () => cutPaths(one) },
            { label: "🗑️ Excluir", danger: true, onClick: () => removeOne(name, false) },
          ]
    );
  };
  const openBackgroundMenu = (x: number, y: number) => {
    clearSel();
    const items = [
      { label: "📁 Nova pasta", onClick: () => setPendingNew("dir") },
      { label: "📄 Novo arquivo", onClick: () => setPendingNew("file") },
      { label: "➕ Adicionar arquivos…", onClick: addFilesHere },
      { label: "📂 Adicionar pasta…", onClick: addFolderHere },
    ];
    if (clipboard.length) items.push({ label: `📋 Colar (${clipboard.length})`, onClick: doPaste });
    if (visible.length) items.push({ label: "☑️ Selecionar tudo", onClick: selectAll });
    openMenu(x, y, items);
  };

  // ---- atalhos de teclado ----
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (manageOpen) return;
      const el = document.activeElement;
      if (el && /^(INPUT|TEXTAREA)$/.test(el.tagName)) return;
      if (e.key === "Escape") clearSel();
      else if (e.key === "Delete" && selected.size) {
        e.preventDefault();
        doRemoveMany();
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "a") {
        e.preventDefault();
        selectAll();
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "x" && selected.size) {
        e.preventDefault();
        doCut();
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "v" && clipboard.length) {
        e.preventDefault();
        doPaste();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, clipboard, visible, manageOpen]);

  return (
    <main className={styles.workspace}>
      <StatsBar stats={info.stats} />
      <Toolbar
        path={path}
        clipboardCount={clipboard.length}
        onNavigate={navigate}
        onAdd={addFilesHere}
        onNewFolder={() => setPendingNew("dir")}
        onPaste={doPaste}
        onManage={() => setManageOpen(true)}
        onMount={doMount}
        onGc={doGc}
        onClose={doClose}
        onMoveTo={moveTo}
      />
      {selected.size > 0 && (
        <BatchBar
          count={selected.size}
          onExtract={doExtractMany}
          onMove={doCut}
          onDelete={doRemoveMany}
          onClear={clearSel}
        />
      )}
      <div className={styles.panels}>
        <div className={styles.panel}>
          <div className={styles.panelHead}>
            <input
              className={styles.filter}
              placeholder={scope === "vault" ? "🌐 buscar no cofre inteiro…" : "🔎 filtrar nesta pasta…"}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <div className={styles.headRight}>
              {scope === "folder" && (
                <span className="sub">{filter ? `${visible.length}/${sorted.length}` : `${sorted.length}`}</span>
              )}
              <div className={styles.scope}>
                <button
                  className={`small ${scope === "folder" ? "primary" : "ghost"}`}
                  onClick={() => setScope("folder")}
                >
                  Pasta
                </button>
                <button
                  className={`small ${scope === "vault" ? "primary" : "ghost"}`}
                  onClick={() => setScope("vault")}
                >
                  Cofre
                </button>
              </div>
            </div>
          </div>
          {scope === "vault" ? (
            <SearchView
              results={results}
              query={filter}
              onReveal={revealHit}
              onExtract={extractHit}
              onRemove={removeHit}
            />
          ) : (
            <FileTable
              entries={visible}
              selected={selected}
              currentPath={path}
              sort={sort}
              onSort={onSort}
              pendingNew={pendingNew}
              renaming={renaming}
              onSelect={handleSelect}
              onOpen={openEntry}
              onExtract={extractOne}
              onStartRename={setRenaming}
              onRemove={removeOne}
              onMoveTo={moveTo}
              onCommitNew={commitNew}
              onCancelNew={() => setPendingNew(null)}
              onCommitRename={commitRename}
              onCancelRename={() => setRenaming(null)}
              onRowMenu={openRowMenu}
              onBackgroundMenu={openBackgroundMenu}
            />
          )}
        </div>
        <SnapshotPanel
          snapshots={info.snapshots}
          onCreate={doSnapCreate}
          onRestore={doSnapRestore}
          onDelete={doSnapDelete}
        />
      </div>
      {progress && <Progress label={progress.label} pct={progress.pct} />}
      {dragOver && (
        <div className={styles.dropOverlay}>
          <div className={styles.dropCard}>⬇️ Solte para adicionar nesta pasta</div>
        </div>
      )}
      {manageOpen && (
        <ManageModal stats={info.stats} onClose={() => setManageOpen(false)} onChanged={refresh} />
      )}
    </main>
  );
}
