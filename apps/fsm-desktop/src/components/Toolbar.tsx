import { Fragment, type DragEvent } from "react";
import { dragState } from "../dragState";
import styles from "./Toolbar.module.css";

interface Props {
  path: string;
  clipboardCount: number;
  onNavigate: (p: string) => void;
  onAdd: () => void;
  onNewFolder: () => void;
  onPaste: () => void;
  onManage: () => void;
  onMount: () => void;
  onGc: () => void;
  onClose: () => void;
  onMoveTo: (paths: string[], destDir: string) => void;
}

export default function Toolbar(p: Props) {
  const parts = p.path.split("/").filter(Boolean);
  const crumbs = [{ label: "🗄️ Cofre", path: "/" }];
  let acc = "";
  for (const part of parts) {
    acc += `/${part}`;
    crumbs.push({ label: part, path: acc });
  }

  const onDragOver = (e: DragEvent) => {
    if (!dragState.items.length) return;
    e.preventDefault();
    e.currentTarget.classList.add(styles.dropTarget);
  };
  const onDragLeave = (e: DragEvent) => e.currentTarget.classList.remove(styles.dropTarget);
  const onDrop = (dest: string) => (e: DragEvent) => {
    e.currentTarget.classList.remove(styles.dropTarget);
    if (!dragState.items.length || dest === p.path) return;
    e.preventDefault();
    const items = dragState.items;
    dragState.items = [];
    p.onMoveTo(items, dest);
  };

  return (
    <div className={styles.toolbar}>
      <nav className={styles.breadcrumbs}>
        {crumbs.map((c, i) => (
          <Fragment key={c.path}>
            {i > 0 && <span className={styles.sep}>/</span>}
            <button
              className={styles.crumb}
              onClick={() => p.onNavigate(c.path)}
              onDragOver={onDragOver}
              onDragLeave={onDragLeave}
              onDrop={onDrop(c.path)}
            >
              {c.label}
            </button>
          </Fragment>
        ))}
      </nav>
      <div className={styles.tools}>
        <button className="primary" onClick={p.onAdd}>
          ➕ Adicionar
        </button>
        <button onClick={p.onNewFolder}>📁 Nova pasta</button>
        {p.clipboardCount > 0 && <button onClick={p.onPaste}>📋 Colar ({p.clipboardCount})</button>}
        <button onClick={p.onManage}>⚙️ Gerenciar</button>
        <button onClick={p.onMount}>🔌 Montar</button>
        <button onClick={p.onGc}>🧹 Compactar</button>
        <button className="ghost" onClick={p.onClose}>
          ✕ Fechar
        </button>
      </div>
    </div>
  );
}
