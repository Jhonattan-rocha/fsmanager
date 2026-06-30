import { fmtBytes, type SearchHit } from "../api";
import styles from "./SearchView.module.css";

interface Props {
  results: SearchHit[];
  query: string;
  onReveal: (path: string, isDir: boolean) => void;
  onExtract: (path: string) => void;
  onRemove: (path: string, isDir: boolean) => void;
}

export default function SearchView({ results, query, onReveal, onExtract, onRemove }: Props) {
  return (
    <div className={styles.wrap}>
      <div className={styles.head}>
        {query.trim()
          ? `${results.length} resultado${results.length === 1 ? "" : "s"} para “${query.trim()}”`
          : "digite para buscar no cofre inteiro"}
      </div>
      {results.length === 0 && query.trim() ? (
        <div className={styles.empty}>nenhum item com esse nome no cofre</div>
      ) : (
        <div className={styles.list}>
          {results.map((h) => {
            const idx = h.path.lastIndexOf("/");
            const parent = idx > 0 ? h.path.slice(0, idx) : "/";
            const base = h.path.slice(idx + 1);
            return (
              <div className={styles.row} key={h.path} onDoubleClick={() => onReveal(h.path, h.is_dir)}>
                <span className={styles.icon}>{h.is_dir ? "📁" : "📄"}</span>
                <div className={styles.label}>
                  <span className={styles.name}>{base}</span>
                  <span className={styles.path}>{parent}</span>
                </div>
                <span className={styles.size}>{h.is_dir ? "" : fmtBytes(h.size)}</span>
                <div className={styles.actions}>
                  <button className="small" title="Ir para a pasta" onClick={() => onReveal(h.path, h.is_dir)}>
                    📂
                  </button>
                  {!h.is_dir && (
                    <button className="small" title="Extrair" onClick={() => onExtract(h.path)}>
                      ⬇️
                    </button>
                  )}
                  <button className="small danger" title="Excluir" onClick={() => onRemove(h.path, h.is_dir)}>
                    🗑️
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
