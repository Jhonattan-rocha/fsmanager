import styles from "./BatchBar.module.css";

interface Props {
  count: number;
  onExtract: () => void;
  onMove: () => void;
  onDelete: () => void;
  onClear: () => void;
}

export default function BatchBar({ count, onExtract, onMove, onDelete, onClear }: Props) {
  return (
    <div className={styles.batchBar}>
      <span className={styles.count}>
        {count} selecionado{count === 1 ? "" : "s"}
      </span>
      <div className={styles.actions}>
        <button className="small" onClick={onExtract}>
          ⬇️ Extrair
        </button>
        <button className="small" onClick={onMove}>
          ✂️ Mover
        </button>
        <button className="small danger" onClick={onDelete}>
          🗑️ Excluir
        </button>
        <button className="small ghost" onClick={onClear}>
          ✕ Limpar seleção
        </button>
      </div>
    </div>
  );
}
