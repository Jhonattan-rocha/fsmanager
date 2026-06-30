import { fmtBytes, fmtDate, type Snapshot } from "../api";
import styles from "./SnapshotPanel.module.css";

interface Props {
  snapshots: Snapshot[];
  onCreate: () => void;
  onRestore: (name: string) => void;
  onDelete: (name: string) => void;
}

export default function SnapshotPanel({ snapshots, onCreate, onRestore, onDelete }: Props) {
  return (
    <div className={styles.panel}>
      <div className={styles.head}>
        <h3>Snapshots</h3>
        <button className="small" onClick={onCreate}>
          📸 Criar
        </button>
      </div>
      <ul className={styles.list}>
        {snapshots.length === 0 ? (
          <li className={styles.empty}>nenhum snapshot</li>
        ) : (
          snapshots.map((sn) => (
            <li key={sn.name}>
              <div className={styles.info}>
                <span className={styles.name}>{sn.name}</span>
                <span className={styles.meta}>
                  {sn.files} arq · {fmtBytes(sn.size)} · {fmtDate(sn.created)}
                </span>
              </div>
              <div className={styles.actions}>
                <button className="small" onClick={() => onRestore(sn.name)}>
                  ↩️
                </button>
                <button className="small danger" onClick={() => onDelete(sn.name)}>
                  🗑️
                </button>
              </div>
            </li>
          ))
        )}
      </ul>
    </div>
  );
}
