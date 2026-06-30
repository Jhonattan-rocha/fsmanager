import { fmtBytes, fmtPct, type Stats } from "../api";
import styles from "./StatsBar.module.css";

export default function StatsBar({ stats: s }: { stats: Stats }) {
  const lock = s.encrypted ? "🔒 cifrado" : "🔓 aberto";
  const badges: [string, string | number][] = [
    ["Arquivos", s.files],
    ["Blocos únicos", s.unique_blocks],
    ["Snapshots", s.snapshots],
    ["Lógico", fmtBytes(s.logical_bytes)],
    ["Em uso", s.quota ? `${fmtBytes(s.used_bytes)} / ${fmtBytes(s.quota)}` : fmtBytes(s.used_bytes)],
    ["Dedup", fmtPct(s.dedup_savings)],
    ["Compressão", fmtPct(s.compression_savings)],
    ["Economia total", fmtPct(s.total_savings)],
  ];
  return (
    <div className={styles.stats}>
      <div className={`${styles.badge} ${styles.state}`}>{lock}</div>
      {badges.map(([k, v]) => (
        <div className={styles.badge} key={k}>
          <span className={styles.k}>{k}</span>
          <span className={styles.v}>{v}</span>
        </div>
      ))}
    </div>
  );
}
