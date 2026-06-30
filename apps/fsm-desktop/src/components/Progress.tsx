import styles from "./Progress.module.css";

export default function Progress({ label, pct }: { label: string; pct: number }) {
  return (
    <div className={styles.progress}>
      <div className={styles.label}>{label}</div>
      <div className={styles.track}>
        <div className={styles.bar} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
