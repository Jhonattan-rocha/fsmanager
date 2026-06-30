import styles from "./Topbar.module.css";

export default function Topbar({ vaultPath }: { vaultPath: string | null }) {
  return (
    <header className={styles.topbar}>
      <div className={styles.brand}>
        <span className={styles.logo}>🗄️</span>
        <div>
          <h1 className={styles.title}>fsmanager</h1>
          <p className="sub">Gerenciador de container virtual</p>
        </div>
      </div>
      {vaultPath && <div className={styles.vaultPath}>{vaultPath}</div>}
    </header>
  );
}
