import { useEffect, useState } from "react";
import { api, errMsg, fmtBytes, type Stats } from "../api";
import { useToast } from "../contexts/ToastContext";
import styles from "./ManageModal.module.css";

interface Props {
  stats: Stats;
  onClose: () => void;
  onChanged: () => Promise<void>;
}

export default function ManageModal({ stats, onClose, onChanged }: Props) {
  const [pw, setPw] = useState("");
  const [quotaMb, setQuotaMb] = useState(stats.quota ? String(Math.round(stats.quota / (1024 * 1024))) : "");
  const [error, setError] = useState("");
  const [verify, setVerify] = useState<{ text: string; cls: string } | null>(null);
  const [backup, setBackup] = useState("");
  const [transferMsg, setTransferMsg] = useState("");
  const [replicas, setReplicas] = useState<string[]>([]);
  const [syncMsg, setSyncMsg] = useState("");
  const toast = useToast();

  useEffect(() => {
    api.getReplicas().then(setReplicas).catch(() => {});
  }, []);

  const guarded = async (fn: () => Promise<void>) => {
    setError("");
    try {
      await fn();
    } catch (e) {
      const m = errMsg(e);
      if (m.includes("cancel")) return;
      setError(m);
      toast(m, { error: true });
    }
  };

  const used = stats.used_bytes || 0;
  const quota = stats.quota;
  const pct = quota ? Math.min(100, Math.round((used / quota) * 100)) : 0;

  const applyPw = () =>
    guarded(async () => {
      toast(`⏳ ${pw ? "Aplicando senha" : "Removendo senha"}… re-encriptando o cofre`, { sticky: true });
      await api.changePassword(pw || null);
      await onChanged();
      setPw("");
      toast(pw ? "senha definida" : "senha removida");
    });
  const applyQuota = () =>
    guarded(async () => {
      const mb = parseFloat(quotaMb);
      if (!isFinite(mb) || mb <= 0) {
        setError("informe um valor em MB maior que zero");
        return;
      }
      await api.setQuota(Math.round(mb * 1024 * 1024));
      await onChanged();
      toast("limite aplicado");
    });
  const clearQuota = () =>
    guarded(async () => {
      await api.setQuota(null);
      await onChanged();
      setQuotaMb("");
      toast("limite removido");
    });
  const runVerify = () =>
    guarded(async () => {
      setVerify({ text: "⏳ verificando todos os blocos…", cls: "" });
      const r = await api.verifyVault();
      if (r.healthy) {
        setVerify({ text: `✓ íntegro — ${r.blocks_ok} blocos verificados`, cls: "ok" });
      } else {
        const det = r.errors.slice(0, 3).join("; ");
        setVerify({
          text: `✗ ${r.blocks_bad} ruim(ns), ${r.missing_blocks} ausente(s)${det ? " — " + det : ""} — use 🔧 Reparar`,
          cls: "error",
        });
      }
    });
  const runRepair = () =>
    guarded(async () => {
      if (!confirm("Reparar trunca/remove arquivos com blocos corrompidos (o dado corrompido é perdido). Continuar?"))
        return;
      setVerify({ text: "⏳ reparando…", cls: "" });
      const r = await api.repairVault();
      await onChanged();
      if (r.files_damaged === 0) {
        setVerify({ text: "✓ nada a reparar — cofre íntegro", cls: "ok" });
      } else {
        setVerify({
          text: `${r.files_damaged} arquivo(s): ${r.truncated.length} truncado(s), ${r.removed.length} removido(s). Rode 🧹 Compactar para liberar espaço.`,
          cls: "",
        });
      }
    });
  const doBackup = (full: boolean) =>
    guarded(async () => {
      setBackup("⏳ escolha o destino…");
      const r = await api.backupVault(full);
      if (!r) {
        setBackup("");
        return;
      }
      const mb = (r.bytes_copied / (1024 * 1024)).toFixed(1);
      const tot = (r.total / (1024 * 1024)).toFixed(1);
      setBackup(`✓ ${r.full ? "completo" : "incremental"} — ${mb} MB de ${tot} MB salvos em ${r.dest}`);
      toast("backup concluído");
    });
  const doTransfer = () =>
    guarded(async () => {
      const pw = prompt("Senha do cofre de DESTINO (vazio = sem cifra / novo cofre):", "");
      if (pw === null) return; // cancelou
      const n = await api.transferTo("/", pw || null);
      if (n === null) {
        setTransferMsg("");
        return;
      }
      setTransferMsg(`✓ ${n} arquivo(s) transferido(s)`);
      toast("transferência concluída");
    });
  const doAddReplica = () =>
    guarded(async () => {
      const list = await api.addReplica();
      if (list) setReplicas(list);
    });
  const doRemoveReplica = (path: string) =>
    guarded(async () => {
      setReplicas(await api.removeReplica(path));
    });
  const doSyncReplicas = () =>
    guarded(async () => {
      setSyncMsg("⏳ sincronizando…");
      const res = await api.syncReplicas();
      const okN = res.filter((r) => r.ok).length;
      setSyncMsg(`✓ ${okN}/${res.length} réplica(s) sincronizada(s)`);
      const failed = res.filter((r) => !r.ok);
      if (failed.length) toast(`falha em ${failed.length}: ${failed[0].error ?? ""}`, { error: true });
      else if (res.length) toast("réplicas sincronizadas");
    });

  return (
    <div className={styles.modal} onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className={styles.card}>
        <div className={styles.head}>
          <h2>⚙️ Gerenciar cofre</h2>
          <button className="ghost small" onClick={onClose}>
            ✕
          </button>
        </div>

        <section className={styles.sec}>
          <h3>🔐 Senha</h3>
          <p className="sub">{stats.encrypted ? "🔒 Cofre cifrado (com senha)." : "🔓 Cofre sem senha."}</p>
          <label className="field">
            <span>Nova senha (deixe vazio para REMOVER a senha)</span>
            <input type="password" placeholder="nova senha" value={pw} onChange={(e) => setPw(e.target.value)} />
          </label>
          <button className="primary" onClick={applyPw}>
            Aplicar senha
          </button>
          <p className="sub mini">Re-encripta todo o cofre — pode levar um tempo em cofres grandes.</p>
        </section>

        <section className={styles.sec}>
          <h3>📐 Tamanho</h3>
          <p className="sub">
            {quota ? `Usado ${fmtBytes(used)} de ${fmtBytes(quota)} (${pct}%)` : `Usado ${fmtBytes(used)} — sem limite`}
          </p>
          <div className={styles.usageTrack}>
            <div className={styles.usageBar} style={{ width: `${quota ? pct : 0}%` }} />
          </div>
          <label className="field">
            <span>Limite em MB (vazio = sem limite)</span>
            <input
              type="number"
              min="0"
              step="1"
              placeholder="ex: 1024"
              value={quotaMb}
              onChange={(e) => setQuotaMb(e.target.value)}
            />
          </label>
          <div className="row">
            <button className="primary" onClick={applyQuota}>
              Aplicar limite
            </button>
            <button onClick={clearQuota}>Remover limite</button>
          </div>
        </section>

        <section className={styles.sec}>
          <h3>🛡️ Integridade</h3>
          <p className="sub">Lê e confere o hash de cada bloco — detecta corrupção/bit-rot.</p>
          <div className="row">
            <button onClick={runVerify}>Verificar agora</button>
            <button onClick={runRepair}>🔧 Reparar</button>
          </div>
          {verify && <p className={`sub ${verify.cls}`}>{verify.text}</p>}
        </section>

        <section className={styles.sec}>
          <h3>💾 Backup</h3>
          <p className="sub">
            Salva uma cópia do cofre. Repetir no MESMO arquivo é incremental (copia só o que mudou).
            Funciona com o cofre aberto — o backup é um .vault válido; restaurar = abrir a cópia.
          </p>
          <div className="row">
            <button className="primary" onClick={() => doBackup(false)}>
              Fazer backup…
            </button>
            <button onClick={() => doBackup(true)}>Completo</button>
          </div>
          {backup && <p className="sub ok">{backup}</p>}
        </section>

        <section className={styles.sec}>
          <h3>📤 Transferir</h3>
          <p className="sub">
            Copia os arquivos deste cofre para OUTRO cofre (mescla; cria se não existir). Re-cifra
            com a chave do destino.
          </p>
          <button className="primary" onClick={doTransfer}>
            Transferir tudo para outro cofre…
          </button>
          {transferMsg && <p className="sub ok">{transferMsg}</p>}
        </section>

        <section className={styles.sec}>
          <h3>🔁 Réplicas</h3>
          <p className="sub">
            Cópias-espelho mantidas em sincronia (backup incremental). Failover = abrir a réplica.
          </p>
          {replicas.length > 0 && (
            <ul className={styles.replicaList}>
              {replicas.map((r) => (
                <li key={r}>
                  <span className={styles.replicaPath}>{r}</span>
                  <button className="small ghost" title="Remover" onClick={() => doRemoveReplica(r)}>
                    ✕
                  </button>
                </li>
              ))}
            </ul>
          )}
          <div className="row">
            <button onClick={doAddReplica}>➕ Adicionar réplica…</button>
            <button className="primary" onClick={doSyncReplicas} disabled={replicas.length === 0}>
              🔄 Sincronizar todas
            </button>
          </div>
          {syncMsg && <p className="sub ok">{syncMsg}</p>}
        </section>

        <p className="error">{error}</p>
      </div>
    </div>
  );
}
