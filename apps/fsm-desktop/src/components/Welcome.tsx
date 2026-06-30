import { useState } from "react";
import { api, errMsg, type VaultInfo } from "../api";
import { useToast } from "../contexts/ToastContext";

export default function Welcome({ onOpened }: { onOpened: (i: VaultInfo) => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const toast = useToast();

  const run = async (fn: () => Promise<VaultInfo>, creating: boolean) => {
    setError("");
    try {
      toast(creating ? "⏳ Criando cofre…" : "⏳ Abrindo cofre…", { sticky: true });
      const info = await fn();
      onOpened(info);
      toast(creating ? "cofre criado" : "cofre aberto");
    } catch (e) {
      const msg = errMsg(e);
      if (msg.includes("cancel")) return;
      setError(msg);
      toast(msg, { error: true });
    }
  };
  const pw = () => password || null;

  return (
    <section className="welcome">
      <div className="card">
        <h2>Abrir ou criar um cofre</h2>
        <label className="field">
          <span>Senha (deixe vazio para sem criptografia)</span>
          <input
            type="password"
            placeholder="senha do cofre"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <div className="row">
          <button className="primary" onClick={() => run(() => api.openVault(pw()), false)}>
            📂 Abrir cofre…
          </button>
          <button onClick={() => run(() => api.createVault(pw()), true)}>✨ Criar cofre…</button>
        </div>
        <p className="error">{error}</p>
      </div>
    </section>
  );
}
