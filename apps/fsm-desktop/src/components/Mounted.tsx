import { useState } from "react";
import { api, errMsg } from "../api";
import { useToast } from "../contexts/ToastContext";

export default function Mounted({
  mountPoint,
  onUnmounted,
}: {
  mountPoint: string;
  onUnmounted: () => void;
}) {
  const [error, setError] = useState("");
  const toast = useToast();

  const unmount = async () => {
    setError("");
    try {
      await api.unmountDrive();
      onUnmounted();
      toast("desmontado");
    } catch (e) {
      const msg = errMsg(e);
      setError(msg);
      toast(msg, { error: true });
    }
  };

  return (
    <section className="welcome">
      <div className="card">
        <h2>🔌 Cofre montado como drive</h2>
        <p>
          Montado em <b>{mountPoint}</b>.
        </p>
        <p className="sub">
          Edite os arquivos pelo gerenciador de arquivos do sistema (Explorer, Files, etc.). O app
          fechou o cofre para evitar conflito de escrita — desmonte para voltar a usá-lo aqui.
        </p>
        <button className="primary" onClick={unmount}>
          ⏏ Desmontar
        </button>
        <p className="error">{error}</p>
      </div>
    </section>
  );
}
