import { useEffect, useState } from "react";
import { api, type VaultInfo } from "./api";
import Topbar from "./components/Topbar";
import Welcome from "./components/Welcome";
import Workspace from "./components/Workspace";
import Mounted from "./components/Mounted";

type Screen = "welcome" | "workspace" | "mounted";

export default function App() {
  const [screen, setScreen] = useState<Screen>("welcome");
  const [info, setInfo] = useState<VaultInfo | null>(null);
  const [mountPoint, setMountPoint] = useState("");

  // Se já houver um drive montado (ex.: recarregou a UI), restaura a tela.
  useEffect(() => {
    api
      .mountStatus()
      .then((mp) => {
        if (mp) {
          setMountPoint(mp);
          setScreen("mounted");
        }
      })
      .catch(() => {});
  }, []);

  return (
    <>
      <Topbar vaultPath={screen === "workspace" ? info?.path ?? null : null} />
      {screen === "welcome" && (
        <Welcome
          onOpened={(i) => {
            setInfo(i);
            setScreen("workspace");
          }}
        />
      )}
      {screen === "workspace" && info && (
        <Workspace
          initialInfo={info}
          onClosed={() => {
            setInfo(null);
            setScreen("welcome");
          }}
          onMounted={(mp) => {
            setMountPoint(mp);
            setScreen("mounted");
          }}
        />
      )}
      {screen === "mounted" && (
        <Mounted
          mountPoint={mountPoint}
          onUnmounted={() => {
            setMountPoint("");
            setScreen("welcome");
          }}
        />
      )}
    </>
  );
}
