import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import styles from "./Toast.module.css";

interface ToastOptions {
  error?: boolean;
  sticky?: boolean;
}
type ShowToast = (msg: string, opts?: ToastOptions) => void;

const ToastCtx = createContext<ShowToast>(() => {});

export function useToast(): ShowToast {
  return useContext(ToastCtx);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ msg: string; error: boolean } | null>(null);
  const timer = useRef<number | undefined>(undefined);

  const show = useCallback<ShowToast>((msg, opts) => {
    window.clearTimeout(timer.current);
    setState({ msg, error: !!opts?.error });
    if (!opts?.sticky) {
      timer.current = window.setTimeout(() => setState(null), 3200);
    }
  }, []);

  return (
    <ToastCtx.Provider value={show}>
      {children}
      {state && (
        <div className={`${styles.toast} ${state.error ? styles.error : ""}`}>{state.msg}</div>
      )}
    </ToastCtx.Provider>
  );
}
