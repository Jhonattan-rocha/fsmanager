import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import styles from "./ContextMenu.module.css";

export interface MenuItem {
  label: string;
  danger?: boolean;
  onClick: () => void;
}
type OpenMenu = (x: number, y: number, items: MenuItem[]) => void;

const Ctx = createContext<OpenMenu>(() => {});

export function useContextMenu(): OpenMenu {
  return useContext(Ctx);
}

interface MenuState {
  x: number;
  y: number;
  items: MenuItem[];
}

export function ContextMenuProvider({ children }: { children: ReactNode }) {
  const [menu, setMenu] = useState<MenuState | null>(null);

  const open = useCallback<OpenMenu>((x, y, items) => setMenu({ x, y, items }), []);
  const close = useCallback(() => setMenu(null), []);

  useEffect(() => {
    if (!menu) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    window.addEventListener("click", close);
    window.addEventListener("scroll", close, true);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("keydown", onKey);
    };
  }, [menu, close]);

  return (
    <Ctx.Provider value={open}>
      {children}
      {menu && (
        <div className={styles.menu} style={{ left: menu.x, top: menu.y }}>
          {menu.items.map((it, i) => (
            <button
              key={i}
              className={it.danger ? "danger" : ""}
              onClick={() => {
                close();
                it.onClick();
              }}
            >
              {it.label}
            </button>
          ))}
        </div>
      )}
    </Ctx.Provider>
  );
}
