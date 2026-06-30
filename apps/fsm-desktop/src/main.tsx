import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { ToastProvider } from "./contexts/ToastContext";
import { ContextMenuProvider } from "./contexts/ContextMenuContext";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ToastProvider>
      <ContextMenuProvider>
        <App />
      </ContextMenuProvider>
    </ToastProvider>
  </React.StrictMode>
);
