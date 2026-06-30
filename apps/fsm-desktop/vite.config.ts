import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Config do Vite para o frontend do Tauri.
// - porta fixa 1420 (o tauri.conf.json aponta devUrl para ela)
// - outDir "dist" (frontendDist = "../dist" relativo ao src-tauri)
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    target: "esnext",
  },
});
