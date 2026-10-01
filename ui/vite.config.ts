import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  plugins: [svelte()],
  // Fixed port: Tauri's devUrl points here and must not drift.
  server: { port: 1420, strictPort: true },
  build: { target: "es2022", sourcemap: false },
  clearScreen: false,
});
